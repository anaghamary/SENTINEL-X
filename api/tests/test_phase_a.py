import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.audit import install_append_only_guards
from app.database import Base, get_db
from app.main import app
from app.models import Role, User
from app.seed import init_default_users
from app.security import hash_password


@pytest.fixture()
def client(monkeypatch):
    from cryptography.fernet import Fernet

    from app import evidence as evidence_module

    monkeypatch.setattr(
        evidence_module, "EVIDENCE_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii")
    )
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSession = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=test_engine)
    with test_engine.begin() as connection:
        install_append_only_guards(connection)
    with TestSession() as db:
        init_default_users(db)
        db.add(
            User(
                username="investigator_bob",
                password_hash=hash_password("Password123!"),
                role=Role.INVESTIGATOR,
                badge_number="INV-002",
            )
        )
        db.commit()

    def override_get_db():
        with TestSession() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client, TestSession
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


def token_for(client: TestClient, username: str, password: str = "Password123!") -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_login_create_update_and_verify_audit(client):
    client, _test_session = client
    headers = token_for(client, "investigator_alice")
    created = client.post(
        "/api/v1/cases",
        json={
            "title": "Synthetic cross-channel analysis",
            "description": "Benign test scenario with fabricated identifiers.",
            "priority": "HIGH",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["case_number"].startswith("SX-")
    assert case["status"] == "OPEN"

    updated = client.patch(
        f"/api/v1/cases/{case['id']}",
        json={"status": "UNDER_REVIEW", "risk_score": 0.82},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["status"] == "UNDER_REVIEW"
    assert updated.json()["risk_score"] == pytest.approx(0.82)

    verification = client.post("/api/v1/audit/verify", headers=headers)
    assert verification.status_code == 200, verification.text
    assert verification.json()["is_valid"] is True
    assert verification.json()["total_records"] >= 3


def test_failed_login_has_non_enumerating_response_and_is_audited(client):
    client, _test_session = client
    known = client.post(
        "/api/v1/auth/login",
        json={"username": "investigator_alice", "password": "wrong"},
    )
    unknown = client.post(
        "/api/v1/auth/login",
        json={"username": "no_such_user", "password": "wrong"},
    )
    assert known.status_code == unknown.status_code == 401
    assert known.json() == unknown.json()
    logs = client.get("/api/v1/audit/logs", headers=token_for(client, "admin_avery"))
    assert logs.status_code == 200
    assert sum(log["action"] == "LOGIN_FAILED" for log in logs.json()) == 2


def test_health_reports_active_local_storage_modes(client):
    from sqlalchemy import inspect

    from app.database import engine

    client, _test_session = client
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["database"] in {"sqlite", "postgresql"}
    assert response.json()["graph_store"] in {"relational", "neo4j"}
    assert response.json()["evidence_encryption"] == "fernet"
    assert "alembic_version" in inspect(engine).get_table_names()


def test_role_boundaries_and_case_isolation(client):
    client, _test_session = client
    alice_headers = token_for(client, "investigator_alice")
    reviewer_headers = token_for(client, "reviewer_riley")
    bob_headers = token_for(client, "investigator_bob")
    forbidden = client.post(
        "/api/v1/cases",
        json={"title": "Reviewer cannot create cases"},
        headers=reviewer_headers,
    )
    assert forbidden.status_code == 403

    created = client.post(
        "/api/v1/cases",
        json={"title": "Private synthetic case"},
        headers=alice_headers,
    )
    assert created.status_code == 201
    case_id = created.json()["id"]
    hidden = client.get(f"/api/v1/cases/{case_id}", headers=reviewer_headers)
    assert hidden.status_code == 200
    other_investigator_case = client.get(f"/api/v1/cases/{case_id}", headers=bob_headers)
    assert other_investigator_case.status_code == 404
    assert client.get("/api/v1/cases", headers=bob_headers).json() == []

    no_token = client.get("/api/v1/cases")
    assert no_token.status_code == 401


def test_audit_log_rejects_mutation_and_detects_chain_tampering(client):
    client, test_session = client
    headers = token_for(client, "investigator_alice")
    client.post("/api/v1/cases", json={"title": "Tamper check"}, headers=headers)
    verify = client.post("/api/v1/audit/verify", headers=headers)
    assert verify.json()["is_valid"] is True

    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    from app.audit import verify_audit_chain
    from app.models import AuditLog

    with test_session() as db:
        entries = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
        valid, _latest = verify_audit_chain(entries)
        assert valid
        entries[-1].details = '{"altered":true}'
        valid, _latest = verify_audit_chain(entries)
        assert not valid
        with pytest.raises(DBAPIError, match="audit log is append-only"):
            db.execute(
                text("UPDATE audit_logs SET details = :details WHERE id = :id"),
                {"details": "tamper", "id": entries[0].id},
            )
        db.rollback()
        with pytest.raises(DBAPIError, match="audit log is append-only"):
            db.execute(
                text("DELETE FROM audit_logs WHERE id = :id"),
                {"id": entries[0].id},
            )
        db.rollback()


def test_synthetic_evidence_upload_hashes_downloads_and_audits(client, monkeypatch, tmp_path):
    from hashlib import sha256

    from app import evidence as evidence_module

    client, _test_session = client
    monkeypatch.setattr(evidence_module, "EVIDENCE_DIR", tmp_path)
    headers = token_for(client, "investigator_alice")
    case = client.post(
        "/api/v1/cases",
        json={"title": "Synthetic evidence intake"},
        headers=headers,
    ).json()
    harmless_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
    uploaded = client.post(
        f"/api/v1/cases/{case['id']}/evidence",
        headers=headers,
        data={"synthetic_data_confirmed": "true"},
        files={"file": ("benign-test.png", harmless_png, "image/png")},
    )
    assert uploaded.status_code == 201, uploaded.text
    item = uploaded.json()
    stored = (tmp_path / next(path.name for path in tmp_path.iterdir() if not path.name.startswith("."))).read_bytes()
    assert stored.startswith(evidence_module.ENCRYPTED_PREFIX)
    assert harmless_png not in stored
    assert item["sha256"] == sha256(harmless_png).hexdigest()
    assert item["size_bytes"] == len(harmless_png)
    assert item["uploaded_by"] == "investigator_alice"

    listed = client.get(f"/api/v1/cases/{case['id']}/evidence", headers=headers)
    assert listed.status_code == 200
    assert [row["id"] for row in listed.json()] == [item["id"]]
    downloaded = client.get(f"/api/v1/evidence/{item['id']}/download", headers=headers)
    assert downloaded.status_code == 200
    assert downloaded.content == harmless_png
    assert "attachment" in downloaded.headers["content-disposition"]

    audit = client.get("/api/v1/audit/logs", headers=headers).json()
    upload_event = next(entry for entry in audit if entry["action"] == "EVIDENCE_UPLOADED")
    assert item["sha256"] in upload_event["details"]
    assert any(entry["action"] == "EVIDENCE_DOWNLOADED" for entry in audit)


def test_evidence_upload_rejects_unsupported_and_mismatched_content(client, monkeypatch, tmp_path):
    from app import evidence as evidence_module

    client, _test_session = client
    monkeypatch.setattr(evidence_module, "EVIDENCE_DIR", tmp_path)
    headers = token_for(client, "investigator_alice")
    case = client.post(
        "/api/v1/cases",
        json={"title": "Synthetic format checks"},
        headers=headers,
    ).json()
    url = f"/api/v1/cases/{case['id']}/evidence"
    unsupported = client.post(
        url,
        headers=headers,
        data={"synthetic_data_confirmed": "true"},
        files={"file": ("payload.exe", b"fake executable bytes", "application/octet-stream")},
    )
    mismatched = client.post(
        url,
        headers=headers,
        data={"synthetic_data_confirmed": "true"},
        files={"file": ("not-a-png.png", b"not an image", "image/png")},
    )
    assert unsupported.status_code == 415
    assert mismatched.status_code == 415
    assert list(tmp_path.iterdir()) == []


def test_evidence_upload_requires_benign_synthetic_attestation(client):
    client, _test_session = client
    headers = token_for(client, "investigator_alice")
    case = client.post(
        "/api/v1/cases",
        json={"title": "Synthetic-only upload gate"},
        headers=headers,
    ).json()
    response = client.post(
        f"/api/v1/cases/{case['id']}/evidence",
        headers=headers,
        files={"file": ("test.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 24, "image/png")},
    )
    assert response.status_code == 422


def test_evidence_upload_requires_encryption_key(client, monkeypatch, tmp_path):
    from app import evidence as evidence_module

    client, _test_session = client
    monkeypatch.setattr(evidence_module, "EVIDENCE_DIR", tmp_path)
    monkeypatch.setattr(evidence_module, "EVIDENCE_ENCRYPTION_KEY", None)
    headers = token_for(client, "investigator_alice")
    case = client.post("/api/v1/cases", json={"title": "Encryption required"}, headers=headers).json()
    response = client.post(
        f"/api/v1/cases/{case['id']}/evidence",
        headers=headers,
        data={"synthetic_data_confirmed": "true"},
        files={"file": ("test.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 24, "image/png")},
    )
    assert response.status_code == 503
    assert "EVIDENCE_ENCRYPTION_KEY" in response.json()["detail"]
    assert list(tmp_path.iterdir()) == []


def test_encrypted_evidence_rejects_wrong_key(client, monkeypatch, tmp_path):
    from cryptography.fernet import Fernet

    from app import evidence as evidence_module

    client, _test_session = client
    monkeypatch.setattr(evidence_module, "EVIDENCE_DIR", tmp_path)
    headers = token_for(client, "investigator_alice")
    case = client.post("/api/v1/cases", json={"title": "Wrong-key test"}, headers=headers).json()
    uploaded = client.post(
        f"/api/v1/cases/{case['id']}/evidence",
        headers=headers,
        data={"synthetic_data_confirmed": "true"},
        files={"file": ("test.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 24, "image/png")},
    )
    assert uploaded.status_code == 201
    monkeypatch.setattr(evidence_module, "EVIDENCE_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    downloaded = client.get(f"/api/v1/evidence/{uploaded.json()['id']}/download", headers=headers)
    assert downloaded.status_code == 503
    assert "decryption failed" in downloaded.json()["detail"].lower()


def test_analysis_fusion_graph_review_and_pdf_report(client, monkeypatch, tmp_path):
    import json
    from hashlib import sha256

    from app import analysis as analysis_module
    from app import evidence as evidence_module

    client, _test_session = client
    monkeypatch.setattr(evidence_module, "EVIDENCE_DIR", tmp_path)
    monkeypatch.setattr(analysis_module, "EVIDENCE_DIR", tmp_path)
    investigator = token_for(client, "investigator_alice")
    reviewer = token_for(client, "reviewer_riley")
    case = client.post(
        "/api/v1/cases",
        json={"title": "Synthetic pattern scenario", "description": "Fabricated messages only."},
        headers=investigator,
    ).json()
    fake_export = {
        "messages": [
            {
                "from": "@sample_operator",
                "date": "2026-01-01T10:00:00Z",
                "text": "You can trust me. Keep this conversation a secret.",
            },
            {
                "from": "@sample_operator",
                "date": "2026-01-01T11:00:00Z",
                "text": "Don't tell anyone. Visit https://demo.invalid/info",
            },
            {
                "from": "@sample_guest",
                "date": "2026-01-01T11:30:00Z",
                "text": "This is a fabricated training example.",
            },
        ]
    }
    content = json.dumps(fake_export).encode()
    uploaded = client.post(
        f"/api/v1/cases/{case['id']}/evidence",
        headers=investigator,
        data={"synthetic_data_confirmed": "true"},
        files={"file": ("synthetic-chat.json", content, "application/json")},
    )
    assert uploaded.status_code == 201, uploaded.text
    evidence_id = uploaded.json()["id"]
    result = client.post(
        f"/api/v1/cases/{case['id']}/evidence/{evidence_id}/analyze",
        headers=investigator,
    )
    assert result.status_code == 200, result.text
    signals = result.json()["signals"]
    assert signals["language"]["cue_category_count"] == 2
    assert signals["behavior"]["message_count"] == 3
    assert signals["behavior"]["repeated_senders"][0]["sender"] == "@sample_operator"
    assert "@sample_operator" in signals["language"]["entities"]["username"]
    assert sha256(content).hexdigest() == uploaded.json()["sha256"]

    fused = client.post(f"/api/v1/cases/{case['id']}/fusion", headers=investigator)
    assert fused.status_code == 200, fused.text
    assert fused.json()["tier"] == "AMBIGUOUS"
    assert fused.json()["review_required"] is True
    assert "no automatic action" in fused.json()["explanation"].lower()

    graph = client.get("/api/v1/graph", headers=investigator)
    assert graph.status_code == 200
    assert any(node["data"]["label"] == "@sample_operator" for node in graph.json()["nodes"])
    possible_link = next(edge["data"] for edge in graph.json()["edges"] if edge["data"]["status"] == "POSSIBLE")
    confirmed = client.post(
        f"/api/v1/graph/links/{possible_link['link_id']}/confirm",
        headers=reviewer,
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "CONFIRMED"

    queue = client.get("/api/v1/review-queue", headers=reviewer)
    assert queue.status_code == 200
    assert queue.json()[0]["assessment_id"] == fused.json()["id"]
    assert len(queue.json()[0]["signal_runs"]) == 1
    decision = client.post(
        f"/api/v1/review-queue/{fused.json()['id']}/decision",
        headers=reviewer,
        json={"decision": "ESCALATE", "notes": "Synthetic example: request human context review."},
    )
    assert decision.status_code == 200, decision.text
    assert decision.json()["decision"] == "ESCALATE"
    duplicate = client.post(
        f"/api/v1/review-queue/{fused.json()['id']}/decision",
        headers=reviewer,
        json={"decision": "REJECT"},
    )
    assert duplicate.status_code == 409

    report = client.get(f"/api/v1/cases/{case['id']}/report.pdf", headers=investigator)
    assert report.status_code == 200
    assert report.headers["content-type"] == "application/pdf"
    assert report.content.startswith(b"%PDF")
    audit = client.get("/api/v1/audit/logs", headers=reviewer).json()
    actions = {entry["action"] for entry in audit}
    assert {"ANALYSIS_COMPLETED", "FUSION_ASSESSED", "CORRELATION_CONFIRMED", "REVIEW_DECISION", "REPORT_GENERATED"} <= actions


def test_image_analysis_uses_non_identifying_perceptual_duplicate_hash(client, monkeypatch, tmp_path):
    import io

    from PIL import Image, ImageDraw

    from app import analysis as analysis_module
    from app import evidence as evidence_module

    client, _test_session = client
    monkeypatch.setattr(evidence_module, "EVIDENCE_DIR", tmp_path)
    monkeypatch.setattr(analysis_module, "EVIDENCE_DIR", tmp_path)
    headers = token_for(client, "investigator_alice")
    case = client.post("/api/v1/cases", json={"title": "Abstract duplicate fixtures"}, headers=headers).json()

    def create_fixture(offset: int) -> bytes:
        image = Image.new("RGB", (80, 60), (20, 50, 80))
        draw = ImageDraw.Draw(image)
        draw.rectangle((15 + offset, 12, 42 + offset, 44), fill=(220, 150, 60))
        stream = io.BytesIO()
        image.save(stream, format="PNG")
        return stream.getvalue()

    results = []
    for filename, content in (("abstract-a.png", create_fixture(0)), ("abstract-b.png", create_fixture(0))):
        uploaded = client.post(
            f"/api/v1/cases/{case['id']}/evidence",
            headers=headers,
            data={"synthetic_data_confirmed": "true"},
            files={"file": (filename, content, "image/png")},
        )
        assert uploaded.status_code == 201, uploaded.text
        analyzed = client.post(
            f"/api/v1/cases/{case['id']}/evidence/{uploaded.json()['id']}/analyze",
            headers=headers,
        )
        assert analyzed.status_code == 200, analyzed.text
        results.append(analyzed.json()["signals"]["visual"])
    assert results[0]["status"] == "complete"
    assert results[0]["width"] == 80
    assert results[1]["duplicate_candidates"][0]["match"] == "exact"
