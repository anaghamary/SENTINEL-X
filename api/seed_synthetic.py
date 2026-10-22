import hashlib
import io
import json
from pathlib import Path

from PIL import Image, ImageDraw
from sqlalchemy import select

from app.audit import append_audit, install_append_only_guards
from app.database import SessionLocal, engine
from app.evidence import (
    ENCRYPTED_PREFIX,
    EVIDENCE_DIR,
    ensure_evidence_encryption,
    store_evidence_bytes,
)
from app.models import Case, CaseStatus, Evidence, Priority, Role, User
from app.seed import init_default_users


SCENARIOS = (
    {
        "title": "Synthetic channel overlap",
        "description": "Fabricated benign chat export with repeated demo identifiers and simple review cues.",
        "priority": Priority.MEDIUM,
        "handle": "@synthetic_guide",
        "guest": "@demo_guest_a",
        "messages": [
            {"from": "@synthetic_guide", "date": "2026-01-10T09:00:00Z", "text": "This is a fabricated training conversation."},
            {"from": "@synthetic_guide", "date": "2026-01-10T09:15:00Z", "text": "Keep this conversation private; you can trust me."},
            {"from": "@demo_guest_a", "date": "2026-01-10T09:20:00Z", "text": "Understood. This is test-only material."},
        ],
    },
    {
        "title": "Synthetic URL reuse",
        "description": "Harmless graph fixture using a deliberately fake reserved-domain URL and dummy identifiers.",
        "priority": Priority.LOW,
        "handle": "@synthetic_guide",
        "guest": "@demo_guest_b",
        "messages": [
            {"from": "@synthetic_guide", "date": "2026-01-11T12:00:00Z", "text": "Demo note: visit https://example.invalid/research for the fictional dataset description."},
            {"from": "@demo_guest_b", "date": "2026-01-11T12:10:00Z", "text": "Acknowledged. Synthetic case record only."},
        ],
    },
    {
        "title": "Synthetic media duplicate check",
        "description": "Abstract generated color cards for non-identifying perceptual hash and duplicate testing.",
        "priority": Priority.MEDIUM,
        "handle": "@demo_visual_lab",
        "guest": "@demo_reviewer",
        "messages": [
            {"from": "@demo_visual_lab", "date": "2026-01-12T14:00:00Z", "text": "Generated graphic version alpha for duplicate matching."},
            {"from": "@demo_reviewer", "date": "2026-01-12T14:05:00Z", "text": "Synthetic visual fixture received."},
        ],
    },
)


def synthetic_png(variant: int) -> bytes:
    image = Image.new("RGB", (320, 200), (14, 28, 34))
    draw = ImageDraw.Draw(image)
    palette = [(79, 190, 127), (55, 123, 150), (196, 166, 93)]
    for index, color in enumerate(palette):
        x = 28 + index * 92 + (variant if index == 0 else 0)
        draw.rounded_rectangle((x, 38 + index * 18, x + 65, 142), radius=12, fill=color)
        draw.line((x, 160, x + 65, 160), fill=(215, 226, 224), width=3)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def write_evidence(db, case: Case, uploader: User, filename: str, media_type: str, content: bytes) -> None:
    if db.scalar(select(Evidence).where(Evidence.case_id == case.id, Evidence.original_filename == filename)):
        return
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    storage_key = hashlib.sha256(f"{case.case_number}:{filename}".encode()).hexdigest()[:32] + Path(filename).suffix
    path = EVIDENCE_DIR / storage_key
    if path.exists() and not path.read_bytes().startswith(ENCRYPTED_PREFIX):
        raise RuntimeError(
            f"Legacy plaintext evidence exists at {path}; run encrypt_legacy_evidence.py before seeding."
        )
    if not path.exists():
        store_evidence_bytes(storage_key, content)
    record = Evidence(
        case_id=case.id,
        uploaded_by_id=uploader.id,
        original_filename=filename,
        media_type=media_type,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        storage_key=storage_key,
    )
    db.add(record)
    db.flush()
    append_audit(
        db,
        uploader.username,
        "EVIDENCE_SEEDED",
        f"evidence:{record.id}",
        {"case_number": case.case_number, "filename": filename, "sha256": record.sha256},
    )


def seed() -> None:
    from app.migrations import upgrade_database

    ensure_evidence_encryption()
    upgrade_database()
    if engine.dialect.name == "sqlite":
        with engine.begin() as connection:
            install_append_only_guards(connection)
    with SessionLocal() as db:
        init_default_users(db)
        investigator = db.scalar(select(User).where(User.username == "investigator_alice"))
        if investigator is None:
            raise RuntimeError("Synthetic demo investigator was not initialized")
        created = 0
        for index, scenario in enumerate(SCENARIOS):
            case = db.scalar(select(Case).where(Case.title == scenario["title"]))
            if case is None:
                case = Case(
                    case_number=f"SX-DEMO-{index + 1:03d}",
                    title=scenario["title"],
                    description=scenario["description"],
                    priority=scenario["priority"],
                    status=CaseStatus.OPEN,
                    risk_score=0.0,
                    created_by_id=investigator.id,
                )
                db.add(case)
                db.flush()
                created += 1
                append_audit(
                    db,
                    investigator.username,
                    "CASE_SEEDED",
                    f"case:{case.case_number}",
                    {"synthetic": True, "title": case.title},
                )
            chat = json.dumps(
                {
                    "synthetic": True,
                    "description": "Fabricated benign test messages. No platform export or real account data.",
                    "messages": scenario["messages"],
                },
                indent=2,
            ).encode("utf-8")
            write_evidence(
                db,
                case,
                investigator,
                f"synthetic-chat-{index + 1}.json",
                "application/json",
                chat,
            )
            if index == 2:
                write_evidence(
                    db,
                    case,
                    investigator,
                    "harmless-abstract-card.png",
                    "image/png",
                    synthetic_png(0),
                )
        db.commit()
    print(f"Synthetic seed complete: {created} new cases; rerunning is safe.")


if __name__ == "__main__":
    seed()
