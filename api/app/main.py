import json
import io
import math
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import quote
from uuid import uuid4

import jwt
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.responses import Response, StreamingResponse
from fastapi.security import OAuth2PasswordBearer
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import GENESIS_HASH, append_audit, install_append_only_guards, verify_audit_chain
from app.analysis import analyze_evidence
from app.config import JWT_ALGORITHM, JWT_SECRET
from app.database import SessionLocal, engine, get_db
from app.evidence import (
    commit_upload,
    ensure_evidence_encryption,
    evidence_encryption_enabled,
    evidence_path,
    read_evidence_bytes,
    stage_upload,
)
from app.fusion import assess_case
from app.graph_store import graph_store
from app.models import (
    AnalysisRun,
    AuditLog,
    Case,
    CaseEntityLink,
    CaseStatus,
    CorrelationEntity,
    EntityMention,
    Evidence,
    FusionAssessment,
    ReviewDecision,
    Priority,
    Role,
    User,
)
from app.schemas import (
    AuditResponse,
    AuditVerification,
    CaseCreate,
    CaseResponse,
    CaseUpdate,
    EvidenceResponse,
    LoginRequest,
    LoginResponse,
)
from app.seed import init_default_users
from app.security import create_access_token, verify_password


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from app.migrations import upgrade_database

    upgrade_database()
    with engine.begin() as connection:
        install_append_only_guards(connection)
    graph_store.verify()
    graph_store.ensure_schema()
    with SessionLocal() as db:
        init_default_users(db)
    try:
        yield
    finally:
        graph_store.close()


app = FastAPI(title="Sentinel-X API", version="0.1.0", lifespan=lifespan)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise unauthorized
    user = db.get(User, user_id)
    if user is None:
        raise unauthorized
    return user


def require_roles(*roles: Role):
    def role_guard(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return role_guard


def require_case_access(db: Session, case_id: int, user: User) -> Case:
    case = db.get(Case, case_id)
    if case is None or (user.role == Role.INVESTIGATOR and case.created_by_id != user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return case


def record_view(db: Session, user: User, resource: str) -> None:
    append_audit(db, user.username, "VIEW", resource)
    db.commit()


def _sync_case_graph_projection(db: Session, cases: list[Case]) -> None:
    if not graph_store.enabled:
        return
    case_ids = [case.id for case in cases]
    for case in cases:
        graph_store.upsert_case(case.id, case.case_number, case.title)
    if not case_ids:
        return
    links = (
        db.query(CaseEntityLink, CorrelationEntity)
        .join(CorrelationEntity, CaseEntityLink.entity_id == CorrelationEntity.id)
        .filter(CaseEntityLink.case_id.in_(case_ids))
        .all()
    )
    cases_by_id = {case.id: case for case in cases}
    for link, entity in links:
        case = cases_by_id[link.case_id]
        graph_store.upsert_case_entity(
            case_id=case.id,
            case_number=case.case_number,
            case_title=case.title,
            entity_id=entity.id,
            entity_type=entity.entity_type,
            display_value=entity.display_value,
            link_id=link.id,
            link_status=link.status,
            reason=link.reason,
        )


@app.get("/api/v1/health")
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(select(1))
    graph_store.verify()
    return {
        "status": "ok",
        "service": "sentinel-x",
        "database": engine.dialect.name,
        "graph_store": "neo4j" if graph_store.enabled else "relational",
        "evidence_encryption": "fernet" if evidence_encryption_enabled() else "not_configured",
    }


@app.post("/api/v1/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        append_audit(
            db,
            payload.username,
            "LOGIN_FAILED",
            "auth",
            {"reason": "invalid credentials"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    append_audit(db, user.username, "LOGIN", "auth")
    db.commit()
    return LoginResponse(
        access_token=create_access_token(user),
        role=user.role,
        badge_number=user.badge_number,
    )


@app.get("/api/v1/auth/me")
def who_am_i(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> dict[str, str]:
    record_view(db, user, "auth/me")
    return {"username": user.username, "role": user.role.value, "badge_number": user.badge_number}


@app.get("/api/v1/cases", response_model=list[CaseResponse])
def list_cases(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[Case]:
    record_view(db, user, "cases")
    query = select(Case).order_by(Case.created_at.desc(), Case.id.desc())
    if user.role == Role.INVESTIGATOR:
        query = query.where(Case.created_by_id == user.id)
    return list(db.scalars(query).all())


@app.post("/api/v1/cases", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    user: User = Depends(require_roles(Role.INVESTIGATOR, Role.ADMIN)),
    db: Session = Depends(get_db),
) -> Case:
    case = Case(
        case_number=f"SX-{uuid4().hex[:10].upper()}",
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        status=CaseStatus.OPEN,
        risk_score=0.0,
        created_by_id=user.id,
    )
    db.add(case)
    db.flush()
    append_audit(
        db,
        user.username,
        "CASE_CREATED",
        f"case:{case.case_number}",
        {"priority": case.priority.value, "title": case.title},
    )
    db.commit()
    db.refresh(case)
    graph_store.upsert_case(case.id, case.case_number, case.title)
    return case


@app.get("/api/v1/cases/{case_id}", response_model=CaseResponse)
def get_case(
    case_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    if user.role == Role.INVESTIGATOR and case.created_by_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    record_view(db, user, f"case:{case.case_number}")
    return case


@app.patch("/api/v1/cases/{case_id}", response_model=CaseResponse)
def update_case(
    case_id: int,
    payload: CaseUpdate,
    user: User = Depends(require_roles(Role.INVESTIGATOR, Role.ADMIN)),
    db: Session = Depends(get_db),
) -> Case:
    case = db.get(Case, case_id)
    if case is None or (user.role == Role.INVESTIGATOR and case.created_by_id != user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="No changes supplied")
    for field, value in changes.items():
        if value is not None:
            setattr(case, field, value)
    append_audit(
        db,
        user.username,
        "CASE_UPDATED",
        f"case:{case.case_number}",
        {
            key: value.value if hasattr(value, "value") else value
            for key, value in changes.items()
            if value is not None
        },
    )
    db.commit()
    db.refresh(case)
    return case


@app.get("/api/v1/cases/{case_id}/evidence", response_model=list[EvidenceResponse])
def list_evidence(
    case_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[EvidenceResponse]:
    case = require_case_access(db, case_id, user)
    record_view(db, user, f"evidence-list:case:{case.case_number}")
    rows = (
        db.query(Evidence, User.username)
        .join(User, Evidence.uploaded_by_id == User.id)
        .filter(Evidence.case_id == case.id)
        .order_by(Evidence.id.desc())
        .all()
    )
    return [
        EvidenceResponse(
            id=evidence.id,
            case_id=evidence.case_id,
            original_filename=evidence.original_filename,
            media_type=evidence.media_type,
            size_bytes=evidence.size_bytes,
            sha256=evidence.sha256,
            uploaded_by=username,
            created_at=evidence.created_at,
        )
        for evidence, username in rows
    ]


@app.post(
    "/api/v1/cases/{case_id}/evidence",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_evidence(
    case_id: int,
    file: UploadFile = File(...),
    synthetic_data_confirmed: bool = Form(...),
    user: User = Depends(require_roles(Role.INVESTIGATOR, Role.ADMIN)),
    db: Session = Depends(get_db),
) -> EvidenceResponse:
    if not synthetic_data_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only synthetic or harmless benign test files may be uploaded",
        )
    case = require_case_access(db, case_id, user)
    try:
        ensure_evidence_encryption()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    staged_content = None
    storage_key = None
    try:
        staged_content, filename, media_type, size, sha256 = await stage_upload(file)
        storage_key = commit_upload(staged_content, filename)
        evidence = Evidence(
            case_id=case.id,
            uploaded_by_id=user.id,
            original_filename=filename,
            media_type=media_type,
            size_bytes=size,
            sha256=sha256,
            storage_key=storage_key,
        )
        db.add(evidence)
        db.flush()
        append_audit(
            db,
            user.username,
            "EVIDENCE_UPLOADED",
            f"evidence:{evidence.id}",
            {
                "case_number": case.case_number,
                "filename": filename,
                "media_type": media_type,
                "sha256": sha256,
                "size_bytes": size,
            },
        )
        db.commit()
        db.refresh(evidence)
    except Exception:
        db.rollback()
        if storage_key:
            evidence_path(storage_key).unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    return EvidenceResponse(
        id=evidence.id,
        case_id=evidence.case_id,
        original_filename=evidence.original_filename,
        media_type=evidence.media_type,
        size_bytes=evidence.size_bytes,
        sha256=evidence.sha256,
        uploaded_by=user.username,
        created_at=evidence.created_at,
    )


@app.get("/api/v1/evidence/{evidence_id}/download")
def download_evidence(
    evidence_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    case = require_case_access(db, evidence.case_id, user)
    try:
        content = read_evidence_bytes(evidence.storage_key, evidence.sha256)
    except FileNotFoundError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file is unavailable")
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    append_audit(
        db,
        user.username,
        "EVIDENCE_DOWNLOADED",
        f"evidence:{evidence.id}",
        {"case_number": case.case_number, "sha256": evidence.sha256},
    )
    db.commit()
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(evidence.original_filename, safe='')}",
            "X-Content-Type-Options": "nosniff",
        },
    )


def _analysis_dict(run: AnalysisRun) -> dict:
    return {
        "id": run.id,
        "case_id": run.case_id,
        "evidence_id": run.evidence_id,
        "signals": json.loads(run.signals_json),
        "requested_by_id": run.requested_by_id,
        "created_at": run.created_at.isoformat(),
    }


@app.post("/api/v1/cases/{case_id}/evidence/{evidence_id}/analyze")
def run_evidence_analysis(
    case_id: int,
    evidence_id: int,
    user: User = Depends(require_roles(Role.INVESTIGATOR, Role.ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    case = require_case_access(db, case_id, user)
    evidence = db.get(Evidence, evidence_id)
    if evidence is None or evidence.case_id != case.id:
        raise HTTPException(status_code=404, detail="Evidence not found in this case")
    prior_query = (
        db.query(AnalysisRun)
        .join(Case, AnalysisRun.case_id == Case.id)
        .filter(AnalysisRun.evidence_id != evidence.id)
    )
    if user.role == Role.INVESTIGATOR:
        prior_query = prior_query.filter(Case.created_by_id == user.id)
    prior_runs = prior_query.all()
    try:
        content = read_evidence_bytes(evidence.storage_key, evidence.sha256)
        signals = analyze_evidence(db, evidence, prior_runs, evidence_content=content)
    except ValueError as error:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(error)) from error
    except FileNotFoundError as error:
        raise HTTPException(status_code=404, detail="Evidence file is unavailable") from error
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    run = AnalysisRun(
        case_id=case.id,
        evidence_id=evidence.id,
        requested_by_id=user.id,
        signals_json=json.dumps(signals, sort_keys=True),
    )
    db.add(run)
    db.flush()
    append_audit(
        db,
        user.username,
        "ANALYSIS_COMPLETED",
        f"analysis:{run.id}",
        {"case_number": case.case_number, "evidence_id": evidence.id, "signal_types": list(signals)},
    )
    db.commit()
    db.refresh(run)
    _sync_case_graph_projection(db, [case])
    return _analysis_dict(run)


@app.get("/api/v1/cases/{case_id}/analysis")
def list_case_analysis(
    case_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    case = require_case_access(db, case_id, user)
    record_view(db, user, f"analysis:case:{case.case_number}")
    runs = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.case_id == case.id)
        .order_by(AnalysisRun.created_at.desc(), AnalysisRun.id.desc())
        .all()
    )
    return [_analysis_dict(run) for run in runs]


@app.post("/api/v1/cases/{case_id}/fusion")
def fuse_case_signals(
    case_id: int,
    user: User = Depends(require_roles(Role.INVESTIGATOR, Role.ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    case = require_case_access(db, case_id, user)
    evidence_rows = db.query(Evidence).filter(Evidence.case_id == case.id).all()
    if not evidence_rows:
        raise HTTPException(status_code=409, detail="Add benign synthetic evidence before fusion")
    evidence_ids = [item.id for item in evidence_rows]
    runs = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.evidence_id.in_(evidence_ids))
        .order_by(AnalysisRun.created_at.desc())
        .all()
    )
    assessment_data = assess_case(evidence_rows, runs)
    assessment = FusionAssessment(
        case_id=case.id,
        created_by_id=user.id,
        score=assessment_data["score"],
        tier=assessment_data["tier"],
        explanation_json=json.dumps(assessment_data, sort_keys=True),
    )
    db.add(assessment)
    db.flush()
    append_audit(
        db,
        user.username,
        "FUSION_ASSESSED",
        f"assessment:{assessment.id}",
        {"case_number": case.case_number, "score": assessment.score, "tier": assessment.tier},
    )
    db.commit()
    assessment_data.update({"id": assessment.id, "case_id": case.id, "created_at": assessment.created_at.isoformat()})
    return assessment_data


@app.get("/api/v1/cases/{case_id}/fusion")
def list_case_fusion(
    case_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    case = require_case_access(db, case_id, user)
    record_view(db, user, f"fusion:case:{case.case_number}")
    rows = (
        db.query(FusionAssessment)
        .filter(FusionAssessment.case_id == case.id)
        .order_by(FusionAssessment.created_at.desc())
        .all()
    )
    return [
        {
            **json.loads(row.explanation_json),
            "id": row.id,
            "case_id": row.case_id,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


@app.get("/api/v1/graph")
def get_correlation_graph(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    cases_query = select(Case).order_by(Case.id)
    if user.role == Role.INVESTIGATOR:
        cases_query = cases_query.where(Case.created_by_id == user.id)
    cases = list(db.scalars(cases_query).all())
    case_ids = [case.id for case in cases]
    if not case_ids:
        record_view(db, user, "correlation-graph")
        return {"nodes": [], "edges": []}
    _sync_case_graph_projection(db, cases)
    if graph_store.enabled:
        graph = graph_store.case_graph(case_ids)
        record_view(db, user, "correlation-graph")
        return graph
    links = (
        db.query(CaseEntityLink, CorrelationEntity)
        .join(CorrelationEntity, CaseEntityLink.entity_id == CorrelationEntity.id)
        .filter(CaseEntityLink.case_id.in_(case_ids))
        .all()
    )
    nodes = [
        {"data": {"id": f"case-{case.id}", "label": case.case_number, "kind": "case", "title": case.title}}
        for case in cases
    ]
    edges = []
    for link, entity in links:
        entity_key = f"entity-{entity.id}"
        if not any(node["data"]["id"] == entity_key for node in nodes):
            nodes.append(
                {
                    "data": {
                        "id": entity_key,
                        "label": entity.display_value,
                        "kind": entity.entity_type,
                    }
                }
            )
        edges.append(
            {
                "data": {
                    "id": f"link-{link.id}",
                    "source": f"case-{link.case_id}",
                    "target": entity_key,
                    "label": link.status.lower(),
                    "status": link.status,
                    "link_id": link.id,
                    "reason": link.reason,
                }
            }
        )
    record_view(db, user, "correlation-graph")
    return {"nodes": nodes, "edges": edges}


@app.post("/api/v1/graph/links/{link_id}/confirm")
def confirm_graph_link(
    link_id: int,
    user: User = Depends(require_roles(Role.INVESTIGATOR, Role.REVIEWER, Role.ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    link = db.get(CaseEntityLink, link_id)
    if link is None:
        raise HTTPException(status_code=404, detail="Correlation link not found")
    case = require_case_access(db, link.case_id, user)
    link.status = "CONFIRMED"
    link.updated_by_id = user.id
    link.updated_at = datetime.now(timezone.utc)
    entity = db.get(CorrelationEntity, link.entity_id)
    append_audit(
        db,
        user.username,
        "CORRELATION_CONFIRMED",
        f"case-entity-link:{link.id}",
        {"case_number": case.case_number, "entity_id": link.entity_id, "status": "CONFIRMED"},
    )
    db.commit()
    if entity is not None:
        graph_store.upsert_case_entity(
            case_id=case.id,
            case_number=case.case_number,
            case_title=case.title,
            entity_id=entity.id,
            entity_type=entity.entity_type,
            display_value=entity.display_value,
            link_id=link.id,
            link_status=link.status,
            reason=link.reason,
        )
    return {"id": link.id, "status": link.status, "confirmed_by": user.username}


@app.get("/api/v1/review-queue")
def get_review_queue(
    user: User = Depends(require_roles(Role.REVIEWER, Role.ADMIN)),
    db: Session = Depends(get_db),
) -> list[dict]:
    assessments = (
        db.query(FusionAssessment, Case)
        .join(Case, FusionAssessment.case_id == Case.id)
        .outerjoin(ReviewDecision, ReviewDecision.assessment_id == FusionAssessment.id)
        .filter(ReviewDecision.id.is_(None))
        .filter(FusionAssessment.tier.in_(["HIGH", "AMBIGUOUS"]))
        .order_by(FusionAssessment.created_at.asc())
        .all()
    )
    append_audit(db, user.username, "VIEW", "review-queue")
    db.commit()
    return [
        {
            "assessment_id": assessment.id,
            "case_id": case.id,
            "case_number": case.case_number,
            "case_title": case.title,
            "score": assessment.score,
            "tier": assessment.tier,
            "explanation": json.loads(assessment.explanation_json),
            "signal_runs": [
                _analysis_dict(run)
                for run in db.query(AnalysisRun)
                .filter(AnalysisRun.case_id == case.id)
                .order_by(AnalysisRun.created_at.desc())
                .all()
            ],
            "created_at": assessment.created_at.isoformat(),
        }
        for assessment, case in assessments
    ]


@app.post("/api/v1/review-queue/{assessment_id}/decision")
def decide_review(
    assessment_id: int,
    payload: dict,
    user: User = Depends(require_roles(Role.REVIEWER, Role.ADMIN)),
    db: Session = Depends(get_db),
) -> dict:
    decision_value = payload.get("decision")
    notes = payload.get("notes", "")
    if decision_value not in {"CONFIRM", "REJECT", "ESCALATE"}:
        raise HTTPException(status_code=422, detail="Decision must be CONFIRM, REJECT, or ESCALATE")
    if not isinstance(notes, str) or len(notes) > 2000:
        raise HTTPException(status_code=422, detail="Notes must be 2000 characters or fewer")
    assessment = db.get(FusionAssessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    prior = db.query(ReviewDecision).filter_by(assessment_id=assessment.id).first()
    if prior:
        raise HTTPException(status_code=409, detail="This assessment already has a recorded decision")
    case = require_case_access(db, assessment.case_id, user)
    decision = ReviewDecision(
        assessment_id=assessment.id,
        reviewer_id=user.id,
        decision=decision_value,
        notes=notes.strip(),
    )
    db.add(decision)
    db.flush()
    append_audit(
        db,
        user.username,
        "REVIEW_DECISION",
        f"assessment:{assessment.id}",
        {
            "case_number": case.case_number,
            "decision": decision_value,
            "notes": notes.strip(),
            "score": assessment.score,
            "tier": assessment.tier,
        },
    )
    db.commit()
    return {
        "id": decision.id,
        "assessment_id": assessment.id,
        "case_id": case.id,
        "decision": decision.decision,
        "reviewer": user.username,
        "notes": decision.notes,
        "created_at": decision.created_at.isoformat(),
    }


@app.get("/api/v1/cases/{case_id}/report.pdf")
def case_report(
    case_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    case = require_case_access(db, case_id, user)
    evidence_rows = db.query(Evidence).filter(Evidence.case_id == case.id).order_by(Evidence.id).all()
    analyses = db.query(AnalysisRun).filter(AnalysisRun.case_id == case.id).order_by(AnalysisRun.id).all()
    assessments = db.query(FusionAssessment).filter(FusionAssessment.case_id == case.id).order_by(FusionAssessment.id).all()
    decisions = (
        db.query(ReviewDecision, User.username)
        .join(User, ReviewDecision.reviewer_id == User.id)
        .join(FusionAssessment, ReviewDecision.assessment_id == FusionAssessment.id)
        .filter(FusionAssessment.case_id == case.id)
        .order_by(ReviewDecision.id)
        .all()
    )
    case_links = (
        db.query(CaseEntityLink, CorrelationEntity)
        .join(CorrelationEntity, CaseEntityLink.entity_id == CorrelationEntity.id)
        .filter(CaseEntityLink.case_id == case.id)
        .all()
    )
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    page_width, page_height = letter
    y = page_height - 52

    def write_line(text: str, *, font_size: int = 10, indent: int = 50) -> None:
        nonlocal y
        if y < 55:
            pdf.showPage()
            y = page_height - 52
        pdf.setFont("Helvetica", font_size)
        safe_text = text.encode("latin-1", "replace").decode("latin-1")
        for chunk in [safe_text[index : index + 105] for index in range(0, len(safe_text), 105)] or [""]:
            if y < 55:
                pdf.showPage()
                y = page_height - 52
            pdf.drawString(indent, y, chunk)
            y -= font_size + 5

    write_line("SENTINEL-X | SYNTHETIC EVIDENCE REPORT", font_size=16)
    write_line("Human-in-the-loop: no autonomous actions", font_size=10)
    write_line(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    write_line(f"Case: {case.case_number} | {case.title}", font_size=13)
    write_line(f"Status: {case.status.value} | Priority: {case.priority.value}")
    write_line(f"Summary: {case.description or 'No summary provided'}")
    timeline: list[tuple[datetime, str]] = []
    timeline.extend((item.created_at, f"Evidence uploaded: {item.original_filename}") for item in evidence_rows)
    timeline.extend((run.created_at, f"Analysis run {run.id} completed for evidence {run.evidence_id}") for run in analyses)
    timeline.extend((item.created_at, f"Fusion assessment {item.id}: {item.tier} ({item.score:.3f})") for item in assessments)
    timeline.extend((decision.created_at, f"Human review: {decision.decision} by {reviewer_name}") for decision, reviewer_name in decisions)
    if timeline:
        write_line("CASE TIMELINE", font_size=12)
        for event_at, description in sorted(timeline, key=lambda item: item[0].replace(tzinfo=timezone.utc).isoformat()):
            normalized_at = event_at if event_at.tzinfo else event_at.replace(tzinfo=timezone.utc)
            write_line(f"{normalized_at.isoformat()} | {description}", font_size=9)
    write_line("EVIDENCE AND PROVENANCE", font_size=12)
    for item in evidence_rows:
        write_line(f"{item.original_filename} | {item.media_type} | {item.size_bytes} bytes")
        write_line(f"SHA-256: {item.sha256}", font_size=8, indent=65)
    write_line("ANALYSIS SIGNALS", font_size=12)
    for run in analyses:
        signals = json.loads(run.signals_json)
        write_line(f"Run {run.id} | evidence {run.evidence_id} | {run.created_at.isoformat()}")
        language = signals.get("language", {})
        write_line(f"Language cue categories: {', '.join(cue['category'] for cue in language.get('language_cue_categories', [])) or 'none observed'}", font_size=9)
        visual = signals.get("visual", {})
        if visual.get("perceptual_hash"):
            write_line(f"Visual perceptual hash: {visual['perceptual_hash']} | {visual.get('width')}x{visual.get('height')}", font_size=9)
        write_line("Signals are contextual review prompts; no age or identity was estimated.", font_size=9)
    write_line("FUSION ASSESSMENTS (REVIEW PRIORITIZATION ONLY)", font_size=12)
    for assessment in assessments:
        write_line(f"Assessment {assessment.id}: {assessment.tier} | score {assessment.score:.3f}")
        data = json.loads(assessment.explanation_json)
        for name, component in data.get("components", {}).items():
            write_line(f"{name}: observed={component['observed']} contribution={component['contribution']}", font_size=9)
    write_line("CORRELATION NETWORK", font_size=12)
    if case_links:
        if y < 180:
            pdf.showPage()
            y = page_height - 52
        center_x = page_width / 2
        center_y = y - 70
        pdf.setStrokeColor(colors.HexColor("#617b6a"))
        pdf.setFillColor(colors.HexColor("#254333"))
        pdf.roundRect(center_x - 64, center_y - 14, 128, 28, 6, stroke=1, fill=1)
        pdf.setFillColor(colors.white)
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawCentredString(center_x, center_y - 3, case.case_number)
        for index, (link, entity) in enumerate(case_links[:8]):
            angle = (index / max(min(len(case_links), 8), 1)) * 6.28318
            node_x = center_x + 155 * math.cos(angle)
            node_y = center_y + 64 * math.sin(angle)
            pdf.setStrokeColor(colors.HexColor("#8b9a91" if link.status == "POSSIBLE" else "#74c78e"))
            pdf.line(center_x, center_y, node_x, node_y)
            pdf.setFillColor(colors.HexColor("#594e31" if entity.entity_type == "wallet" else "#344c61"))
            pdf.circle(node_x, node_y, 22, stroke=1, fill=1)
            pdf.setFillColor(colors.white)
            pdf.setFont("Helvetica", 6)
            pdf.drawCentredString(node_x, node_y + 2, entity.entity_type[:12])
            pdf.drawCentredString(node_x, node_y - 7, entity.display_value[:16])
            pdf.setFillColor(colors.HexColor("#d8cfb1"))
            pdf.setFont("Helvetica", 6)
            pdf.drawCentredString((center_x + node_x) / 2, (center_y + node_y) / 2 + 3, link.status.lower())
        y = center_y - 112
        for link, entity in case_links:
            related_cases = (
                db.query(Case)
                .join(CaseEntityLink, CaseEntityLink.case_id == Case.id)
                .filter(CaseEntityLink.entity_id == entity.id, Case.id != case.id)
                .all()
            )
            write_line(
                f"{entity.entity_type}: {entity.display_value} — {link.status.lower()} link"
            )
            for related in related_cases:
                write_line(f"Related case: {related.case_number} | {related.title} (possible correlation; human confirmation required)", font_size=9, indent=65)
    else:
        write_line("No extracted entity relationships are available for this case.")
    write_line("HUMAN REVIEW DECISIONS", font_size=12)
    for decision, reviewer_name in decisions:
        write_line(f"{decision.decision} by {reviewer_name} | {decision.created_at.isoformat()}")
        if decision.notes:
            write_line(f"Notes: {decision.notes}", font_size=9)
    write_line("This synthetic MVP report is not an automated finding, law-enforcement referral, or determination about a person.")
    pdf.save()
    buffer.seek(0)
    append_audit(db, user.username, "REPORT_GENERATED", f"case:{case.case_number}", {"case_id": case.id})
    db.commit()
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{case.case_number}-report.pdf"'},
    )


@app.get("/api/v1/audit/logs", response_model=list[AuditResponse])
def list_audit_logs(
    user: User = Depends(require_roles(Role.ADMIN, Role.INVESTIGATOR, Role.REVIEWER)),
    db: Session = Depends(get_db),
) -> list[AuditResponse]:
    append_audit(db, user.username, "VIEW", "audit/logs")
    db.commit()
    entries = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(500).all()
    return [
        AuditResponse(
            id=entry.id,
            timestamp_iso=entry.timestamp.isoformat(),
            actor=entry.actor,
            action=entry.action,
            resource=entry.resource,
            details=entry.details,
            previous_hash=entry.previous_hash,
            entry_hash=entry.entry_hash,
        )
        for entry in entries
    ]


@app.post("/api/v1/audit/verify", response_model=AuditVerification)
def verify_audit(
    user: User = Depends(require_roles(Role.ADMIN, Role.INVESTIGATOR, Role.REVIEWER)),
    db: Session = Depends(get_db),
) -> AuditVerification:
    entries = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    is_valid, latest_hash = verify_audit_chain(entries)
    append_audit(
        db,
        user.username,
        "AUDIT_VERIFIED",
        "audit/logs",
        {"is_valid": is_valid, "verified_records": len(entries)},
    )
    db.commit()
    return AuditVerification(
        is_valid=is_valid,
        total_records=len(entries),
        genesis_hash=GENESIS_HASH,
        latest_hash=latest_hash,
        message="Audit chain is valid" if is_valid else "Audit chain integrity check failed",
    )
