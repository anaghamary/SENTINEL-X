from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models import CaseStatus, Priority, Role


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role
    badge_number: str


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10_000)
    priority: Priority = Priority.MEDIUM


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    priority: Priority | None = None
    status: CaseStatus | None = None
    risk_score: float | None = Field(default=None, ge=0, le=1)


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_number: str
    title: str
    description: str
    priority: Priority
    status: CaseStatus
    risk_score: float
    created_by_id: int
    created_at: datetime
    updated_at: datetime


class AuditResponse(BaseModel):
    id: int
    timestamp_iso: str
    actor: str
    action: str
    resource: str
    details: str
    previous_hash: str
    entry_hash: str


class AuditVerification(BaseModel):
    is_valid: bool
    total_records: int
    genesis_hash: str
    latest_hash: str
    message: str


class EvidenceResponse(BaseModel):
    id: int
    case_id: int
    original_filename: str
    media_type: str
    size_bytes: int
    sha256: str
    uploaded_by: str
    created_at: datetime
