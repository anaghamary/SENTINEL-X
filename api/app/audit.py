import hashlib
import json
import threading
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models import AuditLog

GENESIS_HASH = "0" * 64
_append_lock = threading.Lock()


def install_append_only_guards(connection) -> None:
    if connection.dialect.name == "sqlite":
        connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
                BEFORE UPDATE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'audit log is append-only');
                END
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
                BEFORE DELETE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'audit log is append-only');
                END
                """
            )
        )
    elif connection.dialect.name == "postgresql":
        connection.execute(
            text(
                """
                CREATE OR REPLACE FUNCTION reject_audit_log_mutation()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'audit log is append-only';
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )
        connection.execute(
            text(
                """
                DROP TRIGGER IF EXISTS audit_logs_no_mutation ON audit_logs
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TRIGGER audit_logs_no_mutation
                BEFORE UPDATE OR DELETE ON audit_logs
                FOR EACH ROW EXECUTE FUNCTION reject_audit_log_mutation()
                """
            )
        )
        connection.execute(
            text("DROP TRIGGER IF EXISTS audit_logs_no_truncate ON audit_logs")
        )
        connection.execute(
            text(
                """
                CREATE TRIGGER audit_logs_no_truncate
                BEFORE TRUNCATE ON audit_logs
                FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_log_mutation()
                """
            )
        )


def _entry_hash(
    timestamp: str, actor: str, action: str, resource: str, details: str, previous_hash: str
) -> str:
    payload = json.dumps(
        {
            "action": action,
            "actor": actor,
            "details": details,
            "previous_hash": previous_hash,
            "resource": resource,
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit(
    db: Session, actor: str, action: str, resource: str, details: dict | None = None
) -> AuditLog:
    with _append_lock:
        previous = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        previous_hash = previous.entry_hash if previous else GENESIS_HASH
        timestamp = datetime.now(timezone.utc)
        timestamp_text = timestamp.isoformat()
        details_text = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        entry = AuditLog(
            timestamp=timestamp,
            actor=actor,
            action=action,
            resource=resource,
            details=details_text,
            previous_hash=previous_hash,
            entry_hash=_entry_hash(
                timestamp_text, actor, action, resource, details_text, previous_hash
            ),
        )
        db.add(entry)
        db.flush()
        return entry


def verify_audit_chain(entries: list[AuditLog]) -> tuple[bool, str]:
    previous_hash = GENESIS_HASH
    for entry in entries:
        timestamp = entry.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        expected = _entry_hash(
            timestamp.isoformat(),
            entry.actor,
            entry.action,
            entry.resource,
            entry.details,
            previous_hash,
        )
        if entry.previous_hash != previous_hash or entry.entry_hash != expected:
            return False, entry.entry_hash
        previous_hash = entry.entry_hash
    return True, previous_hash
