from hashlib import sha256

from app.audit import append_audit
from app.database import SessionLocal
from app.evidence import ENCRYPTED_PREFIX, ensure_evidence_encryption, evidence_path, store_evidence_bytes
from app.migrations import upgrade_database
from app.models import Evidence
from app.seed import init_default_users


def main() -> None:
    ensure_evidence_encryption()
    upgrade_database()
    encrypted_count = 0
    with SessionLocal() as db:
        init_default_users(db)
        for evidence in db.query(Evidence).order_by(Evidence.id.asc()).all():
            path = evidence_path(evidence.storage_key)
            if not path.is_file():
                raise FileNotFoundError(f"Evidence file is missing for record {evidence.id}")
            content = path.read_bytes()
            if content.startswith(ENCRYPTED_PREFIX):
                continue
            if sha256(content).hexdigest() != evidence.sha256:
                raise ValueError(f"Plaintext hash mismatch for evidence record {evidence.id}; not encrypting")
            store_evidence_bytes(evidence.storage_key, content)
            append_audit(
                db,
                "system:evidence-encryption-migration",
                "EVIDENCE_ENCRYPTED",
                f"evidence:{evidence.id}",
                {"sha256": evidence.sha256, "migration": "fernet-v1"},
            )
            db.commit()
            encrypted_count += 1
    print(f"Encrypted {encrypted_count} legacy evidence files.")


if __name__ == "__main__":
    main()
