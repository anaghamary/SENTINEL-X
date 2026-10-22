from sqlalchemy.orm import Session

from app.models import Role, User
from app.security import hash_password

DEFAULT_USERS = (
    ("investigator_alice", "Password123!", Role.INVESTIGATOR, "INV-001"),
    ("reviewer_riley", "Password123!", Role.REVIEWER, "REV-001"),
    ("admin_avery", "Password123!", Role.ADMIN, "ADM-001"),
)


def init_default_users(db: Session) -> None:
    for username, password, role, badge_number in DEFAULT_USERS:
        if db.query(User).filter(User.username == username).first() is None:
            db.add(
                User(
                    username=username,
                    password_hash=hash_password(password),
                    role=role,
                    badge_number=badge_number,
                )
            )
    db.commit()
