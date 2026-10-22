from pathlib import Path

from alembic import command
from alembic.config import Config

from app.config import DATABASE_URL


def upgrade_database() -> None:
    project_dir = Path(__file__).resolve().parents[1]
    config = Config(str(project_dir / "alembic.ini"))
    config.set_main_option("script_location", str(project_dir / "migrations"))
    config.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))
    command.upgrade(config, "head")
