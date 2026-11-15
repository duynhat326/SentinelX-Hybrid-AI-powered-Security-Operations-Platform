import os

from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from alembic import command
from app.database.models import Base

BACKEND = os.path.dirname(os.path.dirname(__file__))


def test_upgrade_matches_models_and_downgrade_is_clean(tmp_path):
    url = os.environ.get("SENTINELX_TEST_DATABASE_URL") or f"sqlite+pysqlite:///{tmp_path}/m.db"
    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    with engine.begin() as c:
        c.execute(text("DROP TABLE IF EXISTS alembic_version"))
    cfg = Config(os.path.join(BACKEND, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND, "alembic"))
    try:
        with engine.begin() as conn:
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, "head")
            assert compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata) == []
            assert set(Base.metadata.tables) <= set(inspect(conn).get_table_names())
            command.downgrade(cfg, "base")
            assert set(inspect(conn).get_table_names()) <= {"alembic_version"}
            command.upgrade(cfg, "head")  # reversible and repeatable
    finally:
        Base.metadata.drop_all(engine)
        with engine.begin() as c:
            c.execute(text("DROP TABLE IF EXISTS alembic_version"))
