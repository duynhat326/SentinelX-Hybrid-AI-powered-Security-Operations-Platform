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


def test_0002_backfills_alert_time_bounds_from_evidence(tmp_path):
    import uuid
    from datetime import UTC, datetime

    import sqlalchemy as sa

    json_t = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")
    md = sa.MetaData()
    events = sa.Table("security_events", md, sa.Column("id", sa.Uuid), sa.Column("dedup_hash", sa.String), sa.Column("timestamp", sa.DateTime(True)),
                      sa.Column("ingested_at", sa.DateTime(True)), sa.Column("source", sa.String), sa.Column("host", sa.String),
                      sa.Column("category", sa.String), sa.Column("action", sa.String), sa.Column("raw", json_t))
    alerts = sa.Table("alerts", md, sa.Column("id", sa.Uuid), sa.Column("rule_id", sa.String), sa.Column("title", sa.String),
                      sa.Column("severity", sa.String), sa.Column("status", sa.String), sa.Column("host", sa.String),
                      sa.Column("group_key", sa.String), sa.Column("mitre", json_t), sa.Column("event_count", sa.Integer),
                      sa.Column("created_at", sa.DateTime(True)))
    link = sa.Table("alert_events", md, sa.Column("alert_id", sa.Uuid), sa.Column("event_id", sa.Uuid))

    url = os.environ.get("SENTINELX_TEST_DATABASE_URL") or f"sqlite+pysqlite:///{tmp_path}/b.db"
    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    with engine.begin() as c:
        c.execute(text("DROP TABLE IF EXISTS alembic_version"))
    cfg = Config(os.path.join(BACKEND, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND, "alembic"))
    t1, t2, made = (datetime(2026, 11, 15, 10, 0, s, tzinfo=UTC) for s in (1, 9, 30))
    a_with, a_empty = uuid.uuid4(), uuid.uuid4()
    try:
        with engine.begin() as conn:
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, "0001")
            ev_ids = [uuid.uuid4(), uuid.uuid4()]
            for i, (eid, t) in enumerate(zip(ev_ids, (t2, t1), strict=True)):  # inserted out of order on purpose
                conn.execute(events.insert().values(id=eid, dedup_hash=f"h{i}", timestamp=t, ingested_at=t, source="linux_auth",
                                                    host="h", category="authentication", action="failure", raw={}))
            for aid in (a_with, a_empty):
                conn.execute(alerts.insert().values(id=aid, rule_id="SX-001", title="t", severity="high", status="open",
                                                    host="h", group_key=str(aid), mitre=["T1110"], event_count=2, created_at=made))
            for eid in ev_ids:
                conn.execute(link.insert().values(alert_id=a_with, event_id=eid))
            command.upgrade(cfg, "head")
            rows = {r.id: r for r in conn.execute(sa.text("SELECT id, first_event_at, last_event_at FROM alerts")).mappings()}
            norm = lambda d: (d if isinstance(d, datetime) else datetime.fromisoformat(d)).replace(tzinfo=UTC)
            got = {k: (norm(v["first_event_at"]), norm(v["last_event_at"])) for k, v in rows.items()}
            # SQLite returns Uuid as 32-char hex strings, PostgreSQL as UUID objects
            by_hex = {(k if isinstance(k, uuid.UUID) else uuid.UUID(k)): v for k, v in got.items()}
            assert by_hex[a_with] == (t1, t2)
            assert by_hex[a_empty] == (made, made)  # no evidence: falls back to created_at
            command.downgrade(cfg, "0001")
            command.upgrade(cfg, "head")
    finally:
        Base.metadata.drop_all(engine)
        with engine.begin() as c:
            c.execute(text("DROP TABLE IF EXISTS alembic_version"))
