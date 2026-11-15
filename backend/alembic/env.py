import os

from sqlalchemy import create_engine

from alembic import context
from app.database.models import Base

config = context.config
# Read the URL straight from the environment so migrations do not need the API key setting.
url = os.environ.get("SENTINELX_DATABASE_URL") or config.get_main_option("sqlalchemy.url")
if config.attributes.get("connection") is None and url is None:
    raise SystemExit("SENTINELX_DATABASE_URL is not set")


def run() -> None:
    conn = config.attributes.get("connection")  # tests pass an open connection
    if conn is None:
        with create_engine(url).connect() as conn:
            _migrate(conn)
    else:
        _migrate(conn)


def _migrate(conn) -> None:
    context.configure(connection=conn, target_metadata=Base.metadata, render_as_batch=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


run()
