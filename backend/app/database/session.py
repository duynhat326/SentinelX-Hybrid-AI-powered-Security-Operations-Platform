from collections.abc import Iterator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_engine = None
_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    get_factory()
    assert _engine is not None
    return _engine


def get_factory() -> sessionmaker[Session]:
    global _engine, _factory
    if _factory is None:
        _engine = create_engine(get_settings().database_url, pool_pre_ping=True)
        _factory = sessionmaker(_engine, expire_on_commit=False)
    return _factory


def get_db() -> Iterator[Session]:
    with get_factory()() as s:
        yield s
