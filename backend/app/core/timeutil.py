from datetime import UTC, datetime


def utc(d: datetime) -> datetime:
    """SQLite drops tzinfo on read; everything stored is UTC, so a naive value means UTC."""
    return d if d.tzinfo else d.replace(tzinfo=UTC)
