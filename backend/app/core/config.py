from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated at startup; a bad value fails fast. No secret has a default."""

    model_config = SettingsConfigDict(env_prefix="SENTINELX_", env_file=".env", extra="ignore")

    database_url: str = "sqlite+pysqlite:///./sentinelx.db"
    api_key: str = Field(min_length=24)  # shortcut: single shared key, replace with RBAC users in M6
    log_year_default_tz: str = "UTC"  # syslog lines carry no year/tz; we assume UTC
    bruteforce_threshold: int = Field(default=5, ge=2)
    bruteforce_window_seconds: int = Field(default=300, ge=10)
    max_raw_bytes: int = Field(default=8192, ge=256)
    cors_origins: list[str] = []


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
