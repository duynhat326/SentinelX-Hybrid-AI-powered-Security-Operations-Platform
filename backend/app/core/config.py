from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
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
    rate_limit_per_minute: int = Field(default=600, ge=1)
    correlation_window_seconds: int = Field(default=3600, ge=60)  # max gap between related alerts
    # Risk weights (see docs/correlation-and-risk.md). Illustrative, not calibrated; they must sum to 1.
    risk_weight_severity: float = Field(default=0.4, ge=0)
    risk_weight_correlation: float = Field(default=0.3, ge=0)
    risk_weight_threat_intel: float = Field(default=0.2, ge=0)
    risk_weight_asset: float = Field(default=0.1, ge=0)
    llm_provider: Literal["none", "mock"] = "none"  # none = AI off; detection and scoring never depend on it
    llm_max_prompt_chars: int = Field(default=12000, ge=2000)
    cors_origins: list[str] = []

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> "Settings":
        total = self.risk_weight_severity + self.risk_weight_correlation + self.risk_weight_threat_intel + self.risk_weight_asset
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"risk weights must sum to 1.0, got {total}")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
