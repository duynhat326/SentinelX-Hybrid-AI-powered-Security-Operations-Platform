from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
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
    llm_provider: Literal["none", "mock", "mock-adversarial"] = "none"  # none = AI off; mock-adversarial is a lab double that misbehaves on purpose
    llm_max_prompt_chars: int = Field(default=12000, ge=2000)
    llm_timeout_seconds: float = Field(default=30, gt=0, le=300)  # passed to the provider for each call
    llm_rate_limit_per_minute: int = Field(default=10, ge=1)  # per client IP; each run is two model calls
    token_ttl_minutes: int = Field(default=480, ge=5, le=10080)  # bearer session lifetime
    login_rate_limit_per_minute: int = Field(default=10, ge=1)  # per client IP
    # Threat intelligence. External lookups send an indicator to a third party, so they are off by default and
    # each call also needs the caller's explicit confirmation. Keys are SecretStr: never logged, audited or returned.
    ti_external_enabled: bool = False
    vt_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    ti_cache_ttl_hours: int = Field(default=24, ge=1, le=720)
    ti_timeout_seconds: float = Field(default=5, gt=0, le=30)
    ti_external_rate_per_minute: int = Field(default=4, ge=1)  # per provider; the free VirusTotal tier allows 4
    # Response. Real effects are off by default: approval then only simulates. The protected list is addresses and networks
    # (comma separated, e.g. your gateway, DNS and monitoring) that no response may ever target.
    response_real_actions_enabled: bool = False
    protected_ips: str = ""
    cors_origins: list[str] = []

    @field_validator("vt_api_key", "abuseipdb_api_key", mode="before")
    @classmethod
    def _blank_key_is_unset(cls, v):
        return None if v in (None, "") else v  # Compose passes an empty string for an unset variable

    @field_validator("protected_ips")
    @classmethod
    def _protected_ips_parse(cls, v: str) -> str:
        for part in (p.strip() for p in v.split(",") if p.strip()):
            ip_network(part, strict=False)  # a typo fails startup instead of silently protecting nothing
        return v

    @property
    def protected_networks(self) -> list[IPv4Network | IPv6Network]:
        return [ip_network(p.strip(), strict=False) for p in self.protected_ips.split(",") if p.strip()]

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> "Settings":
        total = self.risk_weight_severity + self.risk_weight_correlation + self.risk_weight_threat_intel + self.risk_weight_asset
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"risk weights must sum to 1.0, got {total}")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
