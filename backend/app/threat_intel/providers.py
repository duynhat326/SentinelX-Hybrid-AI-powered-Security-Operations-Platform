"""Thin adapters for VirusTotal and AbuseIPDB. They return a number and a sentence we build ourselves from numbers:
provider text is never copied into a result, so a hostile or compromised provider cannot put words in front of an analyst
or a language model. Anything unexpected is "unavailable", never a guess."""
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from app.core.config import Settings

HTTP_TRANSPORT: httpx.BaseTransport | None = None  # tests inject a MockTransport; production uses the default


class ProviderError(Exception):
    def __init__(self, status: str) -> None:
        super().__init__(status)  # the status only: transport errors can carry URLs, and requests carry keys
        self.status = status  # unavailable | rate_limited


@dataclass(frozen=True)
class Verdict:
    score: int  # 0 clean .. 100 malicious
    summary: str


def _get(cfg: Settings, url: str, headers: dict[str, str], params: dict[str, str | int] | None = None) -> httpx.Response:
    try:
        with httpx.Client(timeout=cfg.ti_timeout_seconds, transport=HTTP_TRANSPORT, follow_redirects=False) as c:
            r = c.get(url, headers=headers, params=params)
    except httpx.HTTPError:
        raise ProviderError("unavailable") from None
    if r.status_code == 429:
        raise ProviderError("rate_limited")
    return r


def abuseipdb(cfg: Settings, kind: str, value: str) -> Verdict | None:
    assert cfg.abuseipdb_api_key
    r = _get(cfg, "https://api.abuseipdb.com/api/v2/check", {"Key": cfg.abuseipdb_api_key.get_secret_value(), "Accept": "application/json"},
             {"ipAddress": value, "maxAgeInDays": 90})
    if r.status_code != 200:
        raise ProviderError("unavailable")
    try:
        d = r.json()["data"]
        score, reports = int(d["abuseConfidenceScore"]), int(d["totalReports"])
    except (ValueError, KeyError, TypeError):
        raise ProviderError("unavailable") from None
    if not 0 <= score <= 100:
        raise ProviderError("unavailable")
    return Verdict(score, f"{reports} reports in the last 90 days, abuse confidence {score}%")  # AbuseIPDB answers 200 with score 0 for unknown IPs


_VT_PATH = {"ip": "ip_addresses", "domain": "domains", "sha256": "files"}


def virustotal(cfg: Settings, kind: str, value: str) -> Verdict | None:
    assert cfg.vt_api_key
    r = _get(cfg, f"https://www.virustotal.com/api/v3/{_VT_PATH[kind]}/{quote(value, safe='')}", {"x-apikey": cfg.vt_api_key.get_secret_value()})
    if r.status_code == 404:
        return None  # VirusTotal has never seen it: that is "no information", not "clean"
    if r.status_code != 200:
        raise ProviderError("unavailable")
    try:
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal, sus = int(stats["malicious"]), int(stats["suspicious"])
        total = sum(v for v in stats.values() if isinstance(v, int))
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ProviderError("unavailable") from None
    if min(mal, sus) < 0 or total < mal + sus:
        raise ProviderError("unavailable")
    # shortcut: illustrative scale (10 per malicious engine, 5 per suspicious, capped), not calibrated
    return Verdict(min(100, 10 * mal + 5 * sus), f"{mal} malicious and {sus} suspicious of {total} engines")
