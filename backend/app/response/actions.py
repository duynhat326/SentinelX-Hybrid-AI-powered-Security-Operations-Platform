"""Typed response actions, the policy that gates them, and what running one means.

The allowlist is the union below. No action carries a command, script, URL or shell string, so nothing a person, a policy
or a language model proposes can be turned into code execution. Only two types can ever have a real effect, and both stay
inside SentinelX: a blocklist record (nothing here enforces it) and a stored report. Blocking at a firewall and isolating
a host are simulation only.
"""
import hashlib
import json
from ipaddress import ip_address
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.incidents import IncidentDetail
from app.core.config import Settings
from app.core.netutil import is_external
from app.database.models import Asset, BlocklistEntry, Incident, IncidentEntity, ResponseAction


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")  # an unknown field (a smuggled command, say) is a validation error


def _canonical_ip(v: str) -> str:
    return str(ip_address(v))


class AddBlocklistEntry(_Params):
    type: Literal["add_blocklist_entry"]
    ip: str
    reason: str = Field(min_length=1, max_length=300)
    _ip = field_validator("ip")(_canonical_ip)


class RequestIpBlock(_Params):
    type: Literal["request_ip_block"]
    ip: str
    duration_minutes: int = Field(ge=1, le=10080)
    reason: str = Field(min_length=1, max_length=300)
    _ip = field_validator("ip")(_canonical_ip)


class RequestHostIsolation(_Params):
    type: Literal["request_host_isolation"]
    host: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=300)


class GenerateReport(_Params):
    type: Literal["generate_report"]


ActionParams = Annotated[AddBlocklistEntry | RequestIpBlock | RequestHostIsolation | GenerateReport, Field(discriminator="type")]
ADAPTER: TypeAdapter = TypeAdapter(ActionParams)
REAL_CAPABLE = frozenset({"add_blocklist_entry", "generate_report"})

GUIDANCE = {
    "add_blocklist_entry": "Roll back with POST /api/v1/response-actions/{id}/rollback, which deactivates the entry. If a firewall or proxy "
                           "already consumed the blocklist, also remove the address there: SentinelX does not enforce it.",
    "request_ip_block": "Nothing was changed by SentinelX (simulation only). If you applied this block yourself, remove the rule from the firewall or security group.",
    "request_host_isolation": "Nothing was changed by SentinelX (simulation only). If you isolated the host yourself, release it in the EDR or network tool.",
    "generate_report": "Nothing to undo: a report is only stored text.",
}


def describe(p: AddBlocklistEntry | RequestIpBlock | RequestHostIsolation | GenerateReport) -> str:
    if p.type == "add_blocklist_entry":
        return f"add {p.ip} to the local blocklist"
    if p.type == "request_ip_block":
        return f"ask the firewall to block {p.ip} for {p.duration_minutes} minutes"
    if p.type == "request_host_isolation":
        return f"isolate host {p.host} from the network"
    return "generate an incident report"


def fingerprint(incident_id: object, params: dict) -> str:
    """Same idempotency key with a different request is a conflict, not a replay."""
    return hashlib.sha256(json.dumps({"incident": str(incident_id), "params": params}, sort_keys=True).encode()).hexdigest()


def violations(db: Session, cfg: Settings, inc: Incident, p: AddBlocklistEntry | RequestIpBlock | RequestHostIsolation | GenerateReport) -> list[str]:
    """Why this action must not be proposed or run. Checked when proposed and again when approved, because the world changes in between."""
    out = []
    if inc.status != "open":
        out.append("the incident is not open")

    def entities(kind: str) -> set[str]:
        return set(db.scalars(select(IncidentEntity.value).where(IncidentEntity.incident_id == inc.id, IncidentEntity.kind == kind)))

    if p.type in ("add_blocklist_entry", "request_ip_block"):
        # documentation ranges are accepted so the lab fixtures work; the blocklist is a local record, nothing is sent anywhere
        if not is_external(p.ip):
            out.append("the address is not public (private, loopback, link-local or multicast)")
        if any(ip_address(p.ip) in n for n in cfg.protected_networks):
            out.append("the address is on the protected list")
        if p.ip not in entities("ip"):
            out.append("the address is not part of this incident's evidence")
        if p.type == "add_blocklist_entry" and db.scalar(select(BlocklistEntry.id).where(BlocklistEntry.ip == p.ip, BlocklistEntry.active)):
            out.append("the address is already on the blocklist")
    if p.type == "request_host_isolation":
        if p.host not in entities("host"):
            out.append("the host is not part of this incident")
        elif not db.scalar(select(Asset.id).where(Asset.hostname == p.host)):
            out.append("the host is not a known asset")
    return out


def _md(v: object, n: int = 200) -> str:
    """Log-derived text is attacker-controlled: one line, bounded, no backticks, and code-formatted so it cannot become markup."""
    return "`" + " ".join(str(v).replace("`", "'").split())[:n] + "`"


def build_report(detail: IncidentDetail, actions: list[ResponseAction]) -> str:
    L = [f"# Incident report: {_md(detail.title)}", "",
         f"- Severity {_md(detail.severity)}, risk score **{detail.risk_score}/100**, status {_md(detail.status)}",
         f"- Seen {_md(detail.first_seen)} to {_md(detail.last_seen)}", f"- MITRE techniques: {', '.join(_md(m) for m in detail.mitre) or 'none'}",
         f"- Hosts: {', '.join(_md(h) for h in detail.hosts) or 'none'}", f"- Users: {', '.join(_md(u) for u in detail.entities.get('user', [])) or 'none'}",
         f"- Addresses: {', '.join(_md(i) for i in detail.entities.get('ip', [])) or 'none'}", "", "## Alerts"]
    L += [f"- {_md(a.rule_id)} {_md(a.title)} ({_md(a.severity)}, {a.event_count} events, grouped by {_md(a.reason)})" for a in detail.alerts]
    L += ["", "## Threat intelligence"] + ([f"- {_md(i.value)}: {i.score}/100 from {_md(i.source)}: {_md(i.summary)}" for i in detail.intel] or ["- none stored"])
    L += ["", f"## Timeline ({min(len(detail.timeline), 100)} of {detail.timeline_total} events)"]
    L += [f"- {_md(t.timestamp)} {_md(t.host)} {_md(t.category)}/{_md(t.action)} {_md(t.user or '')} {_md(t.process_name or t.registry_key or t.src_ip or '')}" for t in detail.timeline[:100]]
    L += ["", "## Response actions"] + ([f"- {_md(a.type)}: {_md(a.status)}, requested by {_md(a.requested_by)}" for a in actions] or ["- none"])
    L += ["", "_Generated by SentinelX. Contents come from logs and are untrusted: render with HTML disabled._"]
    return "\n".join(L)[:200_000]
