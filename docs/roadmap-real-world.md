# Roadmap: from mock data to a real deployment (Milestone 9)

Goal: move every part of SentinelX that is synthetic or simulated today to real inputs and real effects, one phase at a time, with a measurable exit criterion per phase. Durations are rough estimates for one person and do not include waiting for data or a team.

Status of the current code, for reference:
- Real and working: ingestion, normalization, detection, correlation, risk score, authorization, audit, response state machine (dry run by default).
- Synthetic or simulated: log sources (seed script and scenarios), the AI provider (mock only), threat-intel providers (tested with fake HTTP only), response effects (the blocklist is a table; nothing is enforced), and several security and operations settings for a lab.

## Phase 0: decisions before code (about 1 week)

No code until these are written in `docs/decisions.md`:
- Target environment: lab, small company network, or both; expected host count.
- AI data policy: may logs and host details leave the network; if yes, which fields are redacted.
- Response approvers: named people and the minimum number of approvals.
- First response target: Linux firewall, Windows Firewall, or EDR.
- Log retention period and any legal requirement.
- Time zone and clock policy for ingested logs.

Output: `docs/decisions.md`.

## Phase 1: real log ingestion (about 3 to 4 weeks)

- Linux forwarder (rsyslog or journald to `POST /api/v1/events`).
- Windows path: Wazuh agent or Winlogbeat, with Sysmon.
- Script that pushes Wazuh alerts to the API (still open in the checklist).
- More parsers for real event types, built from sanitized samples captured on lab VMs.
- Fix syslog year and time zone according to Phase 0.
- Asset import (hostname, criticality) from a CSV or CMDB, plus an API to change criticality.

Exit: 5 hosts forward logs continuously for 7 days; parse error rate below 1%; no duplicate events; criticality matches the asset list.

## Phase 2: detection tuning (2 to 4 weeks, in parallel with Phase 1)

- Collect a baseline from real logs for 2 to 4 weeks.
- Record every alert with a verdict (true or false positive); track false positives per rule per day.
- Add allowlists for legitimate admin tools and software installers.
- Add an API to enable or disable rules (replacing SQL edits).
- Handle shared addresses (NAT, proxies) that wrongly merge incidents: add an allowlist for shared addresses.

Exit: every rule has a measured false-positive rate and a decision to keep, fix or disable it.

## Phase 3: real AI adapter (2 to 3 weeks; needs Phases 0 and 1)

- Provider: Ollama on the lab host (decided in Phase 0); model pinned after the hardware check.
- Implement `LLM.complete` with a real timeout; never store provider error text.
- Redact sensitive fields before sending; cap prompt size.
- Daily cost limit.
- Bump `PROMPT_VERSION` and record it on every run.
- Evaluate on at least 30 labeled incidents: valid citation rate, wrong-claim rate, and analyst usefulness score.

Exit: an evaluation report with real numbers. If it is below the agreed thresholds, AI stays off for users.

## Phase 4: real threat intelligence (1 to 2 weeks; independent)

- Real VirusTotal and AbuseIPDB keys; configure quota to match the plan.
- Test only on approved public addresses, never on internal ones.
- Keep the confirmation step before any external lookup; audit every external call.
- Check cache expiry, provider outage and quota exhaustion.

Exit: real lookups succeed and are audited; a provider failure never produces a "clean" verdict.

## Phase 5: real response executor (3 to 4 weeks; needs Phase 0, and the key and TLS parts of Phase 6)

- First target: block IP addresses with nftables, through the agent or Wazuh active response.
- Keep dry run as the default and the kill switch.
- Real rollback (unblock) and idempotency checks.
- Protected address list checked again at execution time.
- Host isolation stays simulated until an EDR integration is designed and reviewed separately.

Exit: on a test VM, a real block is applied and removed; the audit log has every step; a proposal that breaks policy is refused.

## Phase 6: security hardening (3 to 4 weeks; starts with Phase 1)

- One key per collector, revocable; retire the shared key.
- TLS through a reverse proxy with a real certificate.
- HttpOnly cookie for the session, with CSRF protection (backend and frontend changes).
- TOTP-based MFA; password change API; temporary lockout after repeated failures.
- Audit that cannot be changed at the database level (INSERT-only role or trigger), or shipped to an external system.
- Shared rate limiting (Redis) if more than one replica runs.
- Secrets outside the plain `.env` file (secret manager or Docker secrets).
- Dependency scanning in CI; penetration test before real use.

Exit: no high-severity findings in the penetration test; a revoked collector key stops working immediately.

## Phase 7: operations (2 to 3 weeks)

- Scheduled, encrypted backups and a restore drill on a schedule.
- Retention job following the Phase 0 policy.
- Metrics and alerts for SentinelX itself: ingest lag, parse errors, worker failures.
- On-call runbook.
- Dashboard: live updates, pagination, user management screen.
- Re-measure performance with real data and concurrent load.

Exit: one documented restore test; the runbook is followed by someone who did not write it.

## Dependencies

- Phase 1 is the base for Phases 2, 3 and 5.
- Phase 4 is independent.
- Phase 6 key and TLS work must be done before exposing Phase 1 outside the lab.
- Phase 5 needs the Phase 6 key and TLS work before accepting commands from a real dashboard.

## Pilot

After Phases 1, 2, the key and TLS parts of 6, and the backup part of 7 are done, run a 2-week pilot on a small set of hosts. AI and response run in suggestion mode only. Expand only when each phase's exit criteria are met.
