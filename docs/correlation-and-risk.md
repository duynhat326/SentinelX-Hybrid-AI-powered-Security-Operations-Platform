# Correlation and risk scoring

Both are deterministic Python (`backend/app/correlation/engine.py`, `backend/app/risk_engine/score.py`). They run with no LLM, and nothing a model produces can change an incident's grouping, severity or score.

## Correlation: alerts into incidents

After every ingested event that creates or extends an alert, each affected alert is correlated:

1. **Entities.** Collect the alert's entities from its evidence events: `host`, `ip` (source or destination), `user`, `process`.
2. **Candidates.** Find open incidents that share at least one entity **and** whose time range is within `correlation_window_seconds` (default 3600 s) of the alert's range.
3. **Attach.** No candidate: open a new incident (reason `seed`). One or more: attach to the oldest. If the alert bridges several incidents they are **merged** into the oldest and the others are deleted, so an attack chain is not split by arrival order.
4. **Recompute** the incident's severity (highest alert severity), title, time range and risk score.

Each alert records `reason`, the entity that linked it (`ip:203.0.113.50`, `user:alice`, `process:...`, `host:...`, or `seed`), so an analyst can see why it was grouped. More specific links win: ip, user, process, then host.

### What counts as an entity
| Kind | Rule | Why |
|---|---|---|
| host | the alert's host | same machine, same window |
| ip | source or destination IP, except loopback, unspecified, link-local, multicast | an attacker address seen as a login source on one host and a C2 destination on another links them |
| user | lower-cased, domain stripped (`LAB\Alice` = `alice`); generic names ignored: root, admin, administrator, guest, system, test, user, ubuntu, pi, oracle, postgres | brute-force alerts carry guessed names that would link unrelated hosts |
| process | full image path, only if not under `C:\Windows\`, `C:\Program Files` or system Linux paths | the same system binary exists everywhere and links nothing; an unusual path repeated across hosts does |

### Properties (each has a test in `tests/test_correlation.py`)
- **No duplicate incidents:** an alert belongs to at most one incident (`incident_alerts.alert_id` is the primary key); re-correlating the same alert changes nothing. Duplicate events never reach correlation.
- **Time bound:** activity more than the window apart stays separate.
- **Out-of-order arrival:** an earlier alert arriving later still joins and widens the incident's bounds.
- **Closed incidents** are never extended (there is no API to close one yet; status is set in SQL).
- **Concurrency (PostgreSQL):** correlation takes a global advisory lock (after the per-host ingestion lock). Without it, alerts on different hosts created at the same instant open separate incidents; the concurrency test fails 4 runs in 5 with the lock removed and passes with it.
- **Backfill:** alerts with no incident (created before this feature) are correlated at application startup; idempotent.

### Timeline
The incident timeline is derived, not stored: events cited as evidence by its alerts, ordered by time, each with `alert_ids` naming the detections that cite it. There is no separate `incident_evidence` table, because the join over `incident_alerts` and `alert_events` is exact and cannot drift. The API caps it (`timeline_limit`, default 500, max 2000) and reports `timeline_total`.

## Risk score (0-100)

```
score = ( w_sev * severity + w_corr * correlation + w_ti * threat_intel + w_asset * asset ) / sum of the weights that were used
```

Defaults `w_sev=0.4`, `w_corr=0.3`, `w_ti=0.2`, `w_asset=0.1`. Override with `SENTINELX_RISK_WEIGHT_SEVERITY`, `..._CORRELATION`, `..._THREAT_INTEL`, `..._ASSET`; startup fails unless they sum to 1.

| Component | Points (0-100) |
|---|---|
| severity | highest alert severity: low 25, medium 50, high 75, critical 100 |
| correlation | distinct detection rules in the incident: 1 gives 0, 2 gives 33.3, 3 gives 66.7, 4 or more gives 100 |
| threat intel | the highest non-expired stored verdict (0 clean to 100 malicious) among the incident's IP addresses; see [threat-intelligence.md](threat-intelligence.md) |
| asset | highest criticality among the incident's hosts, 1..5 mapped to 0..100 (3 is the default and gives 50) |

**Missing data.** A component that is unknown is dropped and the remaining weights are renormalized; it is never silently scored as zero. With no stored threat-intelligence verdict for any of an incident's addresses (the normal case until someone adds an IOC or runs a confirmed lookup), the effective weights are 0.5, 0.375 and 0.125 for severity, correlation and asset. A stored verdict of 0 means "checked and clean": it counts and lowers the score below the unknown case. The API returns `risk_breakdown` with each component's value, weight, whether it was used, the effective weights and the list of missing components. The result is rounded half up and clamped to 0-100.

**Worked examples** (both reproduced in a Compose run):
- SSH failures then success on `web01` (SX-001 + SX-008, critical, 2 rules, asset 3): (0.4*100 + 0.3*33.3 + 0.1*50) / 0.8 = 68.75, score **69**.
- Administrators add plus an external connection on `win10-lab` (SX-004 high + SX-006, 2 rules, asset 3): (0.4*75 + 0.3*33.3 + 0.1*50) / 0.8 = 56.25, score **56**.

### Limits of this score
- The weights and point scales are **illustrative and uncalibrated**. Nothing here was fit to real incidents or validated against analyst judgement, so a score of 69 versus 56 says "more worrying by this heuristic", not a probability or a measured risk.
- Correlation strength counts distinct rules, not how convincing the link is; a link by shared host is as strong as one by shared IP.
- Severity is per rule, set by the author, not per event content.
- Asset criticality defaults to 3 for every host until someone sets it (SQL, no API yet), so it contributes a constant until then.
- Renormalizing missing components raises scores slightly compared with treating them as zero. New or deleted IOCs rescore the open incidents involving that address at once; an expired verdict is only dropped from the score the next time the incident is recomputed.
- Calibration needs labeled incidents from the lab and is part of the Milestone 8 evaluation.

## API
| Method | Path | Returns |
|---|---|---|
| GET | `/api/v1/incidents?limit=&status=&min_risk=` | summaries ordered by risk then recency: id, title, severity, status, risk_score, first/last seen, alert_count, hosts, MITRE techniques |
| GET | `/api/v1/incidents/{id}?timeline_limit=` | summary plus `risk_breakdown`, `entities`, `alerts` (with `reason`), `timeline`, `timeline_total` |

`GET /api/v1/alerts` also returns each alert's `incident_id`.
