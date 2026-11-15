# Implementation plan

## Decisions
- **Modular monolith** (FastAPI + SQLAlchemy 2), PostgreSQL in Compose, SQLite for fast tests. Redis/microservices only if later justified.
- **Detection, correlation, risk, authorization are deterministic Python.** LLM (LangGraph, M5+) only explains/summarizes, behind a mock provider for tests.
- Ingest is idempotent (hash of redacted raw record). Secrets are redacted before storage. Auth: API key now, RBAC users in M6, before any response action exists.
- Detection rules are Python callables with metadata (id, severity, MITRE, references, enabled). Sigma import is deferred.
- Python 3.12+ (dev on 3.13); `uv.lock` pins dependencies.

## Milestones and acceptance
| # | Scope | Acceptance |
|---|---|---|
| 1 | Slice: ingest one event → normalize → store → detect → alert → API | tests, ruff, mypy green; Compose builds (**pending Docker**) |
| 2 | Alembic migrations, Wazuh input, Windows event/Sysmon breadth, assets table | migration up/down tested on Postgres |
| 3 | 5–8 rules with fixtures, enable/disable, labeled benign/malicious set | per-rule TP/FP tests |
| 4 | Correlation → incidents/timeline, risk engine 0–100 | dedup + window tests, documented formula |
| 5 | LangGraph Triage/Investigation, Pydantic outputs, evidence citations, mock LLM | unsupported-claim + prompt-injection tests |
| 6 | Threat intel adapters, Response Agent proposals, RBAC, approval queue, audit log | unauthorized-action blocking 100% in suite |
| 7 | React + TS dashboard | frontend tests |
| 8 | Scenarios A–E, evaluation with measured results, docs, demo | metrics from real runs only |

## Risks
- No Windows/Wazuh lab here: Sysmon/Wazuh inputs are fixtures until a lab VM exists.
- Syslog lacks year/timezone: assumed current UTC year (documented shortcut).
- Alert dedup is one alert per (rule, host, group key) forever; proper time-bounded grouping arrives with correlation (M4).
- Any metric/target in the spec is a goal, not a result.
