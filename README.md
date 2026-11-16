# SentinelX - Hybrid AI-powered Security Operations Platform

> Detect. Investigate. Understand. Respond.

Analyst-assistance mini-SOC: deterministic detection and correlation first, constrained AI assistance second.
**Status: Milestone 7 (dashboard), on top of Milestone 6 (RBAC and audit, threat intelligence, approved response actions) on top of Milestone 5 (deterministic core plus advisory AI investigation).** Ingest → normalize → store → detect → alert → API. Detection, correlation into incidents and risk scoring work without any LLM. AI investigation (a LangGraph Triage → Investigation chain, mock LLM only, off by default) explains incidents with cited evidence and never changes scores. No real LLM adapter, dashboard or response workflow yet; see [docs/progress.md](docs/progress.md) and the roadmap checklist [docs/checklist.md](docs/checklist.md).

## Run the tests (no Docker needed)
```bash
cd backend && uv sync && uv run pytest -q
# against PostgreSQL:
SENTINELX_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/db uv run pytest -q
```

## Try it end to end
A step-by-step test guide (in Vietnamese) with synthetic demo data and the expected results is in [docs/manual-testing.md](docs/manual-testing.md); the seed script is `lab/seed_demo.py` (standard library only).

## Dashboard
`docker compose up --build` also serves a dashboard on <http://localhost:8080> (alerts, incidents with evidence timelines, MITRE view, threat intel, approval queue, AI runs, audit log). See [docs/dashboard.md](docs/dashboard.md).

![Overview](docs/screenshots/overview.jpg)

## Sign in
People use a bearer token; collectors keep using `X-API-Key`. Create the first admin from the host, then log in:
```bash
docker compose exec backend .venv/bin/python -m app.manage create-user alice admin
curl -s localhost:8000/api/v1/auth/login -H 'content-type: application/json' -d '{"username":"alice","password":"..."}'
```
Roles and what each may do: [docs/security-model.md](docs/security-model.md). Threat intelligence and its privacy gates: [docs/threat-intelligence.md](docs/threat-intelligence.md). Response proposals and approval: [docs/response-workflow.md](docs/response-workflow.md).

## Run with Docker Compose
```bash
cp .env.example .env   # fill in SENTINELX_API_KEY and POSTGRES_PASSWORD
docker compose up --build
```
The backend container runs `alembic upgrade head` before starting. If you ran an older build whose tables were created without Alembic (or changed `POSTGRES_PASSWORD` after the first run), reset the volume with `docker compose down -v` (this deletes the database).

## API (`Authorization: Bearer <token>` or `X-API-Key`, see the role table; only `/health` and login are public)
| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness |
| POST | `/api/v1/events` | body `{"source": "linux_auth"\|"sysmon"\|"wazuh", "payload": "<sshd line, Sysmon EventID 1/3/12/13 JSON, or a Wazuh alert JSON wrapping one of those>"}` |
| GET | `/api/v1/alerts` | newest alerts with evidence event IDs |
| GET | `/api/v1/rules` | detection rules and their enabled state |
| POST | `/api/v1/auth/login`, `/logout` | sign in (public, rate limited) and out; `GET /api/v1/auth/me` shows the caller |
| POST/GET/PATCH | `/api/v1/users` | admin only: create, list, change role or disable |
| POST | `/api/v1/enrich`, `/api/v1/incidents/{id}/enrich` | look up an indicator or an incident's addresses: local IOC table first; VirusTotal/AbuseIPDB only if enabled, keyed and `confirm_external=true` |
| GET/POST/DELETE | `/api/v1/iocs` | the local IOC table (writes need approver or admin) |
| POST | `/api/v1/incidents/{id}/response-actions`, `/response-actions/suggest` | propose a typed response action, or ask the Response Agent (policy or AI) for proposals; nothing runs until a different person approves |
| POST | `/api/v1/response-actions/{id}/approve`, `/reject`, `/rollback` | approver or admin; approval is a dry run unless `real: true` and real actions are enabled |
| GET | `/api/v1/response-actions`, `/api/v1/blocklist` | proposals and the local blocklist (advisory: SentinelX does not enforce it) |
| GET | `/api/v1/overview`, `/api/v1/agent-runs` | exact dashboard counts; every AI run |
| GET | `/api/v1/audit-logs` | admin only: who did what (filters `action`, `actor`, `outcome`) |
| GET | `/api/v1/incidents` | incidents ordered by risk (filters: `status`, `min_risk`, `limit`) |
| GET | `/api/v1/incidents/{id}` | risk breakdown, entities, alerts with grouping reason, evidence timeline |
| POST | `/api/v1/incidents/{id}/investigate` | run AI triage + investigation (needs `SENTINELX_LLM_PROVIDER=mock`; 503 when `none`; limited to 10 runs per minute per IP) |
| GET | `/api/v1/incidents/{id}/agent-runs` | stored runs with cited claims, dropped-claim count, refused tool calls |

## Detection rules
| ID | Rule | MITRE |
|---|---|---|
| SX-001 | ≥N failed SSH logins from one IP/host in a window (default 5 in 300 s) | T1110 |
| SX-002 | PowerShell with encoded command / download-cradle / hidden-window flags | T1059.001 |
| SX-003 | Local account created from the command line | T1136.001 |
| SX-004 | Account added to the local Administrators group | T1098 |
| SX-005 | Registry Run key persistence | T1547.001 |
| SX-006 | Script host or LOLBin connecting to an external address | T1071 |
| SX-007 | Office application spawning a shell or script host | T1204.002 |
| SX-008 | Repeated SSH failures followed by a successful login | T1110, T1078 |
| SX-009 | Script host or Office application writing an executable to a user-writable folder | T1105 |

Details, false positives and known gaps: [docs/detection-rules.md](docs/detection-rules.md).

Plan: [docs/implementation-plan.md](docs/implementation-plan.md). Third-party: FastAPI, SQLAlchemy, Pydantic, PostgreSQL. All SentinelX code is original. License: MIT.
