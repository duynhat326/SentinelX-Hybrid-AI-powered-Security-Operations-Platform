# SentinelX - Hybrid AI-powered Security Operations Platform

> Detect. Investigate. Understand. Respond.

Analyst-assistance mini-SOC: deterministic detection and correlation first, constrained AI assistance second.
**Status: Milestone 4 (deterministic core complete).** Ingest → normalize → store → detect → alert → API. Detection, correlation into incidents and risk scoring work without any LLM. No AI agents, dashboard or response workflow yet; see [docs/progress.md](docs/progress.md) and the roadmap checklist [docs/checklist.md](docs/checklist.md).

## Run the tests (no Docker needed)
```bash
cd backend && uv sync && uv run pytest -q
# against PostgreSQL:
SENTINELX_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/db uv run pytest -q
```

## Run with Docker Compose
```bash
cp .env.example .env   # fill in SENTINELX_API_KEY and POSTGRES_PASSWORD
docker compose up --build
```
The backend container runs `alembic upgrade head` before starting. If you ran an older build whose tables were created without Alembic (or changed `POSTGRES_PASSWORD` after the first run), reset the volume with `docker compose down -v` (this deletes the database).

## API (header `X-API-Key` required except `/health`)
| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness |
| POST | `/api/v1/events` | body `{"source": "linux_auth"\|"sysmon"\|"wazuh", "payload": "<sshd line, Sysmon EventID 1/3/12/13 JSON, or a Wazuh alert JSON wrapping one of those>"}` |
| GET | `/api/v1/alerts` | newest alerts with evidence event IDs |
| GET | `/api/v1/rules` | detection rules and their enabled state |
| GET | `/api/v1/incidents` | incidents ordered by risk (filters: `status`, `min_risk`, `limit`) |
| GET | `/api/v1/incidents/{id}` | risk breakdown, entities, alerts with grouping reason, evidence timeline |

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

Details, false positives and known gaps: [docs/detection-rules.md](docs/detection-rules.md).

Plan: [docs/implementation-plan.md](docs/implementation-plan.md). Third-party: FastAPI, SQLAlchemy, Pydantic, PostgreSQL. All SentinelX code is original. License: MIT.
