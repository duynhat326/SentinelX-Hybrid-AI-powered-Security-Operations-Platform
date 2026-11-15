# SentinelX — Hybrid AI-powered Security Operations Platform

> Detect. Investigate. Understand. Respond.

Analyst-assistance mini-SOC: deterministic detection and correlation first, constrained AI assistance second.
**Status: Milestone 1 (vertical slice).** Ingest → normalize → store → detect → alert → API. No AI, dashboard, correlation or response yet; see [docs/progress.md](docs/progress.md) and the roadmap checklist [docs/checklist.md](docs/checklist.md).

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

## API (header `X-API-Key` required except `/health`)
| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness |
| POST | `/api/v1/events` | body `{"source": "linux_auth"\|"sysmon", "payload": "<raw line or Sysmon EventID 1 JSON>"}` |
| GET | `/api/v1/alerts` | newest alerts with evidence event IDs |

## Detection rules (M1)
| ID | Rule | MITRE |
|---|---|---|
| SX-001 | ≥N failed SSH logins from one IP/host in a window (default 5 in 300 s) | T1110 |
| SX-002 | PowerShell with encoded command / download-cradle / hidden-window flags | T1059.001 |

Plan: [docs/implementation-plan.md](docs/implementation-plan.md). Third-party: FastAPI, SQLAlchemy, Pydantic, PostgreSQL. All SentinelX code is original. License: MIT.
