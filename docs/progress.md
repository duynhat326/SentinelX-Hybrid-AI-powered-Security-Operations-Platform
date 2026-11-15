# Progress

## Session 1 — Milestone 1 vertical slice
**Done:** repo scaffold; config validation (`app/core/config.py`); models `security_events`, `alerts`, `alert_events`; normalizers for sshd auth lines and Sysmon EventID 1 JSON with secret redaction; rules SX-001/SX-002; idempotent ingestion; API `/health`, `POST /api/v1/events`, `GET /api/v1/alerts`; Dockerfile + Compose.
**Verified (run):** `uv run pytest -q` → 11 passed; `ruff check` clean; `mypy app` clean (SQLite only).
**Not verified:** Postgres (JSONB/UUID) and `docker compose up` — Docker daemon was not running. Container is non-root with healthcheck, untested.
**Known gaps/shortcuts:** `create_all` instead of Alembic; single shared API key; no rate limiting yet; no `assets`/`detection_rules` tables; `docs/{architecture,database-schema,threat-model,evaluation}.md` not written.
**Next:** (1) start Docker, run tests against Postgres, `docker compose up`; (2) Alembic + initial migration; (3) Wazuh JSON input and Sysmon events 3/12/13; (4) rules SX-003..SX-006 with fixtures; (5) correlation/incidents (M4).
