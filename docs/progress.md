# Progress

## Session 1 — Milestone 1 vertical slice
**Done:** repo scaffold; config validation (`app/core/config.py`); models `security_events`, `alerts`, `alert_events`; normalizers for sshd auth lines and Sysmon EventID 1 JSON with secret redaction; rules SX-001/SX-002; idempotent ingestion; API `/health`, `POST /api/v1/events`, `GET /api/v1/alerts`; Dockerfile + Compose.
**Verified (run):** `uv run pytest -q` → 11 passed; `ruff check` clean; `mypy app` clean (SQLite only).
**Verified (session 2):** same 11 tests pass on PostgreSQL 17 (`SENTINELX_TEST_DATABASE_URL=postgresql+psycopg://... uv run pytest`); `docker compose up --build` gives healthy db and backend; container runs as uid 10001; live smoke test: 401 without key, 5 failed SSH logins create one SX-001 alert with 5 evidence IDs, a repeated event returns `duplicate: true`.
**Not verified:** concurrent ingestion races on the dedup/alert unique indexes; Compose with a real `.env` file (secrets were passed inline).
**Known gaps/shortcuts:** `create_all` instead of Alembic; single shared API key; no rate limiting yet; no `assets`/`detection_rules` tables; `docs/{architecture,database-schema,threat-model,evaluation}.md` not written.
**Next:** (1) ~~Postgres + Compose verification~~ done; (2) Alembic + initial migration; (3) Wazuh JSON input and Sysmon events 3/12/13; (4) rules SX-003..SX-006 with fixtures; (5) correlation/incidents (M4).

**Checklist:** theo dõi từng chức năng tại [checklist.md](checklist.md); tick khi đã chạy test xác nhận.

## Session 2 — M1.5
**Done:** advisory lock per host on PostgreSQL (fixes duplicate-alert `IntegrityError` under concurrency); SX-001 now looks +-window so out-of-order logs still alert with full evidence; in-memory per-IP rate limit on `POST /api/v1/events`; `docs/architecture.md`, `docs/database-schema.md`; `.github/workflows/ci.yml`; `.gitignore` additions.
**Verified (run):** 13 passed + 1 skipped (SQLite), 14 passed (PostgreSQL 17, repeated 13 times with no flake after the fix); ruff and mypy clean; Compose smoke test with 8 concurrent out-of-order requests gives 8x200 and a single alert with 8 evidence events.
**Not verified:** CI on GitHub (workflow only parsed as YAML); rate limit behind a reverse proxy (client IP would be the proxy's); throughput impact of the per-host lock.
**Known shortcuts:** rate limit is in-memory, per process; SX-001 evidence can span up to 2x window; per-host lock serializes ingestion per host.
**Next:** M2 on branch `feat/m2-migrations-wazuh`: Alembic first migration, `assets`, `detection_rules`, Sysmon 3/12/13, Wazuh input.
