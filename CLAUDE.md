# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

SentinelX: an analyst-assistance mini-SOC. Everything built so far (Milestone 4) is a deterministic Python backend: ingest → normalize → store → detect → alert → correlate into incidents → risk score. No LLM, dashboard or response workflow exists yet; those are planned (see `docs/checklist.md`). Keep detection, scoring and authorization deterministic; any future LLM may only explain evidence, never change severity, scores or permissions.

All code lives in `backend/` (Python ≥3.12, FastAPI, SQLAlchemy 2, Alembic, `uv`). `detection-rules/custom/` and `lab/scenarios/` are empty placeholders.

## Commands

Run from `backend/`:

```bash
uv sync                                   # CI uses: uv sync --frozen
uv run pytest -q                          # SQLite (default, no Docker)
uv run pytest tests/test_security.py::test_name -q   # single test
SENTINELX_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/db uv run pytest -q   # PostgreSQL
uv run ruff check .                       # line-length 130
uv run mypy app
```

CI (`.github/workflows/ci.yml`) runs ruff, mypy, then the suite on both SQLite and PostgreSQL 17. Behavior that differs by dialect (advisory locks, `DataError`) must pass on both.

Full stack: `cp .env.example .env` (set `SENTINELX_API_KEY`, `POSTGRES_PASSWORD`) then `docker compose up --build`; the backend container runs `alembic upgrade head` first. Schema changes need a new file in `backend/alembic/versions/` (tests in `test_migrations.py` check them).

## Architecture

Pipeline, one module per stage under `backend/app/`:

- `api/` – `main.py` (routes, API-key auth via `X-API-Key`, security headers, CORS), `ratelimit.py` (in-memory per-IP), `incidents.py`.
- `normalization/normalize.py` – parses `linux_auth` (sshd lines), `sysmon` (EventID 1/3/12/13 JSON) and `wazuh` (wrapper around either) into one event shape, redacts secrets, computes the SHA-256 dedup hash of the redacted raw record.
- `ingestion/service.py` – orchestrates a `POST /api/v1/events`: insert event (unique hash → duplicate is a no-op), run detections, correlate.
- `detection/engine.py` – rules SX-001…SX-008 are Python callables with metadata in a `RULES` list; metadata is synced into the `detection_rules` table at startup (the sync never overwrites `enabled`). Alerts are keyed by `(rule_id, host, group_key)` and merge within a time window. SX-001/SX-008 look ± window around the event so out-of-order logs still work.
- `correlation/engine.py` – alerts sharing an entity inside a window become one incident; a bridging alert merges incidents.
- `risk_engine/score.py` – documented 0-100 weighted formula that renormalizes over missing components (`docs/correlation-and-risk.md`).
- `database/` (models, session), `core/` (settings from `SENTINELX_*` env vars via pydantic-settings, UTC helpers).

Concurrency matters: on PostgreSQL, ingestion takes a per-host advisory lock and correlation takes a global advisory lock; SQLite skips them. Don't add ingestion/correlation steps outside those lock scopes.

Untrusted-input rules (see `docs/architecture.md` "Key decisions"): all log fields are attacker-controlled. sshd lines are parsed from the end so a fake username can't alter the recorded source IP; indexed columns are bounded (hostname >255 → 422, usernames truncated) while path columns are unbounded `TEXT`; a DB `DataError` must become a 422, never a 500 that drops the event.

## Testing

- `tests/conftest.py` `client` fixture builds a fresh DB per test (drops/creates all tables) and a `TestClient` with the API key; it resets the `get_settings` cache and rate limiter — new tests that change env settings must call `config.get_settings.cache_clear()` (see `_fast` in `test_corpus.py`, which raises the rate limit).
- `tests/corpus/sx-00N.json` is a synthetic labeled corpus run through the real API by `corpus_runner.py`/`test_corpus.py`: each rule needs ≥5 malicious and ≥5 benign cases, ids are unique, and `known_gap` cases must still be *missed*. Adding or changing a rule means adding corpus cases and updating `docs/detection-rules.md` (including false positives and known gaps).
- Helpers `ssh_fail` and `sysmon_ps` in `conftest.py` build event payloads; sample raw records are in `tests/fixtures/`.

## Docs

`docs/` is the source of truth for design: `architecture.md`, `detection-rules.md`, `correlation-and-risk.md`, `database-schema.md`, `implementation-plan.md`, `progress.md`, `checklist.md`. Update the relevant doc when behavior changes. Known shortcuts: single shared API key, per-process rate limit, no rule-toggle API (flip `detection_rules.enabled` in SQL), syslog year assumed to be the current UTC year.
