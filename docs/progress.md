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

## Session 3 — M2 (branch `feat/m2-migrations-wazuh`)
**Done:** Alembic (`backend/alembic/`, migration `0001`); tables `assets`, `detection_rules`; event columns `asset_id`, `src_port`, `dst_ip`, `dst_port`, `registry_key`, `registry_value`; Sysmon events 3/12/13; Wazuh transport (`source: "wazuh"` wrapping a Sysmon record or sshd line, normalized `source` stays `sysmon`/`linux_auth` so existing rules apply); rule sync at startup + `GET /api/v1/rules`; container runs migrations on start; fixtures in `backend/tests/fixtures/`.
**Bug fixed (existed since M1):** redaction ran on the raw JSON text, so a secret at the end of a value broke the JSON and the event was rejected with 422. Redaction now happens per value after parsing; dedup hash is over canonical redacted JSON (key order no longer matters).
**Verified (run):** 28 passed + 1 skipped on SQLite, 29 passed on PostgreSQL 17 (3 runs); ruff and mypy clean; `alembic upgrade/downgrade/upgrade/check` on Postgres; Compose smoke test (migration on start, rules listed, Sysmon 3/13, Wazuh PowerShell raises SX-002, 2 assets created).
**Not verified:** real Wazuh output (fixtures follow the documented alert shape but were hand-written); CI run on GitHub for this branch; upgrade path from a database created by the M1 `create_all` (documented as reset with `down -v`).
**Known shortcuts:** no endpoint to toggle rules (flip `detection_rules.enabled` in SQL; no audit log until M6); Sysmon `Initiated` flag ignored for network events; same event sent directly and via Wazuh is not deduplicated across transports; no Wazuh integration script to push alerts yet.
**Next:** M3 rules SX-003..SX-008 with benign/malicious fixtures; alert dedup by time window.

## Session 4 — M3 (branch `feat/m3-detection-rules`)
**Done:** rules SX-003..SX-008 (account creation, Administrators group add, Run key persistence, LOLBin external connection, Office spawning a shell, failures-then-success); alert merging by time window with `first_event_at`/`last_event_at` (migration `0002`, backfills existing alerts from evidence); `docs/detection-rules.md`; labeled corpus of 149 synthetic cases (`backend/tests/corpus/`, runner in `tests/corpus_runner.py`); `first_event_at`/`last_event_at` in the alerts API.
**Bug found by the corpus before it shipped:** SX-006 treated multicast addresses as external (`ipaddress.is_global` is true for 224.0.0.251). Fixed.
**Verified (run):** 35 passed + 1 skipped on SQLite, 36 passed on PostgreSQL 17 (3 runs); ruff and mypy clean; Compose build runs migrations to `0002`; six new rules fire over HTTP and a benign multicast case does not.
**Corpus results (synthetic, same author as the rules, NOT an evaluation):** precision 1.00 for every rule; recall 0.75-0.91 because 13 cases are deliberate known gaps. Real evaluation is Milestone 8.
**Not verified:** any rule on real Windows or Linux telemetry; false-positive rate in a real environment; the 0001 to 0002 upgrade on a Compose volume with real data (covered only by the backfill test); CI for this branch.
**Known shortcuts:** one merge window (the brute-force window) for all rules; SX-001 evidence can span up to 2x window; no API to toggle rules; the corpus generator script is not in the repo (the JSON files are the source of truth); SX-006 ignores direction (Sysmon `Initiated`).
**Next:** M4: correlation into incidents and timelines (SX-001 + SX-008 should become one incident), risk engine 0-100.

## Session 5 — M4 (branch `feat/m4-correlation-risk`)
**Done:** correlation engine (`app/correlation/engine.py`): entity extraction, candidate search by shared entity within a time window, merge of bridged incidents, recompute of severity/title/bounds/risk, startup backfill; risk engine (`app/risk_engine/score.py`) with configurable weights that must sum to 1 and renormalization over missing components; tables `incidents`, `incident_alerts`, `incident_entities` (migration `0003`); API `GET /api/v1/incidents` and `/{id}` with risk breakdown, entities, alerts with grouping reason and an evidence timeline; `incident_id` in alerts; `docs/correlation-and-risk.md`.
**Test-quality catch:** the first concurrency test passed even with the correlation lock disabled, so it proved nothing. Rewritten to start 8 hosts' alerts together behind a barrier; with the lock removed it fails 4 runs in 5, with the lock it passes 5 of 5.
**Verified (run):** 70 passed + 2 skipped on SQLite, 72 passed on PostgreSQL 17 (3 runs before the test rewrite, 1 after); ruff and mypy clean; Compose smoke test: migrations reach `0003`, two incidents scored 69 and 56 (match hand calculation), timeline of 6 events, and wiping the incident tables then restarting the backend rebuilds 2 incidents and 4 links.
**Not verified:** correlation quality on real telemetry (over-linking by host, user or IP is plausible and untested); risk score meaning (weights are illustrative, uncalibrated); behaviour with thousands of events per alert (timeline is capped, entity extraction loads all evidence rows); the correlation lock's throughput cost; CI for this branch.
**Known shortcuts:** one global advisory lock for correlation; fixed generic-user and system-path lists; asset criticality defaults to 3 and is changed in SQL; incidents cannot be closed through the API; list endpoint does a few queries per page rather than one; SQLite returns timestamps without a time zone.
**Next:** M5 (LangGraph Triage and Investigation agents with a mock LLM, Pydantic outputs, evidence citations, prompt-injection tests). The incident detail response is the intended input: every claim must cite an event or alert id from it.

## Session 6 — security fixes (branch `fix/security-review-findings`)
**Found by** a whole-repo /security-review; both findings were reproduced with code before being fixed, and each fix has a regression test that was seen failing first.
**Vuln 1:** sshd usernames are attacker-controlled; `_FAIL`/`_OK` took the first `from <ip>` after the user, so a username containing a fake one set the recorded source IP (evades SX-001/SX-008, misattributes). Now the line is parsed from its end with anchored regexes.
**Vuln 2:** over-long values (a 612-char process path) raised a database `DataError` on PostgreSQL, giving HTTP 500 and no event, hence no alert; SQLite does not enforce lengths so the existing tests never saw it. Now `process_name`/`parent_process_name` are `TEXT` (migration `0004`), `user` is truncated to 255, `host` over 255 is a 422, `group_key` is capped, and any remaining `DataError` becomes a 422.
**Verified (run):** 84 passed + 2 skipped on SQLite, 86 passed on PostgreSQL 17 (twice); ruff and mypy clean; Compose smoke test over HTTP: 800-char path now gives 200 and SX-003, five injected-username attempts give one SX-001 alert with 5 events, a 300-char hostname gives 422, database at `0004`.
**Not verified:** real OpenSSH log output (the injection relies on sshd writing the username with spaces unescaped; behaviour matches a documented fail2ban-class issue but was not tested against a live sshd); the Wazuh `full_log` path shares the same parser but was not separately exercised end to end; the 0003 to 0004 upgrade on a volume with real data (widening is lossless; covered by the migration test only).
**Known gaps:** `redact()` misses secrets written without `=` or `:` (for example `-p secret`); a hostname over 255 characters is rejected, which is correct for hostnames but means such an event is not stored.
