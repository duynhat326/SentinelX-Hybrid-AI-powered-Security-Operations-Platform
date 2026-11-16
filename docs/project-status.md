# Project status (read this first in a new session)

One page: what SentinelX is, what exists, what is real and what is still mock, how to run and test it, and where to look next. For detail, follow the links; this page does not replace them.

## What it is

SentinelX is an analyst-assistance mini security operations platform. Pipeline: ingest logs → normalize → store → detect (deterministic rules) → alert → correlate into incidents → risk score 0–100 → optional AI explanation (advisory only) → response proposals that a second person approves. Stack: Python 3.12+, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 17 (SQLite for fast tests), React 19 + TypeScript + Vite dashboard served by nginx, Docker Compose.

Core rule: detection, scoring and authorization are deterministic code. The AI may only explain evidence; it can never change severity, scores, scope or permissions.

## What is built (by milestone)

| Milestone | Delivered |
|---|---|
| M1–M3 | Ingest of sshd lines and Sysmon JSON (EventID 1/3/11/12/13) and a Wazuh wrapper; idempotent storage by dedup hash; detection rules SX-001…SX-008 with metadata; Alembic migrations; PostgreSQL advisory locks per host |
| M4 | Correlation into incidents by shared host, IP, user or process; bridging merges; deterministic risk score (0.4 severity, 0.3 correlation, 0.2 threat intel, 0.1 asset; missing parts renormalized) |
| M5 | AI investigation: fixed LangGraph chain Triage → Investigation, exactly two model calls; Pydantic-validated output; claims must cite real alert or event ids; techniques must be rule-assigned; provider text never stored |
| M6 | Threat intel (local IOC table; VirusTotal and AbuseIPDB adapters behind a 3-level consent gate; never called against real services); response workflow (typed allowlist, policy checked at proposal and approval, four-eyes, dry run by default, kill switch, rollback, Response Agent); RBAC with roles viewer, analyst, approver, admin, plus a `service` role for the shared key; audit log |
| M7 | React dashboard: sign-in, alerts, incident review with evidence timeline, MITRE view, threat intel, approvals, AI runs, audit log; strict CSP; nginx `/api` proxy |
| M8A | Lab scenarios A–E (`lab/scenarios/`, runner `run.py --check`, asserted in `tests/test_scenarios.py`); rule SX-009 (dropper to user-writable folder, needs Sysmon event 11, migration 0010); lab-only `mock-adversarial` model |
| M8B | Evaluation harness `backend/evaluation/run.py` → `docs/evaluation.md` and `docs/evaluation-results.json` (synthetic data, measurements only); threat model `docs/threat-model.md`; backup and restore `docs/operations.md` (run on PostgreSQL 17) |
| Dashboard (latest) | SIEM-style frame: system bar with quick find, app bar of views, *Security Posture* page with global inputs, single values with trends and sparklines, tables with sparklines, incidents to review, risk ring; theme toggle; logo and cover from `frontend/assets/` served from `frontend/public/brand/`; SF Compact font loaded from `public/fonts/` (git-ignored, licence) |
| Docs | `docs/testing.md` (ten-phase test process with expected results, Vietnamese); `README.md` (rewritten with banner and screenshots) |
| M9 planning | `docs/roadmap-real-world.md` (plan from mock to real), `docs/decisions.md` (Phase 0 answers), `docs/phase1-plan.md` (Phase 1 for the lab laptop), M9 checklist in `docs/checklist.md` |

Full history: `docs/progress.md` (session log) and `docs/checklist.md` (what is ticked and what is not).

## What is still mock or simulated

These are the gaps the M9 roadmap closes. Detail and exit criteria are in `docs/roadmap-real-world.md`.

- **Log sources:** only synthetic data (`lab/seed_demo.py`, scenarios). No collector runs on a real host yet.
- **AI:** only `mock` and `mock-adversarial`. The chosen direction is Ollama on the lab host (`docs/decisions.md`); no adapter exists yet.
- **Threat intel:** adapters exist and are tested with fake HTTP only. Never called against real services.
- **Response:** the blocklist is a table; nothing is enforced on any system. Host isolation is simulated. Planned first target: nftables on a lab Linux VM.
- **Security posture for real use:** shared collector key, no MFA or SSO, token in `sessionStorage`, no TLS in the compose file, in-memory rate limits, audit immutability by convention only, manual backups without schedule or encryption.
- **Dashboard:** only the posture page refreshes (30 s); lists are capped at 200; no user-management screen.
- **Evaluation:** all numbers come from synthetic data written by the rule authors. AI quality, threat-intel accuracy and real false-positive rates are not measured.

## How to run and test

Tests (from `backend/`): `uv sync`, then `uv run pytest -q` (SQLite: 226 passed, 5 skipped), `uv run ruff check .`, `uv run mypy app`. PostgreSQL: `SENTINELX_TEST_DATABASE_URL=postgresql+psycopg://postgres:pgtest@localhost:55432/sx uv run pytest -q` (231 passed) with a throwaway container `sx-pg`.

Frontend (from `frontend/`): `npm ci`, `npm run typecheck`, `npm test` (32 passed), `npm run build`.

Full stack: `cp .env.example .env`, set `SENTINELX_API_KEY` and `POSTGRES_PASSWORD` (never print them), then `docker compose up --build -d`; dashboard on http://localhost:8080, API on loopback port 8000. Create users with `python -m app.manage create-user NAME ROLE`. Demo data: `python3 lab/seed_demo.py` with `SENTINELX_API_KEY` exported. Clean reset: `docker compose down -v` (deletes the database).

Step-by-step test process with expected results: `docs/testing.md`.

## Where things are

- Backend: `backend/app/` (one module per stage: `normalization/`, `ingestion/`, `detection/engine.py`, `correlation/engine.py`, `risk_engine/score.py`, `agents/`, `threat_intel/`, `response/`, `api/`, `core/`, `database/`). Migrations: `backend/alembic/versions/` (head `0010`).
- Tests: `backend/tests/` (conftest fixture, authz matrix `test_authz_matrix.py`, corpus `tests/corpus/`, scenarios `test_scenarios.py`).
- Frontend: `frontend/src/` (`App.tsx` shell, `pages/`, `charts.tsx`, `stats.ts`, `styles.css`).
- Lab: `lab/scenarios/`, `lab/seed_demo.py`.
- Design source of truth: `docs/` (architecture, detection rules, correlation and risk, security model, response workflow, AI investigation, threat intel, database schema).
- Project rules for agents: `CLAUDE.md`.

## Conventions the team relies on

- New route: must declare `Depends(require("<permission>"))` and get a row in `tests/test_authz_matrix.py`, otherwise the test fails.
- Schema change: new Alembic file in `backend/alembic/versions/`; migration tests check it.
- New or changed rule: corpus cases (≥5 malicious and ≥5 benign), update `docs/detection-rules.md`.
- Never use `dangerouslySetInnerHTML`; log text is hostile.
- Severity and numbers are always written as text, never colour alone.
- Commits: never directly on `main`; use a branch and a PR.

## Current git state (as of this note)

- `main` contains milestones through the dashboard (PRs #14, #17, #18, #20 merged).
- Branch `docs/m9-plan` holds commit `0c8cc9f` with the M9 docs; not pushed.
- Uncommitted: `docs/project-status.md` (this file), `graphify-out/` if graphify rebuilt, and `frontend/assets/` plus `.vscode/` and `.gitattributes` which are intentionally untracked.

## Open decisions (see `docs/phase1-plan.md`, "Open questions")

1. Defer Wazuh and Windows/Sysmon until RAM is upgraded? (Recommended: yes.)
2. Accept one Linux VM for seven days as the lab version of the five-host exit criterion? (Recommended: yes.)
3. VM tool: VirtualBox or libvirt/virt-manager?
4. Hardware of the lab host to pick the Ollama model (CPU i7-8565U, 15.4 GiB RAM, no GPU; RAM was 83% used at the last check).
5. Names of the two approver accounts.

## Next step

Phase 0 is done. Phase 1 starts with preflight on the lab laptop (`docs/phase1-plan.md`, Step 1): measure free RAM, check Docker and VM tools, then bring up the stack. No code for Phase 1 has been written yet.
