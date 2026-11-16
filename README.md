# SentinelX

> **Detect. Investigate. Understand. Respond.**
> A hybrid AI security operations platform in miniature: deterministic detection and correlation first, constrained AI assistance second, a person always in charge of response.

![Overview](docs/screenshots/overview.jpg)

## The problem
A small team gets thousands of log lines and a flat list of alerts. Most alerts are one half of a story (a failed login here, an encoded command there), and the tools that promise to explain them with a language model are hard to trust: a model that can be talked into things by the very logs it reads should not decide severity, and should not press the button.

## What SentinelX does about it
1. **Detects deterministically.** Nine rules (SSH brute force, encoded PowerShell, persistence, dropper behaviour, and so on) over Linux auth logs and Sysmon events, relayed directly or through Wazuh. No model is involved.
2. **Correlates into incidents.** Alerts sharing a host, address, user or process are grouped; bridging alerts merge incidents; a weighted 0 to 100 risk score explains itself.
3. **Explains with a guarded AI.** A LangGraph Triage → Investigation chain writes a summary whose every claim must cite real alert or event ids. It cannot change severity, risk, scope or permissions, its tool calls are refused and recorded, and hostile text in the evidence is fenced. Today only offline mocks exist (including one that deliberately misbehaves).
4. **Responds only with approval.** Response actions are a typed allowlist (no command or URL field), checked against policy twice, dry-run by default, and need a *different* person to approve. Real effects need a kill switch that is off by default.
5. **Shows its work.** A dashboard with the evidence timeline, MITRE ATT&CK coverage, threat intelligence, the approval queue, every AI run and the audit log.

![Incident](docs/screenshots/incident.jpg)

## Architecture
```mermaid
flowchart LR
  C[Collectors: sshd, Sysmon, Wazuh] -->|X-API-Key| I[Ingest and normalize]
  I --> S[(PostgreSQL)]
  I --> D[Detection rules SX-001..009]
  D --> A[Alerts] --> K[Correlation into incidents] --> R[Risk score 0-100]
  K --> AI[AI investigation, advisory only]
  K --> T[Threat intel: local IOCs, optional lookups]
  K --> P[Response proposals] -->|different approver| X[Dry run or real action]
  U[Dashboard, nginx] -->|bearer token| API[FastAPI]
  API --- S
  API --> AU[(Audit log)]
```
One module per stage under `backend/app/`; details and design decisions in [docs/architecture.md](docs/architecture.md).

## Quick start
Needs Docker. First, create `.env` from the example file and set `SENTINELX_API_KEY` (24 or more characters) and `POSTGRES_PASSWORD`.
```bash
cp .env.example .env
docker compose up --build            # database, backend (runs migrations first), dashboard
docker compose exec backend .venv/bin/python -m app.manage create-user alice admin   # prompts for a password (12+ characters)
export SENTINELX_API_KEY=...         # the same value you set in the environment file
python3 lab/seed_demo.py             # 20 synthetic events, then open http://localhost:8080
```
`docker compose down -v` deletes the database. Backup and restore: [docs/operations.md](docs/operations.md). A guided tour (in Vietnamese) with expected results: [docs/manual-testing.md](docs/manual-testing.md). A five-minute demo: [docs/demo-script.md](docs/demo-script.md).

### Run the tests (no Docker needed)
```bash
cd backend && uv sync && uv run pytest -q        # SQLite
SENTINELX_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/db uv run pytest -q   # PostgreSQL
cd ../frontend && npm ci && npm test              # dashboard
```
CI runs ruff, mypy, the suite on SQLite and PostgreSQL 17, and the frontend checks.

## Lab scenarios
Five synthetic, repeatable scenarios with expected detections, expected false positives and cleanup: SSH brute force, suspicious PowerShell, registry persistence, a multi-stage chain across two hosts, and prompt injection. `python3 lab/scenarios/run.py all --check` verifies them against a running stack. See [lab/scenarios/README.md](lab/scenarios/README.md).

## Evaluation, honestly
All numbers use **synthetic data written by the rule authors**, so they measure regressions and design properties, not real-world accuracy. On the 171-case labeled corpus: precision 1.00 and recall 0.83 (16 known gaps are deliberate). On 63 labeled episodes, correlation turns 117 alerts into 63 incidents; ranking quality improves from AUROC 0.55 to 0.72 but the intervals overlap, so the data cannot show the risk score beats plain severity. Against a scripted hostile model, 0 of 100 hostile proposals were created and 0 incidents changed. AI explanation quality, threat-intel accuracy and real-world false-positive rate were **not measured**. Full method, tables and caveats: [docs/evaluation.md](docs/evaluation.md). Threats and what is still open: [docs/threat-model.md](docs/threat-model.md).

## Configuration
Settings come from `SENTINELX_*` environment variables (validated at startup; a bad value fails fast). Compose forwards the ones marked ✓.

| Variable | Default | Meaning |
|---|---|---|
| `SENTINELX_API_KEY` ✓ | required, 24+ chars | the shared collector key (`service` role) |
| `SENTINELX_DATABASE_URL` ✓ | SQLite file; Compose uses PostgreSQL | database |
| `SENTINELX_LLM_PROVIDER` ✓ | `none` | `none` (AI off), `mock`, or `mock-adversarial` (lab only: obeys prompt injection) |
| `SENTINELX_TI_EXTERNAL_ENABLED` ✓ | `false` | allow VirusTotal/AbuseIPDB lookups (still needs a key and a per-request confirmation) |
| `SENTINELX_VT_API_KEY`, `SENTINELX_ABUSEIPDB_API_KEY` ✓ | unset | provider keys |
| `SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED` ✓ | `false` | kill switch: approval only simulates while off |
| `SENTINELX_PROTECTED_IPS` ✓ | empty | addresses or networks no response may target |
| `SENTINELX_BRUTEFORCE_THRESHOLD` / `_WINDOW_SECONDS` | 5 / 300 | SX-001 and SX-008 |
| `SENTINELX_CORRELATION_WINDOW_SECONDS` | 3600 | maximum gap between related alerts |
| `SENTINELX_RISK_WEIGHT_*` | 0.4 / 0.3 / 0.2 / 0.1 | severity, correlation, threat intel, asset; must sum to 1 |
| `SENTINELX_RATE_LIMIT_PER_MINUTE`, `_LLM_`, `_LOGIN_` | 600 / 10 / 10 | per client IP |
| `SENTINELX_TOKEN_TTL_MINUTES` | 480 | bearer session lifetime |

## API
Bearer token for people, `X-API-Key` for collectors; only `/health` and login are public. Roles: [docs/security-model.md](docs/security-model.md). Interactive reference at `/docs` on the backend (`localhost:8000`) when the port is open.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness |
| POST | `/api/v1/events` | body `{"source": "linux_auth"\|"sysmon"\|"wazuh", "payload": "<sshd line, Sysmon EventID 1/3/11/12/13 JSON, or a Wazuh alert JSON wrapping one of those>"}` |
| GET | `/api/v1/alerts`, `/api/v1/rules` | newest alerts with evidence ids; rules and their enabled state |
| GET | `/api/v1/incidents`, `/api/v1/incidents/{id}` | incidents by risk (filters `status`, `min_risk`, `limit`); breakdown, entities, alerts, evidence timeline |
| POST | `/api/v1/incidents/{id}/investigate` | AI triage and investigation (503 when the provider is `none`; 10 runs per minute per IP) |
| GET | `/api/v1/incidents/{id}/agent-runs`, `/api/v1/agent-runs` | stored runs: cited claims, dropped-claim count, refused tool calls |
| POST | `/api/v1/auth/login`, `/logout`; GET `/api/v1/auth/me` | sign in and out; the caller and permissions |
| POST/GET/PATCH | `/api/v1/users` | admin only |
| POST | `/api/v1/enrich`, `/api/v1/incidents/{id}/enrich` | local IOC table first; providers only when enabled, keyed and `confirm_external=true` |
| GET/POST/DELETE | `/api/v1/iocs` | local IOC table (writes: approver or admin) |
| POST | `/api/v1/incidents/{id}/response-actions`, `/response-actions/suggest` | propose, or ask the Response Agent (policy or AI) |
| POST | `/api/v1/response-actions/{id}/approve`, `/reject`, `/rollback` | approver or admin; a dry run unless `real: true` and real actions are enabled |
| GET | `/api/v1/response-actions`, `/api/v1/blocklist`, `/api/v1/overview`, `/api/v1/audit-logs` | proposals; the advisory blocklist; dashboard counts; audit log (admin) |

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

## Limitations
- **No real LLM adapter, no real firewall or EDR integration.** The AI is an offline mock and the blocklist is a local record SentinelX does not enforce.
- **Detection is string and path based** and misses obfuscation, renamed binaries and unusual paths (documented known gaps). The evaluation is synthetic.
- **Single shared collector key, in-memory per-process rate limits, no MFA or SSO, audit immutability by convention.** The full list is in [docs/threat-model.md](docs/threat-model.md).
- Alerts that share an address (NAT, proxies) merge unrelated hosts into one incident.
- The dashboard has no live updates or pagination (lists are capped at 200), and keeps its token in `sessionStorage`.
- SF Compact (the dashboard font) is not redistributable and is not in the repository; without it the dashboard falls back to the system font ([docs/dashboard.md](docs/dashboard.md)).

## Documentation
[architecture](docs/architecture.md) · [detection rules](docs/detection-rules.md) · [correlation and risk](docs/correlation-and-risk.md) · [database schema](docs/database-schema.md) · [security model](docs/security-model.md) · [threat intelligence](docs/threat-intelligence.md) · [response workflow](docs/response-workflow.md) · [AI investigation](docs/ai-investigation.md) · [dashboard](docs/dashboard.md) · [evaluation](docs/evaluation.md) · [threat model](docs/threat-model.md) · [operations](docs/operations.md) · [demo script](docs/demo-script.md) · [progress](docs/progress.md) · [checklist](docs/checklist.md) · [implementation plan](docs/implementation-plan.md)

Third-party: FastAPI, SQLAlchemy, Pydantic, LangGraph, PostgreSQL, React. All SentinelX code is original. License: MIT.
