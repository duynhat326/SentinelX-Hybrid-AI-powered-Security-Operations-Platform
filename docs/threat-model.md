# Threat model

What SentinelX protects, who might attack it, and what is and is not covered. Written for a lab and portfolio deployment on one host; nothing here is a claim of production readiness. Each row points to the control and the test or doc that shows it. "Open" means not mitigated.

## What is being protected
- **The integrity of the analyst's picture:** events, alerts, incidents, severity and risk must not be changed by the data they describe or by the AI.
- **The response path:** an approved action must have been proposed within policy and approved by a second person.
- **Credentials and tokens:** user passwords, bearer tokens, the shared API key, third-party provider keys.
- **Confidentiality of indicators:** looking an address up at a third party discloses it.
- **The audit trail.**

## Trust boundaries and actors
| Boundary | Who is on the other side |
|---|---|
| Collector → `POST /api/v1/events` | A host's log pipeline holding the shared `X-API-Key`. **Log content is attacker-controlled**: any user on a monitored host can write a username, a command line or a file name. |
| Browser → nginx → backend | Analysts, approvers and admins (bearer tokens), and anyone who can reach the published port. |
| Backend → LLM provider | A model that can be steered by text inside the evidence. Only a mock exists today. |
| Backend → VirusTotal and AbuseIPDB | Third parties that learn the indicators sent to them. Off by default. |
| Backend → PostgreSQL | Trusted; whoever has the database has everything. |

Actors considered: an attacker on a monitored host (log poisoning); an outsider reaching the API or the dashboard; a malicious or mistaken insider with a valid role; a prompt-injecting document or log line; a compromised collector.

## Threats and controls
| # | Threat | Control | Evidence | Residual |
|---|---|---|---|---|
| T1 | **Log poisoning:** a fake username or field alters the recorded source address or breaks parsing | sshd lines parsed from the end; bounded indexed columns; DB `DataError` becomes 422 not 500; secrets redacted before hashing and storage | `test_normalize.py`, `test_security.py` | New log formats need the same care |
| T2 | **Event flooding / resource exhaustion** | per-IP rate limit (separate stricter bucket for LLM calls), payload bounds | `test_security.py` | Limit is in memory per process and per IP: several workers or addresses multiply it; no queue, no back-pressure. **Open** |
| T3 | **Evasion of detection** (obfuscation, renamed binaries, paths outside patterns) | none beyond the rules; known gaps are tested to stay missed so they are visible | `detection-rules.md`, corpus `known_gap` cases | Recall is below 1 by design; rules are string and path based. **Open, accepted** |
| T4 | **Prompt injection through log text** steers the AI | evidence sent inside a `<data>` fence with `<` escaped; the model can only explain: output is schema-validated, claims need valid alert/event ids, techniques must be rule-assigned, scope comes from the incident, tool calls are refused and recorded, errors store no provider text | lab scenario E, `test_scenarios.py`, `evaluation.md` section 3 | A claim citing real evidence but carrying hostile text is displayed as advice. A person can be misled. **Open, mitigated by labeling** |
| T5 | **The AI changes severity, scores or permissions** | those are computed deterministically in code the model never calls | `test_agents.py`; 0 of 20 incidents changed in the guardrail run | None known |
| T6 | **A response action does harm** (blocks a trusted address, isolates a server) | typed allowlist (no command or URL field); policy checks at proposal **and** at approval (protected networks, private and special addresses, evidence-bound targets); dry run by default; real effects need a kill switch **and** a capable action type; rollback | `test_response.py`, `response-workflow.md` | No real integration exists: the blocklist is data. A future real executor needs its own review. **Open** |
| T7 | **One person proposes and approves** | approver must differ from `requested_by` and `triggered_by` (whoever asked the agent); row lock and idempotency on decisions | `test_response.py` | Compares account names: two accounts held by one person defeat it. **Open** |
| T8 | **Privilege escalation or a missing permission check** | every route declares a permission; a test enumerates all routes and fails on a missing one; roles only add permissions; the service key cannot act as a person | `test_authz_matrix.py` | New routes rely on the test being run |
| T9 | **Credential theft or guessing** | scrypt hashes; only SHA-256 of tokens stored; identical message for unknown user, wrong password and disabled account; per-IP login limit; no default account | `test_auth.py`, `security-model.md` | No per-account lockout, MFA, SSO or password-change endpoint; distributed guessing not stopped. **Open** |
| T10 | **Token theft from the browser** | strict CSP (no inline script, no external origin), no `dangerouslySetInnerHTML`, logs rendered as text | `dashboard.md`, `frontend` tests | Token is in `sessionStorage`, readable by any script that gets in; an HttpOnly cookie would need backend support. **Open** |
| T11 | **Spoofed client address** defeats the per-IP limits | nginx sets `X-Forwarded-For`, the backend trusts it only because the port is published on loopback | forged-header check in `progress.md` (session 12) | Exposing the backend port beyond loopback breaks this assumption |
| T12 | **Indicator disclosure to third parties** | off by default; needs a configured key, a per-request confirmation and a public address; each external call audited; provider text never copied, only a number and a sentence built from numbers | `test_threat_intel.py`, `threat-intelligence.md` | An analyst who confirms still discloses the indicator |
| T13 | **Wrongly clean verdict** (a failed lookup recorded as safe) | failures store nothing; unknown is never "clean" | `test_threat_intel.py` | None known |
| T14 | **Audit tampering** | no route can modify or delete audit rows (tested) | `test_authz_matrix.py` | Not enforced by the database: someone with database access can edit it. Reads and rejected ingestion are not audited. **Open** |
| T15 | **Secrets in the repository or logs** | `.env` and keys come from the environment, never committed; secrets redacted from ingested records | `.env.example`, `test_normalize.py` | Review before publishing any fork |
| T16 | **Compromised collector with the shared key** | the key can read, ingest and investigate, never propose, approve or administer | `security-model.md` | It can inject false events and read everything; rotate by changing the variable. **Open** |
| T17 | **Database loss** | backup and restore procedure, checked | `operations.md` | Backups are manual and unencrypted by default |
| T18 | **Supply chain** (a malicious dependency) | `uv.lock` and `package-lock.json` pin versions; CI installs frozen | `.github/workflows/ci.yml` | No dependency audit or signature check is run. **Open** |
| T19 | **Shared addresses merge unrelated incidents** (NAT, proxies) | none yet | `correlation-and-risk.md` | Analysts see merged incidents. **Open** |

## Not in scope
Denial of service at network level, a hostile database administrator, physical access, multi-tenant isolation (there is one tenant), a real EDR or firewall integration (none exists), a real LLM provider's own data handling (none is configured).

## Before using this beyond a lab
Per-account lockout and MFA or SSO; HttpOnly session cookies; database-enforced audit immutability or an external sink; a rate limiter shared across workers; a shared-address allowlist for correlation; encrypted, scheduled backups; dependency scanning; and a security review of any real response executor and any real LLM adapter before enabling them.
