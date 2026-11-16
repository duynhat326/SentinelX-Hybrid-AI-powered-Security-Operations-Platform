# Security model: who may do what

Added in Milestone 6A, before any response action exists. Every route declares the permission it needs; `tests/test_authz_matrix.py` calls **every route** as every kind of caller and fails if a route has no declared permission, so an endpoint cannot ship unprotected.

## Callers
| Caller | How it authenticates | Role |
|---|---|---|
| A person | `Authorization: Bearer <token>` from `POST /api/v1/auth/login` | `viewer`, `analyst`, `approver` or `admin` |
| A collector or legacy client | `X-API-Key` (the shared `SENTINELX_API_KEY`) | `service` |

A wrong or expired bearer token is a 401 and **never falls back** to the API key, even if a valid key is also sent.

## Permissions
| Permission | viewer | analyst | approver | admin | service |
|---|:-:|:-:|:-:|:-:|:-:|
| `read` (alerts, rules, incidents, agent runs) | yes | yes | yes | yes | yes |
| `ingest` (`POST /api/v1/events`) | | | | | yes |
| `investigate` (run the AI investigation) | | yes | yes | yes | yes |
| `enrich` (look up indicators; external lookups also need confirmation) | | yes | yes | yes | |
| `propose` (propose or suggest response actions) | | yes | yes | yes | |
| `manage_iocs` (write the local IOC table) | | | yes | yes | |
| `approve` (approve, reject, roll back response actions) | | | yes | yes | |
| `manage_users`, `read_audit` | | | | yes | |

Roles only ever add permissions (tested). The shared key can read, ingest and run investigations; it can never propose or approve anything or administer users. Collectors should keep using it; people should not.

## Sessions and passwords
- Passwords are hashed with stdlib `scrypt` (16 MiB, per-password salt), 12 to 128 characters. Nothing else is stored about them.
- A login returns a random 256-bit token valid for `SENTINELX_TOKEN_TTL_MINUTES` (default 480). Only its SHA-256 is stored, so a database read does not yield usable tokens. `POST /api/v1/auth/logout` revokes it; disabling a user cuts off their existing sessions immediately.
- Failed logins return one identical message for an unknown user, a wrong password and a disabled account, and an unknown user costs the same hashing work as a known one. Logins are rate limited per client IP (`SENTINELX_LOGIN_RATE_LIMIT_PER_MINUTE`, default 10).
- The last active admin cannot be demoted or disabled.

## First admin
There is no default account. Create one from the host, with the password read from a prompt (or from stdin with `--password-stdin`, never from the command line):
```bash
docker compose exec backend .venv/bin/python -m app.manage create-user alice admin
```
`set-password USER` resets a password the same way. After that, admins manage users through `/api/v1/users`.

## The dashboard
People sign in through the dashboard with the same bearer tokens; the page hides controls by permission (from `/api/v1/auth/me`) but the server decides. The token is kept in `sessionStorage`; see [dashboard.md](dashboard.md) for that trade-off and for the proxy headers.

## Audit log
`audit_logs` records who did what, to what, with which outcome (`ok` or `denied`), from which IP: logins and failed logins, logouts, user creation and changes, **every refusal of an identified caller** (`authz.denied`, with the permission that was missing), each AI investigation run, IOC creation and deletion, and every response proposal, approval, execution, rejection and rollback (and each refusal), and **every external threat-intelligence lookup** (caller, provider, indicator, outcome; never the key). Details are redacted and capped. Admins read it at `GET /api/v1/audit-logs` (filters `action`, `actor`, `outcome`). The application has no route or code path that updates or deletes a row. An action and its audit row commit in the same transaction; a refusal commits its audit row before answering 403.

## Limits (not done, on purpose or not yet)
- Audit immutability is by convention, not enforced by the database: someone with database access can edit it. A trigger or an external log sink would close that.
- Requests with no valid identity (401) are not audited, to avoid flooding the log; only failed **logins** are.
- No per-account lockout (it would let anyone lock out a known admin); only the per-IP login limit. Distributed guessing against one account is not stopped.
- No password-change endpoint (use the CLI), no token rotation, no MFA, no single sign-on.
- The shared API key still grants broad read access. Rotate it by changing the environment variable.
- Roles are fixed in code; there is no role editor.
