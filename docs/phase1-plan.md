# Phase 1 plan: real log ingestion on the lab laptop

Status: planned, not started. Scope and decisions come from `docs/decisions.md`; the phase goals come from `docs/roadmap-real-world.md`. This plan narrows Phase 1 to what one laptop can run.

## Environment

- Host: ZenBook UX362FA, Debian 13, Intel i7-8565U (4 cores, 8 threads), 15.4 GiB RAM, no swap, 172 GiB free on `/`, integrated GPU only (Ollama runs on CPU).
- Network: a host-only lab network for lab VMs. Lab VMs are not bridged to the home LAN (192.168.1.0/24).
- Power: plugged in; suspend disabled while the lab runs.

## Decisions this plan relies on, and changes it proposes

| Item | Decision in `decisions.md` | Proposal here | Needs your answer |
|---|---|---|---|
| Wazuh | Wazuh manager and agents | Defer. Use a small forwarder for Linux first. Wazuh needs about 4 GB RAM. | yes |
| Windows and Sysmon | Sysmon on Windows | Defer until RAM is upgraded or a second machine is available. | yes |
| Log transport | Wazuh | Stdlib Python forwarder reading `auth.log` and posting to `POST /api/v1/events` | yes |
| Acceptance (Phase 1 exit) | 5 hosts for 7 days | 1 Linux VM for 7 days (lab reduced) | yes |

## RAM budget for Phase 1

| Component | Estimate | Note |
|---|---|---|
| Host OS, GNOME, editor, browser | 4 to 5 GB | Measure first; currently 12.8 GiB used, so close apps before starting |
| SentinelX stack (Postgres, backend, frontend) in Docker | about 1 GB | No lab VM needed |
| Linux target VM | 1 GB | Debian 13 minimal, UTC |
| Ollama | not started in Phase 1 | Phase 3 |

## Steps

### Step 1: preflight (half a day)
1. Measure: `free -h`, `top` sorted by memory. Close what is not needed; target at least 5 GB available.
2. Turn off automatic suspend while on AC power.
3. Check tools: Docker and Compose, `uv`, Python 3.12 or newer, and a VM tool (VirtualBox or libvirt/virt-manager).
4. Create the host-only network.

**Done when:** `docker compose version` works, `free -h` shows at least 5 GB available with the stack idle, and the host-only network exists.

### Step 2: SentinelX stack on the host (half a day)
1. `cp .env.example .env`; set `SENTINELX_API_KEY` and `POSTGRES_PASSWORD` (never print them in chat).
2. `docker compose up --build -d`; leave `SENTINELX_LLM_PROVIDER=none` and the external threat-intel switch off.
3. Create the two approver accounts and one analyst account (`python -m app.manage create-user`).

**Done when:** `curl localhost:8000/health` returns ok, and the dashboard at localhost:8080 signs in.

### Step 3: Linux target VM and forwarder (2 to 3 days)
1. Create a Debian 13 minimal VM (1 GB RAM, 10 GB disk), timezone UTC, openssh-server enabled.
2. Write `lab/forwarder/forward_authlog.py` (stdlib only): follow `/var/log/auth.log`, keep a byte offset so restarts resume, post each line as `{"source": "linux_auth", "payload": <line>}` with `X-API-Key`, retry with backoff, and log failures without the key.
3. Run it as a systemd service on the VM.
4. Generate real sshd traffic from the host: successful logins, failed passwords, invalid users, public-key logins.

**Done when:** every test login appears as an event in SentinelX, and a restart of the forwarder does not duplicate or skip lines.

**Shortcut to record:** the forwarder uses the shared collector key. This is acceptable inside the lab until Phase 6 adds per-collector keys; it must not leave the lab before then.

### Step 4: parser coverage on real samples (2 to 3 days)
1. Capture real `auth.log` lines for each sshd message type; store them as sanitized fixtures in `backend/tests/fixtures/`.
2. Run each through `normalize_linux_auth`; list every line that fails and why.
3. Extend the parser only for lines that are real and security-relevant; keep unknown lines as a counted parse error, not a crash.
4. Add a test per new message type, using the real samples.

**Done when:** on the captured sample set, parse errors are below 1% and every parse error is explained.

### Step 5: timestamps and time zone (1 day)
1. The VM runs UTC, so the forwarder can rely on the syslog year assumption; add a test that a line from the previous year near New Year is handled.
2. Document the assumption as the shortcut it is in `architecture.md` (already listed), with the lab condition written next to it.

**Done when:** the test passes and the lab VM clock is synced (`timedatectl`).

### Step 6: asset criticality API (2 days)
1. Add `PATCH /api/v1/assets/{hostname}` with a `criticality` field (1 to 5), requiring a new permission (`manage_assets`, approver or admin).
2. Add the route to `tests/test_authz_matrix.py`; the test fails otherwise.
3. Audit each change with the old and new value.
4. Recompute the risk of open incidents on that host (same pattern as IOC changes).
5. Add a CSV import script `lab/import_assets.py` only if more than a handful of hosts are needed; otherwise skip it.

**Done when:** the authz matrix passes, the audit row exists, and a changed criticality changes the open incident's risk.

### Step 7: seven-day run (7 days, mostly waiting)
1. Leave the VM and forwarder running for seven days.
2. Each day, record: events count, parse errors, duplicates (should be 0), forwarder restarts.
3. Do not change code during the run except for a bug fix, and record any fix.

**Done when:** the daily log shows parse errors below 1% and no unexplained gaps, and the backend has not crashed.

## Phase 1 exit criteria (lab version)

- One Linux VM forwards continuously for seven days.
- Parse error rate below 1% on real sshd traffic; every error is explained.
- Zero duplicate events from restarts (dedup hash works on real lines).
- Asset criticality can be changed through the API, with audit and a matching authz row.
- `uv run ruff check .`, `uv run mypy app` and `uv run pytest -q` pass on SQLite; PostgreSQL run passes too.
- `docs/checklist.md` items for Phase 1 are ticked with the real numbers, not estimates.

## Files this phase will touch

- New: `lab/forwarder/forward_authlog.py`, `backend/tests/fixtures/` (real sshd samples), `docs/phase1-report.md` (the daily log and results).
- Changed: `backend/app/normalization/normalize.py` (only for real lines), `backend/app/api/` (assets route), `backend/app/core/` if the permission needs a config entry, `backend/tests/test_authz_matrix.py`, `backend/tests/` (new tests).
- Migration only if the asset model changes; none is expected.

## Risks

- **Memory pressure** on a 15 GB laptop: the VM and the stack together can swap-thrash (there is no swap). Mitigation: measure in Step 1; stop the VM when not testing.
- **Real traffic is quiet**: a lab VM may produce few failed logins. Mitigation: generate a scripted, labelled set of logins and failures on schedule, and report it separately from organic traffic.
- **Laptop sleep or lid close** stops the lab. Mitigation: no suspend on AC; document the setting.
- **Shared key leaking**: the forwarder config holds the key. Mitigation: file mode 600, lab network only, rotate at Phase 6.

## Open questions for you

1. Defer Wazuh and Windows for Phase 1 (recommended), or set them up now and accept the RAM limit?
2. Accept one Linux VM for seven days as the lab version of the five-host exit criterion?
3. Which VM tool do you want: VirtualBox or libvirt/virt-manager?
