# Detection rules

Rules are deterministic Python functions in `backend/app/detection/engine.py`. They run on every ingested event, need no LLM, and each carries an id, severity, MITRE ATT&CK technique ids and references. Their metadata is mirrored into the `detection_rules` table at startup; an operator can switch a rule off by setting `detection_rules.enabled = false` (the sync never overwrites that flag). There is no API to toggle rules yet.

| ID | Title | Severity | MITRE | Needs |
|---|---|---|---|---|
| SX-001 | Repeated failed SSH logins from one source | high | T1110 | sshd auth logs |
| SX-002 | Suspicious PowerShell command line | high | T1059.001 | Sysmon 1 |
| SX-003 | Local account created from the command line | high | T1136.001 | Sysmon 1 |
| SX-004 | Account added to the local Administrators group | high | T1098 | Sysmon 1 |
| SX-005 | Registry Run key persistence | medium | T1547.001 | Sysmon 13 |
| SX-006 | Script host or LOLBin connecting to an external address | medium | T1071 | Sysmon 3 |
| SX-007 | Office application spawning a shell or script host | high | T1204.002 | Sysmon 1 |
| SX-008 | Repeated SSH failures followed by a successful login | critical | T1110, T1078 | sshd auth logs |
| SX-009 | Script host or Office application writing an executable to a user-writable folder | medium | T1105 | Sysmon 11 |

Events can arrive directly or relayed by Wazuh (`source: "wazuh"`); relayed events are normalized first, so every rule treats them the same.

## Alert merging

An alert is keyed by `(rule_id, host, group_key)`. A new matching event is added to the existing alert if that alert's evidence window overlaps `+- bruteforce_window_seconds` (default 300 s) around the event; otherwise a new alert is opened. Alerts record `first_event_at` and `last_event_at`. Single-event rules use the event id as group key, so each match is its own alert. Detection tolerates out-of-order arrival: SX-001 and SX-008 look in both time directions.

## Rules

### SX-001 Repeated failed SSH logins from one source
- **Fires when** at least `bruteforce_threshold` (default 5) failed logins from one source IP to one host fall inside `bruteforce_window_seconds` (default 300 s).
- **Expected false positives:** a user or script with a stale password behind one NAT address; vulnerability scanners you own.
- **Known gaps:** low-and-slow attempts (5 failures 2 minutes apart) and password spraying spread over many source IPs.

### SX-002 Suspicious PowerShell command line
- **Fires when** `powershell`/`pwsh` runs with `-e`, `-ec`, `-enc` or `-EncodedCommand`, a `DownloadString` cradle, `Invoke-Expression`/`iex`, or `-nop` together with a hidden window.
- **Expected false positives:** management and deployment tools that use encoded commands.
- **Known gaps:** abbreviated parameters such as `-en` or `-EncodedC`; string-concatenation obfuscation.

### SX-003 Local account created from the command line
- **Fires when** `net.exe`/`net1.exe` runs `user <name> ... /add`, or PowerShell runs `New-LocalUser`. When started through `cmd /c`, the child `net.exe` event is what matches.
- **Expected false positives:** helpdesk and provisioning scripts creating local accounts.
- **Known gaps:** renamed binaries, `dsadd` and other directory tooling, API-level account creation.

### SX-004 Account added to the local Administrators group
- **Fires when** `net localgroup administrators <member> /add` or `Add-LocalGroupMember` targeting `Administrators` runs.
- **Expected false positives:** legitimate administration and onboarding scripts.
- **Known gaps:** the group addressed by SID, localized group names, other privileged groups (for example Remote Desktop Users is deliberately out of scope).

### SX-005 Registry Run key persistence
- **Fires when** a registry value is set under `...\CurrentVersion\Run`, `RunOnce`, `RunOnceEx` or `Policies\Explorer\Run`.
- **Expected false positives:** software installers and updaters write Run keys routinely. This is the noisiest rule; baseline per environment before trusting it.
- **Known gaps:** other persistence locations (for example `Winlogon\Userinit`, services, scheduled tasks, startup folder).

### SX-006 Script host or LOLBin connecting to an external address
- **Fires when** `powershell`, `pwsh`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wscript` or `cscript` opens a connection to an external address. External means globally routable, excluding multicast, plus the RFC 5737 / RFC 3849 documentation ranges so lab fixtures need no real addresses.
- **Expected false positives:** PowerShell fetching modules or updates; `certutil` and `bitsadmin` used by legitimate tooling.
- **Known gaps:** other abusable binaries (for example `msbuild`, `installutil`); inbound connections are not distinguished because the Sysmon `Initiated` field is ignored.

### SX-007 Office application spawning a shell or script host
- **Fires when** Word, Excel, PowerPoint, Outlook, Access, Publisher or OneNote starts `cmd`, PowerShell, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil` or `bitsadmin`.
- **Expected false positives:** macro-enabled business workbooks that legitimately call scripts.
- **Known gaps:** other children such as `msiexec`; web-server parents (planned, not implemented).

### SX-008 Repeated SSH failures followed by a successful login
- **Fires when** a successful login from an IP is preceded, within `bruteforce_window_seconds`, by at least `bruteforce_threshold` failures from the same IP on the same host. Evidence is the failures plus the success. Typically fires together with SX-001; correlating the two is Milestone 4.
- **Expected false positives:** a user who forgets a password, tries many times, then succeeds from the same address.
- **Known gaps:** distributed attempts from several IPs followed by a success from another.

### SX-009 Script host or Office application writing an executable to a user-writable folder
- **Fires when** Sysmon event 11 (file create) shows PowerShell, a script host (`wscript`, `cscript`, `mshta`), `rundll32`, `regsvr32`, `certutil`, `bitsadmin` or an Office application writing a file with an executable or script extension (`exe dll scr js jse vbs vbe hta ps1 bat cmd`) under `Users\<name>\AppData`, `Downloads`, `Desktop`, `Documents`, `Users\Public`, `ProgramData` or any `Temp`.
- **Expected false positives:** administration scripts that write tools or scripts to Temp or ProgramData; installers launched through a script host. Browsers and installers themselves are deliberately not droppers.
- **Known gaps:** other writers (for example `msbuild`), archives and other payload types, folders outside that list (for example `C:\Windows\Tasks`).
- **ATT&CK:** the mapping to T1105 (Ingress Tool Transfer) is a heuristic: the rule sees a file written, not where it came from.

## Labeled corpus

`backend/tests/corpus/sx-00N.json` holds 171 synthetic cases (316 events): 92 malicious, 79 benign, including 16 **known gaps**, which are malicious techniques a rule deliberately does not cover. The test `test_every_corpus_case_behaves_as_labeled` replays every case through the API and requires each rule to behave as labeled; known gaps must still be missed, so improving a rule means flipping that case on purpose.

Result of the last run (the same table prints with `uv run pytest -s tests/test_corpus.py`):

| Rule | TP | FN | FP | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| SX-001 | 6 | 2 | 0 | 5 | 1.00 | 0.75 |
| SX-002 | 9 | 2 | 0 | 8 | 1.00 | 0.82 |
| SX-003 | 9 | 2 | 0 | 10 | 1.00 | 0.82 |
| SX-004 | 8 | 2 | 0 | 9 | 1.00 | 0.80 |
| SX-005 | 8 | 1 | 0 | 8 | 1.00 | 0.89 |
| SX-006 | 9 | 2 | 0 | 11 | 1.00 | 0.82 |
| SX-007 | 10 | 1 | 0 | 9 | 1.00 | 0.91 |
| SX-008 | 8 | 1 | 0 | 9 | 1.00 | 0.89 |
| SX-009 | 9 | 3 | 0 | 10 | 1.00 | 0.75 |

**How to read this.** These are regression numbers, not an evaluation. The same author wrote the rules and the cases, so precision of 1.00 mostly shows the rules do what they were written to do on cases the author thought of, and says little about real traffic. Recall below the 0.85 initial target for SX-001, 002, 003, 004, 006 and 009 comes from the deliberate known-gap cases. The real evaluation (Milestone 8) needs independently produced events from the lab. Nothing here was run on real telemetry.

Case format: `events` are compact descriptions (`k` = `p` process create, `n` network connect, `fc` file create, `r` registry set value, `r12` registry key create/delete, `f` failed SSH login, `s` successful SSH login) expanded into raw Sysmon JSON or sshd lines by `backend/tests/corpus_runner.py`. All hosts, users and addresses are fictional or in documentation ranges; nothing in the corpus executes anything.

## Adding a rule
1. Write a `check(db, ev, cfg)` function returning `(group_key, [evidence events])` or `None`, and add a `Rule(...)` entry to `RULES`.
2. Add at least 5 malicious and 5 benign cases in `backend/tests/corpus/` (include known gaps honestly).
3. Add a section here; `test_rule_metadata_and_docs` fails if the id or title is missing.
4. No migration is needed; `detection_rules` syncs from code at startup.
