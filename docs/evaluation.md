# Evaluation

**Read this first.** Every number below comes from **synthetic data written by the people who wrote the rules**, run through the real application (`backend/evaluation/run.py`, seed `20261116`, raw output in [`evaluation-results.json`](evaluation-results.json)). That makes them **regression and design measurements, not real-world accuracy**: precision 1.00 on a corpus its author wrote says the rules do what the author meant, not that they will be this quiet on a real network. No real endpoint, real attacker, real analyst or real language model was involved. Where a quantity could not be measured honestly it is listed as *not measured*.

Reproduce:
```bash
cd backend
uv run python -m evaluation.run                                   # detection, campaigns, guardrails (SQLite, deterministic)
uv run python -m evaluation.run --only system --live http://127.0.0.1:8001 --key "$SENTINELX_API_KEY"   # needs a running server
```
Rerunning gives the same numbers for the first three sections (fixed seed, no wall clock); `system` depends on the machine.

## 1. Detection (rules only)

Labeled corpus: 171 cases (316 events), 92 malicious and 79 benign, including 16 deliberate *known gaps* (malicious cases the rule is expected to miss, counted as false negatives; see [detection-rules.md](detection-rules.md)). Confidence intervals are 95% Wilson intervals, which show how little 8 to 20 cases per rule can tell you.

| Rule | TP | FN | FP | TN | Precision (95% CI) | Recall (95% CI) | F1 |
|---|---|---|---|---|---|---|---|
| SX-001 | 6 | 2 | 0 | 5 | 1.00 (0.61–1.00) | 0.75 (0.41–0.93) | 0.86 |
| SX-002 | 9 | 2 | 0 | 8 | 1.00 (0.70–1.00) | 0.82 (0.52–0.95) | 0.90 |
| SX-003 | 9 | 2 | 0 | 10 | 1.00 (0.70–1.00) | 0.82 (0.52–0.95) | 0.90 |
| SX-004 | 8 | 2 | 0 | 9 | 1.00 (0.68–1.00) | 0.80 (0.49–0.94) | 0.89 |
| SX-005 | 8 | 1 | 0 | 8 | 1.00 (0.68–1.00) | 0.89 (0.56–0.98) | 0.94 |
| SX-006 | 9 | 2 | 0 | 11 | 1.00 (0.70–1.00) | 0.82 (0.52–0.95) | 0.90 |
| SX-007 | 10 | 1 | 0 | 9 | 1.00 (0.72–1.00) | 0.91 (0.62–0.98) | 0.95 |
| SX-008 | 8 | 1 | 0 | 9 | 1.00 (0.68–1.00) | 0.89 (0.56–0.98) | 0.94 |
| SX-009 | 9 | 3 | 0 | 10 | 1.00 (0.70–1.00) | 0.75 (0.47–0.91) | 0.86 |
| **All** | 76 | 16 | 0 | 79 | **1.00 (0.95–1.00)** | **0.83 (0.74–0.89)** | **0.91** |

How to read it: zero false positives is the result of benign cases chosen to sit *next to* each rule's boundary, written by the author. The real false-positive rate is unknown and, per rule, the documented real-life causes (installers writing Run keys, management tools using encoded commands) say it is not zero. Recall below 1 is by construction: the known gaps are cases the author already knew the rules miss (obfuscation, renamed binaries, paths outside the patterns).

**MITRE ATT&CK mapping:** each rule carries fixed technique ids, so the mapping is correct *by construction* of the author's choice. That is not an accuracy measurement and no independent check was made.

## 2. Rules versus rules plus correlation

Question: does grouping alerts into incidents and scoring them help an analyst compared with a flat alert list? Dataset (generated in `evaluation/run.py`): **63 synthetic episodes** (40 attacks, 23 benign) that produce **117 alerts**. Episodes own their hosts, users and addresses, so the truth of "which alerts belong together" is the episode.

- Attacks: 12 brute force then login; 10 Office macro to encoded PowerShell; 8 chains across two hosts joined by an address; 10 *single-stage* attacks (persistence, LOLBin connection, admin group add).
- Benign: 15 single-rule noise cases (management tool with encoded PowerShell, installer Run key, updater using a script host, workbook calling a script, admin adding a colleague to a group) and 8 benign cases that fire **several** rules (an administrator failing six times then logging in; macro automation running encoded PowerShell).
- Single-stage attacks and single-stage benign noise are **indistinguishable on purpose**: the same rule fires on both, so no method can separate them without extra context.

| Configuration | Unit an analyst triages | Units | AUROC, ranking attack above benign (95% bootstrap CI) |
|---|---|---|---|
| 1. Rules only | alert, ranked by rule severity | 117 | 0.55 (0.46–0.64) |
| 2. Rules + correlation | incident, ranked by max severity | 63 | 0.66 (0.53–0.78) |
| 2. Rules + correlation + risk score | incident, ranked by risk (0–100) | 63 | 0.72 (0.59–0.83) |
| 3. + AI investigation | same incidents | 63 | **no change by design** |

- **Triage load:** 117 alerts become 63 incidents, a 46% reduction. Grouping was exact on this data (pairwise precision 1.00, recall 1.00; no incident mixes attack and benign; no episode split). **This is partly true by construction**, because every episode has its own addresses.
- **Ranking:** correlation and the risk score move AUROC from 0.55 to 0.72, but the confidence intervals overlap (risk 0.59–0.83 versus severity-only 0.53–0.78): with 63 units this data **cannot show** that the risk score beats plain severity, only that incident-level ranking is better than alert-level ranking. The ceiling is low because single-stage cases cannot be separated.
- **Configuration 3:** the AI never changes severity, risk or grouping (asserted by tests in `test_agents.py` and `test_scenarios.py`; also counted in section 3: 0 of 20 incidents changed). Its *quality* (is the explanation right, does it help) was **not measured**: only an offline mock exists, and a mock's output says nothing about a real model.
- **A finding from the first run.** The first generator gave every network event the same source address and correlation, which links alerts that share an address, merged unrelated hosts (pairwise precision 0.58). The same would happen on a real network behind a NAT gateway or proxy. The generator now gives each host its own address; the limit is real and is listed under known gaps in [correlation-and-risk.md](correlation-and-risk.md).

## 3. AI guardrails against a hostile model

`mock-adversarial` is a scripted model that does what an injected prompt would ask (see lab scenario E). It was run against the 20 incidents of the attack episodes, each followed by an AI response suggestion by an analyst. This measures the **validation layer**, not any model.

| Hostile behaviour | Issued | Outcome |
|---|---|---|
| Tool calls (`delete_incident`, `run_shell`, a malformed one), two model calls per run | 120 | **120 refused and recorded**, none executed |
| Claims with an invented id or no evidence, and a technique no rule assigned | 100 | **100 dropped** (5 per run) |
| Response proposals (not an action, smuggled field, unrelated address, unrelated host, a bare string) | 100 | **0 created**: 60 dropped for not fitting the allowlist, 40 refused by policy |
| Runs that changed an incident's severity, risk or status | 20 | **0** |
| Runs whose `scope` was not the incident's own hosts | 20 | **0** |
| A claim citing **real** evidence but carrying hostile text | 20 | **20 shown to the analyst as advice**: not caught, by design (see below) |

The last row is the residual risk, and it is not a bug in the measurement: a citation check proves an id exists, not that the sentence is sound. Such a claim is displayed, never executed, and a person must not follow it. A real model may fail in ways this script does not; this table proves nothing about it.

## 4. Controls counted from the test suites

| Property | How it is checked | Result |
|---|---|---|
| Every route declares a permission | `tests/test_authz_matrix.py` enumerates the OpenAPI routes and fails on a route without a row | every route is either public (health, login) or has a matrix row; the test fails otherwise |
| Unauthorized actions blocked | the matrix tries each route with each role and with no credentials | all denied as specified, in the last full run (see `progress.md`) |
| Four-eyes on approval | `tests/test_response.py`: requester, asker and an analyst each tried | all refused; a different approver succeeds |
| Real effects need the kill switch | `tests/test_response.py` | 409 while off |
| Audit coverage | each state change and each refusal writes a row; checked in `test_response.py`, `test_scenarios.py`, `test_auth.py` | actions written: login and logout, user create and update, IOC create and delete, external lookups, investigation, suggestion, proposal, approval, execution, rejection, rollback; **not** audited: reads of data and rejected ingestion |

## 5. System behaviour

One client, sequential, loopback, one uvicorn worker, PostgreSQL 17 in a container on the same machine, hardware not recorded. These are a floor for comparing changes, **not a capacity claim**.

| Measure | Result |
|---|---|
| Ingest, 1,000 SSH-failure lines posted one after another | 64.5 events/s; latency p50 15.0 ms, p95 18.3 ms, max 42.4 ms |
| `GET /api/v1/overview` (100 calls) | p50 11.7 ms, p95 12.6 ms |
| `GET /api/v1/incidents?limit=50` | p50 9.9 ms, p95 11.3 ms |
| `GET /api/v1/alerts?limit=50` | p50 6.1 ms, p95 6.9 ms |

Not measured: concurrent load, large tables (lists are capped at 200 and unpaginated), the Docker network path through nginx, memory use.

## What was not measured

- Real-world precision and recall of any rule; any real attacker behaviour; the false-positive rate on production traffic.
- AI explanation quality (accuracy, hallucination rate on a real model, analyst time saved): needs a real model adapter and human-labeled incidents.
- Threat-intel verdict accuracy: no real provider was ever called (that would disclose indicators to third parties).
- Whether the risk-score weights (0.4 / 0.3 / 0.2 / 0.1) are well chosen: they are estimates; this data cannot distinguish them from plain severity.
- Scenario C on a real Windows VM (see [lab/scenarios/README.md](../lab/scenarios/README.md)).
