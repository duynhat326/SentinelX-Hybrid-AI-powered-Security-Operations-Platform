# AI investigation (advisory)

`POST /api/v1/incidents/{id}/investigate` runs a bounded workflow over one incident and stores the result in `agent_runs`. It is **off by default** (`SENTINELX_LLM_PROVIDER=none` returns 503) and the only provider today is an offline `mock`; no real LLM is wired in. Detection, correlation, risk scoring and every permission work the same with it off, and nothing it produces feeds back into severity, risk or status.

## Workflow
A LangGraph (`backend/app/agents/investigate.py`) with two nodes in a line and no loops: `run_triage` then `run_investigation`. Exactly two model calls per run, no tools, no retries, `recursion_limit` 10. The context (the incident detail, timeline halved until it fits `SENTINELX_LLM_MAX_PROMPT_CHARS`) is built once, redacted again for secrets, and has `<` escaped so a log line cannot close the `<data>` fence.

## What is enforced in code (each has a test that fails if the guard is removed)
| Guard | Behavior |
|---|---|
| Citations | A claim survives only if it cites at least one id and every id is an **alert or event id** of this incident. The incident id is not evidence. Others are dropped and counted in `dropped_claims`. |
| Techniques | `likely_techniques` keep only technique ids the deterministic rules already assigned to the incident, and only with valid citations. |
| Scope | `scope` (hosts, users, IPs) is derived from the incident's entities. Anything the model says about scope is ignored. |
| Tool calls | There are no tools. Any `tool_calls` the model emits are never executed; each attempt (name and truncated args, at most 20 plus a marker) is stored in `rejected_tool_calls`, whatever its shape. |
| Errors | A failed run stores only the exception class name, or schema field paths for invalid output. Provider messages (which can echo credentials) and model text are never stored or returned. |
| Size | Advisory text (`next_steps`, `uncertainties`, claim text, rationale) is truncated, never a reason to fail the run. List sizes beyond their limit fail the run closed. |
| Cost | `POST /investigate` has its own rate limit (`SENTINELX_LLM_RATE_LIMIT_PER_MINUTE`, default 10 per IP) and passes `SENTINELX_LLM_TIMEOUT_SECONDS` (default 30) to the provider. |

## Output (`agent_runs.output`)
`suggested_priority`, `confidence` (model's own estimate; defaults to `low`), `scope`, `triage_claims`, `findings` (each `{text, cites}`), `likely_techniques` (`{id, rationale, cites}`), `uncertainties`, `next_steps`. Provenance columns: `provider`, `model`, `prompt_version` (bump `PROMPT_VERSION` when the prompt changes), `input_sha256` (hash of the exact context sent), `duration_ms`.

## Limits
- A valid citation proves the id exists in the incident, not that the sentence is true. Evidence accuracy needs labeled data (Milestone 8).
- `next_steps` are uncited advice text from a model that read attacker-controlled logs: show them as suggestions, never as commands.
- `confidence` is not calibrated or checked.
- The mock cannot show how a real model reacts to injected text, so injection resistance of a real provider is untested.
- Data sent to a real provider would include command lines and usernames (secrets are redacted by pattern, which is best effort). Decide whether that is acceptable before wiring one in.

## Adding a real provider
Implement `LLM.complete(system, user, timeout) -> str` in `backend/app/agents/llm.py`, enforce `timeout` yourself, extend `Settings.llm_provider`, and keep exceptions free of credentials where you can (the run stores only the class name anyway). Add a test that a failing provider records a `failed` run.
