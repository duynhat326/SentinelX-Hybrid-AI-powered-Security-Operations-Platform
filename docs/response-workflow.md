# Response workflow

Proposals, approval, dry-run by default, and rollback. SentinelX assists analysts; it does not act on its own. The Response Agent can only *propose*, and a person other than whoever made or requested the proposal must approve it.

## The only things that can be proposed
The allowlist is a typed union (`app/response/actions.py`). No type carries a command, script, URL or shell string, and unknown fields are rejected, so nothing a person, a policy or a language model writes can become code execution.

| Type | Fields | Can run for real? |
|---|---|---|
| `add_blocklist_entry` | `ip`, `reason` | yes: writes a row to the local blocklist. **SentinelX does not enforce it**; whatever consumes the list does |
| `generate_report` | none | yes: stores a markdown report in the action result |
| `request_ip_block` | `ip`, `duration_minutes`, `reason` | no, simulation only |
| `request_host_isolation` | `host`, `reason` | no, simulation only |

## Policy (checked when proposed and again when approved)
The address must be public (documentation ranges are accepted so lab fixtures work), must **appear in the incident's evidence**, must not be on the protected list (`SENTINELX_PROTECTED_IPS`, comma separated addresses or networks; a typo stops startup), and must not already be blocklisted. A host must belong to the incident and be a known asset. The incident must be open. Re-checking at approval matters because the world changes between the two moments (the checklist item "protected list changed after the proposal" is a test).

## States
```
proposed --approve (dry run, the default)--> simulated
proposed --approve (real: switch on, type allows it)--> executed | failed
proposed --reject--> rejected
executed --rollback (blocklist entries)--> rolled_back
```
- **Approval** needs the `approve` permission (approver, admin), a person who is **neither the requester nor the person who triggered the suggestion**, and a passing policy check. `real: true` additionally needs `SENTINELX_RESPONSE_REAL_ACTIONS_ENABLED=true` (default `false`) and a type that allows it. A dry run records what *would* happen (`result.would`) and changes nothing; it cannot later be upgraded to a real run (propose a new action).
- **Repeating** any decision is harmless: approving an approved action, rejecting a rejected one or rolling back a rolled-back one returns the existing record and writes nothing. The action row is locked while it is decided (`SELECT ... FOR UPDATE` on PostgreSQL), so concurrent approvals execute once.
- **Idempotency:** a proposal may carry an `Idempotency-Key` header. The same key from the same person with the same request returns the original (200, even if the policy has since changed); with a different request it is a 409. A concurrent duplicate resolves to one row.
- **Rollback:** deactivates the blocklist entry (and frees the address to be proposed again). Every action stores `rollback_guidance`; for types that cannot be rolled back by SentinelX (simulations, reports) a rollback request answers 409 with that guidance.

## Audit
Each state change writes audit rows in the same transaction as the change, and each refusal commits its row before answering: `response.propose`, `response.approve` plus `response.execute`, `response.reject`, `response.rollback`, `response.suggest`, with outcome `ok`, `denied` or `error`. A replay writes nothing because nothing changed. `tests/test_response.py::test_each_state_change_and_refusal_leaves_exactly_the_audit_rows_it_should` walks every transition and refusal and asserts the exact number of rows each one leaves. Requests rejected by schema validation (an unknown type, a smuggled field) get a 422 and are not audited, like other validation errors.

## Response Agent
`POST /api/v1/incidents/{id}/response-actions/suggest` (permission `propose`):
- **Policy mode (default):** deterministic. Proposes blocklisting each public address in the incident (at most 5) and a report; it lists the candidates the policy refused, with reasons. No model involved.
- **AI mode** (`{"use_ai": true}`, needs `SENTINELX_LLM_PROVIDER` and shares the investigation rate limit): the model's reply is treated as untrusted. Each item must validate against the allowlist, otherwise it is dropped and counted; then the same policy applies. A model suggesting an address or host that is not in the incident is refused, which is also the defence against log text that tells the model to block somebody else. Survivors are `proposed` with `requested_by = agent:<provider>` and `triggered_by` = the person who asked; nothing is approved or run. The log text sits inside the same escaped, redacted data fence as in the investigation.
- Suggestions are idempotent per target, so repeating the call returns the existing proposals instead of duplicates.

## API
| Method | Path | Needs |
|---|---|---|
| POST | `/api/v1/incidents/{id}/response-actions` (typed body, optional `Idempotency-Key`) | `propose` |
| POST | `/api/v1/incidents/{id}/response-actions/suggest` | `propose` |
| GET | `/api/v1/response-actions`, `/{id}`, `/api/v1/blocklist` | `read` |
| POST | `/api/v1/response-actions/{id}/approve` `{real}`, `/reject` `{reason}`, `/rollback` | `approve` |

## Limits
- The blocklist is advisory data. Nothing here blocks traffic; a firewall integration would be a separate, reviewed addition.
- Four-eyes compares account names: two accounts shared by one person defeat it.
- A real action's effect is a database row, so "real" here is modest by design. If a firewall executor is added later it must be a new allowlisted type with its own tests, simulation first.
- Reports contain log-derived text (kept inside code spans, bounded); render them with HTML disabled.
- Merging two incidents moves their actions and AI runs to the surviving incident (a foreign key stops an incident that has actions from being deleted).
- Nobody has run this against a real firewall, EDR or ticketing system.
