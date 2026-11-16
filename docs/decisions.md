# Decisions (Milestone 9, Phase 0)

Recorded decisions that the rest of the roadmap depends on. Change a decision here first, then the code and docs that follow from it.

| # | Question | Decision | Source |
|---|---|---|---|
| 1 | Target environment | **Lab only.** One lab network with Linux and Windows VMs that the project owner controls. No production hosts and no third-party systems. | Owner answer |
| 2 | AI provider and data policy | **Ollama, internal only.** The model runs in Ollama on the lab host. Ollama has no authentication, so it is never published beyond the lab network: it listens on the internal Docker network (or loopback) only. No prompt or log leaves the lab. Model size is chosen after a hardware check (see below). | Owner answer |
| 3 | First response target | **Linux firewall (nftables).** Blocks are applied on a Linux target through Wazuh active response. Windows Firewall and EDR isolation stay simulated. | Owner answer |
| 4 | Log retention | **Chosen by the assistant, owner may change:** raw security events 30 days; alerts and incidents 180 days; audit log 365 days. Deletion runs as a scheduled job (Phase 7). | Assistant default |
| 5 | Time zone | **Store UTC everywhere.** Lab VMs run in UTC. The forwarder converts any local time to UTC with an explicit offset before sending. | Assistant default |
| 6 | Response approvers | **Two approver accounts** (the four-eyes rule already enforced in code). Account names are set by the owner when creating users. | Assistant default, names pending |
| 7 | Log transport | **Wazuh manager and agents** in the lab for Linux and Windows collection, Wazuh alerts pushed to SentinelX. Sysmon on Windows. | Assistant default |

## What the lab scope changes in the roadmap

- Phase 6 keeps the controls that protect the lab itself: per-collector keys, TLS, the HttpOnly cookie change, and audit that cannot be edited at the database level. MFA, Redis rate limiting and an external penetration test are **deferred** until the lab moves to a shared network.
- Phase 3 becomes: an `ollama` provider in `app/agents/llm.py` that calls Ollama's `/api/chat` with a JSON schema in `format`, so the reply is constrained at source; the reply is still validated by the existing Pydantic and citation guardrails. Ollama runs as a Compose service with no published port. The model name and version are pinned and recorded on every run (`model` field).
- Phase 4 (threat intel) stays optional in the lab: a lookup sends an indicator to a third party, so it runs only on addresses the owner approves.

## Open items (not blocking Phase 1)

- Hardware for the Ollama host: CPU, RAM and GPU, to pick the model size and whether it runs on GPU or CPU.
- Model to pin in Ollama (for example a small instruct model), chosen after the hardware check.
- Names of the two approver accounts.
- Exact lab topology: how many Linux and Windows VMs, and which subnet is protected from blocking.
