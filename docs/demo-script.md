# Demo script (about five minutes)

Everything shown is synthetic. Start with the stack running and an admin created ([README quick start](../README.md)). Use `SENTINELX_LLM_PROVIDER=mock` for step 5, or `mock-adversarial` (lab only) for step 6.

1. **Seed and orient (30 s).** `python3 lab/seed_demo.py`, then sign in at `http://localhost:8080`. The overview shows exact counts, alerts and open incidents by severity, and the highest-risk incidents. Say: *"Nothing here used a language model."*
2. **One story, not eight alerts (60 s).** Run `python3 lab/scenarios/run.py D`. Open the new incident: several alerts across two hosts, one incident. Point at *Grouped because* (`ip:203.0.113.70`) and the timeline from the first failed login to the dropped executable. The risk breakdown shows what each component contributed; threat intelligence reads "unknown, not used", never "clean".
3. **MITRE view (20 s).** Techniques grouped by tactic, only the ones the rules assign.
4. **Response needs two people (60 s).** As an analyst, *Suggest (policy)*: proposals appear for evidence-bound addresses only. As the same analyst, try to approve: refused. As an approver, approve: a **dry run**; the result says what it *would* do. Open the audit log as admin: every step and every refusal is there.
5. **AI that explains (45 s).** *Run AI investigation*: each finding cites evidence ids, with confidence and uncertainties. Say: *"It cannot change the score, and it cannot act."*
6. **Prompt injection (60 s, lab model).** `python3 lab/scenarios/run.py E --check` against a stack with `mock-adversarial`: failed logins whose username carries instructions. The run records refused tool calls and dropped claims, the incident's severity and risk are unchanged, and *Suggest (AI)* creates nothing. Then be honest about the residual risk: a claim that cites real evidence but carries hostile text is shown as advice, and a person must not follow it.
7. **Close (15 s).** [evaluation.md](evaluation.md): synthetic data, and what was and was not measured.
