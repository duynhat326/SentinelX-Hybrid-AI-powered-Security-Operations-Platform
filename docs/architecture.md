# Architecture

Modular monolith (FastAPI + SQLAlchemy 2 + PostgreSQL). Detection, correlation, risk scoring and authorization are deterministic and work with no LLM. Solid boxes below exist today; dashed boxes are planned (see [checklist.md](checklist.md)).

```mermaid
flowchart LR
    subgraph L1[Layer 1: Data sources]
        A1[Linux sshd auth logs]
        A2[Sysmon EventID 1 JSON]
        A3[Wazuh alerts]
    end
    subgraph L2[Layer 2: Ingestion and normalization]
        B1[POST /api/v1/events<br/>API key + rate limit]
        B2[normalize + redact secrets<br/>app/normalization]
        B3[(security_events<br/>dedup by hash)]
    end
    subgraph L3[Layer 3: Detection and correlation]
        C1[Rule engine SX-001 to SX-008<br/>app/detection]
        C2[(alerts + alert_events)]
        C3[Correlation / incidents]:::planned
        C4[Risk engine 0-100]:::planned
    end
    subgraph L4[Layer 4: Hybrid AI]
        D1[LangGraph: Triage, Investigation]:::planned
        D2[Threat Intel + Response proposals]:::planned
    end
    subgraph L5[Layer 5: Dashboard and response]
        E1[GET /api/v1/alerts]
        E2[React dashboard]:::planned
        E3[Approval queue + audit log]:::planned
    end
    A1 --> B1
    A2 --> B1
    A3 --> B1
    B1 --> B2 --> B3 --> C1 --> C2
    C2 --> E1
    C2 -.-> C3 -.-> C4 -.-> D1 -.-> D2 -.-> E3
    E1 -.-> E2
    classDef planned stroke-dasharray: 5 5,fill:#f4f4f4,color:#666
```

## Ingest flow (implemented)

```mermaid
sequenceDiagram
    participant C as Client
    participant API as FastAPI
    participant N as Normalizer
    participant DB as PostgreSQL
    participant R as Rule engine
    C->>API: POST /api/v1/events (X-API-Key)
    API->>API: check key, rate limit (429)
    API->>N: prepare(source, payload)
    N-->>API: NormalizedEvent + redacted raw + hash (or 422)
    API->>DB: advisory lock per host (Postgres)
    API->>DB: INSERT security_event (unique hash)
    alt duplicate hash
        DB-->>API: IntegrityError, rollback
        API-->>C: duplicate true
    else new event
        API->>R: run_detections(event)
        R->>DB: query window, upsert alert, attach evidence
        API-->>C: event id + alerts
    end
```

## Key decisions
- **Deterministic core.** Rules are Python callables with metadata (id, severity, MITRE, references, enabled). The LLM (M5+) only explains evidence and never changes severity, scores or permissions.
- **Idempotent ingestion.** A SHA-256 of the redacted raw record is unique; resending is a no-op.
- **Concurrency.** On PostgreSQL, ingestion takes a per-host advisory lock so concurrent events see each other (no duplicate alerts, no missed thresholds). Trade-off: per-host serialization.
- **Out-of-order logs.** SX-001 and SX-008 look +-window around each event, so late-arriving events still produce a complete alert.
- **Alert merging.** Alerts for the same (rule, host, group key) merge inside one time window, then a new alert opens. See [detection-rules.md](detection-rules.md).
- **Untrusted input.** Every field is validated or dropped; secrets are redacted before storage; raw size is capped.
- **Shortcuts to revisit:** single shared API key (RBAC in M6), in-memory rate limit (per process), no rule-toggle API (flip `detection_rules.enabled` in SQL), syslog year assumed current UTC year.

## Code map
| Path | Role |
|---|---|
| `backend/app/api/main.py` | routes, auth, security headers, CORS |
| `backend/app/api/ratelimit.py` | per-IP fixed-window limiter |
| `backend/app/core/config.py` | validated settings from `SENTINELX_*` env vars |
| `backend/app/normalization/normalize.py` | parsers, redaction, dedup hash |
| `backend/app/ingestion/service.py` | store + detect orchestration |
| `backend/app/detection/engine.py` | rules and alert upsert |
| `backend/app/database/` | models and session |
