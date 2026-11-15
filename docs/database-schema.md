# Database schema

PostgreSQL 17 in Compose; SQLite is used for fast tests only. The schema is managed by Alembic (`backend/alembic/`, current head `0002`); the container runs `alembic upgrade head` on start. All timestamps are UTC with time zone. `raw` and `mitre` use JSONB on PostgreSQL (plain JSON on SQLite).

```mermaid
erDiagram
    assets ||--o{ security_events : "observed on"
    security_events ||--o{ alert_events : "is evidence in"
    alerts ||--o{ alert_events : "has evidence"

    assets {
        uuid id PK
        string hostname UK
        int criticality "1-5, default 3, CHECK"
        timestamptz created_at
    }
    detection_rules {
        string id PK "e.g. SX-001"
        string title
        string severity
        jsonb mitre
        bool enabled "operator state, never overwritten by sync"
        timestamptz updated_at
    }
    security_events {
        uuid id PK
        string dedup_hash UK "sha256 of canonical redacted record"
        timestamptz timestamp "event time, indexed"
        timestamptz ingested_at
        uuid asset_id FK "indexed"
        string source "linux_auth | sysmon, indexed"
        string host "indexed"
        string category "authentication | process | network | registry"
        string action "failure | success | create | connect | create_key | delete_key | set_value"
        string user "indexed"
        string src_ip "indexed"
        int src_port
        string dst_ip "indexed"
        int dst_port
        string process_name
        string parent_process_name
        text command_line "secrets redacted"
        text registry_key
        text registry_value "Sysmon Details, redacted"
        jsonb raw "redacted, truncated; via=wazuh when relayed"
    }
    alerts {
        uuid id PK
        string rule_id "indexed, matches detection_rules.id (no FK)"
        string title
        string severity "indexed"
        string status "open by default, indexed"
        string host "indexed"
        string group_key "e.g. src_ip or event id"
        jsonb mitre "technique ids"
        int event_count
        timestamptz first_event_at "earliest evidence event"
        timestamptz last_event_at "latest evidence event"
        timestamptz created_at "indexed"
    }
    alert_events {
        uuid alert_id PK, FK
        uuid event_id PK, FK
    }
```

## Constraints and policies
| Table | Constraint | Purpose |
|---|---|---|
| `security_events` | unique `dedup_hash` | idempotent ingestion |
| `alerts` | non-unique index `(rule_id, host, group_key)` | an alert absorbs matching events inside the merge window; a later match opens a new alert (per-host ingestion lock prevents concurrent duplicates) |
| `assets` | unique `hostname`, CHECK `criticality BETWEEN 1 AND 5` | one asset per host, valid criticality for the risk engine |
| `security_events` | FK `asset_id` to `assets` (`ON DELETE RESTRICT`) | an asset with events cannot be deleted |
| `alert_events` | composite PK, FK to `alerts` (`ON DELETE CASCADE`), FK to `security_events` (`ON DELETE RESTRICT`) | evidence can never silently lose its event |

Events are never deleted by the application. No credentials or API tokens are stored; `redact()` masks `password`, `token`, `api_key` and `secret` values before storage.

## Planned tables (not created yet)
`incidents`, `incident_alerts`, `incident_evidence` (M4), `agent_runs` (M5), `users`, `roles`, `response_actions`, `audit_logs`, `iocs` (M6).

## Migration workflow
Alembic reads `SENTINELX_DATABASE_URL` directly (no API key needed).
```bash
cd backend
export SENTINELX_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/db
uv run alembic revision --autogenerate -m "describe change"   # then review the generated file
uv run alembic upgrade head
uv run alembic check                                           # fails if models and migrations drift
uv run alembic downgrade -1                                    # every migration must be reversible
```
`tests/test_migrations.py` upgrades, compares against the models, downgrades to base and upgrades again, so CI catches a model change without a migration.
