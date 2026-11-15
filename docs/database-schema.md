# Database schema

PostgreSQL 17 in Compose; SQLite is used for fast tests only. Tables are currently created with `create_all`; Alembic migrations arrive in Milestone 2 (see [checklist.md](checklist.md)). All timestamps are UTC with time zone. `raw` and `mitre` use JSONB on PostgreSQL (plain JSON on SQLite).

```mermaid
erDiagram
    security_events ||--o{ alert_events : "is evidence in"
    alerts ||--o{ alert_events : "has evidence"

    security_events {
        uuid id PK
        string dedup_hash UK "sha256 of redacted raw"
        timestamptz timestamp "event time, indexed"
        timestamptz ingested_at
        string source "linux_auth | sysmon, indexed"
        string host "indexed"
        string category "authentication | process"
        string action "failure | success | create"
        string user "indexed"
        string src_ip "indexed"
        string process_name
        string parent_process_name
        text command_line "secrets redacted"
        jsonb raw "redacted, truncated original"
    }
    alerts {
        uuid id PK
        string rule_id "indexed"
        string title
        string severity "indexed"
        string status "open by default, indexed"
        string host "indexed"
        string group_key "e.g. src_ip or event id"
        jsonb mitre "technique ids"
        int event_count
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
| `alerts` | unique `(rule_id, host, group_key)` | one alert per rule, host and group; later events attach evidence |
| `alert_events` | composite PK, FK to `alerts` (`ON DELETE CASCADE`), FK to `security_events` (`ON DELETE RESTRICT`) | evidence can never silently lose its event |

Events are never deleted by the application. No credentials or API tokens are stored; `redact()` masks `password`, `token`, `api_key` and `secret` values before storage.

## Planned tables (not created yet)
`assets` (M2), `detection_rules` (M2), `incidents`, `incident_alerts`, `incident_evidence` (M4), `agent_runs` (M5), `users`, `roles`, `response_actions`, `audit_logs`, `iocs` (M6).

## Migration workflow (target, from M2)
```bash
cd backend
uv run alembic revision --autogenerate -m "describe change"   # review the generated file
uv run alembic upgrade head
uv run alembic downgrade -1                                    # every migration must be reversible
```
