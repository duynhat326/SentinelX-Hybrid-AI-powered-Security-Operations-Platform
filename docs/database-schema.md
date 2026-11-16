# Database schema

PostgreSQL 17 in Compose; SQLite is used for fast tests only. The schema is managed by Alembic (`backend/alembic/`, current head `0008`); the container runs `alembic upgrade head` on start. All timestamps are UTC with time zone. `raw` and `mitre` use JSONB on PostgreSQL (plain JSON on SQLite).

```mermaid
erDiagram
    assets ||--o{ security_events : "observed on"
    security_events ||--o{ alert_events : "is evidence in"
    alerts ||--o{ alert_events : "has evidence"
    incidents ||--o{ incident_alerts : "groups"
    alerts ||--o| incident_alerts : "belongs to at most one"
    incidents ||--o{ incident_entities : "involves"
    incidents ||--o{ agent_runs : "investigated by"
    users ||--o{ auth_tokens : "has sessions"

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
        string host "indexed, max 255 else 422"
        string category "authentication | process | network | registry"
        string action "failure | success | create | connect | create_key | delete_key | set_value"
        string user "indexed, truncated to 255"
        string src_ip "indexed"
        int src_port
        string dst_ip "indexed"
        int dst_port
        text process_name "unbounded: long paths must not drop events"
        text parent_process_name
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
    incidents {
        uuid id PK
        string title "derived"
        string severity "highest alert severity, indexed"
        string status "open | closed, indexed"
        int risk_score "0-100, deterministic, indexed"
        jsonb risk_breakdown "components, weights, missing"
        timestamptz first_seen "indexed"
        timestamptz last_seen "indexed"
        timestamptz created_at
        timestamptz updated_at
    }
    incident_alerts {
        uuid alert_id PK, FK "one incident per alert"
        uuid incident_id FK "indexed"
        string reason "entity that linked it, or seed"
        timestamptz linked_at
    }
    incident_entities {
        uuid incident_id PK, FK
        string kind PK "host | ip | user | process"
        string value PK
    }
    iocs {
        uuid id PK
        string kind "ip | domain | sha256, CHECK"
        string value "canonical form"
        string source "manual | virustotal | abuseipdb"
        int score "0 clean .. 100 malicious, CHECK"
        string summary "built from numbers or written by an analyst"
        timestamptz checked_at
        timestamptz expires_at "null for manual rows, indexed"
        string created_by
    }
    users {
        uuid id PK
        string username UK "3-64 of a-z 0-9 . _ -"
        string password_hash "scrypt, parameters inside the string"
        string role "viewer | analyst | approver | admin, CHECK"
        bool active
        timestamptz created_at
    }
    auth_tokens {
        uuid id PK
        uuid user_id FK "indexed, ON DELETE CASCADE"
        string token_sha256 UK "the token itself is never stored"
        timestamptz expires_at "indexed"
        bool revoked
        timestamptz created_at
    }
    audit_logs {
        uuid id PK
        timestamptz ts "indexed"
        string actor "user:alice | service:api-key | cli | anonymous, indexed"
        string role
        string action "auth.login, authz.denied, user.update, ... indexed"
        string target_type
        string target_id
        string outcome "ok | denied | error, indexed"
        string ip
        jsonb detail "redacted, capped"
    }
    agent_runs {
        uuid id PK
        uuid incident_id FK "indexed"
        string status "ok | failed"
        string provider "none/mock/..."
        string model "provenance"
        string prompt_version "provenance"
        string input_sha256 "hash of the exact context sent"
        int duration_ms
        jsonb output "validated, cited claims only"
        int dropped_claims "claims and techniques without valid citations"
        jsonb rejected_tool_calls "audit of refused tool calls"
        string error "class name or schema paths only"
        timestamptz created_at
    }
```

## Constraints and policies
| Table | Constraint | Purpose |
|---|---|---|
| `security_events` | unique `dedup_hash` | idempotent ingestion |
| `alerts` | non-unique index `(rule_id, host, group_key)` | an alert absorbs matching events inside the merge window; a later match opens a new alert (per-host ingestion lock prevents concurrent duplicates) |
| `assets` | unique `hostname`, CHECK `criticality BETWEEN 1 AND 5` | one asset per host, valid criticality for the risk engine |
| `security_events` | FK `asset_id` to `assets` (`ON DELETE RESTRICT`) | an asset with events cannot be deleted |
| `incident_alerts` | PK `alert_id` (so an alert is in at most one incident), FK to `alerts` and `incidents` (`ON DELETE CASCADE`) | no duplicate grouping |
| `incident_entities` | composite PK `(incident_id, kind, value)`, index `(kind, value)`, FK `ON DELETE CASCADE` | fast lookup of incidents sharing an entity |
| `iocs` | unique `(kind, value, source)`, CHECK `score BETWEEN 0 AND 100`, CHECK on `kind` | one verdict per indicator and source; unknown is never stored |
| `alert_events` | composite PK, FK to `alerts` (`ON DELETE CASCADE`), FK to `security_events` (`ON DELETE RESTRICT`) | evidence can never silently lose its event |

Events are never deleted by the application. No credentials or API tokens are stored; `redact()` masks `password`, `token`, `api_key` and `secret` values before storage.

Incidents have no separate evidence table: the timeline is derived from `incident_alerts` and `alert_events` (see [correlation-and-risk.md](correlation-and-risk.md)). SQLite does not enforce `ON DELETE CASCADE` here, so the application deletes dependent rows explicitly when merging incidents.

## Planned tables (not created yet)
`response_actions`, `blocklist_entries` (M6C). Roles are not a table: they are fixed in code (`app/api/auth.py`) and named by `users.role`.

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
