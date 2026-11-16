# Operations: backup, restore and housekeeping

Everything SentinelX stores is in one PostgreSQL database (events, alerts, incidents, users and token hashes, audit log, IOCs, response actions, the blocklist, AI runs). There are no other stateful services. Settings live in the environment file next to `docker-compose.yml`, which is **not** in the database: keep a copy of it separately and privately.

## Back up
```bash
mkdir -p backups
docker compose exec -T db pg_dump -U sentinelx -Fc sentinelx > backups/sentinelx-$(date +%Y%m%d-%H%M).dump
```
`-Fc` is PostgreSQL's compressed custom format. The file contains password hashes, token hashes and the audit log: treat it like the database itself (restrict permissions, encrypt before it leaves the machine, never commit it). Backups here are manual; scheduling and encryption are yours to add.

## Restore
Into a **new, empty** database first, so a bad backup cannot hurt the live one:
```bash
docker compose exec -T db psql -U sentinelx -d postgres -c "CREATE DATABASE sentinelx_restore"
docker compose exec -T db pg_restore -U sentinelx -d sentinelx_restore --no-owner < backups/sentinelx-YYYYMMDD-HHMM.dump
docker compose exec -T db psql -U sentinelx -d sentinelx_restore -Atc "select count(*) from security_events"
```
To replace the live database with a backup (this destroys the current data), stop the backend first so nothing writes during the swap:
```bash
docker compose stop backend frontend
docker compose exec -T db psql -U sentinelx -d postgres -c "DROP DATABASE sentinelx" -c "CREATE DATABASE sentinelx"
docker compose exec -T db pg_restore -U sentinelx -d sentinelx --no-owner < backups/sentinelx-YYYYMMDD-HHMM.dump
docker compose up -d
```
The restored schema carries its Alembic version, so the backend's `alembic upgrade head` on start applies only newer migrations. Restoring a backup taken on a newer release into an older one is not supported.

## What was checked
The procedure was run with `pg_dump -Fc` and `pg_restore --no-owner` on PostgreSQL 17 against a database holding 247 events, 117 alerts and 63 incidents (the evaluation dataset). The restored database had identical row counts for events, alerts and incidents, `alembic current` reported `0010 (head)`, and `alembic check` reported no new upgrade operations.

**Not checked:** the exact `docker compose exec` forms above against the Compose stack (the run used a standalone PostgreSQL container with the same tools), restore of a very large database, point-in-time recovery, and starting the full application on the restored copy.

## Reset and housekeeping
- `docker compose down` stops everything and keeps the data; `docker compose down -v` also deletes the volume (the database).
- SentinelX never deletes events or alerts; there is no retention job. The database grows with log volume: plan disk space and a retention policy outside the application.
- Rotate the collector key by changing `SENTINELX_API_KEY` and restarting the backend. Reset a person's password with `docker compose exec backend .venv/bin/python -m app.manage set-password USER`.
- The audit log is append-only by convention (no API can edit it); a database administrator can. A restore brings back the audit log as it was at backup time.
