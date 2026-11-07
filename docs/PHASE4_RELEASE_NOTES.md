# Phase 4 — Security Hardening and Worker Reliability

Phase 4 hardens the Phase 3 durable scan workflow without claiming a distributed queue that is not yet installed.

## Delivered

- Added request-scoped tenant context through `TenantContextMiddleware`.
- Added structured request logging with request ID, user, organization, status, and duration fields.
- Added `ScanJob` retry counters, max retry budget, timeout seconds, and heartbeat timestamps.
- Added stale-job recovery through `recover_stale_jobs()` and `--recover-stale`.
- Added failed-job requeue through `requeue_failed_jobs()` and `--retry-failed`.
- Added elapsed-time timeout guards controlled by `SCAN_JOB_TIMEOUT_SECONDS`.
- Added environment controls for retries, stale age, scan timeout, and log level.
- Added a non-root Docker image, healthcheck, and a local web/worker compose baseline.
- Added GitHub Actions checks for Django check, migration check, full tests, and Bandit.
- Added a pre-commit configuration for Ruff, Bandit, Django check, and tests.

## Worker command

```bash
python manage.py process_scan_jobs --limit 10 --recover-stale --retry-failed
```

The command remains finite and safe to run from cron or a process supervisor. Celery/Redis, hard process interruption, distributed locking, and plan-aware queue priority are still later infrastructure work.

## Configuration

```env
SCAN_JOB_TIMEOUT_SECONDS=300
SCAN_JOB_MAX_RETRIES=2
SCAN_JOB_STALE_SECONDS=900
LOG_LEVEL=INFO
```

## Verification

Run `python manage.py check`, `python manage.py makemigrations --check --dry-run`, and `python manage.py test`. Phase 4 should preserve the Phase 3 API contract and all existing scanner, RAG, evaluation, SaaS, and job tests.
