# Phase 3 — Durable Scan Jobs and SaaS Operations

Phase 3 moves scanning from a request-only action into a durable job workflow. The API creates a `ScanJob`, returns `202 Accepted`, and a worker processes it later. The old synchronous `/api/scan/` contract remains available for compatibility.

## API

```text
POST /api/v1/scan-jobs/
GET  /api/v1/scan-jobs/
GET  /api/v1/scan-jobs/<id>/
POST /api/v1/scan-jobs/<id>/       # cancel a pending job
```

A create request can include `filename`, `project_id`, `engines`, and an `Idempotency-Key` header. Repeating the same key in the same Workspace returns the original job instead of creating a duplicate scan.

Jobs expose `PENDING`, `RUNNING`, `SUCCEEDED`, `FAILED`, and `CANCELLED` states with progress and timestamps. A job result contains the persisted `CodeScan` ID, findings, patch proposal, validation data, and engine breakdown.

## Worker

For local development, run the web server and worker in separate terminals:

```bash
python manage.py runserver
python manage.py process_scan_jobs --limit 10
```

The command is intentionally finite and safe for cron, a process supervisor, or a later Redis/Celery adapter. It locks a job before moving it to `RUNNING`, so a terminal job is not executed twice.

## SaaS controls

The job is scoped to the authenticated Workspace and optional Project. The API enforces a configurable source limit through `MAX_SCAN_BYTES` (1 MB by default), prevents cross-Workspace project access, and records creation, cancellation, success, and failure events in `AuditLog`.

## Verification

Phase 3 adds migration `0004_scanjob.py` and `0005_scanjob_engines.py`. The complete project test suite passes after the changes, including idempotency, worker completion, cancellation, existing scanner/RAG regression tests, and all Phase 2 API tests.

A production deployment should run the worker under a process supervisor or queue adapter. Redis/Celery, retries for stale jobs, plan-based quotas, and Docker sandbox execution remain deliberate next steps rather than hidden claims in this release.
