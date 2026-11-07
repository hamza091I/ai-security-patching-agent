# AI Security Patching Agent — SaaS Plan

## Product direction

Turn the current scanner dashboard into a multi-tenant security platform that follows the workflow: Detect → Explain → Prioritize → Assign → Fix → Re-scan → Report.

## Current foundation delivered in this phase

- SQLite remains the default for local development.
- PostgreSQL is selected with `DATABASE_URL` for staging and production.
- Request IDs are added to responses for traceability.
- Health, readiness, and authenticated metrics endpoints exist.
- API v1 aliases are available for current scan, compare, history, and evaluation endpoints.
- Organization, membership, project, API key, audit log, scan ownership, and finding workflow fields are modeled.

## Architecture direction

- Django remains the first-party web/API backend.
- PostgreSQL is the production relational database.
- Redis/Celery will run long scans asynchronously.
- Scanner execution will use an isolated, non-root Docker worker with no network access.
- GitHub/GitLab integrations will be provider adapters behind a common repository interface.
- The dashboard will grow into Overview, Projects, Repositories, Scans, Findings, Reports, Integrations, Team, Billing, Settings, and Audit Logs.

## Design direction

Use a dark security-operations aesthetic: navy-black surfaces, cyan/blue action color, red/amber/green severity states, monospace code blocks, dense but readable data tables, and clear drill-down navigation. The product voice should be direct and evidence-led rather than marketing-heavy.

## Delivery stages

1. SaaS foundation: database switch, tenancy, roles, API keys, audit events, API versioning, observability.
2. Finding workflow: projects, assignments, statuses, comments, filters, report exports.
3. Async execution: queue, progress, retry/cancel, limits, Docker sandbox.
4. Integrations: GitHub/GitLab repositories, push/PR scans, status checks and comments.
5. Commercial layer: usage tracking, plans, billing, notifications, enterprise controls.
