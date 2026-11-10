# SaaS Product TODO

## In progress / foundation

- [x] Support SQLite locally and PostgreSQL through `DATABASE_URL`.
- [x] Add production database dependencies and environment examples.
- [x] Add request IDs to HTTP responses.
- [x] Add `/health/`, `/ready/`, and authenticated `/metrics/` endpoints.
- [x] Add `/api/v1/` aliases for the existing scan, compare, history, and evaluation contracts.
- [x] Add Organization, Membership, Project, APIKey, AuditLog models.
- [x] Add finding status and assignment fields.
- [x] Generate and review the migration for the new SaaS models.
- [x] Add tenant context middleware; continue centralized organization-level query audit.

## Product outcomes

- [ ] Email verification, password reset, login rate limiting, 2FA, and session management.
- [ ] Workspace API-key authentication and key rotation UI.
- [ ] Complete audit events for login, scans, changes, exports, and integrations.
- [ ] Overview, Projects, Repositories, Scans, Findings, Reports, Integrations, Team, Billing, Settings, and Audit Logs pages.
- [x] Projects, Findings, Reports sections added to the Dashboard.
- [x] Finding workflow: status changes and workspace-safe assignment endpoint.
- [x] JSON, CSV, and SARIF exports.
- [x] Durable ScanJob API with progress, cancel, idempotency, file-size limit, and worker command.
- [ ] Redis/Celery adapter and distributed locking; [x] local retries, stale-job recovery, timeout guard, and worker controls.
- [x] Add non-root Docker application baseline; [ ] hardened no-network scan sandbox with read-only filesystem, CPU/memory limits, timeout, and cleanup.
- [x] GitHub/GitLab integration registry, repository-to-project linking, webhook event persistence, and signature verification; [ ] OAuth, repository fetch, scans, comments, and merge blocking.
- [ ] Java, Go, PHP, C#, and Ruby language adapters.
- [ ] SCA, secrets, IaC, container, DAST, and license scanning modules.
- [ ] AI Security Assistant with evidence, safe exploit explanation, patch diff, rescan, regression gate, and human approval.
- [ ] Usage tracking, Free/Pro/Enterprise plans, billing, SSO, SLA, and private deployment.
- [ ] OpenAPI/Swagger, pagination, filtering, sorting, consistent errors, plan-aware rate limits, error tracking, and backups; [x] request IDs, baseline throttling, structured request logging.
- [x] CI baseline for Django check, tests, migration check, and Bandit; [ ] benchmark regression, coverage, Docker build, pip-audit, and full release gates.
