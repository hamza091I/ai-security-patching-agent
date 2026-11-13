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

- [x] Email verification, password reset, login rate limiting, and session management; [ ] production 2FA enrollment.
- [x] Workspace API-key authentication and rotation endpoint; [ ] dedicated UI polish.
- [x] Audit events for login, scans, changes, exports, and integrations.
- [ ] Overview, Projects, Repositories, Scans, Findings, Reports, Integrations, Team, Billing, Settings, and Audit Logs pages.
- [x] Projects, Findings, Reports sections added to the Dashboard.
- [x] Finding workflow: status changes and workspace-safe assignment endpoint.
- [x] JSON, CSV, and SARIF exports.
- [x] Durable ScanJob API with progress, cancel, idempotency, file-size limit, and worker command.
- [x] Redis/Celery adapter contract and task wrappers; [ ] production broker deployment and distributed locking.
- [x] Add non-root Docker application baseline; [x] isolated external-scanner runner with read-only input, CPU/memory limits, timeout, and cleanup; [ ] kernel-level no-network enforcement.
- [x] GitHub/GitLab integration registry, repository-to-project linking, webhook event persistence, and signature verification; [x] OAuth (with token refresh), repository fetch, remote scans, SARIF upload, PR/commit comments, commit statuses, and the merge-blocking gate.
- [x] Generic adapter contract for Java, Go, PHP, C#, Ruby and text files; [ ] language-specific deep parsers.
- [x] Dependency-install, secrets, IaC, and container configuration scanners; [ ] full SCA/DAST/license provider integrations.
- [x] AI Security Assistant draft, evidence, patch proposal, regression flag, and human approval endpoint; [ ] LLM-backed exploit explanation.
- [ ] Usage tracking, Free/Pro/Enterprise plans, billing, SSO, SLA, and private deployment.
- [x] Webhook delivery history with retry visibility (`/api/v1/integrations/<id>/events/`).
- [x] OpenAPI JSON, pagination, filtering, sorting, consistent errors, baseline rate limits, and usage endpoint; [ ] plan-aware billing enforcement, error tracking, and backups.
- [x] CI for Django check, tests, migration check, Bandit, benchmark regression, coverage, Docker build, and pip-audit.
