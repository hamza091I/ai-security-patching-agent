# SaaS Product TODO

## In progress / foundation

- [x] Support SQLite locally and PostgreSQL through `DATABASE_URL`.
- [x] Add production database dependencies and environment examples.
- [x] Add request IDs to HTTP responses.
- [x] Add `/health/`, `/ready/`, and authenticated `/metrics/` endpoints.
- [x] Add `/api/v1/` aliases for the existing scan, compare, history, and evaluation contracts.
- [x] Add Organization, Membership, Project, APIKey, AuditLog models.
- [x] Add finding status and assignment fields.
- [ ] Generate and review the migration for the new SaaS models.
- [ ] Add tenant selection middleware and enforce organization-level query isolation.

## Product outcomes

- [ ] Email verification, password reset, login rate limiting, 2FA, and session management.
- [ ] Workspace API-key authentication and key rotation UI.
- [ ] Complete audit events for login, scans, changes, exports, and integrations.
- [ ] Overview, Projects, Repositories, Scans, Findings, Reports, Integrations, Team, Billing, Settings, and Audit Logs pages.
- [ ] Finding workflow: assign, comments, due dates, labels, false-positive, snooze, ticket link, resolved/reopened.
- [ ] PDF, JSON, CSV, HTML, and SARIF exports.
- [ ] Celery/Redis queue with progress, retry, cancel, timeout, file-size and plan limits.
- [ ] Non-root Docker sandbox with no network, read-only filesystem, CPU/memory limits, timeout, and cleanup.
- [ ] GitHub/GitLab OAuth, repository selection, push/branch/PR scans, comments, and merge blocking.
- [ ] Java, Go, PHP, C#, and Ruby language adapters.
- [ ] SCA, secrets, IaC, container, DAST, and license scanning modules.
- [ ] AI Security Assistant with evidence, safe exploit explanation, patch diff, rescan, regression gate, and human approval.
- [ ] Usage tracking, Free/Pro/Enterprise plans, billing, SSO, SLA, and private deployment.
- [ ] OpenAPI/Swagger, pagination, filtering, sorting, consistent errors, rate limits, structured logging, error tracking, and backups.
- [ ] CI gates for lint, tests, migrations, benchmark regression, security checks, coverage, Docker build, Bandit, and pip-audit.
