# SaaS completion pack

This release adds the executable SaaS layer that can run locally or behind PostgreSQL.

## Included

- Email-verification records and token endpoint: `POST /api/v1/auth/verify-email/`.
- Password-reset request and confirmation endpoints with Django's signed token generator.
- Login throttling by IP and username, session expiry, and login audit events.
- Workspace API-key rotation: `POST /api/v1/api-keys/<prefix>/rotate/`.
- Paginated and filtered finding results (`page`, `page_size`, `status`, `severity`).
- Workspace members and invite endpoint: `GET/POST /api/v1/team/`.
- Usage summary endpoint: `GET /api/v1/usage/`.
- Human-approval patch assistant: `POST/PATCH /api/v1/assistant/`.
- OpenAPI JSON contract at `/api/openapi.json`.
- Optional Celery/Redis tasks in `scanner/tasks.py` and optional dependencies in `requirements-optional.txt`.
- Dependency-free extended scanners for secrets, dependency-install risks, IaC exposure, and container privilege issues.
- Best-effort isolated external-scanner runner with timeout, CPU/memory/file-size limits, clean environment, no inherited stdin, and cleanup.
- CI gates for coverage, benchmark regression, Bandit, pip-audit, and Docker build.

## External-service boundaries

Stripe billing, enterprise SSO/SAML, email delivery, and a production no-network container sandbox require provider credentials or infrastructure. The code exposes safe contracts and local fallbacks; it does not claim that a Stripe/SAML account or kernel isolation is available without configuration. For production, use a managed queue, a real mail provider, Stripe webhooks, SAML/OIDC, and a dedicated sandbox worker (gVisor/Firecracker).
