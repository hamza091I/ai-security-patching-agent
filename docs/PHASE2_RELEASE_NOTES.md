# Phase 2 — SaaS Workflow and Reporting

This release builds on the merged `saas-foundation` work. It is a real workflow layer, not a visual-only dashboard change.

## Delivered

The Dashboard now includes Projects & Repositories, Finding Workflow, and Reports & Integrations sections. The sections call authenticated API endpoints and update without a page reload.

The new API contracts are:

```text
GET/POST  /api/v1/projects/
GET       /api/v1/findings/?status=OPEN&severity=HIGH
PATCH     /api/v1/findings/<id>/
GET/POST  /api/v1/api-keys/
POST      /api/v1/api-keys/<prefix>/revoke/
GET       /api/v1/reports/export/?type=json
GET       /api/v1/reports/export/?type=csv
GET       /api/v1/reports/export/?type=sarif
```

`type` is used instead of `format` because `format` is reserved by Django REST Framework content negotiation.

Projects are scoped to the authenticated user's Workspace. Findings are filtered by Workspace, and status updates accept only the controlled workflow values `OPEN`, `IN_PROGRESS`, `FALSE_POSITIVE`, `RESOLVED`, and `REOPENED`. Assignees must be members of the same Workspace.

Workspace API keys are returned only once at creation. The database stores a SHA-256 digest, not the raw token. CI clients can use `Authorization: Bearer sa_...`, and keys can be revoked without deleting the audit trail.

Reports support JSON for application use, CSV for analysis, and SARIF for GitHub Code Scanning integration. Exported findings are limited to the authenticated user's Workspace.

## Verification

The repository passes Django system checks, has no pending model migrations, and passes all 60 tests. New coverage includes workspace-scoped projects, finding resolution, API-key authentication, SARIF export, and the existing scanner/RAG/evaluation regression suite.

## Not claimed as complete yet

GitHub/GitLab OAuth, Celery/Redis asynchronous workers, Docker sandbox execution, billing, email verification, 2FA, and full tenant middleware remain later phases. The current release creates the application contracts needed by those integrations without pretending that the provider actions already exist.
