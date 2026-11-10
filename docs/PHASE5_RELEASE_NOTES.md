# Phase 5 — Repository Integration Foundation

Phase 5 adds a secure integration foundation for GitHub and GitLab without pretending that OAuth credentials or provider API access exist in the repository.

## Delivered

- Added workspace-scoped `RepositoryIntegration` records for GitHub and GitLab repositories.
- Added automatic Project creation for a connected repository.
- Added `RepositoryEvent` records for Push, Pull Request, and Merge Request events.
- Added integration management endpoint:

```text
GET/POST /api/v1/integrations/
```

- Added provider webhook endpoint:

```text
POST /api/v1/webhooks/<provider>/<integration_id>/
```

- Added GitLab token verification using a SHA-256 digest stored in the database.
- Added GitHub HMAC-SHA256 verification using `GITHUB_WEBHOOK_SECRET` from the environment.
- Added delivery IDs, branch refs, commit SHAs, event payload audit records, and organization-level audit events.
- Added tests for integration creation, project linking, valid webhook ingestion, invalid signature rejection, and secret non-disclosure.

## Example configuration

```env
GITHUB_WEBHOOK_SECRET=replace-with-a-random-secret
```

For GitLab, pass the webhook token when creating the integration. The raw token is never returned and only its SHA-256 digest is stored.

## Important boundary

OAuth connection, repository listing, provider API token exchange, code checkout, and automatic ScanJob creation from remote repository content still require a registered GitHub App/GitLab OAuth application and credentials. The webhook layer records and verifies events first; it does not download repository code without an authenticated provider connection.
