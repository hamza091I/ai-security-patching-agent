# Phase 5 Completion Report

## Scope completed

Phase 5 now contains the provider-integration layer needed to connect the scanner to GitHub and GitLab in a controlled way.

### Implemented

- Workspace-scoped GitHub and GitLab repository integrations.
- OAuth authorization URL generation for both providers.
- OAuth callback and authorization-code exchange.
- Encrypted storage for provider access and refresh tokens using a key derived from `DJANGO_SECRET_KEY`.
- Provider clients for listing repositories, listing branches, and downloading a repository archive at a selected ref.
- Safe archive extraction with path-traversal protection, binary-file filtering, file-size limits, and file-count limits.
- Manual repository sync endpoint that creates durable `ScanJob` records for supported source files.
- Webhook ingestion for GitHub Push/Pull Request and GitLab Push/Merge Request events.
- Webhook delivery de-duplication using provider delivery IDs.
- Queueing of active integration events for background processing.
- `process_repository_events` worker command that fetches the event commit and creates ScanJobs without blocking the webhook request.
- Existing SARIF/CSV/JSON reporting remains available for later provider upload/comment integration.

## API additions

- `GET /api/v1/integrations/<id>/oauth/start/`
- `GET /api/v1/integrations/<provider>/callback/`
- `GET /api/v1/integrations/<id>/repositories/`
- `GET /api/v1/integrations/<id>/branches/`
- `POST /api/v1/integrations/<id>/sync/`
- `POST /api/v1/webhooks/<provider>/<integration_id>/`

## Worker commands

```bash
python manage.py process_repository_events --limit 20
python manage.py process_scan_jobs --limit 20
```

The normal deployment should run both workers. The first worker turns verified repository events into ScanJobs; the second worker executes the scans.

## Required environment variables

Configure provider OAuth credentials in `.env` using `.env.example` as a template. Do not commit client secrets, private keys, or access tokens.

- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_CALLBACK_URL`
- `GITLAB_CLIENT_ID`
- `GITLAB_CLIENT_SECRET`
- `GITLAB_CALLBACK_URL`
- `GITHUB_WEBHOOK_SECRET`
- `DJANGO_SECRET_KEY`

## Verification

- Django system check: passed.
- Migration consistency check: passed.
- Automated tests: **80 passed**.
- New coverage includes OAuth state creation, provider repository mapping, token encryption, archive traversal protection, and webhook delivery de-duplication.

## Remaining provider-specific production setup

The code is complete for the integration layer, but live provider operation still requires configuration outside the repository: create the GitHub App/GitLab OAuth application, generate the GitHub App private key if using App installation authentication, set callback URLs, install/authorize the app, configure a public HTTPS webhook URL, and add the resulting secrets to the deployment secret store. SARIF upload and pull-request comment creation can be added as a separate provider-write adapter after the first live connection is verified.
