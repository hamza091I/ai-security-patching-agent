import io
import zipfile
from datetime import timedelta
from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from scanner.models import (
    Membership,
    Organization,
    RepositoryEvent,
    RepositoryIntegration,
    ScanJob,
)
from scanner.services.provider_actions import ProviderActions
from scanner.services.provider_clients import ProviderClient, ProviderError, normalize_ref
from scanner.services.provider_oauth import _expiry_from_payload, refresh_integration_token
from scanner.services.publish import build_sarif, collect_findings, publish_event
from scanner.services.token_crypto import encrypt_token

GITHUB = "https://github.com/acme/payments"


def zip_archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return stream.getvalue()


def finding(cwe="CWE-95", severity="HIGH", line=3, rule="PY-EVAL"):
    return {
        "cwe_id": cwe,
        "rule_id": rule,
        "type": "Code Injection",
        "severity": severity,
        "confidence": 0.9,
        "engine": "ast",
        "line_start": line,
        "line_end": line,
        "message": "eval() executes untrusted input.",
        "recommendation": "Use ast.literal_eval.",
    }


class PublishingBase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="publish-user", password="strong-pass-123")
        self.organization = Organization.objects.create(name="Publishing", slug="publishing", owner=self.user)
        Membership.objects.create(organization=self.organization, user=self.user, role="OWNER")
        self.integration = RepositoryIntegration.objects.create(
            organization=self.organization,
            provider="GITHUB",
            repository_url=GITHUB,
            status="ACTIVE",
            access_token_encrypted=encrypt_token("provider-token"),
            default_branch="main",
            connected_by=self.user,
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def make_event(self, event_type="PULL_REQUEST", payload=None, commit_sha="abc123456789"):
        return RepositoryEvent.objects.create(
            integration=self.integration,
            event_type=event_type,
            ref="feature/login",
            commit_sha=commit_sha,
            payload=payload or {"pull_request": {"number": 7, "head": {"ref": "feature/login", "sha": commit_sha}}},
            status="PROCESSED",
        )

    def make_job(self, event, findings, filename="repo-abc123/src/app.py", status="SUCCEEDED"):
        return ScanJob.objects.create(
            organization=self.organization,
            requested_by=self.user,
            repository_event=event,
            filename=filename,
            ref=event.ref,
            commit_sha=event.commit_sha,
            source_code="value = eval(input())",
            status=status,
            result={"vulnerabilities": findings} if status == "SUCCEEDED" else {},
        )


class TokenRefreshTests(TestCase):
    def test_expiry_uses_now_when_created_at_is_missing(self):
        expires = _expiry_from_payload({"access_token": "x", "expires_in": 28800})
        self.assertGreater(expires, timezone.now() + timedelta(hours=7))
        self.assertLess(expires, timezone.now() + timedelta(hours=9))

    def test_expiry_accepts_github_iso_created_at(self):
        expires = _expiry_from_payload({"expires_in": 3600, "created_at": "2026-01-01T00:00:00Z"})
        self.assertEqual(expires.year, 2026)
        self.assertEqual(expires.hour, 1)

    @override_settings(GITHUB_CLIENT_ID="client", GITHUB_CLIENT_SECRET="secret")
    def test_refresh_updates_encrypted_credentials(self):
        user = User.objects.create_user(username="refresh-user", password="strong-pass-123")
        organization = Organization.objects.create(name="Refresh", slug="refresh", owner=user)
        integration = RepositoryIntegration.objects.create(
            organization=organization,
            provider="GITHUB",
            repository_url=GITHUB,
            access_token_encrypted=encrypt_token("old-token"),
            refresh_token_encrypted=encrypt_token("refresh-token"),
            token_expires_at=timezone.now() - timedelta(minutes=5),
        )
        with patch("scanner.services.provider_oauth.refresh_access_token") as refresh:
            refresh.return_value = {
                "access_token_encrypted": encrypt_token("new-token"),
                "refresh_token_encrypted": encrypt_token("new-refresh"),
                "token_expires_at": timezone.now() + timedelta(hours=8),
                "oauth_state": "",
            }
            self.assertTrue(refresh_integration_token(integration))
        integration.refresh_from_db()
        self.assertNotEqual(integration.access_token_encrypted, encrypt_token("old-token"))

    def test_refresh_is_skipped_for_non_expiring_tokens(self):
        user = User.objects.create_user(username="valid-user", password="strong-pass-123")
        organization = Organization.objects.create(name="Valid", slug="valid", owner=user)
        integration = RepositoryIntegration.objects.create(
            organization=organization,
            provider="GITHUB",
            repository_url=GITHUB,
            access_token_encrypted=encrypt_token("token"),
        )
        with patch("scanner.services.provider_oauth.refresh_access_token") as refresh:
            self.assertFalse(refresh_integration_token(integration))
        refresh.assert_not_called()


class SarifTests(PublishingBase):
    def test_sarif_uses_repository_relative_paths_and_levels(self):
        event = self.make_event()
        self.make_job(event, [finding(severity="HIGH", line=3), finding(cwe="CWE-89", severity="LOW", rule="SQL-RAW")])
        findings = collect_findings(event.scan_jobs.all())
        sarif = build_sarif(findings)
        results = sarif["runs"][0]["results"]
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/app.py")
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[1]["level"], "note")
        rule_ids = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {"PY-EVAL", "SQL-RAW"})

    def test_ref_normalization(self):
        self.assertEqual(normalize_ref("refs/heads/feature/x"), "feature/x")
        self.assertEqual(normalize_ref("main"), "main")


class PublishEventTests(PublishingBase):
    def _client(self):
        return ProviderClient("GITHUB", "provider-token")

    @override_settings(PROVIDER_PUBLISH_ENABLED=True, PROVIDER_SARIF_UPLOAD=True)
    def test_publish_posts_sarif_comment_and_failing_status(self):
        event = self.make_event()
        self.make_job(event, [finding(severity="CRITICAL")])
        response = Mock(status_code=201)
        response.json.return_value = {}
        client = self._client()
        with patch("scanner.services.publish.client_for", return_value=client), patch.object(client, "_request", return_value=response) as request:
            result = publish_event(event)
        self.assertEqual(result["status"], "published")
        self.assertEqual(result["verdict"], "blocked")
        paths = [call.args[1] for call in request.call_args_list]
        self.assertIn("/repos/acme/payments/code-scanning/sarifs", paths)
        self.assertIn("/repos/acme/payments/issues/7/comments", paths)
        self.assertIn("/repos/acme/payments/statuses/abc123456789", paths)
        status_payload = request.call_args_list[-1].kwargs["json"]
        self.assertEqual(status_payload["state"], "failure")
        event.refresh_from_db()
        self.assertEqual(event.status, "PUBLISHED")
        self.assertIsNotNone(event.published_at)

    @override_settings(PROVIDER_PUBLISH_ENABLED=True, MERGE_BLOCK_SEVERITIES={"CRITICAL", "HIGH"})
    def test_medium_only_findings_pass_the_merge_gate(self):
        event = self.make_event()
        self.make_job(event, [finding(severity="MEDIUM")])
        response = Mock(status_code=201)
        response.json.return_value = {}
        client = self._client()
        with patch("scanner.services.publish.client_for", return_value=client), patch.object(client, "_request", return_value=response) as request:
            result = publish_event(event)
        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(request.call_args_list[-1].kwargs["json"]["state"], "success")

    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_push_without_pull_request_comments_on_the_commit(self):
        event = self.make_event(event_type="PUSH", payload={"ref": "refs/heads/main"})
        event.ref = "main"
        event.save(update_fields=["ref"])
        self.make_job(event, [finding(severity="LOW")])
        response = Mock(status_code=201)
        response.json.return_value = {}
        client = self._client()
        with patch("scanner.services.publish.client_for", return_value=client), \
                patch.object(client, "find_open_pull_request", return_value=None), \
                patch.object(client, "_request", return_value=response) as request:
            publish_event(event)
        paths = [call.args[1] for call in request.call_args_list]
        self.assertIn("/repos/acme/payments/commits/abc123456789/comments", paths)

    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_publish_waits_for_pending_jobs(self):
        event = self.make_event()
        self.make_job(event, [], status="PENDING")
        result = publish_event(event)
        self.assertEqual(result["status"], "waiting")

    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_publish_skips_inactive_integrations(self):
        event = self.make_event()
        self.integration.status = "PENDING"
        self.integration.save(update_fields=["status"])
        self.make_job(event, [finding()])
        self.assertEqual(publish_event(event)["status"], "skipped")

    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_provider_error_keeps_event_retryable(self):
        event = self.make_event()
        self.make_job(event, [finding()])
        client = self._client()
        with patch("scanner.services.publish.client_for", return_value=client), patch.object(client, "_request", side_effect=ProviderError("GitHub API request failed with status 500.")):
            result = publish_event(event)
        self.assertEqual(result["status"], "retry")
        self.assertTrue(result["errors"])
        event.refresh_from_db()
        self.assertEqual(event.status, "PROCESSED")
        self.assertEqual(event.publish_attempts, 1)

    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_publish_is_idempotent(self):
        event = self.make_event()
        self.make_job(event, [finding()])
        response = Mock(status_code=201)
        response.json.return_value = {}
        client = self._client()
        with patch("scanner.services.publish.client_for", return_value=client), patch.object(client, "_request", return_value=response):
            publish_event(event)
            second = publish_event(event)
        self.assertEqual(second["status"], "already_published")

    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_failed_scan_job_marks_the_run_incomplete(self):
        event = self.make_event()
        self.make_job(event, [], status="FAILED")
        response = Mock(status_code=201)
        response.json.return_value = {}
        client = self._client()
        with patch("scanner.services.publish.client_for", return_value=client), patch.object(client, "_request", return_value=response):
            result = publish_event(event)
        self.assertEqual(result["verdict"], "blocked")
        self.assertEqual(result["summary"]["failed_jobs"], 1)


class GitLabPublishingTests(PublishingBase):
    def setUp(self):
        super().setUp()
        self.integration.provider = "GITLAB"
        self.integration.repository_url = "https://gitlab.com/acme/payments"
        self.integration.save(update_fields=["provider", "repository_url"])

    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_gitlab_uses_merge_request_note_and_commit_status(self):
        event = self.make_event(payload={"object_attributes": {"iid": 12, "last_commit": {"id": "abc123456789"}}})
        self.make_job(event, [finding(severity="HIGH")])
        response = Mock(status_code=201)
        response.json.return_value = {}
        client = ProviderClient("GITLAB", "provider-token")
        with patch("scanner.services.publish.client_for", return_value=client), patch.object(client, "_request", return_value=response) as request:
            result = publish_event(event)
        paths = [call.args[1] for call in request.call_args_list]
        self.assertIn("/projects/acme%2Fpayments/merge_requests/12/notes", paths)
        self.assertIn("/projects/acme%2Fpayments/statuses/abc123456789", paths)
        self.assertFalse(result["sarif"].get("uploaded", True))


class WorkerIntegrationTests(PublishingBase):
    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_worker_publishes_after_the_last_job_finishes(self):
        event = self.make_event()
        self.make_job(event, [finding()], filename="repo-abc/src/a.py", status="PENDING")
        self.make_job(event, [finding(severity="LOW")], filename="repo-abc/src/b.py", status="PENDING")
        response = Mock(status_code=201)
        response.json.return_value = {}
        client = ProviderClient("GITHUB", "provider-token")
        with patch("scanner.services.publish.client_for", return_value=client), patch.object(client, "_request", return_value=response):
            call_command("process_scan_jobs", limit=1, verbosity=0)
            event.refresh_from_db()
            self.assertEqual(event.status, "PROCESSED")
            call_command("process_scan_jobs", limit=1, verbosity=0)
        event.refresh_from_db()
        self.assertEqual(event.status, "PUBLISHED")

    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_manual_sync_creates_event_and_jobs(self):
        archive = zip_archive({"acme-payments-abc/src/app.py": "value = eval(input())"})
        with patch("scanner.services.provider_clients.ProviderClient.download_repository", return_value=archive):
            response = self.client.post(f"/api/v1/integrations/{self.integration.id}/sync/", {}, format="json")
        self.assertEqual(response.status_code, 202)
        event = RepositoryEvent.objects.get(integration=self.integration)
        self.assertEqual(event.event_type, "SYNC")
        self.assertEqual(event.status, "PROCESSED")
        self.assertEqual(event.scan_job_count, 1)
        self.assertEqual(ScanJob.objects.get().repository_event_id, event.id)


class EventHistoryApiTests(PublishingBase):
    def test_delivery_history_is_listed(self):
        event = self.make_event()
        event.last_error = "Timeout"
        event.save(update_fields=["last_error"])
        response = self.client.get(f"/api/v1/integrations/{self.integration.id}/events/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["events"][0]["id"], event.id)
        self.assertEqual(response.data["events"][0]["last_error"], "Timeout")

    @override_settings(PROVIDER_PUBLISH_ENABLED=True)
    def test_manual_publish_endpoint(self):
        event = self.make_event()
        self.make_job(event, [finding()])
        response = Mock(status_code=201)
        response.json.return_value = {}
        client = ProviderClient("GITHUB", "provider-token")
        with patch("scanner.services.publish.client_for", return_value=client), patch.object(client, "_request", return_value=response):
            published = self.client.post(f"/api/v1/integrations/{self.integration.id}/events/{event.id}/publish/", {}, format="json")
        self.assertEqual(published.status_code, 200)
        self.assertEqual(published.data["status"], "published")

    def test_events_are_workspace_scoped(self):
        other_user = User.objects.create_user(username="other", password="strong-pass-123")
        other_org = Organization.objects.create(name="Other", slug="other", owner=other_user)
        other = RepositoryIntegration.objects.create(organization=other_org, provider="GITHUB", repository_url=GITHUB)
        response = self.client.get(f"/api/v1/integrations/{other.id}/events/")
        self.assertEqual(response.status_code, 404)


class WebhookDeliveryTests(PublishingBase):
    @override_settings(GITHUB_WEBHOOK_SECRET="hook-secret")
    def test_branch_deletion_is_ignored(self):
        import hashlib
        import hmac
        import json

        payload = {"ref": "refs/heads/old-branch", "after": "0" * 40, "deleted": True}
        body = json.dumps(payload).encode()
        signature = "sha256=" + hmac.new(b"hook-secret", body, hashlib.sha256).hexdigest()
        response = self.client.post(
            f"/api/v1/webhooks/github/{self.integration.id}/",
            data=body,
            content_type="application/json",
            HTTP_X_GITHUB_EVENT="push",
            HTTP_X_HUB_SIGNATURE_256=signature,
        )
        self.assertEqual(response.status_code, 202)
        event = RepositoryEvent.objects.get(integration=self.integration)
        self.assertEqual(event.status, "IGNORED")
        self.assertEqual(event.ref, "old-branch")
