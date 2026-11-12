from datetime import timedelta

from django.test import TestCase, override_settings
from django.core.management import call_command
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.test import APIClient
from scanner.analysis.ast_parser import analyze_code_string
from scanner.analysis.javascript_parser import analyze_javascript
from scanner.analysis.bandit_scanner import scan_code as bandit_scan
from scanner.analysis.security_scanner import full_security_scan
from scanner.contracts import validate_finding
from scanner.core.patcher import propose_patch
from scanner.views import summarize_findings
from scanner.models import AuditLog, Membership, Organization, Project, RepositoryEvent, RepositoryIntegration, ScanJob
from scanner.services.scan_jobs import recover_stale_jobs, requeue_failed_jobs
from scanner.services.integrations import hash_secret
from scanner.services.token_crypto import decrypt_token, encrypt_token
from scanner.services.provider_clients import ProviderClient, extract_source_files
from scanner.services.provider_actions import ProviderActions
from unittest.mock import Mock, patch
import io
import zipfile
class ContractAndRulesTests(TestCase):
    def test_contract_contains_security_fields(self):
        f=analyze_code_string('value = eval(user_input)')[0]
        self.assertEqual(f['cwe_id'],'CWE-95'); self.assertEqual(f['line_start'],1); self.assertEqual(validate_finding(f),[]); self.assertIn('risk_score',f)
    def test_python_rules(self):
        code='import os\nimport pickle\nos.system(cmd)\npickle.loads(data)\npassword="secret"'
        self.assertEqual({x['cwe_id'] for x in analyze_code_string(code)},{'CWE-78','CWE-502','CWE-798'})
    def test_javascript_rules(self):
        fs=analyze_javascript('element.innerHTML = input; eval(input);','javascript')
        self.assertEqual({x['cwe_id'] for x in fs},{'CWE-79','CWE-95'})
    def test_bandit_adapter_returns_contract(self):
        fs=bandit_scan('import subprocess\nsubprocess.call(user, shell=True)')
        self.assertTrue(any(x['engine']=='bandit' for x in fs)); self.assertTrue(all('line_start' in x for x in fs))
    def test_combined_scan_deduplicates(self):
        result=full_security_scan('value = eval(user_input)'); self.assertTrue(result['all_findings']); self.assertEqual(result['language'],'python')
    def test_patch_is_syntax_valid_and_rescanned(self):
        result=propose_patch('value = eval(user_input)'); self.assertTrue(result['validation']['syntax']); self.assertTrue(result['validation']['rescan']); self.assertIn('ast.literal_eval',result['patched_code'])
class APITests(TestCase):
    def setUp(self):
        self.client = APIClient()

        self.user = User.objects.create_user(
            username="test-user",
            password="strong-pass-123",
        )
        self.organization = Organization.objects.create(name="Test Workspace", slug="test-workspace", owner=self.user)
        Membership.objects.create(organization=self.organization, user=self.user, role="OWNER")

        self.client.force_authenticate(user=self.user)
    def test_scan_endpoint(self):
        r=self.client.post('/api/scan/',{'code':'import os\nos.system(user_input)','filename':'x.py'},format='json'); self.assertEqual(r.status_code,200); self.assertTrue(r.data['is_vulnerable']); self.assertIn('engines',r.data)
        self.assertIn('summary', r.data)
        self.assertEqual(r.data['summary']['total_findings'], len(r.data['vulnerabilities']))
    def test_compare_and_history(self):
        r=self.client.post('/api/compare/',{'code':'value = eval(input)','filename':'x.py'},format='json'); self.assertEqual(r.status_code,200); self.assertIn('ast_findings',r.data['counts']); self.client.post('/api/scan/',{'code':'safe=True'},format='json'); self.assertEqual(self.client.get('/api/history/').status_code,200)
    def test_empty_and_syntax(self):
        self.assertEqual(self.client.post('/api/scan/',{'code':''},format='json').status_code,400); self.assertEqual(self.client.post('/api/scan/',{'code':'def broken(:'},format='json').status_code,400)
    def test_dashboard_and_login_pages(self):
        self.client.logout()
        self.assertEqual(self.client.get('/').status_code,302); self.assertEqual(self.client.get('/login/').status_code,200); self.assertEqual(self.client.get('/register/').status_code,200)
    def test_register_and_login(self):
        self.client.logout()
        r=self.client.post('/register/',{'username':'analyst','email':'a@example.com','password':'strong-pass-123'}); self.assertEqual(r.status_code,302); self.client.get('/logout/'); r=self.client.post('/login/',{'username':'analyst','password':'strong-pass-123'}); self.assertEqual(r.status_code,302)
        analyst = User.objects.get(username='analyst')
        self.assertTrue(Organization.objects.filter(owner=analyst).exists())
        self.assertTrue(Membership.objects.filter(user=analyst, role='OWNER').exists())
    def test_dashboard_requires_login(self):
        unauthenticated_client = APIClient()

        response = unauthenticated_client.get(
            "/",
            follow=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])

    def test_health_and_readiness_endpoints(self):
        self.client.logout()
        self.assertEqual(self.client.get('/health/').status_code, 200)
        self.assertEqual(self.client.get('/ready/').status_code, 200)

    def test_v1_scan_alias_requires_authentication(self):
        response = self.client.post('/api/v1/scan/', {'code': 'safe = True'}, format='json')
        self.assertEqual(response.status_code, 200)

    def test_finding_summary_counts_severity_language_and_engine(self):
        summary = summarize_findings([
            {"severity": "HIGH", "language": "python", "engine": "ast"},
            {"severity": "medium", "language": "python", "engine": "bandit"},
        ], duration_ms=12.5)
        self.assertEqual(summary["total_findings"], 2)
        self.assertEqual(summary["severity_counts"]["high"], 1)
        self.assertEqual(summary["severity_counts"]["medium"], 1)
        self.assertEqual(summary["languages"], ["python"])
        self.assertEqual(summary["engines"], ["ast", "bandit"])
        self.assertEqual(summary["duration_ms"], 12.5)

    def test_evaluation_summary_endpoint(self):
        response = self.client.get("/api/evaluation/summary/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "success")
        self.assertIn("metrics", response.data)
        self.assertIn("counts", response.data)

    def test_project_create_and_list_is_workspace_scoped(self):
        response = self.client.post('/api/v1/projects/', {'name': 'Payments API', 'repository_url': 'https://github.com/example/payments'}, format='json')
        self.assertEqual(response.status_code, 201)
        listed = self.client.get('/api/v1/projects/')
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data['projects'][0]['slug'], 'payments-api')
        self.assertTrue(Project.objects.filter(organization=self.organization, slug='payments-api').exists())

    def test_finding_status_can_be_updated(self):
        scan = self.client.post('/api/scan/', {'code': 'value = eval(input)', 'filename': 'x.py'}, format='json')
        self.assertEqual(scan.status_code, 200)
        finding_id = scan.data['scan_id']
        self.assertEqual(self.client.get('/api/v1/findings/').status_code, 200)
        finding = self.client.get('/api/v1/findings/').data['findings'][0]
        updated = self.client.patch(f"/api/v1/findings/{finding['id']}/", {'status': 'RESOLVED'}, format='json')
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.data['finding_status'], 'RESOLVED')

    def test_api_key_is_returned_once_and_can_authenticate(self):
        created = self.client.post('/api/v1/api-keys/', {'name': 'CI'}, format='json')
        self.assertEqual(created.status_code, 201)
        raw_key = created.data['api_key']['token']
        api_client = APIClient()
        response = api_client.get('/api/v1/projects/', HTTP_AUTHORIZATION=f'Bearer {raw_key}')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('token', api_client.get('/api/v1/api-keys/').data.get('api_keys', [{}])[0])

    def test_sarif_report_export(self):
        self.client.post('/api/scan/', {'code': 'value = eval(input)', 'filename': 'x.py'}, format='json')
        response = self.client.get('/api/v1/reports/export/?type=sarif')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/sarif+json')
        self.assertIn('CWE-95', response.content.decode())

    def test_scan_job_is_idempotent_and_worker_completes_it(self):
        headers = {'HTTP_IDEMPOTENCY_KEY': 'checkout-build-001'}
        first = self.client.post('/api/v1/scan-jobs/', {'code': 'value = eval(input)', 'filename': 'worker.py'}, format='json', **headers)
        self.assertEqual(first.status_code, 202)
        job_id = first.data['job']['id']
        replay = self.client.post('/api/v1/scan-jobs/', {'code': 'different code'}, format='json', **headers)
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.data['replayed'])
        self.assertEqual(replay.data['job']['id'], job_id)
        call_command('process_scan_jobs', limit=1, verbosity=0)
        detail = self.client.get(f'/api/v1/scan-jobs/{job_id}/')
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data['job']['status'], 'SUCCEEDED')
        self.assertEqual(detail.data['job']['progress'], 100)
        self.assertTrue(ScanJob.objects.get(pk=job_id).result['scan_id'])

    def test_pending_scan_job_can_be_cancelled(self):
        created = self.client.post('/api/v1/scan-jobs/', {'code': 'safe = True'}, format='json')
        job_id = created.data['job']['id']
        cancelled = self.client.post(f'/api/v1/scan-jobs/{job_id}/')
        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(cancelled.data['job']['status'], 'CANCELLED')


from scanner.rag.vector_db import KnowledgeVectorStore
from scanner.rag.rag_engine import SecurityRAGEngine


class RAGVectorStoreTests(TestCase):

    def setUp(self):
        self.store = KnowledgeVectorStore()

    def test_knowledge_base_loads_records(self):
        self.assertGreater(self.store.count(), 0)

    def test_exact_cwe_lookup(self):
        result = self.store.lookup(
            "CWE-89",
            query="SQL injection"
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["cwe_id"], "CWE-89")
        self.assertEqual(result["match"], "exact_cwe")
        self.assertEqual(result["score"], 1.0)

    def test_token_overlap_search(self):
        result = self.store.lookup(
            None,
            query="How to prevent SQL injection in Python database queries"
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["cwe_id"], "CWE-89")
        self.assertEqual(result["match"], "token_overlap")

    def test_unknown_cwe_returns_none(self):
        result = self.store.lookup(
            "CWE-999",
            query="quantum teleportation galaxy"
        )

        self.assertIsNone(result)

    def test_empty_query_returns_none(self):
        result = self.store.lookup(None, query="")

        self.assertIsNone(result)

    def test_rag_engine_enriches_finding(self):
        engine = SecurityRAGEngine(store=self.store)

        findings = [
            {
                "cwe_id": "CWE-89",
                "message": "SQL injection vulnerability detected"
            }
        ]

        result = engine.enrich_findings(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["rag_suggested_fix"]["cwe_id"],
            "CWE-89"
        )


class Phase4ReliabilityTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="phase4-user", password="strong-pass-123")
        self.organization = Organization.objects.create(name="Phase 4 Workspace", slug="phase4-workspace", owner=self.user)
        Membership.objects.create(organization=self.organization, user=self.user, role="OWNER")

    def make_job(self, status="PENDING", retry_count=0):
        return ScanJob.objects.create(
            organization=self.organization,
            requested_by=self.user,
            source_code="safe = True",
            status=status,
            retry_count=retry_count,
            heartbeat_at=timezone.now() - timedelta(hours=1) if status == "RUNNING" else None,
        )

    def test_request_has_canonical_tenant_context(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        response = client.get("/api/v1/projects/")
        self.assertEqual(response.status_code, 200)

    @override_settings(SCAN_JOB_STALE_SECONDS=60)
    def test_stale_running_job_is_recovered_with_audit_event(self):
        job = self.make_job(status="RUNNING")
        self.assertEqual(recover_stale_jobs(), 1)
        job.refresh_from_db()
        self.assertEqual(job.status, "PENDING")
        self.assertEqual(job.retry_count, 1)
        self.assertTrue(AuditLog.objects.filter(action="scan_job.recovered", metadata__job_id=job.id).exists())

    @override_settings(SCAN_JOB_MAX_RETRIES=2)
    def test_failed_jobs_can_be_requeued_with_a_retry_budget(self):
        job = self.make_job(status="FAILED", retry_count=0)
        self.assertEqual(requeue_failed_jobs(), 1)
        job.refresh_from_db()
        self.assertEqual(job.status, "PENDING")
        self.assertEqual(job.error_message, "Queued for retry by worker policy.")

    @override_settings(SCAN_JOB_MAX_RETRIES=1)
    def test_stale_job_with_exhausted_budget_fails_permanently(self):
        job = self.make_job(status="RUNNING", retry_count=1)
        job.max_retries = 1
        job.save(update_fields=["max_retries"])
        self.assertEqual(recover_stale_jobs(stale_after_seconds=60), 1)
        job.refresh_from_db()
        self.assertEqual(job.status, "FAILED")
        self.assertIn("retry budget", job.error_message)


class Phase5IntegrationTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username="integration-user", password="strong-pass-123")
        self.organization = Organization.objects.create(name="Integration Workspace", slug="integration-workspace", owner=self.user)
        Membership.objects.create(organization=self.organization, user=self.user, role="OWNER")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_create_integration_creates_workspace_project_without_raw_secret(self):
        response = self.client.post("/api/v1/integrations/", {"provider": "GITLAB", "repository_url": "https://gitlab.com/acme/payments", "webhook_secret": "secret-123"}, format="json")
        self.assertEqual(response.status_code, 201)
        integration = RepositoryIntegration.objects.get()
        self.assertEqual(integration.webhook_secret_hash, hash_secret("secret-123"))
        self.assertNotIn("secret-123", response.content.decode())
        self.assertIsNotNone(integration.project_id)

    def test_gitlab_webhook_requires_token_and_records_push(self):
        integration = RepositoryIntegration.objects.create(organization=self.organization, provider="GITLAB", repository_url="https://gitlab.com/acme/payments", webhook_secret_hash=hash_secret("secret-123"))
        payload = {"ref": "refs/heads/main", "after": "abc123", "project": {"web_url": integration.repository_url}}
        response = self.client.post(f"/api/v1/webhooks/gitlab/{integration.id}/", payload, format="json", HTTP_X_GITLAB_EVENT="Push Hook", HTTP_X_GITLAB_TOKEN="secret-123")
        self.assertEqual(response.status_code, 202)
        event = RepositoryEvent.objects.get(integration=integration)
        self.assertEqual(event.event_type, "PUSH")
        self.assertEqual(event.commit_sha, "abc123")

    def test_invalid_webhook_signature_is_rejected(self):
        integration = RepositoryIntegration.objects.create(organization=self.organization, provider="GITLAB", repository_url="https://gitlab.com/acme/payments", webhook_secret_hash=hash_secret("secret-123"))
        response = self.client.post(f"/api/v1/webhooks/gitlab/{integration.id}/", {"ref": "main"}, format="json", HTTP_X_GITLAB_EVENT="Push Hook", HTTP_X_GITLAB_TOKEN="wrong")
        self.assertEqual(response.status_code, 401)
        self.assertFalse(RepositoryEvent.objects.filter(integration=integration).exists())

    @override_settings(GITHUB_CLIENT_ID="client-id", GITHUB_CLIENT_SECRET="client-secret")
    def test_oauth_start_returns_provider_authorization_url(self):
        integration = RepositoryIntegration.objects.create(organization=self.organization, provider="GITHUB", repository_url="https://github.com/acme/payments")
        response = self.client.get(f"/api/v1/integrations/{integration.id}/oauth/start/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("github.com/login/oauth/authorize", response.data["authorization_url"])
        integration.refresh_from_db()
        self.assertTrue(integration.oauth_state)

    def test_provider_client_lists_repositories_without_exposing_token(self):
        response = Mock(status_code=200)
        response.json.return_value = [{"name": "payments", "full_name": "acme/payments", "default_branch": "main", "html_url": "https://github.com/acme/payments"}]
        with patch("scanner.services.provider_clients.requests.request", return_value=response) as request:
            repos = ProviderClient("GITHUB", "secret-token").list_repositories()
        self.assertEqual(repos[0].full_name, "acme/payments")
        self.assertNotIn("secret-token", str(repos))
        self.assertEqual(request.call_args.kwargs["headers"]["Authorization"], "Bearer secret-token")

    def test_remote_archive_extraction_rejects_traversal_and_binary_files(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("repo/main.py", "value = eval(input)")
            archive.writestr("../escape.py", "should not be extracted")
            archive.writestr("repo/image.png", b"\x00\x01")
        files = extract_source_files(stream.getvalue())
        self.assertEqual(files, [("repo/main.py", "value = eval(input)")])

    def test_provider_token_is_reversibly_encrypted_and_not_plaintext(self):
        encrypted = encrypt_token("provider-secret")
        self.assertNotEqual(encrypted, "provider-secret")
        self.assertEqual(decrypt_token(encrypted), "provider-secret")
        self.assertEqual(decrypt_token("not-a-valid-token"), "")

    def test_duplicate_delivery_is_not_recorded_twice(self):
        integration = RepositoryIntegration.objects.create(organization=self.organization, provider="GITLAB", repository_url="https://gitlab.com/acme/payments", webhook_secret_hash=hash_secret("secret-123"), status="ACTIVE")
        payload = {"ref": "refs/heads/main", "after": "abc123"}
        headers = {"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": "secret-123", "X-Gitlab-Event-UUID": "delivery-1"}
        first = self.client.post(f"/api/v1/webhooks/gitlab/{integration.id}/", payload, format="json", **{f"HTTP_{key.upper().replace('-', '_')}": value for key, value in headers.items()})
        second = self.client.post(f"/api/v1/webhooks/gitlab/{integration.id}/", payload, format="json", **{f"HTTP_{key.upper().replace('-', '_')}": value for key, value in headers.items()})
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 202)
        self.assertEqual(RepositoryEvent.objects.filter(integration=integration).count(), 1)
        self.assertEqual(RepositoryEvent.objects.get(integration=integration).status, "QUEUED")

    def test_github_provider_actions_publish_sarif_comment_and_status(self):
        client = ProviderClient("GITHUB", "provider-token")
        response = Mock(status_code=201)
        response.json.return_value = {"url": "https://api.github.com/sarifs/1"}
        with patch.object(client, "_request", return_value=response) as request:
            actions = ProviderActions(client)
            uploaded = actions.upload_sarif("https://github.com/acme/payments", "abc123", "refs/heads/main", {"version": "2.1.0"})
            actions.comment("https://github.com/acme/payments", 7, "Security scan completed.")
            actions.set_security_status("https://github.com/acme/payments", "abc123", "main", False, "Critical findings detected")
        self.assertEqual(uploaded["provider"], "GITHUB")
        self.assertEqual(request.call_count, 3)
        self.assertIn("code-scanning/sarifs", request.call_args_list[0].args[1])
        self.assertEqual(request.call_args_list[2].kwargs["json"]["state"], "failure")
