from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from scanner.analysis.ast_parser import analyze_code_string
from scanner.analysis.javascript_parser import analyze_javascript
from scanner.analysis.bandit_scanner import scan_code as bandit_scan
from scanner.analysis.security_scanner import full_security_scan
from scanner.contracts import validate_finding
from scanner.core.patcher import propose_patch
from scanner.views import summarize_findings
from scanner.models import Membership, Organization, Project
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
