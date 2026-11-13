from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from scanner.models import Membership, Organization


class SaaSPackTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("saas-test", email="saas@example.com", password="strong-pass-123")
        self.org = Organization.objects.create(name="SaaS", slug="saas-test", owner=self.user)
        Membership.objects.create(organization=self.org, user=self.user, role="OWNER")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_openapi_schema_is_public(self):
        client = APIClient()
        response = client.get("/api/openapi.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["openapi"], "3.0.3")

    def test_team_usage_and_pagination_contracts(self):
        self.assertEqual(self.client.get("/api/v1/team/?page=1&page_size=10").status_code, 200)
        usage = self.client.get("/api/v1/usage/")
        self.assertEqual(usage.status_code, 200)
        self.assertEqual(usage.data["plan"], "FREE")

    def test_api_key_rotation(self):
        created = self.client.post("/api/v1/api-keys/", {"name": "rotate"}, format="json")
        old_prefix = created.data["api_key"]["prefix"]
        rotated = self.client.post(f"/api/v1/api-keys/{old_prefix}/rotate/", {}, format="json")
        self.assertEqual(rotated.status_code, 201)
        self.assertNotEqual(rotated.data["api_key"]["prefix"], old_prefix)

    def test_assistant_requires_explicit_approval(self):
        draft = self.client.post("/api/v1/assistant/", {"code": "value = eval(input())", "filename": "x.py"}, format="json")
        self.assertEqual(draft.status_code, 201)
        self.assertEqual(draft.data["status"], "draft")
        approved = self.client.patch(f"/api/v1/assistant/{draft.data['request_id']}/", {"decision": "APPROVE"}, format="json")
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.data["decision"], "APPROVED")

    def test_password_reset_does_not_disclose_account_existence(self):
        response = APIClient().post("/api/v1/auth/password-reset/", {"email": "missing@example.com"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "accepted")

    def test_extended_secret_scan(self):
        response = self.client.post("/api/scan/", {"filename": "config.yaml", "code": "password='super-secret-value'"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(item["cwe_id"] == "CWE-798" for item in response.data["vulnerabilities"]))
