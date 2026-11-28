from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from scanner.analysis.security_scanner import full_security_scan
from scanner.core.patcher import propose_patch, validate_patch
from scanner.models import Membership, Organization
from scanner.providers.llm import normalize_llm_result


class AIHardeningTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("hardening", password="strong-pass-123")
        self.org = Organization.objects.create(name="Hardening", slug="hardening", owner=self.user)
        Membership.objects.create(organization=self.org, user=self.user, role="OWNER")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_scan_api_contains_rag_retrieval(self):
        response = self.client.post("/api/scan/", {"code": "value = eval(user_input)", "filename": "sample.py"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["rag"]["backend"], "KnowledgeVectorStore")
        self.assertEqual(response.data["rag"]["findings"][0]["rag_suggested_fix"]["cwe_id"], "CWE-95")
        self.assertEqual(response.data["llm_advisory"]["status"], "disabled")

    def test_patch_validation_uses_bandit_and_returns_real_test_state(self):
        original = "import subprocess\nsubprocess.run(command, shell=True)"
        result = propose_patch(original)
        before = full_security_scan(original, "sample.py")
        self.assertTrue(any(item["engine"] == "bandit" for item in before["bandit_findings"]))
        self.assertTrue(result["validation"]["rescan"])
        self.assertEqual(result["validation"]["tests"]["status"], "not_run")

    def test_syntactically_valid_but_unchanged_patch_requires_review(self):
        validation = validate_patch("value = eval(user_input)", "value = eval(user_input)")
        self.assertTrue(validation["syntax"])
        self.assertFalse(validation["rescan"])
        self.assertTrue(validation["requires_review"])

    def test_malformed_llm_json_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_llm_result("not-json")

    def test_assistant_keeps_approval_separate_from_regression(self):
        draft = self.client.post("/api/v1/assistant/", {"code": "value = eval(input())", "filename": "x.py"}, format="json")
        self.assertEqual(draft.status_code, 201)
        approved = self.client.patch(
            f"/api/v1/assistant/{draft.data['request_id']}/",
            {"decision": "APPROVE"},
            format="json",
        )
        self.assertEqual(approved.data["approval_decision"], "APPROVED")
        self.assertIn(approved.data["regression_status"], {"PASSED", "FAILED"})
        self.assertFalse(approved.data["auto_apply"])
