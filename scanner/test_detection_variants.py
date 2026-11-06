"""Week 1 tests: detection variants and safe (negative) examples.

The tests only pass code *strings* to the AST analyzer. The submitted code is
parsed, never executed, and no network call is made.
"""
import unittest

from scanner.analysis.ast_parser import analyze_code_string
from scanner.contracts import validate_finding


def findings_for(code, cwe):
    """Return the findings with the given CWE id for a code sample."""
    return [f for f in analyze_code_string(code) if f["cwe_id"] == cwe]


class EvalVariantsTests(unittest.TestCase):
    def test_eval_with_different_variable_names(self):
        for name in ("user_input", "expression", "raw_value"):
            with self.subTest(name=name):
                found = findings_for(f"result = eval({name})", "CWE-95")
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["line_start"], 1)
                self.assertEqual(found[0]["rule_id"], "eval-injection")

    def test_exec_and_builtins_eval(self):
        self.assertEqual(len(findings_for("exec(payload)", "CWE-95")), 1)
        self.assertEqual(len(findings_for("import builtins\nbuiltins.eval(expr)", "CWE-95")), 1)

    def test_line_number_is_reported(self):
        code = "x = 1\ny = 2\nvalue = eval(user_input)\n"
        self.assertEqual(findings_for(code, "CWE-95")[0]["line_start"], 3)

    def test_literal_eval_is_not_reported(self):
        code = "import ast\nvalue = ast.literal_eval(user_input)"
        self.assertEqual(findings_for(code, "CWE-95"), [])

    def test_model_eval_method_is_not_reported(self):
        self.assertEqual(findings_for("model.eval()", "CWE-95"), [])


class CommandInjectionVariantsTests(unittest.TestCase):
    def test_os_system_variants(self):
        self.assertEqual(len(findings_for("import os\nos.system(value)", "CWE-78")), 1)
        self.assertEqual(len(findings_for("import os\nos.system('ping ' + user_input)", "CWE-78")), 1)
        self.assertEqual(len(findings_for("import os\nos.popen(cmd)", "CWE-78")), 1)

    def test_subprocess_shell_true_variants(self):
        samples = [
            "import subprocess\nsubprocess.run(command, shell=True)",
            "import subprocess\nsubprocess.check_output(command, shell=True)",
            "import subprocess\nsubprocess.Popen(command, shell=True)",
        ]
        for code in samples:
            with self.subTest(code=code):
                found = findings_for(code, "CWE-78")
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["line_start"], 2)

    def test_import_aliases_are_resolved(self):
        self.assertEqual(len(findings_for("import subprocess as sp\nsp.run(cmd, shell=True)", "CWE-78")), 1)
        self.assertEqual(len(findings_for("from subprocess import run\nrun(cmd, shell=True)", "CWE-78")), 1)
        self.assertEqual(len(findings_for("from os import system\nsystem(cmd)", "CWE-78")), 1)

    def test_shell_false_with_fixed_arguments_is_safe(self):
        code = "import subprocess\nsubprocess.run(['ping', '-c', '1', host], shell=False, check=True)"
        self.assertEqual(findings_for(code, "CWE-78"), [])

    def test_argument_list_without_shell_is_safe(self):
        code = "import subprocess\nsubprocess.run(['ls', '-l'], check=True)"
        self.assertEqual(findings_for(code, "CWE-78"), [])


class DynamicSqlVariantsTests(unittest.TestCase):
    def test_fstring_query(self):
        code = "cursor.execute(f\"SELECT * FROM users WHERE name = '{username}'\")"
        found = findings_for(code, "CWE-89")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["rule_id"], "sql-dynamic-query")

    def test_string_concatenation_query(self):
        code = "cursor.execute('SELECT * FROM users WHERE name = ' + username)"
        self.assertEqual(len(findings_for(code, "CWE-89")), 1)

    def test_percent_and_format_query(self):
        self.assertEqual(len(findings_for("cursor.execute('SELECT * FROM t WHERE id = %s' % user_id)", "CWE-89")), 1)
        self.assertEqual(len(findings_for("cursor.execute('SELECT * FROM t WHERE id = {}'.format(user_id))", "CWE-89")), 1)

    def test_query_built_in_a_variable_first(self):
        code = "query = f\"SELECT * FROM users WHERE name = '{username}'\"\ncursor.execute(query)"
        found = findings_for(code, "CWE-89")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["line_start"], 2)

    def test_query_extended_with_plus_equals(self):
        code = "query = 'SELECT * FROM users WHERE 1=1'\nquery += ' AND name = ' + name\ncursor.execute(query)"
        self.assertEqual(len(findings_for(code, "CWE-89")), 1)

    def test_chained_cursor_call(self):
        code = "connection.cursor().execute(f'SELECT * FROM t WHERE id = {user_id}')"
        self.assertEqual(len(findings_for(code, "CWE-89")), 1)

    def test_parameterized_query_is_safe(self):
        code = "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))"
        self.assertEqual(findings_for(code, "CWE-89"), [])

    def test_parameterized_query_stored_in_variable_is_safe(self):
        code = "query = 'SELECT * FROM users WHERE username = %s'\ncursor.execute(query, (username,))"
        self.assertEqual(findings_for(code, "CWE-89"), [])

    def test_fixed_query_without_user_data_is_safe(self):
        code = "query = 'SELECT COUNT(*) FROM users'\ncursor.execute(query)"
        self.assertEqual(findings_for(code, "CWE-89"), [])


class HardcodedSecretVariantsTests(unittest.TestCase):
    def test_different_secret_names(self):
        for name in ("password", "api_key", "token", "secret", "SECRET_KEY", "apiKey", "access_token"):
            with self.subTest(name=name):
                found = findings_for(f"{name} = 'abc123'", "CWE-798")
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["line_start"], 1)

    def test_attribute_annotated_and_keyword_forms(self):
        self.assertEqual(len(findings_for("self.api_key = 'abc123'", "CWE-798")), 1)
        self.assertEqual(len(findings_for("API_TOKEN: str = 'abc123'", "CWE-798")), 1)
        self.assertEqual(len(findings_for("connect(host='db', password='hunter2')", "CWE-798")), 1)

    def test_secret_value_is_not_copied_into_the_finding(self):
        finding = findings_for("password = 'hunter2'", "CWE-798")[0]
        self.assertNotIn("hunter2", finding["evidence"])
        self.assertNotIn("hunter2", finding["message"])

    def test_values_loaded_from_environment_are_safe(self):
        code = "import os\npassword = os.environ['DB_PASSWORD']\napi_key = os.getenv('API_KEY')"
        self.assertEqual(findings_for(code, "CWE-798"), [])

    def test_empty_secret_is_not_reported(self):
        self.assertEqual(findings_for("password = ''", "CWE-798"), [])

    def test_names_that_only_look_like_secrets_are_safe(self):
        for name in ("tokenizer", "password_label", "max_tokens", "secret_name"):
            with self.subTest(name=name):
                self.assertEqual(findings_for(f"{name} = 'value'", "CWE-798"), [])


class FindingContractTests(unittest.TestCase):
    def test_findings_follow_the_shared_contract(self):
        code = "import os\nos.system(value)\nresult = eval(raw_value)\npassword = 'abc123'\n"
        findings = analyze_code_string(code)
        self.assertEqual({f["cwe_id"] for f in findings}, {"CWE-78", "CWE-95", "CWE-798"})
        for finding in findings:
            self.assertEqual(validate_finding(finding), [])
            self.assertEqual(finding["engine"], "ast")
            self.assertTrue(finding["rule_id"])
            self.assertGreaterEqual(finding["line_start"], 1)

    def test_syntax_error_is_reported_not_raised(self):
        findings = analyze_code_string("def broken(:\n    pass")
        self.assertEqual(findings[0]["cwe_id"], "SYNTAX")


if __name__ == "__main__":
    unittest.main()
