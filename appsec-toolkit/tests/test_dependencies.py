import unittest
from unittest.mock import patch, MagicMock
import os
import shutil
import json
from appsec_toolkit.checks import dependencies # Ensure this import path is correct

class TestDependencyChecker(unittest.TestCase):

    def setUp(self):
        self.test_project_dir = "temp_dep_test_project_for_tests"
        os.makedirs(self.test_project_dir, exist_ok=True)
        self.requirements_path = os.path.join(self.test_project_dir, "requirements.txt")

    def tearDown(self):
        if os.path.exists(self.test_project_dir):
            shutil.rmtree(self.test_project_dir)

    def _create_requirements_file(self, content="requests==2.19.0"):
        with open(self.requirements_path, "w") as f:
            f.write(content)

    @patch('appsec_toolkit.checks.dependencies.subprocess.run')
    def test_pip_audit_not_found(self, mock_subprocess_run):
        mock_subprocess_run.side_effect = FileNotFoundError("pip-audit not found")
        self._create_requirements_file()
        results = dependencies.check_dependencies(self.test_project_dir)
        self.assertIn("error", results)
        self.assertTrue("pip-audit command not found" in results["error"])

    def test_requirements_file_not_found(self):
        # No requirements.txt created
        results = dependencies.check_dependencies(self.test_project_dir)
        self.assertIn("error", results)
        self.assertTrue("requirements.txt not found" in results["error"])

    @patch('appsec_toolkit.checks.dependencies.subprocess.run')
    def test_no_vulnerabilities_found(self, mock_subprocess_run):
        self._create_requirements_file()
        mock_response = MagicMock()
        mock_response.stdout = json.dumps([]) # Empty list means no vulnerabilities
        mock_response.stderr = ""
        mock_response.returncode = 0 # pip-audit exits 0 if no vulns
        mock_subprocess_run.return_value = mock_response
        
        results = dependencies.check_dependencies(self.test_project_dir)
        self.assertNotIn("error", results, f"Results were: {results}")
        # The current implementation returns a "success" message in this case.
        self.assertTrue(results.get("success") == "No vulnerabilities found by pip-audit." or len(results.get("vulnerabilities", [])) == 0)


    @patch('appsec_toolkit.checks.dependencies.subprocess.run')
    def test_vulnerabilities_found(self, mock_subprocess_run):
        self._create_requirements_file()
        mock_vuln_data = [
            {
                "name": "requests",
                "version": "2.19.0",
                "id": "PYSEC-2021-123",
                "description": "A sample vulnerability.",
                "fix_versions": ["2.20.0"]
            }
        ]
        mock_response = MagicMock()
        mock_response.stdout = json.dumps(mock_vuln_data)
        mock_response.stderr = ""
        mock_response.returncode = 1 # pip-audit exits non-zero if vulns found
        mock_subprocess_run.return_value = mock_response

        results = dependencies.check_dependencies(self.test_project_dir)
        self.assertNotIn("error", results, f"Results were: {results}")
        self.assertEqual(len(results["vulnerabilities"]), 1)
        self.assertEqual(results["vulnerabilities"][0]["package"], "requests")
        self.assertEqual(results["vulnerabilities"][0]["vuln_id"], "PYSEC-2021-123")

    @patch('appsec_toolkit.checks.dependencies.subprocess.run')
    def test_pip_audit_execution_error(self, mock_subprocess_run):
        self._create_requirements_file()
        mock_response = MagicMock()
        mock_response.stdout = "" # No JSON output
        mock_response.stderr = "pip-audit internal error"
        mock_response.returncode = 1 # Non-zero exit code
        mock_subprocess_run.return_value = mock_response

        results = dependencies.check_dependencies(self.test_project_dir)
        self.assertIn("error", results)
        self.assertTrue("pip-audit execution error" in results["error"] or "pip-audit did not produce output" in results["error"])

    @patch('appsec_toolkit.checks.dependencies.subprocess.run')
    def test_pip_audit_json_decode_error(self, mock_subprocess_run):
        self._create_requirements_file()
        mock_response = MagicMock()
        mock_response.stdout = "This is not JSON" # Invalid JSON output
        mock_response.stderr = ""
        mock_response.returncode = 1
        mock_subprocess_run.return_value = mock_response

        results = dependencies.check_dependencies(self.test_project_dir)
        self.assertIn("error", results)
        self.assertTrue("Failed to decode JSON output" in results["error"])
        
    @patch('appsec_toolkit.checks.dependencies.subprocess.run')
    def test_pip_audit_failed_to_create_env_error(self, mock_subprocess_run):
        self._create_requirements_file()
        mock_response = MagicMock()
        mock_response.stdout = "" 
        mock_response.stderr = "Failed to create an ephemeral virtual environment due to ..."
        mock_response.returncode = 1
        mock_subprocess_run.return_value = mock_response

        results = dependencies.check_dependencies(self.test_project_dir)
        self.assertIn("error", results)
        self.assertTrue("pip-audit failed to create virtual environment" in results["error"])

if __name__ == '__main__':
    unittest.main()
