import unittest
import os
import shutil
from appsec_toolkit.checks import debug_mode # Use the correct module name

class TestDebugModeDetection(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for test files
        self.test_project_dir = "temp_test_debug_project"
        os.makedirs(self.test_project_dir, exist_ok=True)
        os.makedirs(os.path.join(self.test_project_dir, "subdir"), exist_ok=True)
        os.makedirs(os.path.join(self.test_project_dir, "venv/subdir_in_venv"), exist_ok=True)


    def tearDown(self):
        # Remove the temporary directory after tests
        if os.path.exists(self.test_project_dir):
            shutil.rmtree(self.test_project_dir)

    def _create_file(self, path_segments, content):
        filepath = os.path.join(self.test_project_dir, *path_segments)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    def test_no_debug_settings(self):
        self._create_file(["app.py"], "SECRET_KEY = 'secure'\nDEBUG = False")
        self._create_file([".env"], "ENVIRONMENT=production")
        findings = debug_mode.scan_for_debug_settings(self.test_project_dir)
        self.assertEqual(len(findings), 0, f"Expected no findings, but got: {findings}")

    def test_python_debug_true(self):
        self._create_file(["app.py"], "DEBUG = True # Dev mode")
        findings = debug_mode.scan_for_debug_settings(self.test_project_dir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding"], "DEBUG = True # Dev mode")
        self.assertEqual(findings[0]["type"], "Python Debug Setting")

    def test_flask_debug_env_vars(self):
        self._create_file(["config.py"], "FLASK_DEBUG = 1")
        self._create_file(["run.py"], "FLASK_ENV = 'development'")
        findings = debug_mode.scan_for_debug_settings(self.test_project_dir)
        self.assertEqual(len(findings), 2)

    def test_env_file_debug_true(self):
        self._create_file([".env"], "DEBUG=True\nOTHER_VAR=value")
        findings = debug_mode.scan_for_debug_settings(self.test_project_dir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding"], "DEBUG=True")
        self.assertEqual(findings[0]["type"], "Environment Config Debug Setting")
        
    def test_env_file_case_insensitivity(self):
        self._create_file(["dev.env"], "debug = true") # lowercase
        findings = debug_mode.scan_for_debug_settings(self.test_project_dir)
        self.assertEqual(len(findings), 1, f"Findings: {findings}")
        self.assertEqual(findings[0]["finding"], "debug = true")

    def test_multiple_findings(self):
        self._create_file(["app.py"], "DEBUG = True")
        self._create_file(["subdir", "settings.py"], "DEBUG = True")
        self._create_file([".env"], "FLASK_ENV = development")
        findings = debug_mode.scan_for_debug_settings(self.test_project_dir)
        self.assertEqual(len(findings), 3)

    def test_ignores_venv(self):
        # Create a file with DEBUG = True inside a 'venv' directory
        self._create_file(["venv", "some_package.py"], "DEBUG = True")
        # Create a non-venv file for control
        self._create_file(["app.py"], "FLASK_DEBUG = 0")
        findings = debug_mode.scan_for_debug_settings(self.test_project_dir)
        # Should only find the non-venv one if it were a debug pattern, or 0 if not.
        # In this case, FLASK_DEBUG = 0 is not a debug pattern.
        self.assertEqual(len(findings), 0, f"Should ignore venv. Findings: {findings}")

    def test_django_debug_true_in_settings(self):
        self._create_file(["project", "settings", "dev.py"], "# Django dev settings\nDEBUG = True")
        findings = debug_mode.scan_for_debug_settings(self.test_project_dir)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "Python Debug Setting")
        self.assertIn("dev.py", findings[0]["file"])
        
    def test_mixed_case_patterns(self):
        self._create_file(["app_mixed.py"], "DeBuG = TrUe")
        findings = debug_mode.scan_for_debug_settings(self.test_project_dir)
        self.assertEqual(len(findings), 1, f"Findings: {findings}")
        self.assertEqual(findings[0]["finding"], "DeBuG = TrUe")

if __name__ == '__main__':
    unittest.main()
