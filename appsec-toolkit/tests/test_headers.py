import unittest
from unittest.mock import patch, MagicMock
from appsec_toolkit.checks import headers # Assuming scanner.py and checks/ are in appsec_toolkit path

# Adjust the import path if your structure is different or add appsec-toolkit to PYTHONPATH for testing
# For example, if appsec-toolkit is the root and you run tests from there:
# from checks import headers

class TestHeaderChecker(unittest.TestCase):

    @patch('appsec_toolkit.checks.headers.requests.get')
    def test_all_headers_present(self, mock_get):
        # Mock the response from requests.get
        mock_response = MagicMock()
        mock_response.headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
            "X-XSS-Protection": "1; mode=block"
        }
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        test_url = "http://example-all-headers.com"
        results = headers.check_security_headers(test_url)

        self.assertEqual(results["url"], test_url)
        self.assertTrue(len(results["found_headers"]) == len(headers.COMMON_SECURITY_HEADERS))
        self.assertTrue(len(results["missing_headers"]) == 0)
        self.assertNotIn("error", results)
        # print("test_all_headers_present results:", results) # For debugging

    @patch('appsec_toolkit.checks.headers.requests.get')
    def test_some_headers_missing(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {
            "Content-Security-Policy": "default-src 'self'",
            # Missing Strict-Transport-Security
            "X-Content-Type-Options": "nosniff",
        }
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        test_url = "http://example-missing-headers.com"
        results = headers.check_security_headers(test_url)
        
        self.assertEqual(results["url"], test_url)
        self.assertTrue("Strict-Transport-Security" in results["missing_headers"])
        self.assertTrue("X-Frame-Options" in results["missing_headers"])
        self.assertTrue("Content-Security-Policy" in results["found_headers"])
        self.assertGreater(len(results["recommendations"]), 0)
        self.assertNotIn("error", results)
        # print("test_some_headers_missing results:", results) # For debugging

    @patch('appsec_toolkit.checks.headers.requests.get')
    def test_no_security_headers(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {"Server": "SomeServer"} # No relevant security headers
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        test_url = "http://example-no-headers.com"
        results = headers.check_security_headers(test_url)

        self.assertEqual(results["url"], test_url)
        self.assertTrue(len(results["found_headers"]) == 0)
        self.assertTrue(len(results["missing_headers"]) == len(headers.COMMON_SECURITY_HEADERS))
        self.assertNotIn("error", results)
        # print("test_no_security_headers results:", results) # For debugging
        
    @patch('appsec_toolkit.checks.headers.requests.get')
    def test_request_exception(self, mock_get):
        # Configure the mock to raise an exception
        mock_get.side_effect = headers.requests.exceptions.RequestException("Test connection error")

        test_url = "http://example-connection-error.com"
        results = headers.check_security_headers(test_url)

        self.assertEqual(results["url"], test_url)
        self.assertIn("error", results)
        self.assertTrue("Could not connect" in results["error"])
        self.assertTrue(len(results["recommendations"]) == 1) # Only the error recommendation
        # print("test_request_exception results:", results) # For debugging

    @patch('appsec_toolkit.checks.headers.requests.get')
    def test_header_case_insensitivity(self, mock_get):
        mock_response = MagicMock()
        mock_response.headers = {
            "content-security-policy": "default-src 'self'", # Lowercase
            "STRICT-TRANSPORT-SECURITY": "max-age=31536000", # Uppercase
        }
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        test_url = "http://example-case-insensitive.com"
        results = headers.check_security_headers(test_url)

        self.assertTrue("Content-Security-Policy" in results["found_headers"])
        self.assertTrue("Strict-Transport-Security" in results["found_headers"])
        self.assertNotIn("error", results)
        # print("test_header_case_insensitivity results:", results) # For debugging

if __name__ == '__main__':
    # This allows running the tests directly if needed, e.g. python -m appsec_toolkit.tests.test_headers
    # However, it's more common to use a test runner like `python -m unittest discover`
    
    # To run these tests, you might need to ensure 'appsec_toolkit' is in your PYTHONPATH
    # e.g., export PYTHONPATH=/path/to/your/project:$PYTHONPATH
    # and then run from the project's root directory:
    # python -m unittest appsec_toolkit.tests.test_headers
    
    # For simplicity in this environment, we'll assume the structure allows direct import for now.
    # If running from `appsec-toolkit` directory: `python -m tests.test_headers` (might need __init__.py in tests)
    # Or, more robustly: `python -m unittest discover -s appsec_toolkit/tests` when in the parent of appsec-toolkit dir.
    
    # The import `from appsec_toolkit.checks import headers` assumes that the tests are run
    # in an environment where `appsec_toolkit` (the directory) is recognized as a package or is in sys.path.
    # This typically means running `python -m unittest discover` from the directory *containing* `appsec-toolkit`.
    
    unittest.main()
