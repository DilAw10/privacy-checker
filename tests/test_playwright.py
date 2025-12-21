import unittest
from unittest.mock import patch
from app import run_full_scan

class PlaywrightMock:
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, url):
        return {"text": "<html><body>Rendered</body></html>", "screenshot": "YmFzZTY0", "error": None}

class PlaywrightTests(unittest.TestCase):
    @patch('app.render_with_playwright')
    def test_run_full_scan_with_playwright_success(self, mock_render):
        mock_render.return_value = {"text": "<html><body>Rendered</body></html>", "screenshot": "YmFzZTY0", "error": None}
        result = run_full_scan('https://example.com', use_js=True)
        self.assertIn('security_score', result)
        self.assertIn('preview', result)
        self.assertIn('screenshot', result)

    @patch('app.render_with_playwright')
    def test_run_full_scan_with_playwright_error(self, mock_render):
        mock_render.return_value = {"text": None, "screenshot": None, "error": 'Playwright error: failed'}
        result = run_full_scan('https://example.com', use_js=True)
        # should still return analysis using requests fallback
        self.assertIn('security_score', result)
        self.assertIsNone(result.get('screenshot'))

if __name__ == '__main__':
    unittest.main()
