import unittest
from unittest.mock import patch
from app import get_preview, preview_cache

class CacheTest(unittest.TestCase):
    def setUp(self):
        # Clear cache before each test
        preview_cache.clear()

    @patch('app.requests.get')
    def test_preview_cache_saves_and_reuses(self, mock_get):
        # Arrange: mock requests.get to return a sample HTML
        class Resp:
            text = '<html><body>First</body></html>'
        mock_get.return_value = Resp()

        # Act: First call should populate cache and call requests.get
        res1 = get_preview('https://example.com', use_js=False, max_chars=50)
        self.assertIn('First', res1)
        self.assertEqual(mock_get.call_count, 1)

        # Change the mock response to ensure cached value is used
        class Resp2:
            text = '<html><body>Second</body></html>'
        mock_get.return_value = Resp2()

        # Second call should return cached result and NOT call requests.get again
        res2 = get_preview('https://example.com', use_js=False, max_chars=50)
        self.assertIn('First', res2)
        self.assertEqual(mock_get.call_count, 1)

if __name__ == '__main__':
    unittest.main()