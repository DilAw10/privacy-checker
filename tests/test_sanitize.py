import unittest
from app import sanitize_html

class SanitizeTests(unittest.TestCase):
    def test_script_removed_and_on_attr(self):
        html = '<div onclick="alert(1)">Hello<script>evil()</script><a href="javascript:alert(2)">link</a></div>'
        cleaned = sanitize_html(html)
        self.assertNotIn('<script', cleaned)
        self.assertNotIn('onclick', cleaned)
        self.assertNotIn('javascript:alert(2)', cleaned)
        self.assertIn('Hello', cleaned)

if __name__ == '__main__':
    unittest.main()
