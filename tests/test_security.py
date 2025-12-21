import unittest
from app import check_security_headers, detect_trackers, check_https, compute_security_score
from bs4 import BeautifulSoup

class SecurityTests(unittest.TestCase):
    def test_check_security_headers_missing(self):
        headers = {}
        findings = check_security_headers(headers)
        self.assertIn('Missing security header: Content-Security-Policy', findings)
        self.assertIn('Missing security header: Strict-Transport-Security', findings)
        self.assertIn('Missing security header: X-Frame-Options', findings)

    def test_detect_trackers_src_and_inline(self):
        html = """
        <html>
            <head>
                <script src="https://www.googletagmanager.com/gtag/js?id=UA-XXXX"></script>
                <script>fbq('init', '12345');</script>
            </head>
            <body></body>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")
        trackers = detect_trackers(soup)
        self.assertIn('Google Analytics', trackers)
        self.assertIn('Facebook Pixel', trackers)

    def test_check_https(self):
        findings = check_https('http://example.com')
        self.assertIn('Site is not served over HTTPS', findings)

        findings2 = check_https('https://example.com')
        self.assertEqual(findings2, [])

    def test_compute_security_score(self):
        # No issues
        self.assertEqual(compute_security_score(0, 0, True), 100)
        # Missing headers reduces score
        self.assertEqual(compute_security_score(2, 0, True), 60)
        # Trackers reduce score
        self.assertEqual(compute_security_score(0, 3, True), 70)
        # Not HTTPS significantly reduces score
        self.assertEqual(compute_security_score(0, 0, False), 70)

if __name__ == '__main__':
    unittest.main()
