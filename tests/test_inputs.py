import unittest
from website_scanner import normalize_url, extract_hostname


class WebsiteScannerInputTests(unittest.TestCase):
    def test_adds_default_https_scheme(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")

    def test_preserves_http_scheme_and_path(self):
        self.assertEqual(normalize_url("http://example.com/path/"), "http://example.com/path")

    def test_rejects_invalid_schemes_and_credentials(self):
        for value in ("", "ftp://example.com", "https://user:pass@example.com", "https:///missing-host"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_url(value)

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            normalize_url("https://example.com:bad")

    def test_extracts_hostname(self):
        self.assertEqual(extract_hostname("https://example.com/path"), "example.com")


if __name__ == "__main__":
    unittest.main()
