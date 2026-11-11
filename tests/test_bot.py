import unittest

from bot import normalize_domain


class NormalizeDomainTests(unittest.TestCase):
    def test_domain_normalization(self):
        self.assertEqual(normalize_domain("EXAMPLE.COM"), "example.com")

    def test_url_normalization(self):
        self.assertEqual(normalize_domain("https://Example.com/path"), "example.com")

    def test_trailing_dot(self):
        self.assertEqual(normalize_domain("example.com."), "example.com")

    def test_reject_ip(self):
        with self.assertRaises(ValueError):
            normalize_domain("https://127.0.0.1")

    def test_reject_private_names(self):
        for value in ("localhost", "router.local", "service.internal", "test.example"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_domain(value)

    def test_reject_credentials(self):
        with self.assertRaises(ValueError):
            normalize_domain("https://u:p@example.com")

    def test_reject_invalid_port(self):
        with self.assertRaises(ValueError):
            normalize_domain("https://example.com:bad")


if __name__ == "__main__":
    unittest.main()
