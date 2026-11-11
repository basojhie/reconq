import unittest

from bot import normalize_domain


class NormalizeDomainTests(unittest.TestCase):
    def test_lowercases_domain(self):
        self.assertEqual(normalize_domain("EXAMPLE.COM"), "example.com")

    def test_accepts_http_url_and_extracts_host(self):
        self.assertEqual(
            normalize_domain("https://Example.com/path?q=1"),
            "example.com",
        )

    def test_accepts_trailing_dot(self):
        self.assertEqual(normalize_domain("example.com."), "example.com")

    def test_rejects_ip_address(self):
        with self.assertRaises(ValueError):
            normalize_domain("https://127.0.0.1")

    def test_rejects_local_names(self):
        for target in ("localhost", "router.local", "service.internal", "host.test"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    normalize_domain(target)

    def test_rejects_credentials(self):
        with self.assertRaises(ValueError):
            normalize_domain("https://user:pass@example.com")

    def test_rejects_bad_port(self):
        with self.assertRaises(ValueError):
            normalize_domain("https://example.com:bad")

    def test_rejects_invalid_domain(self):
        for target in ("", "example", "-bad.example.com", "bad..example.com"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    normalize_domain(target)


if __name__ == "__main__":
    unittest.main()
