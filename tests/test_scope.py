import unittest
from scripts.validate_scope import within, in_authorized_scope

class ScopeTests(unittest.TestCase):
    def test_root_and_subdomain_allowed(self):
        self.assertTrue(within("a.example.com", ["example.com"]))
        self.assertTrue(within("example.com", ["example.com"]))

    def test_suffix_spoof_not_allowed(self):
        self.assertFalse(within("notexample.com", ["example.com"]))

    def test_subdomain_exclusion_overrides_root(self):
        self.assertFalse(in_authorized_scope("a.vendor.example.com", ["example.com"], ["vendor.example.com"]))

    def test_unrelated_root_not_allowed(self):
        self.assertFalse(in_authorized_scope("example.org", ["example.com"], []))

    def test_allowed_host_not_excluded(self):
        self.assertTrue(in_authorized_scope("api.example.com", ["example.com"], ["vendor.example.com"]))

if __name__ == "__main__":
    unittest.main()
