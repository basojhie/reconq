import tempfile
import unittest
from pathlib import Path
from scripts.validate_scope import within

class ScopeTests(unittest.TestCase):
    def test_root_and_subdomain_allowed(self):
        self.assertTrue(within("a.example.com", ["example.com"]))
        self.assertTrue(within("example.com", ["example.com"]))
    def test_suffix_spoof_not_allowed(self):
        self.assertFalse(within("notexample.com", ["example.com"]))
    def test_subdomain_only_excluded(self):
        self.assertFalse(within("a.vendor.example.com", ["vendor.example.com"]))
    def test_unrelated_root_not_allowed(self):
        self.assertFalse(within("example.org", ["example.com"]))

if __name__ == "__main__": unittest.main()
