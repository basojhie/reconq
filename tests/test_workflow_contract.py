import unittest
from pathlib import Path


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = Path(".github/workflows/recon.yml").read_text(encoding="utf-8")

    def test_dnsx_json_resolves_hostnames_not_ip_literals(self):
        self.assertIn("dnsx -l artifacts/subs.txt", self.workflow)
        self.assertIn(".host // .input // empty", self.workflow)
        self.assertNotIn("-resp-only", self.workflow)

    def test_subfinder_iterates_validated_scope_file(self):
        self.assertIn("done < artifacts/scan-roots.txt", self.workflow)

    def test_first_run_is_quiet_baseline(self):
        self.assertIn("steps.state_restore.outputs.first_run", self.workflow)
        self.assertIn("id: state_restore", self.workflow)
        self.assertIn("echo 'baseline=true'", self.workflow)

    def test_anew_and_separate_state_branch_are_used(self):
        self.assertIn("anew state/subs_known.txt", self.workflow)
        self.assertIn("HEAD:refs/heads/state", self.workflow)

    def test_rate_limit_is_configured_for_httpx(self):
        self.assertIn("-rl 2 -threads 5 -timeout 5 -retries 1", self.workflow)


if __name__ == "__main__":
    unittest.main()
