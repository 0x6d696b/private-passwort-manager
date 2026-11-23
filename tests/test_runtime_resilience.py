"""The load drill must fail if access succeeds or throttling was never exercised."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime_resilience import summarize


class LoadAcceptanceTests(unittest.TestCase):
    def test_only_protected_and_throttled_responses_are_accepted(self):
        report = summarize([(401, 0.1), (429, 0.2), (503, 0.3)], 0.5)
        self.assertEqual(report["status_counts"], {401: 1, 429: 1, 503: 1})
        self.assertEqual(report["p95_seconds"], 0.3)

    def test_success_or_unexpected_failure_is_rejected(self):
        for status in (200, 302, 400, 403, 500):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                summarize([(status, 0.1), (429, 0.2)], 0.5)

    def test_missing_throttling_or_missing_results_cannot_pass(self):
        for results in ([], [(401, 0.1)], [(503, 0.1)]):
            with self.subTest(results=results), self.assertRaises(RuntimeError):
                summarize(results, 0.5)


if __name__ == "__main__":
    unittest.main()
