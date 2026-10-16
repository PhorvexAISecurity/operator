import subprocess
import unittest
from pathlib import Path

import operator_provenance as prov

ROOT = Path(__file__).resolve().parents[1]


class OperatorProvenanceTest(unittest.TestCase):
    def test_maps_operator_commits_and_passes_through_local_ones(self):
        # The .166 release recorded by the Mongo evidence and its rewritten commit.
        self.assertEqual(prov.local_commit("24c6e0965a6958d5dc353393b3441bbd0c92cdc9"),
                         "cf44997d6f129c823899e622e909dfa7d9ab94e6")
        self.assertEqual(prov.local_commit("f" * 40), "f" * 40)

    def test_pruned_commit_is_an_explicit_error(self):
        pruned = next(old for old, new in prov._commit_map().items() if new == "pruned")
        with self.assertRaisesRegex(ValueError, "pruned"):
            prov.local_commit(pruned)

    def test_mapped_commit_keeps_message_and_tracked_bytes(self):
        local = prov.local_commit("24c6e0965a6958d5dc353393b3441bbd0c92cdc9")
        shown = subprocess.run(["git", "-C", str(ROOT), "show", "-s", "--format=%s", local],
                               capture_output=True, text=True, timeout=15)
        if shown.returncode:
            self.skipTest("history is not available in this checkout")
        self.assertEqual(shown.stdout.strip(), "release: v0.4.166 [skip ci]")


if __name__ == "__main__":
    unittest.main()
