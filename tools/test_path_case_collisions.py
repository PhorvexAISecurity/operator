import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('gate', Path(__file__).with_name('check-path-case-collisions.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class PathCaseCollisionTest(unittest.TestCase):
    def test_rejects_files_differing_only_by_case(self):
        paths = ['run/CASE.json', 'run/case.json', 'run/case.md', 'run/RESULT.json', 'run/Result.json']
        self.assertEqual(gate.collisions(paths), [['run/CASE.json', 'run/case.json'],
                                                  ['run/RESULT.json', 'run/Result.json']])

    def test_directory_collision_reported_once_at_shortest_prefix(self):
        paths = ['Evidence/a.json', 'evidence/a.json', 'evidence/b.json', 'evidence/sub/C.json']
        self.assertEqual(gate.collisions(paths), [['Evidence', 'evidence']])

    def test_unicode_normalization_forms_collide(self):
        self.assertEqual(gate.collisions(['café.md', 'café.md']),
                         [['café.md', 'café.md']])

    def test_distinct_names_and_same_case_siblings_pass(self):
        paths = ['v2/CASE.json', 'v2/CASE-draft1.json', 'v2/case-handoff.json', 'v2/case.md',
                 'run/RESULT.json', 'run/v1run-3/result.json', 'other/CASE.json']
        self.assertEqual(gate.collisions(paths), [])

if __name__ == '__main__':
    unittest.main()
