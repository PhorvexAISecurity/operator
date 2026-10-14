"""Checks portability, accidental source changes, and the bundled schema subset."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('check_package',ROOT/'tools/check_package.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PackageTests(unittest.TestCase):
    def test_package_checks_and_portable_copy(self):
        report = checker.check(ROOT)
        self.assertEqual(report['source_files_verified'],15)
        self.assertEqual(report['synthetic_cases_checked'],5)
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp)/'portable-package'
            shutil.copytree(ROOT,copied,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            self.assertEqual(checker.check(copied)['source_files_verified'],15)

    def test_required_handoff_documents_cannot_be_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp)/'portable-package'
            shutil.copytree(ROOT,copied,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            for name in ('CODEX-ADAPTER.md','HANDOFF-CONTRACTS.md'):
                path = copied/name
                original = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(ValueError,'Missing/empty required package file: '+name):
                    checker.check(copied)
                path.write_bytes(original)

    def test_source_hash_and_manifest_coverage_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp)/'package'
            shutil.copytree(ROOT/'source',copied/'source')
            checker.check_source(copied)
            path = copied/'source/rev5/HANDOFF-README.md'
            original = path.read_bytes()
            path.write_bytes(original+b'\nUnapproved modification\n')
            with self.assertRaisesRegex(ValueError,'checksum mismatch'):
                checker.check_source(copied)
            path.write_bytes(original)
            extra = copied/'source/rev5/unlisted.txt'
            extra.write_text('extra source without digest')
            with self.assertRaisesRegex(ValueError,'coverage mismatch'):
                checker.check_source(copied)

    def test_case_schema_rejects_missing_metrics_and_invalid_structure(self):
        schema = checker.load(ROOT/'schemas/case.schema.json')
        case = checker.load(ROOT/'templates/case.json')
        checker.validate_schema(case,schema)
        del case['metrics']['S4']
        with self.assertRaisesRegex(ValueError,'missing S4'):
            checker.validate_schema(case,schema)
        case = checker.load(ROOT/'templates/case.json')
        case['synthetic'] = 'true'
        with self.assertRaisesRegex(ValueError,'wrong type'):
            checker.validate_schema(case,schema)
        case = checker.load(ROOT/'templates/case.json')
        case['stage'] = 'S12_FINAL_REVIEW'
        with self.assertRaisesRegex(ValueError,'outside enum'):
            checker.validate_schema(case,schema)

    def test_task_and_return_conditionals(self):
        task_schema = checker.load(ROOT/'schemas/task.schema.json')
        task = checker.load(ROOT/'templates/task.json')
        checker.validate_schema(task,task_schema)
        task['role'] = 'CRITIC'
        task['payload_contract'] = 'WorkloadProfile'
        with self.assertRaisesRegex(ValueError,'constant mismatch'):
            checker.validate_schema(task,task_schema)
        result_schema = checker.load(ROOT/'schemas/return.schema.json')
        result = checker.load(ROOT/'templates/return.json')
        checker.validate_schema(result,result_schema)
        result['status'] = 'BLOCKED'
        result['blockers'] = []
        with self.assertRaisesRegex(ValueError,'array length'):
            checker.validate_schema(result,result_schema)

    def test_schema_subset_does_not_silently_ignore_unknown_keywords(self):
        with self.assertRaisesRegex(ValueError,'Unsupported schema keywords'):
            checker.schema_keywords({'type':'object','dependentRequired':{'x':['y']}})
        checker.validate_schema(True,{'const':True})
        with self.assertRaisesRegex(ValueError,'constant mismatch'):
            checker.validate_schema(1,{'const':True})
        with self.assertRaisesRegex(ValueError,'wrong type'):
            checker.validate_schema(True,{'type':'integer'})

    def test_relative_link_checker_rejects_broken_local_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'readme.md').write_text('[missing](missing.md)')
            with self.assertRaisesRegex(ValueError,'Broken/escaping'):
                checker.check_links(root)
            (root/'missing.md').write_text('exists')
            self.assertEqual(checker.check_links(root),1)


if __name__ == '__main__':
    unittest.main()
