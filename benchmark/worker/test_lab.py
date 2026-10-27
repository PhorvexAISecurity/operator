"""Runs the self-service lab tests (benchmark/lab/tests) under the existing
benchmark CI step, `python -m unittest discover -s benchmark/worker`, so they
need no workflow change. They are offline: aws and docker are stubs."""
import importlib.util
from pathlib import Path

LAB_TESTS = Path(__file__).resolve().parent.parent / 'lab' / 'tests'


def load_tests(loader, tests, pattern):
    for path in sorted(LAB_TESTS.glob('test_*.py')):
        spec = importlib.util.spec_from_file_location(f'benchmark_lab_{path.stem}', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tests.addTests(loader.loadTestsFromModule(module))
    return tests
