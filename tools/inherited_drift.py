"""Mark tests that already failed at the import point, operator@65af1c99.

Each marked test records drift between the legacy umbrella chart, values-eks.yaml
and the test's expectations. The test still runs: unittest reports an unexpected
success, which fails the suite, once the drift is fixed and the marker must go.
Phase 5 replaces the umbrella chart and retires these tests.
"""
import unittest


def inherited_drift(reason):
    def mark(test):
        test.inherited_drift = reason
        return unittest.expectedFailure(test)
    return mark
