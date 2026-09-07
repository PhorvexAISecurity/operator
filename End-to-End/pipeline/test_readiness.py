import unittest
from unittest.mock import Mock, patch
from transport import Console, TransportError


class ReadinessTests(unittest.TestCase):
    def run_probe(self, responses, timeout=8):
        clock = [0.0]
        console = Console(None, {})
        console.get_json = Mock(side_effect=responses)
        def sleep(seconds):
            clock[0] += seconds
        with patch('transport.time.monotonic', side_effect=lambda: clock[0]), \
             patch('transport.time.sleep', side_effect=sleep):
            return console.wait_preflight(timeout=timeout), console.get_json, clock[0]

    def test_recovers_from_rollout_endpoint_gap(self):
        result, calls, elapsed = self.run_probe([
            TransportError('no endpoints available'), {'ok': True}, {'operator': 'fixture'}])
        self.assertEqual(result, ({'ok': True}, {'operator': 'fixture'}))
        self.assertEqual(elapsed, 2)
        self.assertEqual([c.args[0] for c in calls.call_args_list],
                         ['/api/health', '/api/health', '/api/version'])

    def test_permanent_unavailability_fails(self):
        with self.assertRaisesRegex(TransportError, 'readiness deadline'):
            self.run_probe([TransportError('no endpoints')] * 10)

    def test_unhealthy_or_missing_version_never_passes(self):
        for responses in [[{'ok': False}] * 10,
                          [{'ok': True}, {}] * 10]:
            with self.subTest(responses=responses), self.assertRaises(TransportError):
                self.run_probe(responses)

    def test_healthy_endpoint_returns_without_sleep(self):
        _, _, elapsed = self.run_probe([{'ok': True}, {'operator': 'fixture'}])
        self.assertEqual(elapsed, 0)
