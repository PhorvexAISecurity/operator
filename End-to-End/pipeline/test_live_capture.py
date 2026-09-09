"""Real subprocess regression: capture is connected before the fast reaction."""
import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

from transport import Console, Transport, TransportError


def command(code):
    return shlex.join([sys.executable, "-u", "-c", code])


class LiveCaptureTests(unittest.TestCase):
    def test_fast_reaction_during_callback_is_retained(self):
        transport = Transport({"kind": "local"})
        fired = []
        with tempfile.TemporaryDirectory() as directory:
            trigger = Path(directory) / "fire"
            code = f"""
import time
from pathlib import Path
print(': connected\\n', flush=True)
while not Path({str(trigger)!r}).exists(): time.sleep(0.005)
print('data: {{"action":"rotate","actuated":true}}\\n', flush=True)
time.sleep(10)
"""
            def fire():
                fired.append(True)
                trigger.touch()

            out = transport.capture_live(command(code), 0.15, 10000, fire)
            self.assertIn('"actuated":true', out)
            self.assertEqual(fired, [True])

    def test_heartbeat_split_across_reads(self):
        fired = []
        code = "import sys,time; sys.stdout.write(': con'); sys.stdout.flush(); time.sleep(.05); print('nected\\n',flush=True); time.sleep(10)"
        Transport({"kind": "local"}).capture_live(command(code), .1, 1000, lambda: fired.append(True))
        self.assertEqual(fired, [True])

    def test_dead_stream_never_fires(self):
        fired = []
        with self.assertRaises(TransportError):
            Transport({"kind": "local"}).capture_live(command("print('not SSE')"), .1, 1000, lambda: fired.append(True))
        self.assertEqual(fired, [])

    def test_byte_cap_fails_instead_of_silently_losing_decisions(self):
        code = "import time; print(': connected\\n',flush=True); time.sleep(.05); print('x'*2000,flush=True); time.sleep(10)"
        with self.assertRaisesRegex(TransportError, "byte cap"):
            Transport({"kind": "local"}).capture_live(command(code), .5, 1000, lambda: None)

    def test_callback_failure_propagates(self):
        def fire():
            raise ValueError("injection failed")
        with self.assertRaisesRegex(ValueError, "injection failed"):
            Transport({"kind": "local"}).capture_live(
                command("import time; print(': connected\\n',flush=True); time.sleep(10)"), .1, 1000, fire)

    def test_console_uses_live_transport_and_parses_records(self):
        class FakeTransport:
            def capture_live(self, cmd, seconds, max_bytes, on_connected):
                self.cmd = cmd
                on_connected()
                return ': connected\n\ndata: {"action":"rotate"}\n\n'
        t = FakeTransport()
        called = []
        records, malformed = Console(t, {"mode": "kubectl-proxy"}).stream_decisions(
            45, 8000000, lambda: called.append(True))
        self.assertEqual(records, [{"action": "rotate"}])
        self.assertEqual(malformed, 0)
        self.assertEqual(called, [True])
        self.assertIn("timeout 135", t.cmd)


if __name__ == "__main__":
    unittest.main()
