"""Real-subprocess regressions for the bounded, incremental audit capture.

Everything here drives `Transport.capture_live` against an actual child process writing
actual SSE bytes: the framing, the scope filter, the caps and the connect-before-fire
ordering are the code under test, not a stand-in for it.
"""
import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

import fixtures as F
from capture import CaptureLimits, CaptureScope, StreamCapture
from transport import Console, Transport, TransportError

LIMITS = CaptureLimits(max_total_bytes=10_000, max_records=1_000)


def command(code):
    return shlex.join([sys.executable, "-u", "-c", code])


def limits(total=10_000, records=1_000, frame=1 << 20):
    return CaptureLimits(max_total_bytes=total, max_records=records, max_frame_bytes=frame)


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
print('data: {{"namespace":"voice","action":"rotate","actuated":true}}\\n', flush=True)
time.sleep(10)
"""
            def fire():
                fired.append(True)
                trigger.touch()

            got = transport.capture_live(command(code), 0.3, limits(), None, fire)
            self.assertEqual(fired, [True])
            self.assertEqual([r["action"] for r in got.records], ["rotate"])
            self.assertTrue(got.complete, got.reason)

    def test_heartbeat_split_across_reads(self):
        fired = []
        code = ("import sys,time; sys.stdout.write(': con'); sys.stdout.flush(); "
                "time.sleep(.05); print('nected\\n',flush=True); time.sleep(10)")
        Transport({"kind": "local"}).capture_live(command(code), .1, limits(), None,
                                                  lambda: fired.append(True))
        self.assertEqual(fired, [True])

    def test_dead_stream_never_fires(self):
        fired = []
        with self.assertRaises(TransportError):
            Transport({"kind": "local"}).capture_live(
                command("print('not SSE')"), .1, limits(), None, lambda: fired.append(True))
        self.assertEqual(fired, [])

    def test_byte_cap_fails_instead_of_silently_losing_decisions(self):
        code = ("import time; print(': connected\\n',flush=True); time.sleep(.05); "
                "print('x'*4000,flush=True); time.sleep(10)")
        with self.assertRaisesRegex(TransportError, "byte cap"):
            Transport({"kind": "local"}).capture_live(
                command(code), .5, limits(total=1000), None, lambda: None)

    def test_record_cap_fails_rather_than_keeping_a_shorter_window(self):
        code = ("import json,time; print(': connected\\n',flush=True)\n"
                "for i in range(50): print('data: '+json.dumps({'namespace':'voice','i':i})+'\\n',flush=True)\n"
                "time.sleep(10)")
        with self.assertRaisesRegex(TransportError, "record cap"):
            Transport({"kind": "local"}).capture_live(
                command(code), .5, limits(records=5), None, lambda: None)

    def test_callback_failure_propagates(self):
        def fire():
            raise ValueError("injection failed")
        with self.assertRaisesRegex(ValueError, "injection failed"):
            Transport({"kind": "local"}).capture_live(
                command("import time; print(': connected\\n',flush=True); time.sleep(10)"),
                .1, limits(), None, fire)

    def test_a_stream_that_ends_early_fails_closed_and_never_reconnects(self):
        # There is no cursor that could prove the resumed stream had no hole in it, so the
        # only honest response to a dropped stream is to fail.
        code = ("import time; print(': connected\\n',flush=True); time.sleep(.05)")
        with self.assertRaisesRegex(TransportError, "closed before observation completed"):
            Transport({"kind": "local"}).capture_live(command(code), 5, limits(), None,
                                                      lambda: None)

    def test_high_volume_unrelated_traffic_does_not_evict_the_target_reaction(self):
        """The CI abort, reproduced: minutes of other-namespace traffic around one reaction.

        Scoped, the reaction survives inside a small record budget. Unscoped, the same
        stream exhausts that budget — which is the failure the scope declaration exists to
        make visible rather than silent.
        """
        payload = "x" * 200
        code = f"""
import json, time
print(': connected\\n', flush=True)
for i in range(3000):
    print('data: ' + json.dumps({{'namespace': 'other-' + str(i % 7), 'pod': 'p', 'pad': {payload!r}}}) + '\\n', flush=True)
print('data: ' + json.dumps({{'namespace': 'voice', 'pod': 'voice-a', 'action': 'rotate', 'actuated': True}}) + '\\n', flush=True)
time.sleep(10)
"""
        scoped = Transport({"kind": "local"}).capture_live(
            command(code), 2.0, limits(total=4_000_000, records=50), CaptureScope(["voice"]),
            lambda: None)
        self.assertTrue(scoped.complete, scoped.reason)
        self.assertEqual([r["action"] for r in scoped.records], ["rotate"])
        self.assertGreater(scoped.counters["filtered"], 2000)
        self.assertEqual(scoped.counters["accepted"], 1)
        self.assertFalse(scoped.scope.is_global)

        with self.assertRaisesRegex(TransportError, "record cap"):
            Transport({"kind": "local"}).capture_live(
                command(code), 2.0, limits(total=4_000_000, records=50), None, lambda: None)

    def test_observe_mode_has_the_same_completeness_semantics(self):
        code = ("import json,time; "
                "print('data: '+json.dumps({'namespace':'voice','pod':'a'})+'\\n',flush=True); "
                "time.sleep(10)")
        got = Transport({"kind": "local"}).capture_live(command(code), .3, limits())
        self.assertEqual(len(got.records), 1)
        self.assertTrue(got.complete, got.reason)
        self.assertEqual(got.counters["accepted"], 1)

    def test_observe_mode_treats_its_own_bounded_window_ending_as_normal(self):
        # Without a callback the remote `timeout`/`curl -m` bounds the window and exits on
        # its own. That is the ordinary path, not a dropped stream.
        code = ("import json; "
                "print('data: '+json.dumps({'namespace':'voice','pod':'a'})+'\\n',flush=True)")
        got = Transport({"kind": "local"}).capture_live(command(code), 5, limits())
        self.assertTrue(got.complete, got.reason)
        self.assertEqual(got.counters["accepted"], 1)

    def test_observe_mode_reports_an_unexpected_command_failure(self):
        # A non-zero exit that does not mean "the window elapsed" is a failed read; the
        # records collected before it cannot stand as a complete observation.
        code = ("import json,sys; "
                "print('data: '+json.dumps({'namespace':'voice','pod':'a'})+'\\n',flush=True); "
                "sys.stderr.write('error from server (InternalError)'); sys.exit(7)")
        got = Transport({"kind": "local"}).capture_live(command(code), 5, limits())
        self.assertFalse(got.complete)
        self.assertIn("exited 7", got.reason)
        self.assertIn("InternalError", got.reason)

    def test_observe_mode_accepts_the_timeout_exit_code(self):
        code = ("import json,sys; "
                "print('data: '+json.dumps({'namespace':'voice','pod':'a'})+'\\n',flush=True); "
                "sys.exit(124)")
        got = Transport({"kind": "local"}).capture_live(command(code), 5, limits())
        self.assertTrue(got.complete, got.reason)

    def test_console_uses_live_transport_and_parses_records(self):
        class FakeTransport:
            def capture_live(self, cmd, seconds, limits_, scope, on_connected):
                self.cmd = cmd
                on_connected()
                stream = StreamCapture(limits_, scope)
                stream.feed(F.sse([F.record(action="rotate")]))
                return stream.finish()
        t = FakeTransport()
        called = []
        got = Console(t, {"mode": "kubectl-proxy"}).stream_decisions(
            45, limits(), CaptureScope(["voice"]), lambda: called.append(True))
        self.assertEqual([r["action"] for r in got.records], ["rotate"])
        self.assertEqual(called, [True])
        self.assertIn("timeout 135", t.cmd)
        # The remote side no longer truncates: a `head -c` cut is indistinguishable from a
        # decision we failed to read, so the budget is enforced where it can be reported.
        self.assertNotIn("head -c", t.cmd)


class FramingTests(unittest.TestCase):
    """Accounting, in isolation: every byte lands in exactly one counter."""

    def feed(self, chunks, scope=None, limit=None):
        stream = StreamCapture(limit or limits(), scope)
        for chunk in chunks:
            stream.feed(chunk)
        return stream

    def test_full_window_is_complete_and_counted(self):
        got = self.feed([F.sse([F.record(), F.record(pod="voice-b")])]).finish()
        self.assertTrue(got.complete)
        self.assertEqual(got.counters["accepted"], 2)
        self.assertEqual(got.counters["malformed"], 0)
        self.assertEqual(got.counters["incompleteFrames"], 0)
        self.assertEqual(got.counters["heartbeats"], 1)

    def test_a_truncated_final_frame_is_incomplete_not_harmless(self):
        got = self.feed([F.sse([F.record()], trailing_partial=True)]).finish()
        self.assertFalse(got.complete)
        self.assertEqual(got.counters["accepted"], 1)
        self.assertEqual(got.counters["incompleteFrames"], 1)
        self.assertIn("middle of a frame", got.reason)

    def test_a_whole_frame_that_does_not_parse_is_malformed_and_incomplete(self):
        got = self.feed([b'data: {"namespace": "voice"\n\n']).finish()
        self.assertFalse(got.complete)
        self.assertEqual(got.counters["malformed"], 1)
        self.assertEqual(got.counters["accepted"], 0)
        self.assertTrue(got.counters["malformedSamples"])

    def test_frames_split_across_arbitrary_chunk_boundaries(self):
        body = F.sse([F.record(pod=f"voice-{i}") for i in range(5)])
        got = self.feed([body[i:i + 7] for i in range(0, len(body), 7)]).finish()
        self.assertTrue(got.complete)
        self.assertEqual(got.counters["accepted"], 5)

    def test_scope_filters_without_dropping_the_accounting(self):
        body = F.sse([F.record(namespace="voice"), F.record(namespace="nats")])
        got = self.feed([body], CaptureScope(["voice"])).finish()
        self.assertEqual(got.counters["accepted"], 1)
        self.assertEqual(got.counters["filtered"], 1)
        self.assertEqual(got.scope.to_json()["namespaces"], ["voice"])

    def test_a_single_unterminated_frame_cannot_exhaust_memory(self):
        from capture import CaptureOverflow
        with self.assertRaises(CaptureOverflow):
            self.feed([b"data: " + b"x" * 5000], limit=limits(total=1 << 20, frame=1000))

    def test_a_non_object_frame_is_malformed_rather_than_a_record(self):
        got = self.feed([b'data: [1,2,3]\n\n']).finish()
        self.assertEqual(got.counters["malformed"], 1)
        self.assertEqual(got.records, [])


if __name__ == "__main__":
    unittest.main()
