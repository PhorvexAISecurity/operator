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


class SourceContinuityTests(unittest.TestCase):
    """The console's own `event: notice` frames say the window has a hole in it.

    Reading only `data:` lines turned each of these into a decision that failed to parse
    or, under a namespace scope, into somebody else's traffic that was quietly filtered —
    and the capture then reported itself complete.
    """

    def feed(self, wire, scope=None):
        stream = StreamCapture(limits(), scope)
        stream.feed(wire)
        return stream.finish()

    def test_the_rotation_notice_makes_the_window_incomplete(self):
        got = self.feed(F.sse([F.record()], notices=[F.ROTATION_NOTICE]),
                        CaptureScope(["voice"]))
        self.assertFalse(got.complete)
        self.assertIn("source-rotated", got.reason)
        self.assertEqual(got.counters["notices"], 1)
        self.assertEqual(got.counters["filtered"], 0)   # never mistaken for other traffic
        self.assertEqual(got.counters["malformed"], 0)  # nor for a broken decision frame
        self.assertEqual(got.counters["accepted"], 1)   # the real decision still arrives
        self.assertEqual(got.counters["sourceNotices"][0]["reason"], "source-rotated")

    def test_a_clean_window_with_no_notice_is_complete(self):
        got = self.feed(F.sse([F.record()]), CaptureScope(["voice"]))
        self.assertTrue(got.complete, got.reason)
        self.assertEqual(got.counters["notices"], 0)

    def test_every_notice_the_console_emits_is_treated_as_lost_continuity(self):
        for message, reason in ((F.ROTATION_NOTICE, "source-rotated"),
                                (F.READ_FAILED_NOTICE, "source-read-failed"),
                                (F.OMITTED_NOTICE, "record-omitted"),
                                (F.REPLAY_LIMIT_NOTICE, "replay-truncated"),
                                ("Audit replay changed while reading.", "source-changed"),
                                ("Replay scan budget reached; use /api/live/history.",
                                 "scan-budget-reached")):
            with self.subTest(message=message):
                got = self.feed(F.sse([F.record()], notices=[message]))
                self.assertFalse(got.complete)
                self.assertIn(reason, got.reason)

    def test_an_unrecognised_notice_still_fails_closed(self):
        got = self.feed(F.sse([F.record()], notices=["Something new the reader has not seen"]))
        self.assertFalse(got.complete)
        self.assertIn("source-notice-unrecognised", got.reason)

    def test_a_notice_split_across_chunk_boundaries_is_still_a_notice(self):
        wire = F.sse([F.record()], notices=[F.ROTATION_NOTICE])
        stream = StreamCapture(limits())
        for i in range(0, len(wire), 5):
            stream.feed(wire[i:i + 5])
        got = stream.finish()
        self.assertFalse(got.complete)
        self.assertEqual(got.counters["notices"], 1)

    def test_a_multi_line_data_frame_is_joined_rather_than_split(self):
        # SSE allows a payload to span several data: lines; they concatenate with \n.
        got = self.feed(b'data: {"namespace":"voice",\ndata: "pod":"voice-a"}\n\n')
        self.assertEqual(got.counters["accepted"], 1)
        self.assertEqual(got.records[0]["pod"], "voice-a")

    def test_frame_fields_without_their_terminating_blank_line_are_incomplete(self):
        got = self.feed(b'data: {"namespace":"voice","pod":"voice-a"}\n')
        self.assertFalse(got.complete)
        self.assertEqual(got.counters["incompleteFrames"], 1)


class FrameCapTests(unittest.TestCase):
    """The per-frame bound has to hold wherever the newline happens to land."""

    def oversized(self, terminated):
        payload = json.dumps({"namespace": "voice", "pad": "x" * 150}).encode()
        return b"data: " + payload + (b"\n\n" if terminated else b"")

    def feed(self, wire):
        from capture import CaptureOverflow
        stream = StreamCapture(limits(total=100000, records=10, frame=64),
                               CaptureScope(["voice"]))
        try:
            stream.feed(wire)
            return None, stream
        except CaptureOverflow as overflow:
            return overflow, stream

    def test_a_complete_oversized_line_overflows_like_an_unterminated_one(self):
        for terminated in (True, False):
            with self.subTest(terminated=terminated):
                overflow, _ = self.feed(self.oversized(terminated))
                self.assertIsNotNone(overflow)
                self.assertEqual(overflow.limit, "frame")

    def test_the_overflow_carries_the_evidence_collected_before_it(self):
        stream = StreamCapture(limits(total=100000, records=10, frame=64),
                               CaptureScope(["voice"]))
        stream.feed(b'data: {"namespace":"voice","pod":"a"}\n\n')
        from capture import CaptureOverflow
        with self.assertRaises(CaptureOverflow) as caught:
            stream.feed(self.oversized(True))
        self.assertEqual(caught.exception.counters["accepted"], 1)
        self.assertEqual(len(caught.exception.records), 1)

    def test_a_frame_within_the_bound_is_accepted(self):
        overflow, stream = self.feed(b'data: {"namespace":"voice","pod":"a"}\n\n')
        self.assertIsNone(overflow)
        self.assertEqual(stream.finish().counters["accepted"], 1)

    def test_the_bound_is_on_the_whole_frame_not_on_each_line(self):
        """SSE lets one payload span any number of data: lines.

        Three 30-byte lines hold 90 bytes, so a per-line bound is not a bound. The frame
        below is valid JSON and every line of it is under the cap.
        """
        wire = (b'data: {"namespace":"voice",\n'
                b'data: "one":"' + b"x" * 30 + b'",\n'
                b'data: "two":"' + b"y" * 30 + b'"}\n\n')
        overflow, stream = self.feed(wire)
        self.assertIsNotNone(overflow)
        self.assertEqual(overflow.limit, "frame")
        self.assertIn("data line(s) accumulated", str(overflow))
        self.assertEqual(stream.records, [])

    def test_a_multi_line_frame_inside_the_bound_is_still_accepted(self):
        # The control for the case above: same shape, under the cap, still parsed.
        overflow, stream = self.feed(b'data: {"namespace":\ndata: "voice"}\n\n')
        self.assertIsNone(overflow)
        self.assertEqual(stream.finish().counters["accepted"], 1)

    def test_an_event_line_is_charged_to_its_frame(self):
        wire = b'event: notice\ndata: {"message":"' + b"z" * 60 + b'"}\n\n'
        overflow, _ = self.feed(wire)
        self.assertIsNotNone(overflow)

    def test_the_bound_holds_across_arbitrary_chunk_boundaries(self):
        from capture import CaptureOverflow
        wire = (b'data: {"namespace":"voice",\n'
                b'data: "one":"' + b"x" * 30 + b'",\n'
                b'data: "two":"' + b"y" * 30 + b'"}\n\n')
        stream = StreamCapture(limits(total=100000, records=10, frame=64),
                               CaptureScope(["voice"]))
        with self.assertRaises(CaptureOverflow):
            for i in range(0, len(wire), 3):
                stream.feed(wire[i:i + 3])

    def test_the_frame_budget_resets_between_frames(self):
        # Many small frames in a row must not accumulate against one another's bound.
        overflow, stream = self.feed(b''.join(
            b'data: {"namespace":"voice","n":%d}\n\n' % i for i in range(8)))
        self.assertIsNone(overflow)
        self.assertEqual(stream.finish().counters["accepted"], 8)


class NoticeRetentionTests(unittest.TestCase):
    """Retained notice text is bounded; the count and the verdict are not."""

    def flood(self, count, retained=5, notice_bytes=40):
        stream = StreamCapture(
            CaptureLimits(max_total_bytes=10_000_000, max_records=100,
                          max_frame_bytes=1 << 20, max_retained_notices=retained,
                          max_notice_bytes=notice_bytes))
        stream.feed(F.sse([F.record()], notices=[F.ROTATION_NOTICE] * count))
        return stream.finish()

    def test_the_count_survives_even_when_the_text_is_dropped(self):
        got = self.flood(40, retained=5)
        self.assertEqual(got.counters["notices"], 40)
        self.assertEqual(got.counters["noticesRetained"], 5)
        self.assertEqual(got.counters["noticesDropped"], 35)
        self.assertEqual(len(got.counters["sourceNotices"]), 5)

    def test_a_dropped_notice_still_makes_the_window_incomplete(self):
        got = self.flood(40, retained=1)
        self.assertFalse(got.complete)
        self.assertIn("source-rotated", got.reason)

    def test_a_long_notice_message_is_truncated_to_its_declared_bound(self):
        got = self.flood(1, notice_bytes=20)
        self.assertLessEqual(len(got.counters["sourceNotices"][0]["message"]), 20)
        self.assertEqual(got.limits.to_json()["maxNoticeBytes"], 20)

    def test_the_bounds_are_recorded_beside_the_counters(self):
        got = self.flood(3)
        self.assertEqual(got.to_json()["limits"]["maxRetainedNotices"], 5)
        self.assertEqual(got.to_json()["counters"]["notices"], 3)


if __name__ == "__main__":
    unittest.main()
