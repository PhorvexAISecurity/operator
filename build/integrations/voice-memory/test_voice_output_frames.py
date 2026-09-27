"""Exercise the actual bot output processor methods without service imports."""

import ast
import asyncio
import hashlib
import pathlib
import tempfile
import unittest

from voice_output_policy import (VoiceOutputPolicy, UtteranceGate, UNAVAILABLE_ANSWER,
                                 canonical_bytes, marker_for_run)


class Frame:
    pass


class TextFrame(Frame):
    def __init__(self, text):
        self.text = text


class LLMTextFrame(TextFrame):
    pass


class LLMFullResponseStartFrame(Frame):
    pass


class LLMFullResponseEndFrame(Frame):
    pass


class InterruptionFrame(Frame):
    pass


class CancelFrame(Frame):
    pass


class EndFrame(Frame):
    pass


class TTSAudioRawFrame(Frame):
    def __init__(self, audio):
        self.audio = audio


class FrameDirection:
    DOWNSTREAM = 1
    UPSTREAM = 2


class FrameProcessor:
    def __init__(self):
        self.pushed = []

    async def process_frame(self, frame, direction):
        pass

    async def push_frame(self, frame, direction):
        self.pushed.append((frame, direction))


def load_actual_processors(policy):
    source = pathlib.Path(__file__).with_name("bot.py").read_text()
    parsed = ast.parse(source)
    classes = [node for node in parsed.body if isinstance(node, ast.ClassDef) and
               node.name in ("VoiceOutputGuard", "VoiceOutputAudioTap")]
    if len(classes) != 2:
        raise AssertionError("actual bot output processors missing")
    namespace = {"FrameProcessor": FrameProcessor, "Frame": Frame, "FrameDirection": FrameDirection,
                 "TextFrame": TextFrame, "LLMTextFrame": LLMTextFrame,
                 "LLMFullResponseStartFrame": LLMFullResponseStartFrame,
                 "LLMFullResponseEndFrame": LLMFullResponseEndFrame, "InterruptionFrame": InterruptionFrame,
                 "CancelFrame": CancelFrame, "EndFrame": EndFrame, "TTSAudioRawFrame": TTSAudioRawFrame,
                 "UtteranceGate": UtteranceGate, "UNAVAILABLE_ANSWER": UNAVAILABLE_ANSWER,
                 "hashlib": hashlib, "_output_policy": policy, "_output_source": "a" * 64,
                 "write_private_receipt": lambda *args: True}
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(pathlib.Path(__file__).with_name("bot.py")), "exec"), namespace)
    return namespace["VoiceOutputGuard"], namespace["VoiceOutputAudioTap"], namespace


class ActualFrameGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = pathlib.Path(self.temp.name)
        policy_dir, state_dir = root / "policy", root / "state"
        policy_dir.mkdir()
        state_dir.mkdir(mode=0o700)
        self.policy = VoiceOutputPolicy(policy_dir, state_dir, "a" * 64, "p" * 36, required=True)
        self.rule = {"version": 1, "configMapUID": "a" * 8 + "-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
                     "deploymentUID": "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
                     "policyUID": "cccccccc-cccc-4ccc-cccc-cccccccccccc", "sourceSHA256": "a" * 64,
                     "revision": 0, "operationId": "", "entries": []}
        self.rule_path = policy_dir / "rule.json"
        self.rule_path.write_bytes(canonical_bytes(self.rule))
        self.Guard, self.AudioTap, self.ns = load_actual_processors(self.policy)

    def step(self, guard, frame):
        asyncio.run(guard.process_frame(frame, FrameDirection.DOWNSTREAM))

    def test_split_marker_is_never_forwarded_to_tts_when_active(self):
        run = "a1b2c3d4e5f60708"
        marker = marker_for_run(run)
        marker_sha = hashlib.sha256(marker.encode()).hexdigest()
        self.rule["entries"] = [{"markerSHA256": marker_sha, "operationId": "d" * 64}]
        self.rule["revision"], self.rule["operationId"] = 1, "d" * 64
        self.rule_path.write_bytes(canonical_bytes(self.rule))
        guard = self.Guard("CA" + "1" * 32, False)
        self.step(guard, LLMFullResponseStartFrame())
        self.step(guard, LLMTextFrame("Here is PHORVEX_INTER"))
        self.step(guard, LLMTextFrame("NAL_" + marker.split("_")[-1]))
        self.assertFalse(any(isinstance(frame, TextFrame) for frame, _ in guard.pushed))
        self.step(guard, LLMFullResponseEndFrame())
        released = [frame.text for frame, _ in guard.pushed if isinstance(frame, TextFrame)]
        self.assertEqual(len(released), 1)
        self.assertNotIn(marker, released[0])

    def test_unterminated_and_unframed_text_never_escape(self):
        guard = self.Guard("CA" + "1" * 32, False)
        self.step(guard, LLMTextFrame("secret prefix"))
        self.assertEqual(guard.pushed, [])
        self.step(guard, LLMFullResponseStartFrame())
        self.step(guard, LLMTextFrame("private"))
        self.step(guard, InterruptionFrame())
        self.assertFalse(any(isinstance(frame, TextFrame) for frame, _ in guard.pushed))
        self.step(guard, LLMFullResponseStartFrame())
        self.step(guard, LLMTextFrame("public reply"))
        self.step(guard, LLMFullResponseEndFrame())
        self.assertEqual([frame.text for frame, _ in guard.pushed if isinstance(frame, TextFrame)],
                         ["public reply"])


if __name__ == "__main__":
    unittest.main()
