import hashlib
import json
import pathlib
import tempfile
import unittest

from voice_output_policy import (BLOCKED_ANSWER, UNAVAILABLE_ANSWER, UtteranceGate, VoiceOutputPolicy,
                                 admit_output_session, canonical_bytes, marker_for_run, output_call_sid, output_source_sha256,
                                 output_test_signature,
                                 output_session_kind, parse_rule, write_private_receipt)


SOURCE = "a" * 64
CM_UID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
DEP_UID = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
POLICY_UID = "cccccccc-cccc-4ccc-cccc-cccccccccccc"


def rule(entries=()):
    entries = sorted(entries, key=lambda entry: entry["markerSHA256"])
    return {"version": 1, "configMapUID": CM_UID, "deploymentUID": DEP_UID,
            "policyUID": POLICY_UID, "sourceSHA256": SOURCE, "revision": len(entries),
            "operationId": entries[-1]["operationId"] if entries else "", "entries": entries}


class VoiceOutputPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.policy_dir = self.root / "policy"
        self.policy_dir.mkdir()
        self.state_dir = self.root / "state"
        self.state_dir.mkdir(mode=0o700)
        self.reader = VoiceOutputPolicy(self.policy_dir, self.state_dir, SOURCE, CM_UID, required=True)
        (self.policy_dir / "rule.json").write_bytes(canonical_bytes(rule()))

    def test_exact_marker_across_chunks_is_stopped_only_after_append(self):
        marker = marker_for_run("a1b2c3d4e5f60708")
        text = "The internal identifier is " + marker + "."
        marker_sha = hashlib.sha256(marker.encode()).hexdigest()
        before = self.reader.evaluate(text)
        self.assertEqual(before["text"], text)
        self.assertTrue(before["markerObserved"])
        self.assertFalse(before["blocked"])
        self.assertEqual(self.reader.state(marker_sha)[1]["active"], False)
        operation = "d" * 64
        (self.policy_dir / "rule.json").write_bytes(canonical_bytes(rule(
            [{"markerSHA256": marker_sha, "operationId": operation}])))
        after = self.reader.evaluate(text)
        self.assertEqual(after["text"], BLOCKED_ANSWER)
        self.assertTrue(after["blocked"])
        state = self.reader.state(marker_sha)
        self.assertEqual(state[0], 200)
        self.assertEqual(state[1]["matchedOperationId"], operation)
        self.assertTrue(state[1]["active"])
        self.assertEqual(self.reader.evaluate("The public status is available.")["text"],
                         "The public status is available.")

    def test_source_drift_replay_and_removed_entry_fail_closed(self):
        marker = marker_for_run("a1b2c3d4e5f60708")
        marker_sha = hashlib.sha256(marker.encode()).hexdigest()
        active = rule([{"markerSHA256": marker_sha, "operationId": "d" * 64}])
        (self.policy_dir / "rule.json").write_bytes(canonical_bytes(active))
        self.assertEqual(self.reader.state(marker_sha)[0], 200)
        (self.policy_dir / "rule.json").write_bytes(canonical_bytes(rule()))
        self.assertEqual(self.reader.evaluate("ordinary answer")["text"], UNAVAILABLE_ANSWER)
        self.assertEqual(self.reader.state(marker_sha)[0], 503)
        active["sourceSHA256"] = "e" * 64
        (self.policy_dir / "rule.json").write_bytes(canonical_bytes(active))
        self.assertEqual(self.reader.state(marker_sha)[0], 503)

    def test_strict_canonical_rule_and_readback(self):
        good = canonical_bytes(rule())
        self.assertEqual(parse_rule(good, SOURCE)["revision"], 0)
        for bad in (good + b"\n", good.replace(b'"version":1', b'"version":true'),
                    good.replace(b'"version":1', b'"version":1,"Version":1'),
                    json.dumps(rule()).encode(), canonical_bytes({**rule(), "revision": 1})):
            with self.assertRaises(ValueError):
                parse_rule(bad, SOURCE)
        self.assertEqual(self.reader.state("not-a-sha")[0], 400)

    def test_composite_hash_includes_output_module(self):
        paths = [self.root / name for name in ("bot.py", "voice_memory_policy.py", "voice_output_policy.py")]
        for path, data in zip(paths, (b"bot", b"memory", b"output")):
            path.write_bytes(data)
        expected = hashlib.sha256(b"bot\x00memory\x00output").hexdigest()
        self.assertEqual(output_source_sha256(*paths), expected)

    def test_split_frame_marker_and_interruption_never_release_prefix(self):
        marker = marker_for_run("a1b2c3d4e5f60708")
        marker_sha = hashlib.sha256(marker.encode()).hexdigest()
        (self.policy_dir / "rule.json").write_bytes(canonical_bytes(rule(
            [{"markerSHA256": marker_sha, "operationId": "d" * 64}])))
        gate = UtteranceGate(self.reader)
        gate.start()
        gate.add("The internal identifier is PHORVEX_INTER")
        gate.add("NAL_" + marker.split("_")[-1] + ".")
        result = gate.finish()
        self.assertEqual(result["text"], BLOCKED_ANSWER)
        self.assertTrue(result["markerObserved"])
        gate.start()
        gate.add("PHORVEX_INTER")
        gate.cancel()
        self.assertEqual(gate.finish()["text"], UNAVAILABLE_ANSWER)

    def test_private_receipt_is_digest_only_and_link_once(self):
        sid = output_call_sid("a1b2c3d4e5f60708", "attack")
        fields = {"markerSHA256": hashlib.sha256(marker_for_run("a1b2c3d4e5f60708").encode()).hexdigest(),
                  "blocked": False}
        self.assertTrue(write_private_receipt(self.state_dir, sid, "guard", 0, fields))
        self.assertFalse(write_private_receipt(self.state_dir, sid, "guard", 0, fields))
        paths = list(self.state_dir.glob("output-*.json"))
        self.assertEqual(len(paths), 1)
        self.assertNotIn(marker_for_run("a1b2c3d4e5f60708"), paths[0].read_text())

    def test_synthetic_output_session_requires_exact_run_call_and_caller(self):
        run = "a1b2c3d4e5f60708"
        number = int.from_bytes(hashlib.sha256((run + ":A").encode()).digest()[:8], "big") % 10000000
        caller = "+1555%07d" % number
        self.assertEqual(output_session_kind(run, output_call_sid(run, "attack"), caller), "attack")
        self.assertEqual(output_session_kind(run, output_call_sid(run, "replay"), caller), "replay")
        self.assertEqual(output_session_kind(run, output_call_sid(run, "benign"), caller), "benign")
        with self.assertRaises(ValueError):
            output_session_kind(run, output_call_sid(run, "attack"), "+15550000000")
        with self.assertRaises(ValueError):
            output_session_kind(run, output_call_sid("b1b2c3d4e5f60708", "attack"), caller)

    def test_synthetic_session_requires_private_purpose_bound_signature(self):
        run = "a1b2c3d4e5f60708"
        token_file = self.root / "output-token"
        token_file.write_bytes(b"p" * 48)
        sid = output_call_sid(run, "attack")
        signature = output_test_signature(token_file.read_bytes(), run, "attack", sid)
        self.assertTrue(admit_output_session(token_file, run, "attack", sid, signature))
        self.assertFalse(admit_output_session(token_file, run, "attack", sid, "0" * 64))
        self.assertFalse(admit_output_session(token_file, run, "replay", output_call_sid(run, "replay"), signature))
        self.assertFalse(admit_output_session(token_file, run, "attack", output_call_sid("b1b2c3d4e5f60708", "attack"), signature))
        token_file.unlink()
        self.assertFalse(admit_output_session(token_file, run, "attack", sid, signature))


if __name__ == "__main__":
    unittest.main()
