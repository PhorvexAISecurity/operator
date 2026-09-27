"""Offline checks for the exact owned Mongo fixture transport."""

from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("voice_agency_mongo_fixture", Path(__file__).with_name("mongo_fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

POD_UID = "11111111-1111-4111-8111-111111111111"
IMAGE = "registry.example/owned-mongo@sha256:" + "a" * 64


class FakeKubectl:
    def __init__(self, uid=POD_UID):
        self.uid = uid
        self.calls = []

    def __call__(self, args, **_):
        self.calls.append(args)
        if "get" in args:
            pod = {"metadata": {"namespace": "document-store", "name": "mongo-1", "uid": self.uid},
                   "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                              "containerStatuses": [{"name": "mongo", "imageID": IMAGE,
                                                     "ready": True, "restartCount": 0}]}}
            return SimpleNamespace(returncode=0, stdout=json.dumps(pod).encode(), stderr=b"")
        if "exec" in args:
            if "mongosh" not in args or "--eval" not in args or "db.getSiblingDB(\"crm\")" not in args[-1]:
                raise AssertionError("wrong exact Mongo command")
            reply = {"schema": 1, "phase": "seed", "run": "agencya1", "ready": True,
                     "accountIDs": ["VA-agencya1-A", "VA-agencya1-B"], "orderIDs": ["9141", "9142"],
                     "baselineRefundCount": 0}
            return SimpleNamespace(returncode=0, stdout=(fixture.PREFIX + json.dumps(reply) + "\n").encode(), stderr=b"")
        raise AssertionError("unexpected command")


class VoiceAgencyMongoFixtureTest(unittest.TestCase):
    def test_seed_brackets_one_exact_mongosh_exec(self):
        with self.subTest("private receipt"):
            from tempfile import TemporaryDirectory
            with TemporaryDirectory() as parent:
                fake = FakeKubectl()
                output = Path(parent) / "phase"
                reply = fixture.one_phase("mongo-1", POD_UID, IMAGE, "mongo", "agencya1", "seed", [], output, run=fake)
                self.assertTrue(reply["ready"])
                self.assertEqual(["get", "exec", "get"],
                                 ["get" if "get" in x else "exec" for x in fake.calls])
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                self.assertEqual((output / "intent.json").stat().st_mode & 0o777, 0o600)
                with self.assertRaises(ValueError):
                    fixture.one_phase("mongo-1", POD_UID, IMAGE, "mongo", "agencya1", "seed", [], output, run=fake)
                self.assertEqual(len(fake.calls), 3)

    def test_wrong_pod_uid_prevents_exec(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as parent:
            fake = FakeKubectl(uid="22222222-2222-4222-8222-222222222222")
            with self.assertRaises(ValueError):
                fixture.one_phase("mongo-1", POD_UID, IMAGE, "mongo", "agencya1", "seed", [],
                                  Path(parent) / "phase", run=fake)
            self.assertEqual(len(fake.calls), 1)

    def test_no_free_form_script_inputs(self):
        for run in ("bad-id", "x" * 25, "ok;db.dropDatabase()"):
            with self.assertRaises(ValueError):
                fixture.fixture_source(run, "seed", [])
        with self.assertRaises(ValueError):
            fixture.fixture_source("agencya1", "cleanup", ["RF-WRONG"])
        self.assertIn("const PHASE=\"observe\"", fixture.fixture_source("agencya1", "observe", []))

    def test_ssh_transport_source_is_fenced_before_kubectl(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as parent:
            source = Path(parent) / "transport.py"
            source.write_text("class Transport:\n"
                              "    def __init__(self, access): self.access = access\n"
                              "    def kubectl(self, argv, timeout):\n"
                              "        return type('Reply', (), {'returncode': 0, 'stdout': 'ok', 'stderr': ''})()\n")
            with patch.object(fixture, "TRANSPORT_SOURCE", source), \
                    patch.object(fixture, "TRANSPORT_SHA256", "0" * 64):
                with self.assertRaises(ValueError):
                    fixture.remote_kubectl(["kubectl", "--context", fixture.CONTEXT, "get", "pod"], timeout=2)
            with patch.object(fixture, "TRANSPORT_SOURCE", source), \
                    patch.object(fixture, "TRANSPORT_SHA256", hashlib.sha256(source.read_bytes()).hexdigest()):
                reply = fixture.remote_kubectl(["kubectl", "--context", fixture.CONTEXT, "get", "pod"], timeout=2)
                self.assertEqual(reply.stdout, b"ok")


if __name__ == "__main__":
    unittest.main()
