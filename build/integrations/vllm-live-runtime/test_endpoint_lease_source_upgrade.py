import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import render_endpoint_lease_source_upgrade as renderer
import render_guardrail_profile as g
from endpoint_lease_source_upgrade import canonical, validate_upgrade
from test_render_guardrail_profile import lease_fixture, obj, uid


def fixture():
    objects, raw = lease_fixture()
    p = g.unique_json(raw)
    prior_cm = objects["lease_policy"]
    before = g.unique_json(prior_cm["data"]["state.json"].encode())
    prior = dict(before, revision=1, allowedClientHMACs=[p["clientBHMAC"]],
                 revokedClientHMACs=[p["clientAHMAC"]], lastOperationID="f" * 32)
    prior_cm["data"]["state.json"] = canonical(prior).decode()
    row = {"phase": "terminal-full", "oldRevision": 0, "newRevision": 1,
           "oldStateSHA256": g.digest(canonical(before)), "newStateSHA256": g.digest(canonical(prior)),
           "operationID": prior["lastOperationID"], "policyUID": p["policyUID"],
           "policyConfigMapUID": p["policyConfigMapUID"], "secretUID": p["tenantSecretUID"],
           "serviceUID": p["serviceUID"], "proxySourceSHA256": p["proxySourceSHA256"],
           "seedSHA256": p["seedSHA256"], "retainedClientHMAC": p["clientBHMAC"], "revokedClientHMAC": p["clientAHMAC"]}
    journal = obj("ConfigMap", "phorvex-endpoint-lease-journal", "phorvex-system", 23, resourceVersion="8")
    journal["data"] = {"receipts.json": canonical({"version": 1, "receipts": [row]}).decode()}
    source = copy.deepcopy(objects["source"])
    source["metadata"]["uid"] = uid(25)
    source["data"]["drain_v11.py"] += "\n# synthetic reviewed maintenance fixture\n"
    new_sha = g.digest(b"\0".join(source["data"][k].encode() for k in g.LEASE_SOURCE_FILES))
    current_cm = copy.deepcopy(prior_cm)
    current_cm["metadata"]["resourceVersion"] = "9"
    current_cm["data"]["state.json"] = canonical(dict(prior, revision=2, proxySourceSHA256=new_sha)).decode()
    return raw, prior_cm, current_cm, journal, source, p["proxySourceSHA256"], new_sha


class SourceUpgradeTest(unittest.TestCase):
    def test_new_reviewed_capacity_closure_requires_witness(self):
        # The override is an offline pre-integration source path, never a live pin.
        path = Path(os.environ.get("PHORVEX_TEST_CAPACITY_DRAIN_PATH", str(g.PROXY.parent / "drain_v11.py")))
        new_drain = path.read_bytes()
        if g.digest(new_drain) != g.CAPACITY_REPAIRED_DRAIN_SOURCE_SHA256["drain_v11.py"]:
            self.skipTest("capacity source commit not integrated; use labelled offline source override")
        objects, old_raw = lease_fixture()
        _, prior, current, journal, _, _, _ = fixture()
        source = objects["source"]
        source["metadata"]["uid"] = uid(25)
        source["data"]["drain_v11.py"] = new_drain.decode()
        current_state = g.unique_json(current["data"]["state.json"].encode())
        current_state["proxySourceSHA256"] = renderer.NEW_SOURCE
        current["data"]["state.json"] = canonical(current_state).decode()
        profile_raw = renderer.render(old_raw, prior, current, journal, source)
        objects["lease_policy"] = current
        pod = objects["pod"]
        pod["metadata"]["annotations"]["phorvex.ai/endpoint-lease-source-sha256"] = renderer.NEW_SOURCE
        guard = next(c for c in pod["spec"]["containers"] if c["name"] == "guardrail")
        next(e for e in guard["env"] if e["name"] == "PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256")["value"] = renderer.NEW_SOURCE
        for item in (objects["console"], objects["console_replicaset"]["spec"]["template"],
                     objects["console_deployment"]["spec"]["template"]):
            spec = item["spec"]
            console = next(c for c in spec["containers"] if c["name"] == "console")
            next(e for e in console["env"] if e["name"] == "PHORVEX_CONSOLE_ENDPOINT_LEASE_PROFILE_SHA256")["value"] = g.digest(profile_raw)
            next(v for v in spec["volumes"] if v["name"] == "lease-profile")["configMap"]["name"] = "phorvex-catalogue-endpoint-lease-" + g.digest(profile_raw)[:12]
        with tempfile.TemporaryDirectory() as directory:
            proxy = Path(directory) / "guardrail_proxy.py"
            proxy.write_bytes(g.PROXY.read_bytes())
            (proxy.parent / "drain_v11.py").write_bytes(new_drain)
            (proxy.parent / "drain_v11_init.py").write_bytes((g.PROXY.parent / "drain_v11_init.py").read_bytes())
            with patch.object(g, "PROXY", proxy):
                g.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test", profile_raw)
                stripped = g.unique_json(profile_raw)
                del stripped["sourceUpgrade"]
                with self.assertRaises(ValueError):
                    g.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test", canonical(stripped))
                (proxy.parent / "drain_v11.py").write_bytes(new_drain + b"\n# tampered\n")
                with self.assertRaises(ValueError):
                    g.render(objects, "arn:aws:eks:us-east-2:123456789012:cluster/test", profile_raw)

    def test_exact_archived_production_state_and_terminal(self):
        root = Path(__file__).resolve().parents[3] / "phorvex/internal/console/testdata/endpoint-lease-source-upgrade"
        p = g.unique_json((root / "prior-profile.json").read_bytes())
        prior_raw, journal_raw = ((root / name).read_bytes() for name in ("prior-state.json", "prior-journal.json"))
        self.assertEqual(g.digest(journal_raw), "1c4784d41c51d939b54af49bf372514343601664c0a54277cc07554bcd4cd668")
        prior = g.unique_json(prior_raw)
        old_uid = p["sourceConfigMapUID"]
        p["sourceConfigMapUID"] = uid(25)  # explicitly synthetic offline current UID
        p["proxySourceSHA256"] = "9" * 64
        current = dict(prior, revision=2, proxySourceSHA256=p["proxySourceSHA256"])
        p["sourceUpgrade"] = {"version": 1, "priorStateJSON": prior_raw.decode(),
                              "priorStateSHA256": g.digest(prior_raw), "priorJournalSHA256": g.digest(journal_raw),
                              "currentStateSHA256": g.digest(canonical(current)), "priorSourceConfigMapUID": old_uid}
        validate_upgrade(p, current, journal_raw)
        g.retained_lease_profile(canonical(p), p["serviceUID"], p["sourceConfigMapUID"], p["proxySourceSHA256"],
                                 p["policyUID"], p["policyGeneration"], p["policyConfigMapUID"], current,
                                 {"image": p["proxyImage"]}, {"image": p["approvedEngineImage"]})

    def test_render_exact_transition_and_parse_by_existing_renderer(self):
        raw, prior, current, journal, source, old_sha, new_sha = fixture()
        with patch.object(renderer, "OLD_SOURCE", old_sha), patch.object(renderer, "NEW_SOURCE", new_sha):
            result = renderer.render(raw, prior, current, journal, source)
        p, state = g.unique_json(result), g.unique_json(current["data"]["state.json"].encode())
        validate_upgrade(p, state, journal["data"]["receipts.json"].encode())
        g.retained_lease_profile(result, p["serviceUID"], p["sourceConfigMapUID"], p["proxySourceSHA256"],
                                 p["policyUID"], p["policyGeneration"], p["policyConfigMapUID"], state,
                                 {"image": p["proxyImage"]}, {"image": p["approvedEngineImage"]})
        self.assertEqual(state["lastOperationID"], "f" * 32)
        self.assertEqual(state["revokedClientHMACs"], [p["clientAHMAC"]])

    def test_render_refuses_unreviewed_bundle(self):
        raw, prior, current, journal, source, _, _ = fixture()
        with self.assertRaises(ValueError):
            renderer.render(raw, prior, current, journal, source)

    def test_preserving_validator_rejects_state_journal_and_schema_changes(self):
        raw, prior, current, journal, source, old_sha, new_sha = fixture()
        with patch.object(renderer, "OLD_SOURCE", old_sha), patch.object(renderer, "NEW_SOURCE", new_sha):
            profile = g.unique_json(renderer.render(raw, prior, current, journal, source))
        state = g.unique_json(current["data"]["state.json"].encode())
        for key, value in (("revision", 3), ("lastOperationID", "e" * 32), ("seedSHA256", "0" * 64),
                           ("allowedClientHMACs", [profile["clientAHMAC"], profile["clientBHMAC"]])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_upgrade(profile, dict(state, **{key: value}))
        j = g.unique_json(journal["data"]["receipts.json"].encode())
        j["receipts"].append({"phase": "prepared"})
        changed = copy.deepcopy(profile)
        changed["sourceUpgrade"]["priorJournalSHA256"] = g.digest(canonical(j))
        with self.assertRaises(ValueError):
            validate_upgrade(changed, state, canonical(j))
        changed = copy.deepcopy(profile)
        changed["sourceUpgrade"]["unknown"] = True
        with self.assertRaises(ValueError):
            validate_upgrade(changed, state)
        with self.assertRaises(ValueError):
            validate_upgrade(profile, state, journal["data"]["receipts.json"].encode() + b"\n")


if __name__ == "__main__":
    unittest.main()
