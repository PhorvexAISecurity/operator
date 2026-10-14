import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("litellm_metrics_render", Path(__file__).with_name("render_metrics.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ROOT = Path(__file__).resolve().parents[4]
CONTRACT = ROOT / "build/integrations/litellm-gateway-runtime/image-contract.json"
OLD_SHA = "4bf046ce690c280da4b4f0f613ac52d2b4511285454f18c25b2e144b574d5cc1"


def originals():
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"namespace": "litellm", "name": "litellm", "uid": "fixture-owner", "resourceVersion": "42"},
        "spec": {"template": {"metadata": {
            "labels": {"app": "litellm", "existing": "preserved"},
            "annotations": {module.SOURCE_ANNOTATION: OLD_SHA, "status-policy": "preserved"}},
            "spec": {"containers": [
                {"name": "litellm", "image": "fixture-upstream:unchanged", "ports": [{"name": "http", "containerPort": 4000}]},
                {"name": module.CONTAINER, "image": json.loads(CONTRACT.read_text())["imageByDigest"],
                 "command": ["python3", "-B", "/opt/phorvex/gateway.py"],
                 "ports": [{"name": "admission", "containerPort": 4001}, {"name": "admin-status", "containerPort": 4002}],
                 "env": [{"name": module.SOURCE_ENV, "value": OLD_SHA},
                         {"name": "LITELLM_MASTER_KEY", "valueFrom": {"secretKeyRef": {"name": "existing-master", "key": "master-key"}}}],
                 "volumeMounts": [{"name": "litellm-live-gateway-source", "mountPath": "/opt/phorvex", "readOnly": True}]}],
                "volumes": [{"name": "litellm-live-gateway-source", "configMap": {"name": "phorvex-litellm-admission-gateway-" + OLD_SHA[:12]}}]}}}}
    profile_value = {"version": 2, "sourceSHA256": OLD_SHA,
                     "gatewayImage": deployment["spec"]["template"]["spec"]["containers"][1]["image"],
                     "clientsSHA256": "b" * 64, "seedSHA256": "a" * 64,
                     "policyName": "litellm-defense", "modelAlias": "gpt-4o-mini",
                     "eventCreator": "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
                     "auditSourceIdentity": "fixture-audit-source", "maxRunSeconds": 900}
    raw = module.canonical(profile_value)
    profile = {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
               "metadata": {"namespace": "phorvex-system", "name": "phorvex-litellm-live-profile-" + hashlib.sha256(raw.encode()).hexdigest()[:12]},
               "data": {"profile.json": raw}}
    policies = [{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                 "metadata": {"namespace": "litellm", "name": "fixture-serving-status"},
                 "spec": {"podSelector": {"matchLabels": {"app": "litellm"}}, "policyTypes": ["Ingress"],
                          "ingress": [
                              {"from": [{"namespaceSelector": {"matchLabels": {"fixture": "serving-clients"}}}], "ports": [{"port": 4001}]},
                              {"from": [{"podSelector": {"matchLabels": {"fixture": "status-readers"}}}], "ports": [{"port": 4002}]}]}}]
    return deployment, [profile], policies, {"app.kubernetes.io/name": "prometheus", "prometheus": "fixture-prometheus"}


def patched(document, patch):
    result = copy.deepcopy(document)
    for operation in patch:
        parts = [part.replace("~1", "/").replace("~0", "~") for part in operation["path"].split("/")[1:]]
        parent = result
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        key = parts[-1]
        if operation["op"] == "test":
            value = parent[int(key)] if isinstance(parent, list) else parent[key]
            if value != operation["value"]:
                raise ValueError("stale JSON patch")
        elif isinstance(parent, list):
            if key == "-":
                parent.append(copy.deepcopy(operation["value"]))
            else:
                parent[int(key)] = copy.deepcopy(operation["value"])
        else:
            parent[key] = copy.deepcopy(operation["value"])
    return result


class MetricsRenderTests(unittest.TestCase):
    def test_default_off_emits_nothing(self):
        self.assertEqual(module.render(), {})
        self.assertEqual(module.render(*originals()), {})

    def test_installed_status_token_mount_path_is_preserved(self):
        d, profiles, policies, labels = originals()
        gateway = d["spec"]["template"]["spec"]["containers"][1]
        path_env = {"name": "PHORVEX_LITELLM_STATUS_TOKEN_FILE",
                    "value": "/etc/phorvex-litellm-status/token"}
        gateway["env"].append(path_env)
        objects = module.render(d, profiles, policies, labels, enabled=True)
        result = patched(d, objects["deployment-metrics-json-patch.json"])
        self.assertIn(path_env, result["spec"]["template"]["spec"]["containers"][1]["env"])
        gateway["env"][-1]["value"] = "literal-private-token"
        with self.assertRaisesRegex(ValueError, "Secret references"):
            module.render(d, profiles, policies, labels, enabled=True)

    def test_opt_in_closure_is_content_derived_and_preserves_owner_state(self):
        d, profiles, policies, labels = originals()
        original = copy.deepcopy((d, profiles, policies, labels))
        objects = module.render(d, profiles, policies, labels, enabled=True)
        self.assertEqual((d, profiles, policies, labels), original)
        closure = objects["metrics-closure.json"]
        digest = hashlib.sha256(module.GATEWAY_SOURCE.read_bytes()).hexdigest()
        self.assertEqual(closure["gatewaySourceSHA256"], digest)
        self.assertEqual(closure["engineContract"]["status"], "activation-required")
        self.assertEqual(closure["engineContract"]["installedSourceSHA256"], OLD_SHA)
        self.assertEqual(closure["engineContract"]["candidateSourceSHA256"], digest)
        self.assertEqual(closure["gatewayImageByDigest"], d["spec"]["template"]["spec"]["containers"][1]["image"])
        self.assertEqual(closure["sourceConfigMapName"], "phorvex-litellm-admission-gateway-" + digest[:12])
        result = patched(d, objects["deployment-metrics-json-patch.json"])
        self.assertEqual(patched(result, objects["deployment-metrics-rollback-json-patch.json"]), d)
        other_edit = copy.deepcopy(result)
        other_edit["spec"]["template"]["metadata"]["labels"]["other-owner"] = "preserve"
        with self.assertRaisesRegex(ValueError, "stale"):
            patched(other_edit, objects["deployment-metrics-rollback-json-patch.json"])
        before = d["spec"]["template"]
        after = result["spec"]["template"]
        self.assertEqual(before["spec"]["containers"][0], after["spec"]["containers"][0])
        self.assertEqual(before["spec"]["containers"][1]["volumeMounts"], after["spec"]["containers"][1]["volumeMounts"])
        self.assertEqual(after["metadata"]["annotations"]["status-policy"], "preserved")
        self.assertEqual(after["spec"]["containers"][1]["ports"][-1]["containerPort"], 4003)
        env = {e["name"]: e for e in after["spec"]["containers"][1]["env"]}
        self.assertEqual(env["PHORVEX_LITELLM_METRICS_ENABLED"]["value"], "1")
        self.assertEqual(env["POD_NAMESPACE"]["valueFrom"]["fieldRef"]["fieldPath"], "metadata.namespace")
        self.assertEqual(env["POD_NAME"]["valueFrom"]["fieldRef"]["fieldPath"], "metadata.name")
        binding = closure["profiles"][0]
        candidate = objects[binding["configMapName"] + ".json"]
        raw = candidate["data"]["profile.json"]
        self.assertEqual(binding["profileSHA256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(json.loads(raw), {**json.loads(profiles[0]["data"]["profile.json"]), "sourceSHA256": digest,
                                          "gatewayImage": json.loads(CONTRACT.read_text())["imageByDigest"]})
        self.assertNotEqual(candidate["metadata"]["name"], profiles[0]["metadata"]["name"])

    def test_original_runtime_migrates_and_unisolated_baseline_is_explicit(self):
        d, p, _, labels = originals()
        contract = json.loads(CONTRACT.read_text())
        d["spec"]["template"]["spec"]["containers"][1]["image"] = contract["baseImage"]
        value = json.loads(p[0]["data"]["profile.json"])
        value["gatewayImage"] = contract["baseImage"]
        raw = module.canonical(value)
        p[0]["data"]["profile.json"] = raw
        p[0]["metadata"]["name"] = "phorvex-litellm-live-profile-" + hashlib.sha256(raw.encode()).hexdigest()[:12]
        with self.assertRaisesRegex(ValueError, "preserve"):
            module.render(d, p, [], labels, enabled=True)
        objects = module.render(d, p, [], labels, enabled=True, preserve_unisolated_ingress=True)
        result = patched(d, objects["deployment-metrics-json-patch.json"])
        self.assertEqual(result["spec"]["template"]["spec"]["containers"][1]["image"], contract["imageByDigest"])
        self.assertEqual(patched(result, objects["deployment-metrics-rollback-json-patch.json"]), d)
        rules = objects["metrics-networkpolicy.json"]["spec"]["ingress"]
        self.assertEqual([x["port"] for x in rules[1]["ports"]], [4000, 4001, 4002])
        self.assertEqual(rules[0]["ports"], [{"port": 4003, "protocol": "TCP"}])
        self.assertEqual(objects["metrics-closure.json"]["previousGatewayImageByDigest"], contract["baseImage"])
        changed = copy.deepcopy(d)
        changed["spec"]["replicas"] = 3
        with self.assertRaisesRegex(ValueError, "stale"):
            patched(changed, objects["deployment-metrics-json-patch.json"])

    def test_private_named_port_monitor_and_intersection_network_source(self):
        d, p, n, labels = originals()
        objects = module.render(d, p, n, labels, enabled=True)
        service = objects["metrics-service.json"]
        self.assertEqual(service["spec"]["type"], "ClusterIP")
        self.assertEqual(service["spec"]["selector"], {"app": "litellm", module.LABEL: "enabled"})
        endpoint = objects["metrics-servicemonitor.json"]["spec"]["endpoints"][0]
        self.assertEqual((endpoint["port"], endpoint["path"], endpoint["honorLabels"]), ("gateway-metrics", "/metrics", False))
        self.assertEqual([r["targetLabel"] for r in endpoint["relabelings"]], ["namespace", "pod", "target"])
        self.assertNotIn("bearerTokenSecret", endpoint)
        policy = objects["metrics-networkpolicy.json"]["spec"]
        self.assertEqual(policy["ingress"], [{"from": [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "monitoring"}},
            "podSelector": {"matchLabels": labels}}], "ports": [{"port": 4003, "protocol": "TCP"}]}])
        self.assertEqual(policy["policyTypes"], ["Ingress"])
        self.assertFalse(any(obj.get("kind") == "Ingress" for obj in objects.values() if isinstance(obj, dict)))

    def test_refuses_conflicts_unreviewed_network_and_incomplete_profile(self):
        d, p, n, labels = originals()
        for change, expected in [
            (lambda d,p,n,l: d["spec"]["template"]["spec"]["containers"][0]["ports"].append({"containerPort": 4003}), "conflicts"),
            (lambda d,p,n,l: n[0]["spec"]["ingress"].append({}), "all ports"),
            (lambda d,p,n,l: n[0]["spec"]["ingress"].append({"ports": [{"port": 4003}]}), "permits metrics"),
            (lambda d,p,n,l: n[0]["spec"]["ingress"].append({"ports": [{"port": 4000, "endPort": 4010}]}), "permits metrics"),
            (lambda d,p,n,l: n[0]["spec"].update({"ingress": []}), "preserve"),
            (lambda d,p,n,l: p.clear(), "profiles"),
            (lambda d,p,n,l: l.clear(), "Prometheus"),
            (lambda d,p,n,l: d["spec"]["template"]["spec"]["containers"][1].update({"image": "registry/foreign@sha256:" + "b" * 64}), "convergence"),
            (lambda d,p,n,l: d["spec"]["template"]["spec"]["containers"][1].update({"ports": []}), "declarations"),
            (lambda d,p,n,l: p[0]["metadata"].update({"name": "profile-stale"}), "hash/runtime"),
            (lambda d,p,n,l: d["spec"]["template"]["spec"]["containers"][1]["env"].append({"name": "STATUS_TOKEN", "value": "private"}), "Secret references"),
        ]:
            with self.subTest(expected=expected):
                args = copy.deepcopy((d, p, n, labels))
                change(*args)
                with self.assertRaisesRegex(ValueError, expected):
                    module.render(*args, enabled=True)
        with self.assertRaisesRegex(ValueError, "preserve"):
            module.render(d, p, [], labels, enabled=True)
        with self.assertRaisesRegex(ValueError, "catalogue profile source"):
            p[0]["data"]["profile.json"] = module.canonical({"sourceSHA256": "f" * 64})
            module.render(d, p, n, labels, enabled=True)

    def test_stale_owner_patch_fails_and_active_output_trial_blocks_migration(self):
        d, p, n, labels = originals()
        objects = module.render(d, p, n, labels, enabled=True)
        changed = copy.deepcopy(d)
        changed["metadata"]["resourceVersion"] = "43"
        with self.assertRaisesRegex(ValueError, "stale"):
            patched(changed, objects["deployment-metrics-json-patch.json"])
        d["spec"]["template"]["spec"]["containers"][1]["env"].append({"name": "PHORVEX_LITELLM_OUTPUT_POLICY_FILE", "value": "/existing/policy.json"})
        with self.assertRaisesRegex(ValueError, "quiescent"):
            module.render(d, p, n, labels, {"version": 2, "revision": 1, "entries": [{}]}, enabled=True)
        module.render(d, p, n, labels, {"version": 2, "revision": 0, "entries": []}, enabled=True)


if __name__ == "__main__":
    unittest.main()
