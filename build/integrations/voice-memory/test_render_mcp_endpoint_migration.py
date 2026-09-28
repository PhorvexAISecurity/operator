import copy
import unittest

from render_mcp_endpoint_migration import LEGACY_URL, MCP_URL, render


class EndpointMigrationTest(unittest.TestCase):
    def setUp(self):
        self.uid = "9212e1a8-c21d-49cd-9854-85a1b306a8f4"
        self.deployment = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {
            "namespace": "voice", "name": "voice-bot", "uid": self.uid, "resourceVersion": "123"},
            "spec": {"template": {"metadata": {"annotations": {"source": "preserved"}}, "spec": {
                "containers": [{"name": "sidecar"}, {"name": "bot", "env": [
                    {"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "existing", "key": "token"}}},
                    {"name": "MCP_URL", "value": LEGACY_URL}], "volumeMounts": [{"name": "source"}]}],
                "volumes": [{"name": "source", "configMap": {"name": "existing"}}]}}}}

    def apply(self, deployment, patch):
        result = copy.deepcopy(deployment)
        for operation in patch:
            parts = operation["path"].split("/")[1:]
            parent = result
            for part in parts[:-1]:
                parent = parent[int(part)] if isinstance(parent, list) else parent[part]
            key = int(parts[-1]) if isinstance(parent, list) else parts[-1]
            if operation["op"] == "test":
                if parent[key] != operation["value"]:
                    raise ValueError("stale patch")
            else:
                self.assertEqual(operation["op"], "replace")
                parent[key] = operation["value"]
        return result

    def test_only_endpoint_changes_and_stale_uid_rv_or_env_are_rejected(self):
        patch = render(self.deployment, self.uid, "123")
        expected = copy.deepcopy(self.deployment)
        expected["spec"]["template"]["spec"]["containers"][1]["env"][1]["value"] = MCP_URL
        self.assertEqual(self.apply(self.deployment, patch), expected)
        for path, replacement in [("uid", "other"), ("resourceVersion", "124")]:
            stale = copy.deepcopy(self.deployment)
            stale["metadata"][path] = replacement
            with self.assertRaises(ValueError):
                self.apply(stale, patch)
        stale = copy.deepcopy(self.deployment)
        stale["spec"]["template"]["spec"]["containers"][1]["env"][1]["value"] = MCP_URL
        with self.assertRaises(ValueError):
            self.apply(stale, patch)

    def test_renderer_refuses_foreign_ambiguous_or_indirect_endpoints(self):
        for value in [MCP_URL, LEGACY_URL + "?x=1", "http://other/mcp/"]:
            changed = copy.deepcopy(self.deployment)
            changed["spec"]["template"]["spec"]["containers"][1]["env"][1]["value"] = value
            with self.assertRaises(ValueError):
                render(changed, self.uid, "123")
        for change in ["duplicate", "valueFrom", "missing"]:
            changed = copy.deepcopy(self.deployment)
            env = changed["spec"]["template"]["spec"]["containers"][1]["env"]
            if change == "duplicate":
                env.append(copy.deepcopy(env[1]))
            elif change == "valueFrom":
                env[1] = {"name": "MCP_URL", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}
            else:
                env.pop()
            with self.assertRaises(ValueError):
                render(changed, self.uid, "123")
        with self.assertRaises(ValueError):
            render(self.deployment, self.uid, "124")


if __name__ == "__main__":
    unittest.main()
