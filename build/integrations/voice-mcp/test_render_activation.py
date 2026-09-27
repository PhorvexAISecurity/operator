"""The MCP source rollout preserves the actual Service and rejects stale inputs."""

from pathlib import Path
import unittest

from render_activation import SOURCE_CONFIGMAP, SOURCE_SHA256, render


DEPLOYMENT = "11111111-1111-4111-8111-111111111111"
SERVICE = "22222222-2222-4222-8222-222222222222"
SOURCE = "33333333-3333-4333-8333-333333333333"
IMAGE = "python:3.11-slim"
IMAGE_ID = "docker-pullable://python@sha256:" + "a" * 64
APPROVED = "registry.example/mcp@sha256:" + "b" * 64


def meta(kind, name, uid):
    return {"kind": kind, "metadata": {"name": name, "namespace": "mcp",
                                     "uid": uid, "resourceVersion": "19"}}


def deployment():
    value = meta("Deployment", "mcp-server", DEPLOYMENT)
    value["spec"] = {"replicas": 1, "template": {
        "metadata": {"annotations": {"prior": "keep"}},
        "spec": {"volumes": [{"name": "mcp-code", "configMap": {"name": "mcp-code"}}],
                 "containers": [{"name": "mcp-server", "image": IMAGE,
                                 "workingDir": "/app", "ports": [{"containerPort": 8000, "protocol": "TCP"}],
                                 "command": ["/bin/sh", "-c", "pip install fastmcp && python server.py"],
                                 "volumeMounts": [{"name": "mcp-code", "mountPath": "/app"}]}]}}}
    return value


def service():
    value = meta("Service", "mcp-server", SERVICE)
    value["spec"] = {"ports": [{"port": 8000, "targetPort": 8000, "protocol": "TCP"}]}
    return value


def legacy():
    value = meta("ConfigMap", "mcp-code", SOURCE)
    # A minimal fixture uses the exact retained source bytes in this package.
    value["data"] = {"server.py": (Path(__file__).with_name("legacy_server.py")).read_text()}
    return value


class RenderMCPActivationTest(unittest.TestCase):
    def test_source_pin_secret_and_narrow_patch(self):
        objects = render(deployment(), service(), legacy(), b"m" * 48,
                         DEPLOYMENT, SERVICE, SOURCE, IMAGE, IMAGE_ID, APPROVED, [IMAGE_ID])
        source = objects["source-configmap.json"]
        self.assertEqual(source["metadata"]["name"], SOURCE_CONFIGMAP)
        self.assertTrue(source["immutable"])
        self.assertEqual(set(source["data"]), {"server.py"})
        self.assertEqual(len(source["data"]["server.py"].encode()),
                         (Path(__file__).with_name("server.py")).stat().st_size)
        self.assertEqual(service()["spec"]["ports"][0]["targetPort"], 8000)
        patch = objects["deployment-patch.json"]
        self.assertIn({"op": "test", "path": "/metadata/resourceVersion", "value": "19"}, patch)
        self.assertTrue(any(op.get("value") == ["python3", "-B", "/app/server.py"] for op in patch))
        self.assertTrue(any(op.get("value", {}).get("configMap", {}).get("name") == SOURCE_CONFIGMAP
                            for op in patch if isinstance(op.get("value"), dict)))
        self.assertTrue(any(op.get("value", {}).get("subPath") == "server.py" and
                            op["value"].get("readOnly") for op in patch if isinstance(op.get("value"), dict)))
        self.assertEqual(SOURCE_SHA256, __import__("hashlib").sha256(
            (Path(__file__).with_name("server.py")).read_bytes()).hexdigest())

    def test_stale_source_or_service_refused(self):
        changed = legacy()
        changed["data"]["server.py"] += "\n# drift\n"
        with self.assertRaises(ValueError):
            render(deployment(), service(), changed, b"m" * 48,
                   DEPLOYMENT, SERVICE, SOURCE, IMAGE, IMAGE_ID, APPROVED, [IMAGE_ID])
        changed_service = service()
        changed_service["spec"]["ports"][0]["targetPort"] = 8001
        with self.assertRaises(ValueError):
            render(deployment(), changed_service, legacy(), b"m" * 48,
                   DEPLOYMENT, SERVICE, SOURCE, IMAGE, IMAGE_ID, APPROVED, [IMAGE_ID])


if __name__ == "__main__":
    unittest.main()
