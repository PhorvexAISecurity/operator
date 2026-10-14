"""One bounded in-cluster generation. Never read an existing Secret or emit data.

The off-cluster companion creates empty slots and supplies their exact identities.
Only this Job receives patch authority. Successful PATCH bodies are consumed here,
inside the cluster, and reduced to a strict nonsecret whitelist before output.
"""
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import ssl
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, HTTPSHandler, HTTPRedirectHandler, build_opener

NAME = "phorvex-vllm-native-metrics-token-v1"
NAMESPACES = ("vllm", "monitoring")
IMAGE = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:cb16b9b573dea616b184263915f7cb259f39e012650d8ad398456e0e6c91a108"
PAIR_LABEL = "phorvex.ai/metrics-token-pair"
PROVENANCE_LABEL = "phorvex.ai/metrics-token-provenance"
READY_LABEL = "phorvex.ai/metrics-token-ready"
PROVENANCE = "stage6-v1"
LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration"
PARTIAL_ACCEPT = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
SAFE_KEYS = {"namespace", "name", "uid", "resourceVersion", "pairID", "provenance", "ready", "lastAppliedPresent"}


class SafeFailure(ValueError):
    """Only fixed, nonsecret categories may be supplied as messages."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise SafeFailure("API redirects forbidden")


def utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def labels(pair_id, ready=False):
    if not isinstance(pair_id, str) or not re.fullmatch(r"[0-9a-f]{32}", pair_id):
        raise SafeFailure("invalid generation identity")
    return {PAIR_LABEL: pair_id, PROVENANCE_LABEL: PROVENANCE, READY_LABEL: str(ready).lower()}


def runtime_image_matches(value):
    if not isinstance(value, str):
        return False
    identity = value.split("://", 1)[-1]
    return identity in (IMAGE, IMAGE.split("@", 1)[1])


def secret_path(namespace):
    if namespace not in NAMESPACES:
        raise SafeFailure("invalid credential namespace")
    return f"/api/v1/namespaces/{namespace}/secrets/{NAME}"


def safe_record(obj, namespace, pair_id, partial=False, immutable=False):
    if not isinstance(obj, dict):
        raise SafeFailure("invalid credential response")
    if partial and (obj.get("kind") != "PartialObjectMetadata" or
                    obj.get("apiVersion") != "meta.k8s.io/v1" or
                    set(obj) - {"kind", "apiVersion", "metadata"}):
        raise SafeFailure("metadata-only response required")
    meta = obj.get("metadata", {})
    if (meta.get("namespace") != namespace or meta.get("name") != NAME or
            not isinstance(meta.get("uid"), str) or not meta["uid"] or
            not isinstance(meta.get("resourceVersion"), str) or not meta["resourceVersion"]):
        raise SafeFailure("credential identity missing")
    expected = labels(pair_id, immutable)
    actual = meta.get("labels", {})
    if any(actual.get(key) != value for key, value in expected.items()):
        raise SafeFailure("credential provenance differs")
    if LAST_APPLIED in meta.get("annotations", {}) or meta.get("ownerReferences"):
        raise SafeFailure("unsafe credential ownership or annotation")
    result = {"namespace": namespace, "name": NAME, "uid": meta["uid"],
              "resourceVersion": meta["resourceVersion"], "pairID": pair_id,
              "provenance": PROVENANCE, "ready": immutable, "lastAppliedPresent": False}
    if immutable:
        if not partial and obj.get("immutable") is not True:
            raise SafeFailure("credential not immutable")
        if not partial:
            result["immutable"] = True
    return result


def validate_record(record, pair_id, filled=False):
    keys = SAFE_KEYS | ({"immutable"} if filled else set())
    if (not isinstance(record, dict) or set(record) != keys or
            record.get("namespace") not in NAMESPACES or record.get("name") != NAME or
            not isinstance(record.get("uid"), str) or not record["uid"] or
            not isinstance(record.get("resourceVersion"), str) or not record["resourceVersion"] or
            record.get("pairID") != pair_id or record.get("provenance") != PROVENANCE or
            record.get("lastAppliedPresent") is not False or record.get("ready") is not filled or
            (filled and record.get("immutable") is not True)):
        raise SafeFailure("invalid sanitized credential record")
    labels(pair_id)
    return record


def patch_for(slot, pair_id, token):
    validate_record(slot, pair_id)
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise SafeFailure("invalid generated credential")
    return [{"op": "test", "path": "/metadata/uid", "value": slot["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": slot["resourceVersion"]},
            {"op": "add", "path": "/data", "value": {"token": base64.b64encode(token.encode("ascii")).decode("ascii")}},
            {"op": "add", "path": "/immutable", "value": True},
            {"op": "add", "path": "/metadata/labels", "value": labels(pair_id, True)}]


class ClusterPatcher:
    def __init__(self):
        root = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
        port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        if not host or not port.isdigit():
            raise SafeFailure("cluster API unavailable")
        # These credentials remain in the cluster process. They never enter argv.
        self.authorization = "Bearer " + (root / "token").read_text().strip()
        self.base = "https://" + (f"[{host}]" if ":" in host else host) + ":" + port
        context = ssl.create_default_context(cafile=str(root / "ca.crt"))
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())

    def patch(self, namespace, patch):
        request = Request(self.base + secret_path(namespace), data=canonical(patch).encode("ascii"),
                          method="PATCH", headers={"Content-Type": "application/json-patch+json",
                          "Authorization": self.authorization, "Accept": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise SafeFailure("credential PATCH response exceeds bound")
                return json.loads(raw)
        except HTTPError:
            # Do not read or display an API error body (JSON Patch errors can echo values).
            raise SafeFailure("credential PATCH refused") from None
        except Exception:
            raise SafeFailure("credential PATCH failed") from None


def generate(inputs, patcher, token_factory=secrets.token_hex):
    if (set(inputs) != {"schema", "pairID", "slots"} or
            inputs.get("schema") != "phorvex-vllm-native-metrics-token-inputs-v1" or
            len(inputs.get("slots", [])) != 2):
        raise SafeFailure("invalid generation inputs")
    pair_id = inputs["pairID"]
    slots = [validate_record(item, pair_id) for item in inputs["slots"]]
    if {slot["namespace"] for slot in slots} != set(NAMESPACES):
        raise SafeFailure("complete empty slot pair required")
    report = {"schema": "phorvex-vllm-native-metrics-token-generation-v1", "utc": utc(),
              "pairID": pair_id, "result": "partial", "records": []}
    token = token_factory(32)  # Exactly one 256-bit value, inside the Job only.
    try:
        for namespace in NAMESPACES:
            slot = next(item for item in slots if item["namespace"] == namespace)
            response = patcher.patch(namespace, patch_for(slot, pair_id, token))
            record = safe_record(response, namespace, pair_id, immutable=True)
            if record["uid"] != slot["uid"] or record["resourceVersion"] == slot["resourceVersion"]:
                raise SafeFailure("post-PATCH identity differs")
            report["records"].append(record)
        report["result"] = "complete"
    except Exception:
        # Successful first-patch identity remains usable for guarded partial cleanup.
        report["error"] = "credential generation incomplete"
    finally:
        token = None
    return report


def main():
    try:
        inputs = json.loads(Path("/opt/phorvex-token/slots.json").read_text())
        report = generate(inputs, ClusterPatcher())
        print(canonical(report), flush=True)
        return 0 if report["result"] == "complete" else 1
    except Exception:
        print('{"error":"credential generation failed"}', flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

# Stage6 parent provenance (committed bytes; re-derive if parent changes).
PARENT_PROVENANCE = {'branch': 'fix/cfx-stage5-auth-metrics', 'commit': 'ea70951ccf871b58bd60f71202f52228b70c83bc', 'path': 'build/test-harness/fixtures/litellm-live/generate_metrics_token.py', 'blob': 'c3b3e80ae3ddc9af7106714280d1aae8d2834a81', 'sha256': '1b28e7752f073eb75517f128457fb6815a4a4034ed6030dc0ea939d705289c4c'}
# End Stage6 parent provenance.
