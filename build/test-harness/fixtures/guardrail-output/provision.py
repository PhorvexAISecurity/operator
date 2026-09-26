"""Validate or explicitly provision one reviewed CPU support-output fixture.

Without --execute this command only validates the rendered private package.
It never changes the shared vLLM Deployment or Service.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import render


def _strict(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate package key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def load_package(directory: Path):
    if not directory.is_dir() or directory.stat().st_mode & 0o077:
        raise ValueError("package directory must be private")
    plan = render.validate_plan(_strict((directory / "plan.json").read_bytes()))
    source = _strict((directory / "source-configmap.json").read_bytes())
    if type(source) is not dict or type(source.get("data")) is not dict or set(source["data"]) != set(render.SOURCE_FILES):
        raise ValueError("source ConfigMap must contain exactly three reviewed files")
    marker_secret = _strict((directory / "marker-secret.json").read_bytes())
    try:
        marker = base64.b64decode(marker_secret["data"]["marker"], validate=True).decode("ascii")
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise ValueError("marker Secret invalid") from exc
    if not render.MARKER.fullmatch(marker):
        raise ValueError("marker Secret shape invalid")
    expected = render.documents(plan, marker, source["data"])
    for name in ("source-configmap.json", "marker-secret.json", "fixture-pod.json",
                 "fixture-service.json", "fixture-policy.json"):
        actual = (directory / name).read_bytes()
        if actual != render.canonical(expected[name]):
            raise ValueError(f"rendered {name} changed")
    for name in render.SOURCE_FILES:
        if source["data"][name].encode() != (render.SOURCE_DIR / name).read_bytes():
            raise ValueError(f"current source differs from sealed {name}")
    summary = _strict((directory / "summary.json").read_bytes())
    expected_summary = {
        "schema": "phorvex.guardrail-output-fixture-package.v1",
        "podName": render.POD_NAME, "serviceName": render.SERVICE_NAME,
        "context": plan["context"], "clusterUID": plan["clusterUID"],
        "modelServiceName": plan["modelServiceName"],
        "modelServiceUID": plan["modelServiceUID"],
        "modelTargetPodName": plan["modelTargetPodName"],
        "modelTargetPodUID": plan["modelTargetPodUID"],
        "modelTargetImageID": plan["modelTargetImageID"],
        "modelID": plan["modelID"],
        "sourceConfigMapName": render.SOURCE_NAME,
        "policyConfigMapName": render.POLICY_CM_NAME,
        "sourceSHA256": expected["sourceSHA256"],
        "supportSourceSHA256": expected["supportSourceSHA256"],
        "files": ["plan.json", "source-configmap.json", "marker-secret.json",
                  "fixture-pod.json", "fixture-service.json", "fixture-policy.json"],
    }
    if summary != expected_summary:
        raise ValueError("package source digest mismatch")
    return plan, summary


class Kubectl:
    def __init__(self, kubeconfig: Path, context: str):
        if not kubeconfig.is_file():
            raise ValueError("kubeconfig unavailable")
        self.prefix = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", context]

    def call(self, *args, stdin=None):
        result = subprocess.run([*self.prefix, *args], input=stdin, capture_output=True,
                                text=True, timeout=240, check=False)
        if result.returncode:
            # kubectl errors can contain object names, never Secret bytes.
            raise RuntimeError(f"kubectl {args[0]} failed: {result.stderr.strip()[:500]}")
        return result.stdout

    def get(self, kind, name, namespace="vllm"):
        return _strict(self.call("-n", namespace, "get", kind, name, "-o", "json"))

    def absent(self, kind, name, namespace="vllm"):
        output = self.call("-n", namespace, "get", kind, name,
                           "--ignore-not-found", "-o", "json")
        if output.strip():
            raise ValueError(f"refusing to replace existing {kind}/{name}")

    def create_file(self, path):
        self.call("-n", "vllm", "create", "-f", str(path))

    def create_object(self, value):
        self.call("-n", "vllm", "create", "-f", "-", stdin=json.dumps(value))

    def patch(self, kind, name, uid, resource_version, operations):
        patch = [{"op": "test", "path": "/metadata/uid", "value": uid},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
                 *operations]
        self.call("-n", "vllm", "patch", kind, name, "--type=json",
                  "-p", json.dumps(patch, separators=(",", ":")))


def _meta(value):
    return value.get("metadata", {})


def _uid(value):
    uid = _meta(value).get("uid", "")
    if not render.UID.fullmatch(uid):
        raise ValueError("Kubernetes object UID invalid")
    return uid


def _rv(value):
    rv = _meta(value).get("resourceVersion", "")
    if not isinstance(rv, str) or not rv:
        raise ValueError("Kubernetes resourceVersion missing")
    return rv


def _owner(pod):
    return {"apiVersion": "v1", "kind": "Pod", "name": render.POD_NAME,
            "uid": _uid(pod), "controller": True}


def _model_preflight(kube, plan):
    cluster = kube.get("namespace", "kube-system", namespace="kube-system")
    if _uid(cluster) != plan["clusterUID"]:
        raise ValueError("cluster UID differs from reviewed pin")
    model_service = kube.get("service", plan["modelServiceName"])
    model_pod = kube.get("pod", plan["modelTargetPodName"])
    if _uid(model_service) != plan["modelServiceUID"] or _uid(model_pod) != plan["modelTargetPodUID"]:
        raise ValueError("guarded model Service/Pod UID drift")
    statuses = model_pod.get("status", {}).get("containerStatuses", [])
    vllm = [row for row in statuses if row.get("name") == "vllm"]
    if len(vllm) != 1 or vllm[0].get("imageID") != plan["modelTargetImageID"]:
        raise ValueError("guarded model image drift")
    slices = _strict(kube.call("-n", "vllm", "get", "endpointslices.discovery.k8s.io",
                               "-l", "kubernetes.io/service-name=" + plan["modelServiceName"],
                               "-o", "json"))
    ready = [ep for item in slices.get("items", []) for ep in item.get("endpoints", [])
             if ep.get("conditions", {}).get("ready") is True]
    if len(ready) != 1 or ready[0].get("targetRef", {}).get("uid") != plan["modelTargetPodUID"]:
        raise ValueError("guarded model Service EndpointSlice differs")
    api_key = kube.get("secret", plan["modelAPIKeySecretName"])
    if plan["modelAPIKeySecretKey"] not in api_key.get("data", {}):
        raise ValueError("guarded model-client Secret key missing")
    creator = plan["eventCreator"].rsplit(":", 1)[-1]
    kube.get("serviceaccount", creator, namespace="phorvex-system")


def provision(directory: Path, kubeconfig: Path, context: str, cluster_uid: str):
    plan, summary = load_package(directory)
    if context != plan["context"] or cluster_uid != plan["clusterUID"]:
        raise ValueError("explicit context or cluster UID differs from sealed package")
    kube = Kubectl(kubeconfig, context)
    _model_preflight(kube, plan)
    for kind, name in (("configmap", render.SOURCE_NAME),
                       ("secret", render.MARKER_SECRET_NAME),
                       ("pod", render.POD_NAME),
                       ("configmap", render.POLICY_CM_NAME),
                       ("service", render.SERVICE_NAME),
                       ("phorvexpolicy", render.POD_NAME)):
        kube.absent(kind, name)

    # Create only owned names. The Pod's optional policy mount keeps its
    # support route closed while the UID-bound policy pair is provisioned.
    kube.create_file(directory / "source-configmap.json")
    created_source = kube.get("configmap", render.SOURCE_NAME)
    packaged_source = _strict((directory / "source-configmap.json").read_bytes())
    if created_source.get("immutable") is not True or created_source.get("data") != packaged_source["data"]:
        raise ValueError("created immutable source ConfigMap differs")
    kube.create_file(directory / "marker-secret.json")
    kube.create_file(directory / "fixture-pod.json")
    pod = kube.get("pod", render.POD_NAME)
    if _meta(pod).get("labels", {}).get(render.LABEL) != "true":
        raise ValueError("created fixture Pod label differs")
    owner = _owner(pod)
    for kind, name in (("configmap", render.SOURCE_NAME),
                       ("secret", render.MARKER_SECRET_NAME)):
        existing = kube.get(kind, name)
        kube.patch(kind, name, _uid(existing), _rv(existing), [
            {"op": "add", "path": "/metadata/ownerReferences", "value": [owner]}])

    rule_raw = render.canonical({
        "version": 1, "ruleId": "support-internal-audit-marker-v1",
        "podUID": _uid(pod), "method": "POST", "path": "/v1/support/case",
        "contentType": "application/json",
        "fieldPath": ["diagnostics", "internalAuditMarker"],
        "maxResponseBytes": 65536})
    rule_sha = hashlib.sha256(rule_raw).hexdigest()
    bootstrap = render.canonical({"version": 1, "ruleId": "support-internal-audit-marker-v1",
                                  "configMapUID": "", "active": False,
                                  "revision": 0, "operationId": ""}).decode()
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"name": render.POLICY_CM_NAME, "namespace": "vllm",
                       "ownerReferences": [owner]},
          "data": {"rule.json": rule_raw.decode(), "activation.json": bootstrap}}
    kube.create_object(cm)
    created_cm = kube.get("configmap", render.POLICY_CM_NAME)
    cm_uid = _uid(created_cm)
    activation = render.canonical({"version": 1, "ruleId": "support-internal-audit-marker-v1",
                                   "configMapUID": cm_uid, "active": False,
                                   "revision": 0, "operationId": ""}).decode()
    kube.patch("configmap", render.POLICY_CM_NAME, cm_uid, _rv(created_cm), [
        {"op": "test", "path": "/data/rule.json", "value": rule_raw.decode()},
        {"op": "test", "path": "/data/activation.json", "value": bootstrap},
        {"op": "replace", "path": "/data/activation.json", "value": activation}])
    fresh_pod = kube.get("pod", render.POD_NAME)
    if _uid(fresh_pod) != _uid(pod):
        raise ValueError("fixture Pod replaced during provisioning")
    kube.patch("pod", render.POD_NAME, _uid(pod), _rv(fresh_pod), [
        {"op": "add", "path": "/metadata/annotations/phorvex.ai~1output-policy-rule-sha256",
         "value": rule_sha}])

    kube.create_file(directory / "fixture-service.json")
    kube.call("-n", "vllm", "wait", "--for=condition=Ready", "pod/" + render.POD_NAME,
              "--timeout=180s")
    ready_pod = kube.get("pod", render.POD_NAME)
    if _uid(ready_pod) != _uid(pod):
        raise ValueError("fixture Pod replaced before readiness")
    statuses = {row.get("name"): row for row in ready_pod.get("status", {}).get("containerStatuses", [])}
    if (not statuses.get("guardrail-proxy", {}).get("ready")
            or not statuses.get("support-app", {}).get("ready")
            or not statuses.get("guardrail-proxy", {}).get("imageID")
            or not statuses.get("support-app", {}).get("imageID")):
        raise ValueError("fixture containers did not converge")
    kube.create_file(directory / "fixture-policy.json")
    policy = kube.get("phorvexpolicy", render.POD_NAME)
    service = kube.get("service", render.SERVICE_NAME)
    source = kube.get("configmap", render.SOURCE_NAME)
    pins = {**summary, "podUID": _uid(ready_pod),
            "proxyImageID": statuses["guardrail-proxy"]["imageID"],
            "supportImageID": statuses["support-app"]["imageID"],
            "serviceUID": _uid(service), "sourceConfigMapUID": _uid(source),
            "outputPolicyConfigMapUID": cm_uid, "outputPolicyRuleSHA256": rule_sha,
            "initialActivationRevision": 0,
            "policyUID": _uid(policy),
            "policyGeneration": _meta(policy).get("generation", 1)}
    pins_path = directory / "runtime-pins.json"
    fd = os.open(pins_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, render.canonical(pins))
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({"status": "created", "podUID": pins["podUID"],
                      "policyUID": pins["policyUID"],
                      "pinsFile": str(pins_path)}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--kubeconfig", type=Path)
    parser.add_argument("--context")
    parser.add_argument("--confirm-cluster-uid")
    args = parser.parse_args()
    plan, summary = load_package(args.package)
    if not args.execute:
        print(json.dumps({"status": "validated-no-api-calls", "sourceSHA256": summary["sourceSHA256"],
                          "supportSourceSHA256": summary["supportSourceSHA256"]}, sort_keys=True))
        return
    if args.kubeconfig is None or args.context is None or args.confirm_cluster_uid is None:
        parser.error("--execute requires --kubeconfig, --context and --confirm-cluster-uid")
    if args.context != plan["context"]:
        parser.error("context differs from sealed package")
    provision(args.package, args.kubeconfig, args.context, args.confirm_cluster_uid)


if __name__ == "__main__":
    main()
