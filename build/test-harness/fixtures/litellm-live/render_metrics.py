"""Prepare opt-in metrics and source/profile migration; never calls Kubernetes.

Inputs are reviewed nonsecret owner snapshots. Existing ingress policies must
preserve serving/status access. Broad metrics ingress is recorded in bearer mode;
it remains a blocker for the explicitly legacy network protection branch.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

from render import canonical

GATEWAY_SOURCE = Path(__file__).with_name("gateway_metrics.py")


NAMESPACE = "litellm"
NAME = "phorvex-litellm-gateway-metrics"
LABEL = "phorvex.ai/litellm-gateway-metrics"
CONTAINER = "litellm-admission-gateway"
SOURCE_ENV = "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256"
SOURCE_ANNOTATION = "phorvex.ai/litellm-gateway-source-sha256"
IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_VOLUME = "litellm-gateway-metrics-token"
TOKEN_DIRECTORY = "/etc/phorvex-litellm-metrics"
TOKEN_FILE = TOKEN_DIRECTORY + "/token"
TOKEN_ENV = "PHORVEX_LITELLM_METRICS_TOKEN_FILE"
SECRET_NAME = "phorvex-litellm-gateway-metrics-token-v1"
SECRET_KEY = "token"


def protection(protection_mode, metrics_secret_name, metrics_secret_key, source_sha):
    if protection_mode != "bearerToken":
        raise ValueError("explicit bearerToken protection mode required")
    if (not isinstance(metrics_secret_name, str) or not 1 <= len(metrics_secret_name) <= 253 or
            any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in metrics_secret_name.split("."))):
        raise ValueError("valid metrics Secret name required")
    if metrics_secret_key != SECRET_KEY:
        raise ValueError("metrics Secret key must be token")
    return {"mode": protection_mode, "authenticatedSourceSHA256": source_sha,
            "secretName": metrics_secret_name, "secretKey": metrics_secret_key,
            "gatewayNamespace": NAMESPACE, "monitorNamespace": "monitoring", "tokenFile": TOKEN_FILE}


def object_hash(value):
    return hashlib.sha256((canonical(value) + "\n").encode()).hexdigest()


def bind_artifacts(objects):
    closure = objects["metrics-closure.json"]
    closure["artifactsSHA256"] = {name: object_hash(value) for name, value in sorted(objects.items())
                                  if name != "metrics-closure.json"}
    closure["monitoringSpecsSHA256"] = {name: hashlib.sha256(canonical(objects[name]["spec"]).encode()).hexdigest()
        for name in ("metrics-service.json", "metrics-servicemonitor.json", "metrics-networkpolicy.json")}
    return objects


def selected(selector, labels):
    if selector.get("matchExpressions"):
        raise ValueError("review NetworkPolicy matchExpressions before activation")
    return all(labels.get(key) == value for key, value in selector.get("matchLabels", {}).items())


def validate_network(policies, labels, containers, preserve_unisolated_ingress=False,
                     protection_mode="networkEnforced", audit=None):
    ports = {port["name"]: port["containerPort"] for container in containers
             for port in container.get("ports", []) if "name" in port}
    allowed = set()
    selected_policies = 0
    for policy in policies:
        if policy.get("kind") != "NetworkPolicy" or policy.get("metadata", {}).get("namespace") != NAMESPACE:
            raise ValueError("only reviewed LiteLLM NetworkPolicy snapshots are accepted")
        spec = policy["spec"]
        if not selected(spec.get("podSelector", {}), labels):
            continue
        if "Ingress" not in spec.get("policyTypes", ["Ingress"]):
            continue
        selected_policies += 1
        for rule in spec.get("ingress", []):
            for peer in rule.get("from", []):
                for selector_name in ("namespaceSelector", "podSelector"):
                    if peer.get(selector_name, {}).get("matchExpressions"):
                        raise ValueError("review ingress peer matchExpressions before activation")
            if not rule.get("ports"):
                if protection_mode != "bearerToken":
                    raise ValueError("existing ingress permits all ports including metrics")
                allowed.update((4001, 4002))
                if audit is not None:
                    audit.append({"name": policy["metadata"]["name"], "reason": "all ports including metrics"})
                continue
            for port in rule["ports"]:
                if port.get("protocol", "TCP") != "TCP":
                    continue
                number = port.get("port")
                if isinstance(number, str):
                    if number not in ports:
                        raise ValueError("unresolved named ingress port requires owner review")
                    number = ports[number]
                if type(number) is not int:
                    raise ValueError("unbounded ingress port requires owner review")
                end = port.get("endPort", number)
                if type(end) is not int or not 1 <= number <= end <= 65535:
                    raise ValueError("invalid ingress port range requires owner review")
                if number <= 4003 <= end:
                    if protection_mode != "bearerToken":
                        raise ValueError("existing ingress already permits metrics port")
                    if audit is not None:
                        audit.append({"name": policy["metadata"]["name"], "reason": "metrics port admitted"})
                for required in (4001, 4002):
                    if number <= required <= end:
                        allowed.add(required)
    if not selected_policies and preserve_unisolated_ingress:
        return True
    if not selected_policies or allowed != {4001, 4002}:
        raise ValueError("reviewed ingress must preserve admission and protected status access")
    return False


def monitoring_objects(prometheus_labels, metrics_protection=None):
    if (not isinstance(prometheus_labels, dict) or not prometheus_labels or
            any(not isinstance(k, str) or not isinstance(v, str) or not k or not v
                for k, v in prometheus_labels.items())):
        raise ValueError("verified Prometheus pod labels required")
    service_labels = {"app.kubernetes.io/name": NAME}
    objects = {
        "metrics-service.json": {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": NAME, "namespace": NAMESPACE, "labels": service_labels},
            "spec": {"type": "ClusterIP", "selector": {"app": "litellm", LABEL: "enabled"},
                     "ports": [{"name": "gateway-metrics", "port": 4003,
                                "targetPort": "gateway-metrics", "protocol": "TCP"}]}},
        "metrics-servicemonitor.json": {
            "apiVersion": "monitoring.coreos.com/v1", "kind": "ServiceMonitor",
            "metadata": {"name": NAME, "namespace": "monitoring", "labels": {"release": "kube-prom-stack"}},
            "spec": {"selector": {"matchLabels": service_labels},
                     "namespaceSelector": {"matchNames": [NAMESPACE]},
                     "endpoints": [{"port": "gateway-metrics", "path": "/metrics", "scheme": "http",
                                    "interval": "30s", "scrapeTimeout": "5s", "honorLabels": False,
                                    "relabelings": [
                                        {"sourceLabels": ["__meta_kubernetes_namespace"], "targetLabel": "namespace"},
                                        {"sourceLabels": ["__meta_kubernetes_pod_name"], "targetLabel": "pod"},
                                        {"targetLabel": "target", "replacement": "litellm"}]}]}},
        "metrics-networkpolicy.json": {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": NAME, "namespace": NAMESPACE},
            "spec": {"podSelector": {"matchLabels": {"app": "litellm", LABEL: "enabled"}},
                     "policyTypes": ["Ingress"], "ingress": [{
                         "from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "monitoring"}},
                                   "podSelector": {"matchLabels": prometheus_labels}}],
                         "ports": [{"port": 4003, "protocol": "TCP"}]}]}},
    }
    if metrics_protection is not None:
        endpoint = objects["metrics-servicemonitor.json"]["spec"]["endpoints"][0]
        endpoint["authorization"] = {"type": "Bearer", "credentials": {
            "name": metrics_protection["secretName"], "key": metrics_protection["secretKey"], "optional": False}}
        endpoint["followRedirects"] = False
    return objects


def render(deployment=None, profiles=None, networkpolicies=None, prometheus_labels=None,
           output_policy=None, *, enabled=False, preserve_unisolated_ingress=False,
           protection_mode=None, metrics_secret_name=None, metrics_secret_key=None):
    if not enabled:
        return {}  # No opt-in objects, ports, env, source or profile changes by default.
    metrics_protection = protection(protection_mode, metrics_secret_name, metrics_secret_key, "")
    if not isinstance(deployment, dict):
        raise ValueError("exact installed gateway Deployment snapshot required")
    metadata = deployment.get("metadata", {})
    if (deployment.get("kind") != "Deployment" or metadata.get("namespace") != NAMESPACE or
            metadata.get("name") != "litellm" or not metadata.get("uid") or not metadata.get("resourceVersion")):
        raise ValueError("exact installed gateway Deployment snapshot required")
    template = deployment["spec"]["template"]
    if template["spec"].get("securityContext", {}).get("fsGroup") != 10001:
        raise ValueError("installed gateway fsGroup 10001 required for token projection")
    labels = template["metadata"].get("labels", {})
    annotations = template["metadata"].get("annotations", {})
    old_sha = annotations.get(SOURCE_ANNOTATION, "")
    if labels.get("app") != "litellm" or not HEX.fullmatch(old_sha):
        raise ValueError("installed gateway source authority differs")
    if LABEL in labels:
        raise ValueError("metrics already configured; review the owner closure")
    containers = template["spec"]["containers"]
    indices = [i for i, c in enumerate(containers) if c.get("name") == CONTAINER]
    if len(indices) != 1:
        raise ValueError("one installed gateway sidecar required")
    i = indices[0]
    gateway = containers[i]
    if (not IMAGE.fullmatch(gateway.get("image", "")) or
            gateway.get("command") != ["python3", "-B", "/opt/phorvex/gateway.py"]):
        raise ValueError("reviewed source-free runtime digest and command required")
    contract_path = Path(__file__).resolve().parents[4] / "build/integrations/litellm-gateway-runtime/image-contract.json"
    contract = json.loads(contract_path.read_text())
    if gateway["image"] not in (contract["imageByDigest"], contract["baseImage"]):
        raise ValueError("installed image needs separate verified runtime convergence")
    if {p.get("containerPort") for p in gateway.get("ports", [])} != {4001, 4002}:
        raise ValueError("installed admission/status port declarations differ")
    if any(p.get("containerPort") == 4003 or p.get("name") == "gateway-metrics"
           for c in containers for p in c.get("ports", [])):
        raise ValueError("metrics port conflicts with existing container")
    security = gateway.get("securityContext", {})
    if (security.get("runAsUser") != 10001 or security.get("runAsGroup") != 10001 or
            security.get("runAsNonRoot") is not True or security.get("readOnlyRootFilesystem") is not True):
        raise ValueError("reviewed gateway nonroot read-only runtime required")
    env = gateway.get("env", [])
    source_env = [j for j, e in enumerate(env) if e.get("name") == SOURCE_ENV and e.get("value") == old_sha]
    if len(source_env) != 1 or any(e.get("name") in ("PHORVEX_LITELLM_METRICS_ENABLED", TOKEN_ENV, "POD_NAMESPACE", "POD_NAME") for e in env):
        raise ValueError("gateway source/metrics env differs")
    for container in containers:
        for entry in container.get("env", []):
            name, value = entry.get("name", ""), entry.get("value")
            if not value or not any(word in name for word in ("KEY", "TOKEN", "PASSWORD")):
                continue
            # This literal is the installed Secret mount path, never token bytes.
            # Match its exact container, env name and path; all other literals fail.
            if (container.get("name") == CONTAINER and
                    name == "PHORVEX_LITELLM_STATUS_TOKEN_FILE" and
                    value == "/etc/phorvex-litellm-status/token"):
                continue
            if container.get("name") == "litellm" and name == "OPENAI_API_KEY" and value == "sk-placeholder-replace-me":
                continue  # Verified inert installed placeholder, never a credential.
            raise ValueError("owner snapshot must contain Secret references only")
    if any(e.get("name") == "PHORVEX_LITELLM_OUTPUT_POLICY_FILE" for e in env):
        if (not isinstance(output_policy, dict) or output_policy != {"version": 2, "revision": 0, "entries": []}):
            raise ValueError("output policy must be quiescent before source migration")
    volumes = template["spec"].get("volumes", [])
    if any(v.get("name") == TOKEN_VOLUME for v in volumes):
        raise ValueError("metrics token volume already configured")
    for container in containers:
        for mount in container.get("volumeMounts", []):
            path = mount.get("mountPath", "").rstrip("/")
            if (mount.get("name") == TOKEN_VOLUME or not path or path == TOKEN_DIRECTORY or
                    TOKEN_DIRECTORY.startswith(path + "/") or path.startswith(TOKEN_DIRECTORY + "/")):
                raise ValueError("metrics token mount conflict requires owner review")
    source_volume = [j for j, v in enumerate(volumes) if v.get("name") == "litellm-live-gateway-source"]
    if len(source_volume) != 1 or "configMap" not in volumes[source_volume[0]]:
        raise ValueError("installed source volume differs")
    if volumes[source_volume[0]]["configMap"].get("name") != "phorvex-litellm-admission-gateway-" + old_sha[:12]:
        raise ValueError("installed source volume is outside the reviewed source closure")
    opted_labels = {**labels, LABEL: "enabled"}
    network_audit = []
    was_unisolated = validate_network(networkpolicies or [], opted_labels, containers, preserve_unisolated_ingress,
                                     protection_mode, network_audit)
    objects = monitoring_objects(prometheus_labels, metrics_protection)
    if was_unisolated:
        # Explicitly preserve all currently declared serving/status listeners.
        # No selectors on this rule: the baseline had no ingress isolation.
        objects["metrics-networkpolicy.json"]["spec"]["ingress"].append(
            {"ports": [{"protocol": "TCP", "port": port} for port in (4000, 4001, 4002)]})
    source = GATEWAY_SOURCE.read_text()
    source_sha = hashlib.sha256(source.encode()).hexdigest()
    if source_sha != contract["gatewaySourceSHA256"]:
        raise ValueError("candidate source is outside the reviewed runtime contract")
    if old_sha != contract["legacyGatewaySourceSHA256"]:
        raise ValueError("installed source is outside the preserved engine contract")
    metrics_protection["authenticatedSourceSHA256"] = source_sha
    source_name = "phorvex-litellm-admission-gateway-" + source_sha[:12]
    objects["gateway-metrics-source-configmap.json"] = {
        "apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
        "metadata": {"namespace": NAMESPACE, "name": source_name}, "data": {"gateway.py": source}}
    bindings = []
    if not profiles:
        raise ValueError("all enabled source-bound catalogue profiles must be supplied")
    for profile in profiles:
        meta = profile.get("metadata", {})
        if (profile.get("kind") != "ConfigMap" or profile.get("immutable") is not True or
                meta.get("namespace") != "phorvex-system" or not meta.get("name") or
                set(profile.get("data", {})) != {"profile.json"}):
            raise ValueError("immutable catalogue profile snapshot required")
        value = json.loads(profile["data"]["profile.json"])
        if value.get("sourceSHA256") != old_sha:
            raise ValueError("catalogue profile source differs")
        if (profile["data"]["profile.json"] != canonical(value) or
                not meta["name"].endswith(hashlib.sha256(profile["data"]["profile.json"].encode()).hexdigest()[:12]) or
                value.get("gatewayImage", gateway["image"]) != gateway["image"]):
            raise ValueError("catalogue profile hash/runtime differs")
        value["sourceSHA256"] = source_sha
        value["gatewayImage"] = contract["imageByDigest"]
        raw = canonical(value)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        # The owner records these derived bindings in M1b, never in M1a values.
        name = meta["name"].rsplit("-", 1)[0] + "-" + digest[:12]
        candidate = copy.deepcopy(profile)
        candidate["metadata"] = {"namespace": "phorvex-system", "name": name}
        candidate["data"]["profile.json"] = raw
        objects[f"{name}.json"] = candidate
        bindings.append({"previousConfigMapName": meta["name"], "configMapName": name,
                         "profileSHA256": digest, "sourceConfigMapName": source_name})
    candidate_template = copy.deepcopy(template)
    candidate_template["metadata"]["annotations"][SOURCE_ANNOTATION] = source_sha
    candidate_template["metadata"]["annotations"]["phorvex.ai/litellm-gateway-image"] = contract["imageByDigest"]
    candidate_template["metadata"]["labels"][LABEL] = "enabled"
    candidate_template["spec"]["volumes"][source_volume[0]]["configMap"]["name"] = source_name
    candidate_gateway = candidate_template["spec"]["containers"][i]
    candidate_gateway["image"] = contract["imageByDigest"]
    candidate_gateway["env"][source_env[0]]["value"] = source_sha
    candidate_template["spec"]["volumes"].append({"name": TOKEN_VOLUME, "secret": {
        "secretName": metrics_secret_name, "optional": False, "defaultMode": 288,
        "items": [{"key": metrics_secret_key, "path": "token", "mode": 288}]}})
    candidate_gateway["volumeMounts"].append({"name": TOKEN_VOLUME, "mountPath": TOKEN_DIRECTORY, "readOnly": True})
    candidate_gateway["ports"].append({"name": "gateway-metrics", "containerPort": 4003, "protocol": "TCP"})
    candidate_gateway["env"].extend([
        {"name": "PHORVEX_LITELLM_METRICS_ENABLED", "value": "1"},
        {"name": TOKEN_ENV, "value": TOKEN_FILE},
        {"name": "POD_NAMESPACE", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.namespace"}}},
        {"name": "POD_NAME", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "metadata.name"}}}])
    candidate_spec = {**copy.deepcopy(deployment["spec"]), "template": candidate_template}
    objects["deployment-metrics-json-patch.json"] = [
        {"op": "test", "path": "/metadata/uid", "value": metadata["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": metadata["resourceVersion"]},
        {"op": "test", "path": "/spec", "value": deployment["spec"]},
        {"op": "replace", "path": "/spec/template", "value": candidate_template}]
    objects["deployment-metrics-rollback-json-patch.json"] = [
        {"op": "test", "path": "/metadata/uid", "value": metadata["uid"]},
        {"op": "test", "path": "/spec", "value": candidate_spec},
        {"op": "replace", "path": "/spec/template", "value": template}]
    objects["metrics-closure.json"] = {"schema": "phorvex-litellm-metrics-candidate-v2",
        "metricsProtection": metrics_protection, "nativeVLLMPolicy": "hardGate", "nativeDecision": "B",
        "candidateTemplateSHA256": hashlib.sha256(canonical(candidate_template).encode()).hexdigest(),
        "networkAudit": {"existingMetricsIngress": network_audit, "enforcement": "not inferred from policies"},
        "gatewaySourceSHA256": source_sha, "previousGatewaySourceSHA256": old_sha,
        "gatewayImageByDigest": contract["imageByDigest"], "previousGatewayImageByDigest": gateway["image"],
        "sourceConfigMapName": source_name, "previousIngressUnisolated": was_unisolated,
        "profiles": bindings,
        "engineContract": {"status": "activation-required",
                           "installedSourceSHA256": old_sha,
                           "candidateSourceSHA256": source_sha,
                           "candidateSourceConfigMapName": source_name},
        "activation": "S5b only after compatible release, actual-image/auth/idle proof and healthy native vLLM"}
    for obj in objects.values():
        if isinstance(obj, dict) and obj.get("kind") in ("ConfigMap", "Service", "ServiceMonitor", "NetworkPolicy"):
            obj["metadata"].setdefault("annotations", {})["helm.sh/resource-policy"] = "keep"
            obj["metadata"]["annotations"]["argocd.argoproj.io/sync-options"] = "Prune=false,Delete=false"
    return bind_artifacts(objects)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--enable-metrics", action="store_true")
    parser.add_argument("--preserve-unisolated-ingress", action="store_true")
    parser.add_argument("--protection-mode")
    parser.add_argument("--metrics-secret-name")
    parser.add_argument("--metrics-secret-key")
    for name in ("deployment-original", "profiles-original", "networkpolicies-original", "prometheus-pod-labels", "output-policy-original"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    def read(path):
        return json.loads(path.read_text()) if path else None
    objects = render(read(args.deployment_original), read(args.profiles_original),
                     read(args.networkpolicies_original), read(args.prometheus_pod_labels),
                     read(args.output_policy_original), enabled=args.enable_metrics,
                     preserve_unisolated_ingress=args.preserve_unisolated_ingress,
                     protection_mode=args.protection_mode, metrics_secret_name=args.metrics_secret_name,
                     metrics_secret_key=args.metrics_secret_key)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, value in objects.items():
        (args.output / name).write_text(canonical(value) + "\n")
    print("rendered", ",".join(sorted(objects)) or "disabled")


if __name__ == "__main__":
    main()
