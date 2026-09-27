"""Render reviewable two-phase GitOps inputs for the real LiteLLM Service.

Phase one installs the source, clients, policy, and protected journal ConfigMaps.
After reading the actual policy CM UID,
phase two emits JSON patches for the *existing* Deployment and Service. The
existing master key is never copied into generated output: the owner must
provision a Secret and replace the old literal env binding during rollout.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re


NAMESPACE = "litellm"
SOURCE_NAME = "phorvex-litellm-admission-gateway"
CLIENTS_NAME = "phorvex-litellm-live-clients"
POLICY_NAME = "phorvex-litellm-client-policy"
PHORVEX_POLICY_NAME = "litellm-live-client"
POLICY_LABEL = "phorvex.ai/litellm-live"
MASTER_SECRET = "phorvex-litellm-master-key"
STATUS_SECRET = "phorvex-litellm-status-token"
TRIAL_SEED_SECRET = "phorvex-litellm-trial-seed"
GATEWAY_SOURCE = Path(__file__).with_name("gateway.py")
HEX = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}\Z")


def canonical(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def manifest(name, data, immutable=False):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": NAMESPACE},
            "data": data, "immutable": immutable}


def render(seed_sha, gateway_image, model_alias,
           deployment=None, service=None, policy_uid=None):
    if (not HEX.fullmatch(seed_sha) or not IMAGE.fullmatch(gateway_image) or
            model_alias != "gpt-4o-mini"):
        raise ValueError("owned LiteLLM render authority invalid")
    source = GATEWAY_SOURCE.read_text()
    source_sha = hashlib.sha256(source.encode()).hexdigest()
    clients = canonical({"version": 2, "seedSHA256": seed_sha, "modelAlias": model_alias})
    state = canonical({"version": 2, "revision": 0, "entries": []})
    objects = {
        "gateway-source-configmap.json": manifest(SOURCE_NAME, {"gateway.py": source}, True),
        "owned-clients-configmap.json": manifest(CLIENTS_NAME, {"clients.json": clients}, True),
        "client-policy-configmap.json": manifest(POLICY_NAME, {"state.json": state}),
        "protected-journal-configmap.json": {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "phorvex-litellm-revoke-journal", "namespace": "phorvex-system",
                         "labels": {"phorvex.ai/litellm-client-revoke-journal": "v2"}},
            "data": {"receipts.json": canonical({"version": 2, "receipts": []})},
        },
        "phorvex-policy.json": {
            "apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy",
            "metadata": {"name": PHORVEX_POLICY_NAME, "namespace": NAMESPACE},
            "spec": {
                "tenant": NAMESPACE,
                "selector": {"matchLabels": {POLICY_LABEL: "true"}},
                "objective": {"lambda": "0.4", "costWeights": {"normSparsity": "0.4", "flowDisruption": "0.6"}},
                "budget": {"maxMovesPerTick": 1, "tickInterval": "10s",
                           "antiOverRotationWindow": "90s", "proactiveFloor": "15m"},
                "slo": {"minAvailableReplicas": 1},
                "assetValue": {"fromLabels": {"app": {"litellm": "0.4"}},
                               "weightSecrets": "0.8", "blastRadiusFromGraph": True},
                "triggers": {"eventDriven": True, "reactiveOnly": True},
                "actions": {"enabled": ["rotate", "quarantine", "litellm-client-revoke"]},
                "mode": "active",
            },
        },
    }
    if deployment is None and service is None and policy_uid is None:
        return objects, source_sha
    if deployment is None or service is None or not policy_uid:
        raise ValueError("phase-two authority incomplete")
    if (deployment.get("kind") != "Deployment" or
            deployment.get("metadata", {}).get("namespace") != NAMESPACE or
            deployment["metadata"].get("name") != "litellm" or
            service.get("kind") != "Service" or
            service.get("metadata", {}).get("namespace") != NAMESPACE or
            service["metadata"].get("name") != "litellm" or
            not service["metadata"].get("uid") or
            len(service.get("spec", {}).get("ports", [])) != 1 or
            service["spec"]["ports"][0].get("port") != 4000 or
            service["spec"]["ports"][0].get("targetPort") != 4000 or
            service["spec"].get("selector") != {"app": "litellm"}):
        raise ValueError("installed LiteLLM service/deployment differs")
    template = deployment["spec"]["template"]
    podspec = template["spec"]
    containers = podspec.get("containers", [])
    if (len(containers) != 1 or containers[0].get("name") != "litellm" or
            any(v.get("name") in ("litellm-live-gateway-source", "litellm-live-clients",
                                  "litellm-live-policy", "litellm-live-status", "litellm-live-trial-seed")
                for v in podspec.get("volumes", [])) or
            any(v.get("name") == "litellm-admission-gateway" for v in containers)):
        raise ValueError("LiteLLM deployment already modified or differs")
    env = containers[0].get("env", [])
    master = [i for i, row in enumerate(env) if row.get("name") == "LITELLM_MASTER_KEY"]
    if len(master) != 1 or not env[master[0]].get("value") or env[master[0]].get("valueFrom"):
        raise ValueError("installed master-key binding differs")
    if not template.get("metadata", {}).get("annotations"):
        annotations_patch = [{"op": "add", "path": "/spec/template/metadata/annotations", "value": {}}]
    else:
        annotations_patch = []
    annotations = {
        "phorvex.ai/litellm-gateway-source-sha256": source_sha,
        "phorvex.ai/litellm-gateway-image": gateway_image,
        "phorvex.ai/litellm-client-policy-configmap-uid": policy_uid,
        "phorvex.ai/litellm-live-service-uid": service["metadata"]["uid"],
        "phorvex.ai/litellm-trial-seed-sha256": seed_sha,
    }
    patch = list(annotations_patch)
    labels = template.get("metadata", {}).get("labels")
    if not isinstance(labels, dict) or labels.get("app") != "litellm" or POLICY_LABEL in labels:
        raise ValueError("installed LiteLLM Pod labels differ")
    patch.append({"op": "add", "path": "/spec/template/metadata/labels/" + POLICY_LABEL.replace("/", "~1"),
                  "value": "true"})
    for key, value in annotations.items():
        patch.append({"op": "add", "path": "/spec/template/metadata/annotations/" + key.replace("/", "~1"),
                      "value": value})
    if not podspec.get("securityContext"):
        patch.append({"op": "add", "path": "/spec/template/spec/securityContext", "value": {"fsGroup": 10001}})
    elif podspec["securityContext"].get("fsGroup") != 10001:
        patch.append({"op": "add", "path": "/spec/template/spec/securityContext/fsGroup", "value": 10001})
    volumes = [
        {"name": "litellm-live-gateway-source", "configMap": {"name": SOURCE_NAME}},
        {"name": "litellm-live-clients", "configMap": {"name": CLIENTS_NAME}},
        # A directory mount, not subPath: Kubelet must project actor updates.
        {"name": "litellm-live-policy", "configMap": {"name": POLICY_NAME}},
        {"name": "litellm-live-status", "secret": {"secretName": STATUS_SECRET, "defaultMode": 288}},
        {"name": "litellm-live-trial-seed", "secret": {"secretName": TRIAL_SEED_SECRET, "defaultMode": 288}},
    ]
    if "volumes" not in podspec:
        patch.append({"op": "add", "path": "/spec/template/spec/volumes", "value": volumes})
    else:
        for volume in volumes:
            patch.append({"op": "add", "path": "/spec/template/spec/volumes/-", "value": volume})
    patch.append({"op": "replace", "path": "/spec/template/spec/containers/0/env/" + str(master[0]),
                  "value": {"name": "LITELLM_MASTER_KEY", "valueFrom": {"secretKeyRef":
                            {"name": MASTER_SECRET, "key": "master-key"}}}})
    sidecar = {
        "name": "litellm-admission-gateway", "image": gateway_image,
        "command": ["python3", "-B", "/opt/phorvex/gateway.py"],
        "ports": [{"name": "admission", "containerPort": 4001, "protocol": "TCP"},
                  {"name": "admission-status", "containerPort": 4002, "protocol": "TCP"}],
        "securityContext": {"allowPrivilegeEscalation": False, "runAsNonRoot": True,
                            "runAsUser": 10001, "runAsGroup": 10001,
                            "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
        "env": [
            {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
            {"name": "LITELLM_MASTER_KEY", "valueFrom": {"secretKeyRef":
                                           {"name": MASTER_SECRET, "key": "master-key"}}},
            {"name": "PHORVEX_LITELLM_CLIENTS_FILE", "value": "/etc/phorvex-litellm/clients.json"},
            {"name": "PHORVEX_LITELLM_POLICY_FILE", "value": "/etc/phorvex-litellm-policy/state.json"},
            {"name": "PHORVEX_LITELLM_STATUS_TOKEN_FILE", "value": "/etc/phorvex-litellm-status/token"},
            {"name": "PHORVEX_LITELLM_TRIAL_SEED_FILE", "value": "/etc/phorvex-litellm-seed/seed"},
            {"name": "PHORVEX_LITELLM_POLICY_CONFIGMAP_UID", "value": policy_uid},
            {"name": "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256", "value": source_sha},
        ],
        "volumeMounts": [
            {"name": "litellm-live-gateway-source", "mountPath": "/opt/phorvex", "readOnly": True},
            {"name": "litellm-live-clients", "mountPath": "/etc/phorvex-litellm", "readOnly": True},
            {"name": "litellm-live-policy", "mountPath": "/etc/phorvex-litellm-policy", "readOnly": True},
            {"name": "litellm-live-status", "mountPath": "/etc/phorvex-litellm-status", "readOnly": True},
            {"name": "litellm-live-trial-seed", "mountPath": "/etc/phorvex-litellm-seed", "readOnly": True},
        ],
        "readinessProbe": {"tcpSocket": {"port": 4001}, "periodSeconds": 5},
    }
    patch.append({"op": "add", "path": "/spec/template/spec/containers/-", "value": sidecar})
    objects["deployment-json-patch.json"] = patch
    objects["service-json-patch.json"] = [
        {"op": "test", "path": "/spec/ports/0/targetPort", "value": 4000},
        {"op": "replace", "path": "/spec/ports/0/targetPort", "value": 4001},
    ]
    return objects, source_sha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-sha256", required=True)
    parser.add_argument("--gateway-image", required=True)
    parser.add_argument("--model-alias", default="gpt-4o-mini")
    parser.add_argument("--deployment-original", type=Path)
    parser.add_argument("--service-original", type=Path)
    parser.add_argument("--policy-cm-uid")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    deployment = json.loads(args.deployment_original.read_text()) if args.deployment_original else None
    service = json.loads(args.service_original.read_text()) if args.service_original else None
    objects, source_sha = render(args.seed_sha256, args.gateway_image, args.model_alias,
                                 deployment, service, args.policy_cm_uid)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, value in objects.items():
        (args.output / name).write_text(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")
    print("gateway-source-sha256", source_sha)
    print("rendered", ",".join(sorted(objects)))


if __name__ == "__main__":
    main()
