"""Render reviewable two-phase GitOps inputs for the real LiteLLM Service.

Phase one installs the three ConfigMaps. After reading the actual policy CM UID,
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
MASTER_SECRET = "phorvex-litellm-master-key"
STATUS_SECRET = "phorvex-litellm-status-token"
GATEWAY_SOURCE = Path(__file__).with_name("gateway.py")
HEX = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}\Z")


def canonical(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def manifest(name, data, immutable=False):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": NAMESPACE},
            "data": data, "immutable": immutable}


def render(attacker_sha, control_sha, gateway_image, model_alias,
           deployment=None, service=None, policy_uid=None):
    if (not HEX.fullmatch(attacker_sha) or not HEX.fullmatch(control_sha) or
            attacker_sha == control_sha or not IMAGE.fullmatch(gateway_image) or
            model_alias not in ("gpt-3.5-turbo", "gpt-4o-mini")):
        raise ValueError("owned LiteLLM render authority invalid")
    source = GATEWAY_SOURCE.read_text()
    source_sha = hashlib.sha256(source.encode()).hexdigest()
    clients = canonical({"version": 1, "attackerSHA256": attacker_sha,
                         "controlSHA256": control_sha, "modelAlias": model_alias})
    state = canonical({"version": 1, "active": False, "revision": 0,
                       "operationId": "", "clientSHA256": attacker_sha})
    objects = {
        "gateway-source-configmap.json": manifest(SOURCE_NAME, {"gateway.py": source}, True),
        "owned-clients-configmap.json": manifest(CLIENTS_NAME, {"clients.json": clients}, True),
        "client-policy-configmap.json": manifest(POLICY_NAME, {"state.json": state}),
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
                                  "litellm-live-policy", "litellm-live-status")
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
        "phorvex.ai/litellm-owned-client-sha256": attacker_sha,
    }
    patch = list(annotations_patch)
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
        "command": ["python", "-B", "/opt/phorvex/gateway.py"],
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
            {"name": "PHORVEX_LITELLM_POLICY_CONFIGMAP_UID", "value": policy_uid},
            {"name": "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256", "value": source_sha},
        ],
        "volumeMounts": [
            {"name": "litellm-live-gateway-source", "mountPath": "/opt/phorvex", "readOnly": True},
            {"name": "litellm-live-clients", "mountPath": "/etc/phorvex-litellm", "readOnly": True},
            {"name": "litellm-live-policy", "mountPath": "/etc/phorvex-litellm-policy", "readOnly": True},
            {"name": "litellm-live-status", "mountPath": "/etc/phorvex-litellm-status", "readOnly": True},
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
    parser.add_argument("--attacker-sha256", required=True)
    parser.add_argument("--control-sha256", required=True)
    parser.add_argument("--gateway-image", required=True)
    parser.add_argument("--model-alias", default="gpt-4o-mini")
    parser.add_argument("--deployment-original", type=Path)
    parser.add_argument("--service-original", type=Path)
    parser.add_argument("--policy-cm-uid")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    deployment = json.loads(args.deployment_original.read_text()) if args.deployment_original else None
    service = json.loads(args.service_original.read_text()) if args.service_original else None
    objects, source_sha = render(args.attacker_sha256, args.control_sha256,
                                 args.gateway_image, args.model_alias,
                                 deployment, service, args.policy_cm_uid)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, value in objects.items():
        (args.output / name).write_text(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")
    print("gateway-source-sha256", source_sha)
    print("rendered", ",".join(sorted(objects)))


if __name__ == "__main__":
    main()
