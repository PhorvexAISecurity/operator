"""Render an opt-in extension to the existing LiteLLM gateway owner rollout.

Seed-bearing Secret manifests are private deployment inputs; never commit the
output directory. This renderer performs no Kubernetes write.
"""

import argparse
import base64
import json
from pathlib import Path

from render import canonical, render as render_client


NAMESPACE = "litellm"
OUTPUT_POLICY = "litellm-output-policy"
DOCUMENT_SECRET = "phorvex-litellm-output-document"
PROMPT_SECRET = "phorvex-litellm-output-prompt"


def owner(deployment):
    metadata = deployment.get("metadata", {})
    if (deployment.get("kind") != "Deployment" or metadata.get("namespace") != NAMESPACE or
            metadata.get("name") != "litellm" or not metadata.get("uid")):
        raise ValueError("exact LiteLLM Deployment owner required")
    return [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "litellm",
             "uid": metadata["uid"], "controller": True, "blockOwnerDeletion": True}]


def output_phase_one(deployment, document_seed: bytes, prompt_seed: bytes):
    refs = owner(deployment)
    for seed in (document_seed, prompt_seed):
        if not isinstance(seed, bytes) or not 32 <= len(seed) <= 64:
            raise ValueError("private output seed bound")
    if document_seed == prompt_seed:
        raise ValueError("distinct private output origins required")
    def secret(name, seed):
        return {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                "metadata": {"namespace": NAMESPACE, "name": name,
                             "ownerReferences": refs},
                "immutable": True, "data": {"seed": base64.b64encode(seed).decode()}}
    return {
        "output-policy-configmap.json": {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"namespace": NAMESPACE, "name": OUTPUT_POLICY,
                         "ownerReferences": refs},
            "data": {"policy.json": canonical({"version": 2, "revision": 0, "entries": []})}},
        "output-document-secret.json": secret(DOCUMENT_SECRET, document_seed),
        "output-prompt-secret.json": secret(PROMPT_SECRET, prompt_seed),
    }


def output_phase_two(deployment, service, policy, client_policy_cm_uid,
                     output_policy_cm_uid, document_secret_uid, prompt_secret_uid,
                     trial_seed_sha, gateway_image, model_alias="gpt-4o-mini"):
    for value in (output_policy_cm_uid, document_secret_uid, prompt_secret_uid):
        if not isinstance(value, str) or not value:
            raise ValueError("output object UID required")
    objects, source_sha = render_client(trial_seed_sha, gateway_image, model_alias,
                                        deployment, service, policy, client_policy_cm_uid)
    patch = objects["deployment-json-patch.json"]
    sidecar = patch[-1]
    if (sidecar.get("op") != "add" or sidecar.get("path") != "/spec/template/spec/containers/-" or
            sidecar["value"].get("name") != "litellm-admission-gateway"):
        raise ValueError("base gateway patch differs")
    annotations = {
        "phorvex.ai/litellm-output-policy-configmap-uid": output_policy_cm_uid,
        "phorvex.ai/litellm-output-document-secret-uid": document_secret_uid,
        "phorvex.ai/litellm-output-prompt-secret-uid": prompt_secret_uid,
    }
    for key, value in annotations.items():
        patch.insert(-1, {"op": "add", "path": "/spec/template/metadata/annotations/" + key.replace("/", "~1"),
                          "value": value})
    volumes = [
        ("litellm-output-policy", "configMap", {"name": OUTPUT_POLICY}, "/etc/phorvex-litellm-output"),
        ("litellm-output-document", "secret", {"secretName": DOCUMENT_SECRET, "defaultMode": 288},
         "/etc/phorvex-litellm-output-doc"),
        ("litellm-output-prompt", "secret", {"secretName": PROMPT_SECRET, "defaultMode": 288},
         "/etc/phorvex-litellm-output-prompt"),
    ]
    volume_patch = next((x for x in patch if x.get("path") == "/spec/template/spec/volumes"), None)
    if volume_patch is not None:
        volume_patch["value"].extend({"name": name, kind: spec} for name, kind, spec, _ in volumes)
    else:
        for name, kind, spec, _ in volumes:
            patch.insert(-1, {"op": "add", "path": "/spec/template/spec/volumes/-",
                              "value": {"name": name, kind: spec}})
    container = sidecar["value"]
    container["volumeMounts"].extend({"name": name, "mountPath": mount, "readOnly": True}
                                      for name, _, _, mount in volumes)
    container["env"].extend([
        {"name": "PHORVEX_LITELLM_OUTPUT_POLICY_FILE",
         "value": "/etc/phorvex-litellm-output/policy.json"},
        {"name": "PHORVEX_LITELLM_OUTPUT_D_SEED_FILE",
         "value": "/etc/phorvex-litellm-output-doc/seed"},
        {"name": "PHORVEX_LITELLM_OUTPUT_P_SEED_FILE",
         "value": "/etc/phorvex-litellm-output-prompt/seed"},
        {"name": "PHORVEX_LITELLM_OUTPUT_D_SECRET_UID", "value": document_secret_uid},
        {"name": "PHORVEX_LITELLM_OUTPUT_P_SECRET_UID", "value": prompt_secret_uid},
        {"name": "PHORVEX_LITELLM_OUTPUT_POLICY_CONFIGMAP_UID", "value": output_policy_cm_uid},
        {"name": "PHORVEX_LITELLM_OUTPUT_SERVICE_UID", "value": service["metadata"]["uid"]},
        {"name": "PHORVEX_LITELLM_OUTPUT_DEPLOYMENT_UID", "value": deployment["metadata"]["uid"]},
    ])
    policy_patch = objects["existing-policy-json-patch.json"]
    old_actions = policy["spec"]["actions"]["enabled"]
    if "sensitive-output-policy-activate" in old_actions:
        raise ValueError("output action already present in existing policy")
    policy_patch.append({"op": "add", "path": "/spec/actions/enabled/-",
                         "value": "sensitive-output-policy-activate"})
    return objects, source_sha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployment-original", required=True, type=Path)
    parser.add_argument("--document-seed-file", required=True, type=Path)
    parser.add_argument("--prompt-seed-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--service-original", type=Path)
    parser.add_argument("--policy-original", type=Path)
    parser.add_argument("--trial-seed-sha256")
    parser.add_argument("--gateway-image")
    parser.add_argument("--client-policy-cm-uid")
    parser.add_argument("--output-policy-cm-uid")
    parser.add_argument("--document-secret-uid")
    parser.add_argument("--prompt-secret-uid")
    args = parser.parse_args()
    deployment = json.loads(args.deployment_original.read_text())
    values = [args.service_original, args.policy_original, args.trial_seed_sha256,
              args.gateway_image, args.client_policy_cm_uid, args.output_policy_cm_uid,
              args.document_secret_uid, args.prompt_secret_uid]
    if any(values) and not all(values):
        raise ValueError("complete phase-two source pins required")
    if all(values):
        service = json.loads(args.service_original.read_text())
        policy = json.loads(args.policy_original.read_text())
        objects, source_sha = output_phase_two(deployment, service, policy,
            args.client_policy_cm_uid, args.output_policy_cm_uid,
            args.document_secret_uid, args.prompt_secret_uid,
            args.trial_seed_sha256, args.gateway_image)
        print("gateway-source-sha256", source_sha)
    else:
        objects = output_phase_one(deployment, args.document_seed_file.read_bytes(),
                                   args.prompt_seed_file.read_bytes())
    args.output.mkdir(parents=True, exist_ok=False)
    for name, value in objects.items():
        (args.output / name).write_text(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")
    print("rendered", ",".join(sorted(objects)))


if __name__ == "__main__":
    main()
