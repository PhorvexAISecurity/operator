"""Render an opt-in extension to the existing LiteLLM gateway owner rollout.

Seed-bearing Secret manifests are private deployment inputs; never commit the
output directory. This renderer performs no Kubernetes write.
"""

import argparse
import base64
import json
import os
import hashlib
from pathlib import Path

from render import GATEWAY_SOURCE, canonical, render as render_client


NAMESPACE = "litellm"
OUTPUT_POLICY = "litellm-output-policy"
DOCUMENT_SECRET = "phorvex-litellm-output-document"
PROMPT_SECRET = "phorvex-litellm-output-prompt"
LEGACY_SOURCE_SHA = "59a0521cf3a7621dc6e8db6f0a2f5e0c66a6cad8228253638c039edf110f0450"


def output_source():
    source = GATEWAY_SOURCE.read_text()
    digest = hashlib.sha256(source.encode()).hexdigest()
    name = "phorvex-litellm-admission-gateway-" + digest[:12]
    return name, digest, {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
                          "metadata": {"namespace": NAMESPACE, "name": name},
                          "data": {"gateway.py": source}}


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
    profile = canonical({"version": 2,
                         "documentSeedSHA256": hashlib.sha256(document_seed).hexdigest(),
                         "promptSeedSHA256": hashlib.sha256(prompt_seed).hexdigest(),
                         "maxRunSeconds": 900})
    profile_sha = hashlib.sha256(profile.encode()).hexdigest()
    objects = {
        "gateway-output-source-configmap.json": output_source()[2],
        "output-policy-configmap.json": {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"namespace": NAMESPACE, "name": OUTPUT_POLICY,
                         "ownerReferences": refs},
            "data": {"policy.json": canonical({"version": 2, "revision": 0, "entries": []})}},
        "protected-output-journal-configmap.json": {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"namespace": "phorvex-system", "name": "phorvex-litellm-output-journal",
                         "labels": {"phorvex.ai/litellm-output-policy-journal": "v2"}},
            "data": {"receipts.json": canonical({"version": 2, "receipts": []})}},
        "output-document-secret.json": secret(DOCUMENT_SECRET, document_seed),
        "output-prompt-secret.json": secret(PROMPT_SECRET, prompt_seed),
        "console-output-profile-configmap.json": {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"namespace": "phorvex-system",
                         "name": "phorvex-catalogue-litellm-output-" + profile_sha[:12]},
            "immutable": True, "data": {"profile.json": profile}},
    }
    for slot in range(32):
        name = f"litellm-output-rule-{slot:02d}"
        objects[f"{name}.json"] = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"namespace": NAMESPACE, "name": name, "ownerReferences": refs},
            "data": {"rule.json": ""}}
    return objects


def output_phase_two(deployment, service, policy, client_policy_cm_uid,
                     output_policy_cm_uid, document_secret_uid, prompt_secret_uid,
                     trial_seed_sha, gateway_image, model_alias="gpt-4o-mini",
                     live_profile=None):
    for value in (output_policy_cm_uid, document_secret_uid, prompt_secret_uid):
        if not isinstance(value, str) or not value:
            raise ValueError("output object UID required")
    source_name, source_sha, source_cm = output_source()
    if service.get("spec", {}).get("ports", [{}])[0].get("targetPort") == 4001:
        return output_phase_two_existing(deployment, service, policy, client_policy_cm_uid,
            output_policy_cm_uid, document_secret_uid, prompt_secret_uid,
            trial_seed_sha, gateway_image, live_profile, source_name, source_sha, source_cm)
    objects, source_sha = render_client(trial_seed_sha, gateway_image, model_alias,
                                        deployment, service, policy, client_policy_cm_uid)
    objects["gateway-source-configmap.json"] = source_cm
    patch = objects["deployment-json-patch.json"]
    for row in patch:
        if row.get("path") == "/spec/template/spec/volumes" and row.get("op") == "add":
            for volume in row["value"]:
                if volume.get("name") == "litellm-live-gateway-source":
                    volume["configMap"]["name"] = source_name
        elif row.get("path") == "/spec/template/spec/volumes/-" and row.get("value", {}).get("name") == "litellm-live-gateway-source":
            row["value"]["configMap"]["name"] = source_name
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


def output_phase_two_existing(deployment, service, policy, client_policy_cm_uid,
                              output_policy_cm_uid, document_secret_uid, prompt_secret_uid,
                              trial_seed_sha, gateway_image, live_profile,
                              source_name, source_sha, source_cm):
    """Migrate an installed first-batch gateway without replacing its immutable source."""
    if not isinstance(live_profile, dict) or set(live_profile) != {
            "version", "sourceSHA256", "gatewayImage", "clientsSHA256", "seedSHA256",
            "policyName", "modelAlias", "eventCreator", "auditSourceIdentity", "maxRunSeconds"} or \
            live_profile["version"] != 2 or live_profile["sourceSHA256"] != LEGACY_SOURCE_SHA or \
            live_profile["gatewayImage"] != gateway_image or \
            live_profile["seedSHA256"] != trial_seed_sha or \
            live_profile["policyName"] != "litellm-defense" or \
            live_profile["modelAlias"] != "gpt-4o-mini" or \
            live_profile["maxRunSeconds"] != 900:
        raise ValueError("installed first-batch live profile differs")
    depmeta, svcmeta, policymeta = (deployment.get("metadata", {}), service.get("metadata", {}),
                                    policy.get("metadata", {}))
    if (deployment.get("kind") != "Deployment" or depmeta.get("name") != "litellm" or
            depmeta.get("namespace") != NAMESPACE or not depmeta.get("uid") or
            not depmeta.get("resourceVersion") or
            service.get("kind") != "Service" or svcmeta.get("name") != "litellm" or
            svcmeta.get("namespace") != NAMESPACE or not svcmeta.get("uid") or
            service.get("spec", {}).get("selector") != {"app": "litellm"} or
            len(service.get("spec", {}).get("ports", [])) != 1 or
            service["spec"]["ports"][0].get("port") != 4000 or
            service["spec"]["ports"][0].get("targetPort") != 4001 or
            policy.get("kind") != "PhorvexPolicy" or policymeta.get("name") != "litellm-defense" or
            policymeta.get("namespace") != NAMESPACE or not policymeta.get("uid") or
            type(policymeta.get("generation")) is not int or policymeta["generation"] < 1):
        raise ValueError("installed first-batch owner graph differs")
    actions = policy.get("spec", {}).get("actions", {}).get("enabled", [])
    if ("litellm-client-revoke" not in actions or
            "sensitive-output-policy-activate" in actions or len(actions) < 2 or
            len(actions) != len(set(actions)) or
            policy["spec"].get("tenant") != NAMESPACE or
            policy["spec"].get("selector") != {"matchLabels": {"r6th.io/rotation-target": "true"}} or
            policy["spec"].get("mode") != "active" or
            policy["spec"].get("triggers", {}).get("eventDriven") is not True or
            policy["spec"].get("triggers", {}).get("reactiveOnly") is not True):
        raise ValueError("existing policy action alternatives differ")
    template = deployment.get("spec", {}).get("template", {})
    podspec = template.get("spec", {})
    containers = podspec.get("containers", [])
    volumes = podspec.get("volumes", [])
    if len(containers) != 2 or containers[1].get("name") != "litellm-admission-gateway" or \
            containers[1].get("image") != gateway_image or \
            containers[1].get("command") != ["python3", "-B", "/opt/phorvex/gateway.py"] or \
            template.get("metadata", {}).get("labels", {}).get("app") != "litellm" or \
            template.get("metadata", {}).get("labels", {}).get("r6th.io/rotation-target") != "true":
        raise ValueError("installed gateway sidecar differs")
    annotations = template.get("metadata", {}).get("annotations", {})
    if annotations.get("phorvex.ai/litellm-gateway-source-sha256") != LEGACY_SOURCE_SHA or \
            annotations.get("phorvex.ai/litellm-live-service-uid") != svcmeta["uid"] or \
            annotations.get("phorvex.ai/litellm-client-policy-configmap-uid") != client_policy_cm_uid:
        raise ValueError("installed first-batch annotation authority differs")
    source_indices = [i for i, item in enumerate(volumes)
                      if item.get("name") == "litellm-live-gateway-source" and
                      item.get("configMap", {}).get("name") == "phorvex-litellm-admission-gateway"]
    env_indices = [i for i, item in enumerate(containers[1].get("env", []))
                   if item.get("name") == "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256" and
                   item.get("value") == LEGACY_SOURCE_SHA]
    existing_env = {row.get("name"): row for row in containers[1].get("env", [])}
    existing_mounts = {row.get("name"): row for row in containers[1].get("volumeMounts", [])}
    if len(source_indices) != 1 or len(env_indices) != 1 or any(
            item.get("name", "").startswith("litellm-output-") for item in volumes) or \
            existing_mounts.get("litellm-live-gateway-source") != {
                "name": "litellm-live-gateway-source", "mountPath": "/opt/phorvex", "readOnly": True} or \
            existing_env.get("PHORVEX_LITELLM_POLICY_CONFIGMAP_UID", {}).get("value") != client_policy_cm_uid or \
            existing_env.get("PHORVEX_LITELLM_TRIAL_SEED_FILE", {}).get("value") != "/etc/phorvex-litellm-seed/seed":
        raise ValueError("installed source volume or output state differs")
    profile = dict(live_profile)
    profile["sourceSHA256"] = source_sha
    profile_raw = canonical(profile)
    profile_sha = hashlib.sha256(profile_raw.encode()).hexdigest()
    objects = {
        "gateway-output-source-configmap.json": source_cm,
        "console-live-profile-configmap.json": {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"namespace": "phorvex-system",
                         "name": "phorvex-catalogue-litellm-live-" + profile_sha[:12]},
            "immutable": True, "data": {"profile.json": profile_raw}},
    }
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": depmeta["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": depmeta["resourceVersion"]},
        {"op": "test", "path": "/spec/template/metadata/annotations/phorvex.ai~1litellm-gateway-source-sha256",
         "value": LEGACY_SOURCE_SHA},
        {"op": "replace", "path": "/spec/template/metadata/annotations/phorvex.ai~1litellm-gateway-source-sha256",
         "value": source_sha},
        {"op": "replace", "path": f"/spec/template/spec/volumes/{source_indices[0]}/configMap/name",
         "value": source_name},
        {"op": "replace", "path": f"/spec/template/spec/containers/1/env/{env_indices[0]}/value",
         "value": source_sha},
    ]
    for key, value in {
            "phorvex.ai/litellm-output-policy-configmap-uid": output_policy_cm_uid,
            "phorvex.ai/litellm-output-document-secret-uid": document_secret_uid,
            "phorvex.ai/litellm-output-prompt-secret-uid": prompt_secret_uid}.items():
        if key in annotations:
            raise ValueError("output Pod annotation already installed")
        patch.append({"op": "add", "path": "/spec/template/metadata/annotations/" + key.replace("/", "~1"),
                      "value": value})
    output_volumes = [
        ("litellm-output-policy", "configMap", {"name": OUTPUT_POLICY}, "/etc/phorvex-litellm-output"),
        ("litellm-output-document", "secret", {"secretName": DOCUMENT_SECRET, "defaultMode": 288},
         "/etc/phorvex-litellm-output-doc"),
        ("litellm-output-prompt", "secret", {"secretName": PROMPT_SECRET, "defaultMode": 288},
         "/etc/phorvex-litellm-output-prompt")]
    for name, kind, spec, mount in output_volumes:
        patch.append({"op": "add", "path": "/spec/template/spec/volumes/-",
                      "value": {"name": name, kind: spec}})
        patch.append({"op": "add", "path": "/spec/template/spec/containers/1/volumeMounts/-",
                      "value": {"name": name, "mountPath": mount, "readOnly": True}})
    for name, value in [
            ("PHORVEX_LITELLM_OUTPUT_POLICY_FILE", "/etc/phorvex-litellm-output/policy.json"),
            ("PHORVEX_LITELLM_OUTPUT_D_SEED_FILE", "/etc/phorvex-litellm-output-doc/seed"),
            ("PHORVEX_LITELLM_OUTPUT_P_SEED_FILE", "/etc/phorvex-litellm-output-prompt/seed"),
            ("PHORVEX_LITELLM_OUTPUT_D_SECRET_UID", document_secret_uid),
            ("PHORVEX_LITELLM_OUTPUT_P_SECRET_UID", prompt_secret_uid),
            ("PHORVEX_LITELLM_OUTPUT_POLICY_CONFIGMAP_UID", output_policy_cm_uid),
            ("PHORVEX_LITELLM_OUTPUT_SERVICE_UID", svcmeta["uid"]),
            ("PHORVEX_LITELLM_OUTPUT_DEPLOYMENT_UID", depmeta["uid"])]:
        patch.append({"op": "add", "path": "/spec/template/spec/containers/1/env/-",
                      "value": {"name": name, "value": value}})
    objects["deployment-json-patch.json"] = patch
    objects["existing-policy-json-patch.json"] = [
        {"op": "test", "path": "/metadata/uid", "value": policymeta["uid"]},
        {"op": "test", "path": "/metadata/generation", "value": policymeta["generation"]},
        {"op": "test", "path": "/spec/actions/enabled", "value": actions},
        {"op": "add", "path": "/spec/actions/enabled/-", "value": "sensitive-output-policy-activate"},
    ]
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
    parser.add_argument("--live-profile-original", type=Path,
                        help="required when migrating an already installed first-batch gateway")
    args = parser.parse_args()
    deployment = json.loads(args.deployment_original.read_text())
    values = [args.service_original, args.policy_original, args.trial_seed_sha256,
              args.gateway_image, args.client_policy_cm_uid, args.output_policy_cm_uid,
              args.document_secret_uid, args.prompt_secret_uid]
    if (any(values) or args.live_profile_original) and not all(values):
        raise ValueError("complete phase-two source pins required")
    if all(values):
        service = json.loads(args.service_original.read_text())
        policy = json.loads(args.policy_original.read_text())
        objects, source_sha = output_phase_two(deployment, service, policy,
            args.client_policy_cm_uid, args.output_policy_cm_uid,
            args.document_secret_uid, args.prompt_secret_uid,
            args.trial_seed_sha256, args.gateway_image,
            live_profile=json.loads(args.live_profile_original.read_text())
            if args.live_profile_original else None)
        print("gateway-source-sha256", source_sha)
        if "console-live-profile-configmap.json" in objects:
            migrated = objects["console-live-profile-configmap.json"]["data"]["profile.json"]
            print("migrated-live-profile-sha256", hashlib.sha256(migrated.encode()).hexdigest())
    else:
        objects = output_phase_one(deployment, args.document_seed_file.read_bytes(),
                                   args.prompt_seed_file.read_bytes())
        profile = objects["console-output-profile-configmap.json"]["data"]["profile.json"]
        print("console-output-profile-sha256", hashlib.sha256(profile.encode()).hexdigest())
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    args.output.chmod(0o700)
    for name, value in objects.items():
        target = args.output / name
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")
    print("rendered", ",".join(sorted(objects)))


if __name__ == "__main__":
    main()
