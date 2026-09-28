"""Local phased activation renderer. Never initializes or changes legacy rules."""
import argparse
import copy
import json
import os
from pathlib import Path
import re

from policy import LEGACY_FILES, POLICY_NAME, PROFILE_KEYS, UID, HEX, canonical, digest, parse, require, source_digest

ANNOTATION = "phorvex.ai/voice-admission-"
SA = "voice-bot-admission-reader"
LEGACY_PATHS = {
    "VOICE_MEMORY_POLICY_DIR": "/etc/phorvex/voice-memory-policy",
    "VOICE_REFUND_POLICY_DIR": "/etc/phorvex/voice-refund-policy",
    "VOICE_MCP_POLICY_DIR": "/etc/phorvex/voice-mcp-tool-policy",
    "VOICE_OUTPUT_POLICY_DIR": "/etc/phorvex/voice-output-policy",
    "VOICE_MEMORY_STATE_DIR": "/var/lib/phorvex-voice-memory",
    "VOICE_MEMORY_STATE_TOKEN_FILE": "/etc/phorvex/voice-memory-state-token/token",
}


def owned(obj, deployment, kind, name=None):
    meta = obj.get("metadata", {})
    require(obj.get("kind") == kind and meta.get("namespace") == "voice" and
            (name is None or meta.get("name") == name) and UID.fullmatch(meta.get("uid", "")) and
            isinstance(meta.get("resourceVersion"), str) and meta["resourceVersion"].isdecimal() and not meta.get("deletionTimestamp"))
    owners = meta.get("ownerReferences", [])
    require(len(owners) == 1 and owners[0].get("apiVersion") == "apps/v1" and owners[0].get("kind") == "Deployment" and
            owners[0].get("name") == "voice-bot" and owners[0].get("uid") == deployment["metadata"]["uid"] and
            owners[0].get("controller") is True)


def prepare(deployment, legacy, security_policy, ingress, profile_raw, *, directory=Path(__file__).parent):
    meta = deployment.get("metadata", {})
    require(deployment.get("apiVersion") == "apps/v1" and deployment.get("kind") == "Deployment" and
            meta.get("namespace") == "voice" and meta.get("name") == "voice-bot" and UID.fullmatch(meta.get("uid", "")) and
            isinstance(meta.get("resourceVersion"), str) and meta["resourceVersion"].isdecimal() and not meta.get("deletionTimestamp"))
    profile = parse(profile_raw)
    require(set(profile) == PROFILE_KEYS and canonical(profile) == profile_raw and type(profile["version"]) is int and
            profile["version"] == 1 and profile["deploymentUID"] == meta["uid"] and
            profile["publicHost"] == "voicebot.phorvex.ai" and profile["websocketSigningURLs"] == ["wss://voicebot.phorvex.ai/ws"] and
            profile["webhookSigningURL"] == "https://voicebot.phorvex.ai/" and profile["twilioSecretName"] == "voice-secrets" and
            isinstance(profile["authTokenSHA256"], str) and HEX.fullmatch(profile["authTokenSHA256"]))
    policy_meta = security_policy.get("metadata", {})
    require(security_policy.get("kind") == "PhorvexPolicy" and policy_meta.get("namespace") == "voice" and
            policy_meta.get("name") == "voice-defense" and UID.fullmatch(policy_meta.get("uid", "")) and not policy_meta.get("deletionTimestamp"))
    owned(legacy, deployment, "ConfigMap")
    require(legacy.get("immutable") is True and set(legacy.get("data", {})) == set(LEGACY_FILES) and not legacy.get("binaryData"))
    legacy_sha = digest(b"\0".join(legacy["data"][name].encode() for name in LEGACY_FILES))
    require(legacy["metadata"]["name"] == "voice-memory-source-" + legacy_sha[:12])
    # Local historical sources must exactly equal the live immutable bundle.
    for name in LEGACY_FILES:
        require((directory.parent / "voice-memory" / name).read_bytes() == legacy["data"][name].encode())
    rules = ingress.get("spec", {}).get("rules", [])
    require(ingress.get("kind") == "Ingress" and ingress.get("metadata", {}).get("namespace") == "voice" and
            ingress["metadata"].get("name") == "voice-bot-public" and len(rules) == 1 and rules[0].get("host") == profile["publicHost"])
    paths = rules[0].get("http", {}).get("paths", [])
    require(len(paths) == 1 and paths[0].get("path") == "/" and paths[0].get("pathType") == "Prefix" and
            paths[0].get("backend", {}).get("service") == {"name": "voice-bot", "port": {"number": 8080}})
    bot = [c for c in deployment["spec"]["template"]["spec"]["containers"] if c["name"] == "bot"]
    require(len(bot) == 1 and bot[0].get("command") == ["python3", "-B", "/app/bot.py"] and not bot[0].get("args"))
    env = bot[0].get("env", [])
    host = [e for e in env if e["name"] == "PUBLIC_HOST"]
    require(host == [{"name": "PUBLIC_HOST", "value": profile["publicHost"]}] and
            not any(e["name"] in ("PYTHONPATH", "PYTHONHOME") or e["name"].startswith("VOICE_ADMISSION_") for e in env))
    token_sources = [e for e in env if e["name"] == "TWILIO_AUTH_TOKEN"]
    env_from = [e for e in bot[0].get("envFrom", []) if not e.get("prefix")]
    require((not token_sources and env_from == [{"secretRef": {"name": "voice-secrets"}}]) or
            (not env_from and token_sources == [{"name": "TWILIO_AUTH_TOKEN", "valueFrom": {
                "secretKeyRef": {"name": "voice-secrets", "key": "TWILIO_AUTH_TOKEN"}}}]))
    source_sha = source_digest(directory, ("entry.py", "policy.py"))
    joint = digest((directory / "entry.py").read_bytes() + b"\0" + (directory / "policy.py").read_bytes() + b"\0" + profile_raw)
    owner = [{"apiVersion": "apps/v1", "kind": "Deployment", "name": "voice-bot", "uid": meta["uid"],
              "controller": True, "blockOwnerDeletion": False}]
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"namespace": "voice", "name": "voice-admission-source-" + joint[:12],
          "ownerReferences": owner}, "immutable": True, "data": {"entry.py": (directory / "entry.py").read_text(),
          "policy.py": (directory / "policy.py").read_text(), "auth-profile.json": profile_raw.decode()}}
    state = {"sourceSHA": source_sha, "legacySHA": legacy_sha, "profileSHA": digest(profile_raw),
             "deploymentUID": meta["uid"], "securityPolicyUID": policy_meta["uid"]}
    rbac = [{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"namespace": "voice", "name": SA}},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"namespace": "voice", "name": SA},
             "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [POLICY_NAME], "verbs": ["get"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"namespace": "voice", "name": SA},
             "subjects": [{"kind": "ServiceAccount", "namespace": "voice", "name": SA}],
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": SA}}]
    return cm, state, rbac


def new_policy(deployment, wrapper, desired_wrapper, state):
    owned(wrapper, deployment, "ConfigMap", desired_wrapper["metadata"]["name"])
    require(wrapper.get("immutable") is True and wrapper.get("data") == desired_wrapper["data"] and not wrapper.get("binaryData"))
    rule = {"version": 1, "deploymentUID": state["deploymentUID"], "securityPolicyUID": state["securityPolicyUID"],
            "wrapperCMUID": wrapper["metadata"]["uid"], "admissionSourceSHA256": state["sourceSHA"],
            "legacyBundleSHA256": state["legacySHA"], "authProfileSHA256": state["profileSHA"],
            "revision": 0, "mode": "observe", "operationId": ""}
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"namespace": "voice", "name": POLICY_NAME,
            "ownerReferences": desired_wrapper["metadata"]["ownerReferences"]}, "data": {"rule.json": canonical(rule).decode()}}


def deployment_patch(deployment, wrapper, policy, desired_policy, state, image, creator):
    owned(policy, deployment, "ConfigMap", POLICY_NAME)
    require(policy.get("data") == desired_policy["data"] and not policy.get("binaryData") and
            re.fullmatch(r"753556437180\.dkr\.ecr\.us-east-2\.amazonaws\.com/phorvex@sha256:[0-9a-f]{64}", image) and
            re.fullmatch(r"system:serviceaccount:phorvex-system:[a-z0-9-]+", creator))
    before = copy.deepcopy(deployment["spec"]["template"])
    after = copy.deepcopy(before)
    annotations = after["metadata"].setdefault("annotations", {})
    for key, value in {"wrapper-configmap": wrapper["metadata"]["name"], "source-sha256": state["sourceSHA"],
                       "auth-profile-sha256": state["profileSHA"], "legacy-bundle-sha256": state["legacySHA"],
                       "policy-configmap": POLICY_NAME, "event-creator": creator}.items():
        require(ANNOTATION + key not in annotations)
        annotations[ANNOTATION + key] = value
    spec = after["spec"]
    spec["serviceAccountName"], spec["automountServiceAccountToken"] = SA, True
    bot = next(c for c in spec["containers"] if c["name"] == "bot")
    # Explicit literals take precedence over envFrom, without reading its Secret.
    # Existing explicit values must already match; never migrate an old path.
    for name, value in LEGACY_PATHS.items():
        existing = [e for e in bot.get("env", []) if e.get("name") == name]
        require(not existing or existing == [{"name": name, "value": value}])
        if not existing:
            bot.setdefault("env", []).append({"name": name, "value": value})
    bot["command"], bot["workingDir"], bot["image"] = ["python3", "-B", "/opt/voice-admission/entry.py"], "/app", image
    require(not any(m["mountPath"] == "/app" or m["mountPath"] in ("/", "/opt") or
                    m["mountPath"].startswith("/opt/voice-admission") for m in bot.get("volumeMounts", [])))
    spec.setdefault("volumes", []).append({"name": "voice-admission-source", "configMap": {"name": wrapper["metadata"]["name"]}})
    bot.setdefault("volumeMounts", []).append({"name": "voice-admission-source", "mountPath": "/opt/voice-admission", "readOnly": True})
    for name, value in {"DEPLOYMENT_UID": state["deploymentUID"], "SECURITY_POLICY_UID": state["securityPolicyUID"],
                        "POLICY_CM_UID": policy["metadata"]["uid"], "WRAPPER_CM_UID": wrapper["metadata"]["uid"],
                        "SOURCE_SHA256": state["sourceSHA"], "LEGACY_BUNDLE_SHA256": state["legacySHA"],
                        "AUTH_PROFILE_SHA256": state["profileSHA"]}.items():
        bot.setdefault("env", []).append({"name": "VOICE_ADMISSION_" + name, "value": value})
    return [{"op": "test", "path": "/metadata/uid", "value": deployment["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": deployment["metadata"]["resourceVersion"]},
            {"op": "test", "path": "/spec/template", "value": before},
            {"op": "replace", "path": "/spec/template", "value": after}]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("deployment", "legacy-source", "security-policy", "ingress", "auth-profile", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("wrapper", "admission-policy"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--approved-image")
    parser.add_argument("--event-creator")
    args = parser.parse_args()
    read = lambda p: json.loads(p.read_text())
    dep = read(args.deployment)
    cm, state, rbac = prepare(dep, read(args.legacy_source), read(args.security_policy), read(args.ingress), args.auth_profile.read_bytes())
    output = {"wrapper-configmap.json": cm, "runtime-rbac.json": {"apiVersion": "v1", "kind": "List", "items": rbac}, "source-pins.json": state}
    if args.wrapper:
        wrapper = read(args.wrapper)
        policy = new_policy(dep, wrapper, cm, state)
        output["admission-policy-create.json"] = policy
        if args.admission_policy:
            require(args.approved_image and args.event_creator)
            output["deployment-wrapper-patch.json"] = deployment_patch(dep, wrapper, read(args.admission_policy), policy,
                                                                        state, args.approved_image, args.event_creator)
    require(not args.admission_policy or args.wrapper)
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, value in output.items():
        with os.fdopen(os.open(args.out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            file.write(json.dumps(value, indent=2) + "\n")


if __name__ == "__main__":
    main()
