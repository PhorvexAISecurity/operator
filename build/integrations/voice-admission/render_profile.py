"""Render local Console/chart admission pins after exact runtime activation.

No cluster calls or credential reads. Inputs are the returned immutable wrapper
and owner-bound policy objects. Existing legacy policies/journals are never output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
CREATOR = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
UID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
AUDIO_SHA = "6b634936283ce28c2e25b71fa3575d0e23c69839999eed6e917fb52d8d176e37"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def require(value, message):
    if not value:
        raise ValueError(message)


def render(wrapper, policy, audit_url, audit_dns, root=ROOT):
    parsed = urlsplit(audit_url)
    require(parsed.scheme == "https" and parsed.hostname and parsed.port and not parsed.username and not parsed.password and
            parsed.path in ("", "/") and not parsed.query and not parsed.fragment and len(audit_url) <= 253 and
            re.fullmatch(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?", audit_dns) and len(audit_dns) <= 253, "exact HTTPS audit source required")
    wm, pm = wrapper.get("metadata", {}), policy.get("metadata", {})
    require(wrapper.get("apiVersion") == policy.get("apiVersion") == "v1" and wrapper.get("kind") == policy.get("kind") == "ConfigMap" and
            wrapper.get("immutable") is True and wm.get("namespace") == pm.get("namespace") == "voice" and
            UID.fullmatch(wm.get("uid", "")) and UID.fullmatch(pm.get("uid", "")) and pm.get("name") == "voice-session-admission-policy" and
            isinstance(pm.get("resourceVersion"), str) and pm["resourceVersion"] and not wm.get("deletionTimestamp") and not pm.get("deletionTimestamp"), "returned runtime ConfigMap identity required")
    data = wrapper.get("data", {})
    require(set(data) == {"entry.py", "policy.py", "auth-profile.json"} and not wrapper.get("binaryData") and
            all(isinstance(v, str) and v for v in data.values()), "immutable exact wrapper bundle required")
    app = root / "build/integrations/voice-admission"
    require((app / "entry.py").read_text() == data["entry.py"] and (app / "policy.py").read_text() == data["policy.py"], "wrapper differs from reviewed repository bytes")
    profile = json.loads(data["auth-profile.json"], object_pairs_hook=unique)
    require(set(profile) == {"version", "deploymentUID", "publicHost", "websocketSigningURLs", "webhookSigningURL", "twilioSecretName", "authTokenSHA256"} and
            type(profile["version"]) is int and profile["version"] == 1 and UID.fullmatch(profile["deploymentUID"]) and profile["publicHost"] == "voicebot.phorvex.ai" and
            profile["websocketSigningURLs"] == ["wss://voicebot.phorvex.ai/ws"] and profile["webhookSigningURL"] == "https://voicebot.phorvex.ai/" and
            profile["twilioSecretName"] == "voice-secrets" and SHA.fullmatch(profile["authTokenSHA256"]) and
            canonical(profile).decode() == data["auth-profile.json"], "reviewed canonical authentication authority required")
    code_sha = sha((data["entry.py"] + "\0" + data["policy.py"]).encode())
    source_sha = sha((data["entry.py"] + "\0" + data["policy.py"] + "\0" + data["auth-profile.json"]).encode())
    require(wm.get("name") == "voice-admission-source-" + source_sha[:12], "wrapper immutable name differs")
    require(set(policy.get("data", {})) == {"rule.json"} and not policy.get("binaryData"), "exact admission rule required")
    rule = json.loads(policy["data"]["rule.json"], object_pairs_hook=unique)
    require(set(rule) == {"version", "deploymentUID", "securityPolicyUID", "wrapperCMUID", "admissionSourceSHA256", "legacyBundleSHA256", "authProfileSHA256", "revision", "mode", "operationId"} and
            type(rule["version"]) is int and rule["version"] == 1 and rule["deploymentUID"] == profile["deploymentUID"] and UID.fullmatch(rule["securityPolicyUID"]) and
            rule["wrapperCMUID"] == wm["uid"] and rule["admissionSourceSHA256"] == code_sha and rule["authProfileSHA256"] == sha(data["auth-profile.json"].encode()) and
            type(rule["revision"]) is int and rule["revision"] == 0 and rule["mode"] == "observe" and rule["operationId"] == "" and
            canonical(rule).decode() == policy["data"]["rule.json"], "initial one-way admission rule required")
    for meta in (wm, pm):
        owners = meta.get("ownerReferences", [])
        require(len(owners) == 1 and owners[0].get("apiVersion") == "apps/v1" and owners[0].get("kind") == "Deployment" and
                owners[0].get("name") == "voice-bot" and owners[0].get("uid") == profile["deploymentUID"] and owners[0].get("controller") is True,
                "Voice Deployment ownership required")
    legacy = root / "build/integrations/voice-memory"
    legacy_sha = sha(b"\0".join((legacy / name).read_bytes() for name in ("bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py")))
    require(rule["legacyBundleSHA256"] == legacy_sha, "legacy application bundle changed")
    assets = root / "phorvex/internal/console"
    probe = (assets / "voice_admission_probe.py").read_bytes()
    require(0 < len(probe) <= 24 << 10 and sha((assets / "voice_mcp_benign.ulaw").read_bytes()) == AUDIO_SHA, "fixed admission probe/audio differs")
    console_profile = {"version": 1, "deploymentUID": rule["deploymentUID"], "policyCMUID": pm["uid"], "admissionSourceSHA256": code_sha,
        "legacyBundleSHA256": legacy_sha, "authProfileSHA256": rule["authProfileSHA256"], "wrapperConfigMapName": wm["name"],
        "legacyConfigMapName": "voice-memory-source-" + legacy_sha[:12], "probeSHA256": sha(probe), "audioSHA256": AUDIO_SHA,
        "eventCreator": CREATOR, "auditSourceIdentity": audit_url + "|" + audit_dns, "maxRunSeconds": 900}
    raw = canonical(console_profile); profile_sha = sha(raw)
    cm_name = "phorvex-voice-admission-profile-" + profile_sha[:12]
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"namespace": "phorvex-system", "name": cm_name},
          "immutable": True, "data": {"profile.json": raw.decode()}}
    # Runtime source objects and the journal must already be installed. No rearm
    # or old policy manifests are generated by this Console renderer.
    values = {"phorvex": {"voiceAdmission": {"enabled": True, "sourceConfigMapName": wm["name"], "legacyConfigMapName": console_profile["legacyConfigMapName"]},
         "console": {"voiceAdmissionLive": {"enabled": True, "configMapName": cm_name, "profileSHA256": profile_sha,
                     "sourceConfigMapName": wm["name"], "legacyConfigMapName": console_profile["legacyConfigMapName"]}}}}
    return raw, cm, values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper-configmap", type=Path, required=True)
    parser.add_argument("--policy-configmap", type=Path, required=True)
    parser.add_argument("--audit-source-url", required=True)
    parser.add_argument("--audit-source-server-dns", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    wrapper, policy = (json.loads(path.read_bytes(), object_pairs_hook=unique) for path in (args.wrapper_configmap, args.policy_configmap))
    raw, cm, values = render(wrapper, policy, args.audit_source_url, args.audit_source_server_dns)
    args.output_dir.mkdir(mode=0o700)
    for name, content in (("profile.json", raw), ("profile-configmap.json", canonical(cm) + b"\n"),
                          ("console-values.json", canonical(values) + b"\n"), ("umbrella-values.json", canonical({"phorvex": values}) + b"\n")):
        fd = os.open(args.output_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)


if __name__ == "__main__":
    main()
