"""Render a Voice refund console profile from reviewed bytes and API snapshots.

Local files only: this tool never contacts Kubernetes or reads credentials.
Snapshots are installation preflight evidence; Fire rechecks live identities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "build/integrations/voice-memory"))
from render_activation import SOURCE_SHA
from voice_memory_policy import parse_refund_rule

CREATOR = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
UID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
DNS = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\Z")
CLIPS = {
    "confirm_other": "581e1e2e9224261a02982b53872239770114b3f60c04e2e8984bf28d3f6db5ed",
    "confirm_own": "0290983c757f711666bada61dcb2c19c465d5753f9ef60508f70698e2b8c43fb",
    "attack": "be4b83510ff1f0a194938432f27821366ef2ef07ec64c140d96e33259fe4a81f",
    "benign": "99e1c867196a96fcdcbb09a5488b847fec2f137d0e3e70c5f903595347397630",
    "own_control": "deebe76b65645a0d320387e6732a31e3c0d4758fb45cef6a037c3d5eaa73a0c2",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def unique_object(pairs: list) -> dict:
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate snapshot key")
        value[key] = item
    return value


def metadata(obj: dict, kind: str, namespace: str, name: str) -> dict:
    meta = obj.get("metadata", {})
    require(obj.get("kind") == kind and meta.get("namespace") == namespace and
            meta.get("name") == name and isinstance(meta.get("uid"), str) and
            bool(UID.fullmatch(meta["uid"])) and bool(meta.get("resourceVersion")) and
            not meta.get("deletionTimestamp"), f"{kind} identity differs")
    return meta


def owned(meta: dict, kind: str, name: str, uid: str) -> bool:
    owners = meta.get("ownerReferences", [])
    return len(owners) == 1 and owners[0].get("apiVersion") == "apps/v1" and \
        owners[0].get("kind") == kind and owners[0].get("name") == name and \
        owners[0].get("uid") == uid and owners[0].get("controller") is True


def bot(spec: dict) -> dict:
    found = [c for c in spec.get("containers", []) if c.get("name") == "bot"]
    require(len(found) == 1, "exact bot container required")
    return found[0]


def check_spec(spec: dict, source_name: str) -> dict:
    container = bot(spec)
    env = container.get("env", [])
    for key in ("VOICE_REFUND_POLICY_REQUIRED", "VOICE_AGENCY_TEST_ENABLED"):
        require([e for e in env if e.get("name") == key] == [{"name": key, "value": "true"}],
                "required refund or agency test mode differs")
    require(container.get("command") == ["python3", "-B", "/app/bot.py"], "bot source command differs")
    mounts = container.get("volumeMounts", [])
    volumes = spec.get("volumes", [])
    for path, subpath, cm_name in (("/app/bot.py", "bot.py", source_name),
                                 ("/app/voice_memory_policy.py", "voice_memory_policy.py", source_name),
                                 ("/etc/phorvex/voice-refund-policy", "", "voice-refund-policy")):
        matches = [m for m in mounts if m.get("mountPath") == path]
        require(len(matches) == 1 and matches[0].get("readOnly") is True and
                matches[0].get("subPath", "") == subpath, "reviewed source or rule mount differs")
        found = [v for v in volumes if v.get("name") == matches[0]["name"]]
        require(len(found) == 1 and found[0].get("configMap", {}).get("name") == cm_name and
                not found[0]["configMap"].get("optional"), "reviewed source or rule volume differs")
    return container


def audit_identity(console: dict) -> str:
    metadata(console, "Deployment", "phorvex-system", "phorvex-phorvex-console")
    spec = console.get("spec", {}).get("template", {}).get("spec", {})
    require(spec.get("serviceAccountName") == "phorvex-phorvex-console", "console creator differs")
    containers = [c for c in spec.get("containers", []) if c.get("name") == "console"]
    require(len(containers) == 1, "console container differs")
    args = containers[0].get("args", [])
    def flag(name: str) -> str:
        values = [arg[len(name) + 2:] for arg in args if arg.startswith("-" + name + "=")]
        require(len(values) == 1, "exact console audit flag required")
        return values[0]
    url, dns = flag("audit-source-url"), flag("audit-source-server-dns")
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname == dns and parsed.port is not None and
            not parsed.username and not parsed.password and parsed.path in ("", "/") and
            not parsed.query and not parsed.fragment and len(url) <= 253 and len(dns) <= 253 and
            bool(DNS.fullmatch(dns)), "exact HTTPS audit source identity required")
    return url + "|" + dns


def render(deployment: dict, policy: dict, source_cm: dict, rule_cm: dict, pods: dict,
           replicasets: dict, console: dict, root: Path = ROOT) -> tuple[bytes, dict, str, bytes]:
    dep = metadata(deployment, "Deployment", "voice", "voice-bot")
    policy_meta = metadata(policy, "PhorvexPolicy", "voice", "voice-defense")
    require(policy.get("spec", {}).get("mode") == "active" and
            "voice-refund-pair-deny" in policy["spec"].get("actions", {}).get("enabled", []),
            "refund action unavailable among normal choices")
    source_name = source_cm.get("metadata", {}).get("name", "")
    source_meta = metadata(source_cm, "ConfigMap", "voice", source_name)
    require(source_name.startswith("voice-memory-source-") and source_cm.get("immutable") is True and
            not source_cm.get("binaryData") and owned(source_meta, "Deployment", "voice-bot", dep["uid"]),
            "immutable Deployment-owned source ConfigMap required")
    app = root / "build/integrations/voice-memory"
    source = [(app / name).read_bytes() for name in ("bot.py", "voice_memory_policy.py")]
    require(sha(b"\0".join(source)) == SOURCE_SHA, "reviewed refund source differs")
    for name, raw in zip(("bot.py", "voice_memory_policy.py"), source):
        require(source_cm.get("data", {}).get(name, "").encode() == raw, "observed source bytes differ")
    cm_meta = metadata(rule_cm, "ConfigMap", "voice", "voice-refund-policy")
    require(owned(cm_meta, "Deployment", "voice-bot", dep["uid"]) and
            set(rule_cm.get("data", {})) == {"rule.json"} and not rule_cm.get("binaryData"),
            "refund ConfigMap owner or shape differs")
    rule = parse_refund_rule(rule_cm["data"]["rule.json"].encode(), SOURCE_SHA)
    require(rule["deploymentUID"] == dep["uid"] and rule["policyUID"] == policy_meta["uid"],
            "refund rule owner or policy differs")
    template = deployment["spec"]["template"]
    annotations = {"phorvex.ai/voice-refund-source-sha256": SOURCE_SHA,
                   "phorvex.ai/voice-refund-policy-configmap": "voice-refund-policy",
                   "phorvex.ai/voice-refund-event-creator": CREATOR}
    require(all(template.get("metadata", {}).get("annotations", {}).get(k) == v
                for k, v in annotations.items()), "Deployment refund annotations differ")
    expected_bot = check_spec(template["spec"], source_name)
    labels = deployment["spec"].get("selector", {}).get("matchLabels", {})
    require(labels and not deployment["spec"]["selector"].get("matchExpressions"), "exact selector required")
    serving = [p for p in pods.get("items", []) if all(p.get("metadata", {}).get("labels", {}).get(k) == v
                                                    for k, v in labels.items())]
    require(type(deployment["spec"].get("replicas")) is int and len(serving) == deployment["spec"]["replicas"] > 0,
            "serving roster differs")
    rs_by_name = {r.get("metadata", {}).get("name"): r for r in replicasets.get("items", [])}
    for pod in serving:
        meta = metadata(pod, "Pod", "voice", pod["metadata"]["name"])
        require(all(meta.get("annotations", {}).get(k) == v for k, v in annotations.items()),
                "serving Pod source or creator differs")
        owners = meta.get("ownerReferences", [])
        require(len(owners) == 1, "serving Pod owner differs")
        rs = rs_by_name.get(owners[0].get("name"), {})
        rs_meta = metadata(rs, "ReplicaSet", "voice", owners[0].get("name", ""))
        require(owned(meta, "ReplicaSet", rs_meta["name"], rs_meta["uid"]) and
                owned(rs_meta, "Deployment", "voice-bot", dep["uid"]), "serving owner chain differs")
        pod_bot = check_spec(pod["spec"], source_name)
        require(pod_bot.get("image") == expected_bot.get("image"), "serving bot image differs")
        status = pod.get("status", {})
        bot_status = [s for s in status.get("containerStatuses", []) if s.get("name") == "bot"]
        require(status.get("phase") == "Running" and status.get("podIP") and
                any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", [])) and
                len(bot_status) == 1 and bot_status[0].get("ready") is True and
                bot_status[0].get("containerID") and bot_status[0].get("imageID"), "serving bot not Ready")
    assets = root / "phorvex/internal/console"
    for phase, expected_sha in CLIPS.items():
        require(sha((assets / f"voice_agency_{phase}.ulaw").read_bytes()) == expected_sha, "fixed agency clip differs")
    probe = (assets / "voice_agency_probe.py").read_bytes()
    require(0 < len(probe) <= 32 << 10, "agency probe exceeds bound")
    profile = {"version": 1, "sourceSHA256": SOURCE_SHA, "probeSHA256": sha(probe),
               "attackClipSHA256": CLIPS["attack"], "benignClipSHA256": CLIPS["benign"],
               "policyName": "voice-defense", "eventCreator": CREATOR,
               "auditSourceIdentity": audit_identity(console), "maxRunSeconds": 900}
    raw = canonical(profile)
    digest = sha(raw)
    cm_name = "phorvex-voice-agency-profile-" + digest[:12]
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
          "namespace": "phorvex-system", "name": cm_name}, "immutable": True,
          "data": {"profile.json": raw.decode()}}
    values = ("phorvex:\n  console:\n    voiceAgencyLive:\n      enabled: true\n"
              f"      configMapName: {cm_name}\n      profileSHA256: {digest}\n"
              f"      deploymentUID: {dep['uid']}\n").encode()
    return raw, cm, digest, values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    names = ("deployment", "policy", "source-cm", "rule-cm", "pods", "replicasets", "console")
    for name in names:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    snapshots = [json.loads(getattr(args, name.replace("-", "_")).read_bytes(),
                           object_pairs_hook=unique_object) for name in names]
    raw, cm, _, values = render(*snapshots)
    args.output_dir.mkdir(mode=0o700)
    for name, content in (("profile.json", raw), ("profile-configmap.json", canonical(cm) + b"\n"),
                          ("console-values.yaml", values)):
        fd = os.open(args.output_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)


if __name__ == "__main__":
    main()
