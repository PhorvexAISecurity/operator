"""Render the exact Voice output console profile from reviewed source bytes.

This tool writes local files only. It does not read cluster credentials or call Kubernetes.
The operator supplies the audit source URL and DNS values from the intended Helm release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from render_activation import OUTPUT_SOURCE_SHA


ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "build/integrations/voice-memory"
CONSOLE = ROOT / "phorvex/internal/console"
CREATOR = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
ATTACK_SHA = "eeb77c21eb175368c0a0658525bc81487d77344d1821bef95fecdf45e30ecaa4"
BENIGN_SHA = "bbc1efce2f7380b634726666e884fafae5716482cacf510ee4f164dfbb357d9d"
DNS = re.compile(r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?\Z")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def render(audit_url: str, audit_dns: str, root: Path = ROOT) -> tuple[bytes, dict, str]:
    parsed = urlsplit(audit_url)
    if (parsed.scheme != "https" or not parsed.hostname or not parsed.port or parsed.username or parsed.password or
            parsed.path not in ("", "/") or parsed.query or parsed.fragment or len(audit_url) > 253 or
            not DNS.fullmatch(audit_dns) or len(audit_dns) > 253):
        raise ValueError("exact HTTPS audit source URL and server DNS are required")
    app = root / "build/integrations/voice-memory"
    console = root / "phorvex/internal/console"
    bot, memory, output = ((app / name).read_bytes() for name in (
        "bot.py", "voice_memory_policy.py", "voice_output_policy.py"))
    source_sha = sha(bot + b"\0" + memory + b"\0" + output)
    if source_sha != OUTPUT_SOURCE_SHA:
        raise ValueError("Voice output source differs from the reviewed joint renderer")
    attack_sha = sha((console / "voice_output_attack.ulaw").read_bytes())
    benign_sha = sha((console / "voice_output_benign.ulaw").read_bytes())
    if attack_sha != ATTACK_SHA or benign_sha != BENIGN_SHA:
        raise ValueError("fixed Voice output clip differs")
    probe = (console / "voice_output_probe.py").read_bytes()
    if not probe or len(probe) > 24 << 10:
        raise ValueError("fixed Voice output probe exceeds bound")
    profile = {
        "version": 1,
        "sourceSHA256": source_sha,
        "probeSHA256": sha(probe),
        "attackClipSHA256": attack_sha,
        "benignClipSHA256": benign_sha,
        "policyName": "voice-defense",
        "eventCreator": CREATOR,
        "auditSourceIdentity": audit_url + "|" + audit_dns,
        "maxRunSeconds": 900,
    }
    raw = canonical(profile)
    profile_sha = sha(raw)
    cm_name = "phorvex-voice-output-profile-" + profile_sha[:12]
    cm = {"apiVersion": "v1", "kind": "ConfigMap",
          "metadata": {"namespace": "phorvex-system", "name": cm_name},
          "immutable": True, "data": {"profile.json": raw.decode("utf-8")}}
    return raw, cm, profile_sha


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-source-url", required=True)
    parser.add_argument("--audit-source-server-dns", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    raw, cm, profile_sha = render(args.audit_source_url, args.audit_source_server_dns)
    args.output_dir.mkdir(mode=0o700)
    def write(name: str, value: bytes) -> None:
        fd = os.open(args.output_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
    write("profile.json", raw)
    write("profile-configmap.json", canonical(cm) + b"\n")
    values = ("phorvex:\n  console:\n    voiceOutputLive:\n      enabled: true\n"
              f"      configMapName: {cm['metadata']['name']}\n"
              f"      profileSHA256: {profile_sha}\n")
    write("console-values.yaml", values.encode("utf-8"))


if __name__ == "__main__":
    main()
