"""Offline SDK-only image overlay; assert every pre-existing dependency/file."""
from importlib import metadata
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def installed():
    return {dist.metadata["Name"].lower().replace("_", "-"): dist.version for dist in metadata.distributions()}


def files():
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in Path("/app").rglob("*") if path.is_file()}


def main():
    before, source = installed(), files()
    if "twilio" in before or before.get("pipecat-ai") != "0.0.94":
        raise SystemExit("unreviewed base dependency set")
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes",
                    "--find-links=/opt/admission-sdk/wheelhouse", "-r", "/opt/admission-sdk/requirements.lock"], check=True)
    after = installed()
    if after != before | {"twilio": "9.8.4"} or files() != source:
        raise SystemExit("overlay changed pre-existing dependency or /app bytes")
    from twilio.request_validator import RequestValidator
    validator = RequestValidator("local-build-control")
    url = "wss://voicebot.phorvex.ai/ws"
    if not validator.validate(url, {}, validator.compute_signature(url, {})):
        raise SystemExit("official validator positive control failed")
    Path("/opt/admission-sdk/attestation.json").write_text(json.dumps({"version": 1, "added": {"twilio": "9.8.4"},
        "preservedDependencies": before, "preservedAppSHA256": source}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
