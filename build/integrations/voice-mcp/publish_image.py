"""Main-only, one-attempt MCP dependency image build and registry publication.

Run only after the reviewed source is merged and existing Docker registry auth
is available. This helper performs no login, Kubernetes call, or source rollout.
It writes a private receipt containing source and immutable image digests.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from verify_wheelhouse import verify


HERE = Path(__file__).resolve().parent
REGISTRY = "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex"
SOURCE_SHA256 = "85cbd0f201b9b65e3b7cc770aed28884fc9835130cc61154499b873537883252"


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bounded_command(argv, timeout=60, limit=1024 * 1024):
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(argv, cwd=HERE, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr, start_new_session=True)
        started = time.monotonic()
        while proc.poll() is None:
            if time.monotonic() - started > timeout or \
                    os.fstat(stdout.fileno()).st_size > limit or os.fstat(stderr.fileno()).st_size > limit:
                os.killpg(proc.pid, 15)
                proc.wait(timeout=5)
                raise RuntimeError("bounded image command exceeded time/output limit")
            time.sleep(0.25)
        if os.fstat(stdout.fileno()).st_size > limit or \
                os.fstat(stderr.fileno()).st_size > limit or proc.returncode:
            raise RuntimeError("image command failed or output exceeded limit")
        stdout.seek(0)
        return stdout.read()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--receipt-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.publish or args.receipt_dir.exists():
        raise SystemExit("exact --publish and new private receipt directory required")
    branch = bounded_command(["git", "branch", "--show-current"]).decode().strip()
    head = bounded_command(["git", "rev-parse", "HEAD"]).decode().strip()
    if branch != "main" or not re.fullmatch(r"[0-9a-f]{40}", head) or \
            bounded_command(["git", "status", "--porcelain"]):
        raise SystemExit("MCP image publication requires clean merged main")
    if sha(HERE / "server.py") != SOURCE_SHA256:
        raise SystemExit("MCP server source changed")
    count = verify(HERE / "requirements.lock", HERE / "wheelhouse.sha256", HERE / "wheelhouse")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tag = f"voice-mcp-{head[:12]}-{SOURCE_SHA256[:12]}-{stamp}"
    image = REGISTRY + ":" + tag
    args.receipt_dir.mkdir(mode=0o700)
    receipt_path = args.receipt_dir / "receipt.json"
    receipt = {"status": "INCOMPLETE", "gitHead": head, "sourceSHA256": SOURCE_SHA256,
               "lockSHA256": sha(HERE / "requirements.lock"),
               "wheelManifestSHA256": sha(HERE / "wheelhouse.sha256"),
               "dockerfileSHA256": sha(HERE / "Dockerfile"), "wheelCount": count,
               "imageTag": image, "registryPushAttempts": 0}
    def save():
        descriptor = os.open(receipt_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
    save()
    try:
        bounded_command(["docker", "build", "--network=none", "--pull=false", "--quiet",
                         "-t", image, str(HERE)], timeout=900)
        inspected = json.loads(bounded_command(["docker", "image", "inspect", image], limit=1024 * 1024))
        if len(inspected) != 1 or inspected[0].get("Os") != "linux" or \
                inspected[0].get("Architecture") != "amd64" or \
                inspected[0].get("Config", {}).get("User") != "10001:10001":
            raise RuntimeError("built MCP image identity differs")
        receipt["localImageID"] = inspected[0]["Id"]
        if sha(HERE / "server.py") != SOURCE_SHA256 or \
                sha(HERE / "requirements.lock") != receipt["lockSHA256"] or \
                sha(HERE / "wheelhouse.sha256") != receipt["wheelManifestSHA256"]:
            raise RuntimeError("MCP build source changed")
        receipt["registryPushAttempts"] = 1
        save()
        bounded_command(["docker", "push", "--quiet", image], timeout=900)
        manifest = bounded_command(["docker", "buildx", "imagetools", "inspect", "--raw", image],
                                   timeout=120, limit=1024 * 1024)
        decoded = json.loads(manifest)
        if decoded.get("schemaVersion") != 2 or not decoded.get("layers"):
            raise RuntimeError("published MCP manifest is not a single-image manifest")
        receipt["imageDigest"] = "sha256:" + hashlib.sha256(manifest).hexdigest()
        receipt["immutableImage"] = REGISTRY + "@" + receipt["imageDigest"]
        receipt["status"] = "PUBLISHED_AND_MANIFEST_VERIFIED"
    except Exception as exc:
        receipt["status"] = "FAILED_OR_AMBIGUOUS"
        receipt["failureClass"] = type(exc).__name__
        raise
    finally:
        save()
    print(json.dumps({"status": receipt["status"], "immutableImage": receipt["immutableImage"],
                      "sourceSHA256": SOURCE_SHA256, "receipt": str(receipt_path)}, sort_keys=True))


if __name__ == "__main__":
    main()
