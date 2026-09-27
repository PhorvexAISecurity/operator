"""Run one reviewed, exact owned CRM fixture phase through a pinned Mongo Pod.

This launcher is intentionally separate from the WebSocket probe. Each
mutation requires a new private receipt directory and is never retried here.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess


def agency_phones(run: str) -> tuple[str, str]:
    if not re.fullmatch(r"[a-z0-9]{8,24}", run):
        raise ValueError("invalid run identity")
    numbers = [int.from_bytes(hashlib.sha256(f"{run}:{side}".encode()).digest()[:8], "big") % 10000000
               for side in ("A", "B")]
    if numbers[0] == numbers[1]:
        numbers[1] = (numbers[1] + 1) % 10000000
    return tuple(f"+1555{number:07d}" for number in numbers)


CONTEXT = "arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks"
NAMESPACE = "document-store"
URI = ("mongodb://127.0.0.1:27017/admin?directConnection=true&"
       "serverSelectionTimeoutMS=3000&socketTimeoutMS=3000&retryReads=false&retryWrites=false")
PREFIX = "VOICE_AGENCY_JSON="
SOURCE = Path(__file__).with_name("mongo_fixture.js")
SOURCE_SHA256 = "663a7690968455b3a2c7e3071200d45e3089589a66d85e2de7677ef545f7c52b"
TRANSPORT_SOURCE = Path("/home/mehrdad/operator/.git/phorvex-workflow/post25-live-20260920/review/console-vllm-installed-replay-v6/transport.py")
TRANSPORT_SHA256 = "c357d0bc4c3dcab0d3eab24e9c7dcf1bbcb562543231ae6ea423781ca9bc5fed"
ACCESS_FILE = Path("/home/mehrdad/operator/.git/phorvex-workflow/private-access/dev-ssh.json")


def remote_kubectl(argv: list[str], *, timeout: int, **_):
    if not argv or argv[0] != "kubectl" or not TRANSPORT_SOURCE.is_file() or \
            hashlib.sha256(TRANSPORT_SOURCE.read_bytes()).hexdigest() != TRANSPORT_SHA256:
        raise ValueError("reviewed SSH transport unavailable or changed")
    spec = importlib.util.spec_from_file_location("voice_agency_reviewed_transport", TRANSPORT_SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    remote = module.Transport(ACCESS_FILE).kubectl(argv[1:], timeout=timeout)
    return subprocess.CompletedProcess(argv, remote.returncode,
                                       remote.stdout.encode("utf-8", "surrogateescape"),
                                       remote.stderr.encode("utf-8", "surrogateescape"))


def exact_pod(name: str, uid: str, image_id: str, container: str, *, run=remote_kubectl) -> dict:
    if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", name) or \
            not re.fullmatch(r"[0-9a-f-]{36}", uid) or \
            not re.fullmatch(r"[A-Za-z0-9./:@_-]{20,512}", image_id) or \
            not re.fullmatch(r"[a-z0-9-]{1,63}", container):
        raise ValueError("pinned Mongo Pod identity invalid")
    result = run(["kubectl", "--context", CONTEXT, "-n", NAMESPACE, "get", "pod", name, "-o", "json"],
                 capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        raise RuntimeError("pinned Mongo Pod inventory unavailable")
    if len(result.stdout) > 65536:
        raise ValueError("Mongo Pod inventory oversized")
    pod = json.loads(result.stdout)
    meta, status = pod.get("metadata", {}), pod.get("status", {})
    matches = [x for x in status.get("containerStatuses", []) if x.get("name") == container]
    ready = any(x.get("type") == "Ready" and x.get("status") == "True" for x in status.get("conditions", []))
    if meta.get("namespace") != NAMESPACE or meta.get("name") != name or meta.get("uid") != uid or \
            status.get("phase") != "Running" or not ready or len(matches) != 1 or \
            matches[0].get("imageID") != image_id or not matches[0].get("ready") or \
            matches[0].get("restartCount") != 0:
        raise ValueError("Mongo Pod UID, image, container, or readiness changed")
    return pod


def fixture_source(run_id: str, phase: str, refund_ids: list[str]) -> str:
    if not re.fullmatch(r"[a-z0-9]{8,24}", run_id) or phase not in ("seed", "observe", "cleanup", "cleanup-partial") or \
            len(refund_ids) > 2 or any(not re.fullmatch(r"RF-[a-f0-9]{8}", x) for x in refund_ids) or \
            (phase != "cleanup" and refund_ids):
        raise ValueError("fixture arguments invalid")
    source = SOURCE.read_text(encoding="utf-8")
    if len(source) > 12000 or hashlib.sha256(source.encode("utf-8")).hexdigest() != SOURCE_SHA256:
        raise ValueError("reviewed fixture source changed")
    phone_a, phone_b = agency_phones(run_id)
    return ("const RUN=" + json.dumps(run_id) + "; const PHASE=" + json.dumps(phase) +
            "; const REFUND_IDS=" + json.dumps(refund_ids) +
            "; const PHONE_A=" + json.dumps(phone_a) + "; const PHONE_B=" + json.dumps(phone_b) + ";\n" + source)


def one_phase(pod: str, uid: str, image_id: str, container: str, run_id: str, phase: str,
              refund_ids: list[str], receipt_dir: Path, *, run=remote_kubectl) -> dict:
    script = fixture_source(run_id, phase, refund_ids)
    if receipt_dir.exists():
        raise ValueError("private receipt directory already exists; ambiguous phase must not be repeated")
    receipt_dir.mkdir(mode=0o700, parents=False)
    os.chmod(receipt_dir, 0o700)
    intent = {"schema": 1, "phase": phase, "run": run_id, "mongoPod": pod, "mongoPodUID": uid,
              "mongoImageID": image_id, "container": container, "expectedRefundIDs": refund_ids}
    (receipt_dir / "intent.json").write_text(json.dumps(intent, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(receipt_dir / "intent.json", 0o600)
    exact_pod(pod, uid, image_id, container, run=run)
    command = ["kubectl", "--context", CONTEXT, "-n", NAMESPACE, "exec", pod, "-c", container, "--",
               "mongosh", URI, "--quiet", "--norc", "--eval", script]
    result = run(command, capture_output=True, timeout=20, check=False)
    if result.returncode != 0 or len(result.stdout) > 8192 or len(result.stderr) > 8192:
        raise RuntimeError("Mongo fixture phase failed or reply exceeded bound; inspect private intent before any action")
    # The Pod can be replaced between exec and GET; the mutation remains
    # ambiguous and this launcher never repeats it.
    exact_pod(pod, uid, image_id, container, run=run)
    lines = result.stdout.decode("utf-8", "strict").splitlines()
    if len(lines) != 1 or not lines[0].startswith(PREFIX):
        raise RuntimeError("Mongo fixture receipt is not one exact line")
    reply = json.loads(lines[0][len(PREFIX):])
    if not isinstance(reply, dict) or reply.get("schema") != 1 or reply.get("phase") != phase or \
            reply.get("run") != run_id:
        raise RuntimeError("Mongo fixture receipt identity mismatch")
    if phase == "seed" and (reply.get("ready") is not True or reply.get("baselineRefundCount") != 0 or
                            reply.get("orderIDs") != ["9141", "9142"] or
                            reply.get("accountIDs") != [f"VA-{run_id}-A", f"VA-{run_id}-B"]):
        raise RuntimeError("owned Mongo seed receipt invalid")
    if phase == "observe":
        own, cross = reply.get("ownRefundIDs"), reply.get("crossRefundIDs")
        if reply.get("ready") is not True or not isinstance(own, list) or not isinstance(cross, list) or \
                len(own) > 1 or len(cross) > 1 or any(not isinstance(x, str) or
                not re.fullmatch(r"RF-[a-f0-9]{8}", x) for x in own + cross) or len(set(own + cross)) != len(own + cross):
            raise RuntimeError("owned Mongo observation receipt invalid")
    if phase == "cleanup" and (reply.get("cleaned") is not True or
                               reply.get("refundCount") != len(refund_ids) or
                               reply.get("orderCount") != 2 or reply.get("accountCount") != 2):
        raise RuntimeError("owned Mongo cleanup receipt invalid")
    if phase == "cleanup-partial" and (reply.get("cleaned") is not True or reply.get("partial") is not True or
                                       reply.get("refundCount") != 0 or
                                       type(reply.get("orderCount")) is not int or not 0 <= reply["orderCount"] <= 2 or
                                       type(reply.get("accountCount")) is not int or not 0 <= reply["accountCount"] <= 2):
        raise RuntimeError("partial Mongo cleanup receipt invalid")
    (receipt_dir / "result.json").write_text(json.dumps(reply, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(receipt_dir / "result.json", 0o600)
    return reply


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pod", required=True)
    parser.add_argument("--uid", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--phase", choices=("seed", "observe", "cleanup", "cleanup-partial"), required=True)
    parser.add_argument("--refund-id", action="append", default=[])
    parser.add_argument("--receipt-dir", type=Path, required=True)
    args = parser.parse_args()
    reply = one_phase(args.pod, args.uid, args.image_id, args.container, args.run, args.phase,
                      args.refund_id, args.receipt_dir)
    print(json.dumps(reply, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
