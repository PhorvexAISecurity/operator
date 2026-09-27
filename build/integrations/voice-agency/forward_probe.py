"""One owned Voice Pod port-forward and fixed speech probe. Inert by default."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import subprocess
import time

import mongo_fixture
import ws_probe


def reviewed_transport():
    path = mongo_fixture.TRANSPORT_SOURCE
    if hashlib.sha256(path.read_bytes()).hexdigest() != mongo_fixture.TRANSPORT_SHA256:
        raise ValueError("reviewed SSH transport changed")
    spec = importlib.util.spec_from_file_location("voice_agency_forward_transport", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class ContextTransport(module.Transport):
        def kubectl(self, argv, timeout=35, stdin=None):
            return super().kubectl(["--context", mongo_fixture.CONTEXT, *argv], timeout=timeout, stdin=stdin)

        def start_forward(self, namespace, pod, local_port, remote_port, container_port, log_path):
            address = f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}"
            remote = ["timeout", "45s", "kubectl", "--context", mongo_fixture.CONTEXT,
                      "--request-timeout=30s", "-n", namespace, "port-forward", "pod/" + pod,
                      f"{remote_port}:{container_port}", "--address=127.0.0.1"]
            script = ("pid=$$; start=$(awk '{print $22}' /proc/$$/stat); "
                      'printf "PHORVEX_REMOTE_FORWARD pid=%s start=%s\\n" "$pid" "$start"; exec ' +
                      shlex.join(remote))
            log = open(log_path, "x", encoding="utf-8")
            os.chmod(log_path, 0o600)
            try:
                process = self.popen_impl([*self.ssh_prefix(), "-o", "ExitOnForwardFailure=yes", "-L", address,
                                           self.dest, shlex.join(["sh", "-c", script])], stdout=log,
                                          stderr=subprocess.STDOUT, text=True, start_new_session=True)
            except BaseException:
                log.close()
                raise
            return module.OwnedForward(self, process, log, Path(log_path), address, local_port)

    return ContextTransport(mongo_fixture.ACCESS_FILE)


def json_read(transport, namespace: str, kind: str, name: str = "") -> dict:
    args = ["-n", namespace, "get", kind]
    if name:
        args.append(name)
    result = transport.kubectl(args + ["-o", "json"], timeout=25)
    if result.returncode or len(result.stdout) > 1_000_000:
        raise RuntimeError("pinned Voice Kubernetes inventory unavailable")
    return json.loads(result.stdout)


def source_sha(transport, pod: str) -> str:
    reply = transport.kubectl(["-n", "voice", "exec", pod, "-c", "bot", "--", "sha256sum", "/app/bot.py"], timeout=20)
    if reply.returncode or len(reply.stdout) != 78 or not reply.stdout.endswith("  /app/bot.py\n"):
        raise RuntimeError("installed Voice bot source hash unavailable")
    digest = reply.stdout[:64]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("installed Voice bot source hash malformed")
    return digest


def authority(transport, pins: dict) -> dict:
    cluster = json_read(transport, "kube-system", "namespace", "kube-system")
    pod = json_read(transport, "voice", "pod", pins["pod"])
    service = json_read(transport, "voice", "service", "voice-bot")
    slices = json_read(transport, "voice", "endpointslices")
    meta, status = pod.get("metadata", {}), pod.get("status", {})
    containers = [x for x in status.get("containerStatuses", []) if x.get("name") == "bot"]
    ready = any(x.get("type") == "Ready" and x.get("status") == "True" for x in status.get("conditions", []))
    ports = service.get("spec", {}).get("ports", [])
    bot_specs = [x for x in pod.get("spec", {}).get("containers", []) if x.get("name") == "bot"]
    agency_env = [x for x in bot_specs[0].get("env", []) if x.get("name") == "VOICE_AGENCY_TEST_ENABLED"] if len(bot_specs) == 1 else []
    if cluster.get("metadata", {}).get("uid") != pins["clusterUID"] or meta.get("uid") != pins["podUID"] or \
            meta.get("namespace") != "voice" or meta.get("name") != pins["pod"] or \
            meta.get("deletionTimestamp") or status.get("phase") != "Running" or not ready or \
            len(containers) != 1 or not containers[0].get("ready") or containers[0].get("restartCount") != 0 or \
            containers[0].get("imageID") != pins["imageID"] or \
            containers[0].get("containerID") != pins["containerID"] or \
            service.get("metadata", {}).get("uid") != pins["serviceUID"] or \
            service.get("spec", {}).get("selector") != {"app": "voice-bot"} or \
            len(agency_env) != 1 or agency_env[0].get("value") != "true" or "valueFrom" in agency_env[0] or \
            len(ports) != 1 or ports[0].get("port") != 8080 or ports[0].get("targetPort") != 8080 or \
            ports[0].get("protocol", "TCP") != "TCP" or source_sha(transport, pins["pod"]) != pins["sourceSHA256"]:
        raise RuntimeError("Voice cluster, Pod, source, or Service authority changed")
    matching = []
    for item in slices.get("items", []):
        if item.get("metadata", {}).get("labels", {}).get("kubernetes.io/service-name") != "voice-bot":
            continue
        if not any(x.get("port") == 8080 and x.get("protocol", "TCP") == "TCP" for x in item.get("ports", [])):
            raise RuntimeError("Voice EndpointSlice port differs")
        matching.extend(x for x in item.get("endpoints", []) if x.get("targetRef", {}).get("uid") == pins["podUID"])
    if len(matching) != 1 or matching[0].get("conditions", {}).get("ready") is not True or \
            matching[0].get("targetRef", {}).get("name") != pins["pod"] or \
            matching[0].get("addresses") != [status.get("podIP")]:
        raise RuntimeError("exact Voice Pod not uniquely Ready on pinned Service")
    return {"clusterUID": pins["clusterUID"], "podUID": pins["podUID"],
            "containerID": pins["containerID"], "imageID": pins["imageID"],
            "sourceSHA256": pins["sourceSHA256"], "serviceUID": pins["serviceUID"],
            "podIP": status["podIP"]}


def save(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dispatch", action="store_true")
    for key in ("run", "phase", "pod", "pod_uid", "image_id", "container_id", "source_sha256",
                "service_uid", "cluster_uid", "out_dir"):
        parser.add_argument("--" + key.replace("_", "-"))
    args = parser.parse_args()
    if not args.dispatch:
        print("INERT: requires --dispatch and fresh exact installed Voice identity pins")
        return
    if any(not getattr(args, key) for key in ("run", "phase", "pod", "pod_uid", "image_id", "container_id",
                                                "source_sha256", "service_uid", "cluster_uid", "out_dir")):
        parser.error("dispatch requires all exact authority pins and new output directory")
    ws_probe.identity(args.run, args.phase)
    if not re.fullmatch(r"[a-z0-9-]{1,63}", args.pod) or not re.fullmatch(r"[0-9a-f]{64}", args.source_sha256):
        parser.error("target Pod or source digest invalid")
    os.umask(0o077)
    output = Path(args.out_dir)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    pins = {"pod": args.pod, "podUID": args.pod_uid, "imageID": args.image_id,
            "containerID": args.container_id, "sourceSHA256": args.source_sha256,
            "serviceUID": args.service_uid, "clusterUID": args.cluster_uid, "run": args.run}
    receipt = {"schema": "voice-agency-baseline-v1", "run": args.run, "phase": args.phase,
               "pins": pins, "status": "INTENT_RECORDED", "scope": "one fixed direct WebSocket speech probe",
               "crmEffect": "NOT_ATTESTED_BY_TRANSPORT", "callerAuthentication": "NOT_PROVED"}
    save(output / "intent.json", receipt)
    transport = reviewed_transport()
    initial = authority(transport, pins)
    forward = None
    try:
        local, remote = free_port(), free_port()
        if local == remote:
            raise RuntimeError("forward ports collided")
        forward = transport.start_forward("voice", pins["pod"], local, remote, 8080, output / "forward.log")
        forward.wait_ready(time.monotonic() + 20)
        if authority(transport, pins) != initial:
            raise RuntimeError("Voice identity changed before speech probe")
        receipt["status"] = "FORWARD_READY"
        save(output / "progress.json", receipt)
        receipt["transport"] = asyncio.run(ws_probe.run_probe(f"ws://127.0.0.1:{local}/ws", args.run, args.phase))
        receipt["status"] = "PROBE_SENT"
    except BaseException as error:
        receipt["status"] = "UNKNOWN"
        receipt["errorClass"] = type(error).__name__
    finally:
        if forward is not None:
            try:
                forward.close()
                receipt["forwardCleanup"] = "PASS"
            except BaseException as error:
                receipt["forwardCleanup"] = "UNVERIFIED"
                receipt["cleanupErrorClass"] = type(error).__name__
        try:
            receipt["authorityStable"] = authority(transport, pins) == initial
        except BaseException:
            receipt["authorityStable"] = False
        if receipt.get("forwardCleanup") != "PASS" or not receipt["authorityStable"]:
            receipt["status"] = "UNKNOWN"
        save(output / "result.json", receipt)
    print(json.dumps({"status": receipt["status"], "run": args.run, "phase": args.phase,
                      "receipt": str(output / "result.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
