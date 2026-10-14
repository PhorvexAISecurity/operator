"""Offline S6-D renderer; no Kubernetes client or runtime probe.

Render requires fresh full API captures and an independently supplied SHA-bound
capability receipt. Capability is not final Kubernetes/serving acceptance. The
prepared inverse is deliberately unusable until `rollback` binds a fresh RV.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[3]
COUNTERS_FILE = ROOT / "deploy/monitoring/dcgm-exporter-counters.csv"
NAMESPACE = "gpu-telemetry"
DAEMONSET = "dcgm-exporter"
IMAGE_TAG = "nvcr.io/nvidia/k8s/dcgm-exporter:3.3.9-3.6.1-ubuntu22.04"
IMAGE_DIGEST = "sha256:3d4e0dfa5fc4d7d12689d29fc6b56cd6c610750e8d187a393882e341fbba6c12"
IMAGE_REPO = "nvcr.io/nvidia/k8s/dcgm-exporter"
IMAGES = (IMAGE_TAG, IMAGE_REPO + "@" + IMAGE_DIGEST, IMAGE_TAG + "@" + IMAGE_DIGEST)
DEFAULT_SHA256 = "ff9cb546733c68d9b22454a7cd726830801854aaa887d997c884e56f8cabba86"
INSTANCE = "i-06b63c8303d407825"
AMI = "ami-0732d3ea96de1b939"
DRIVER = "580.159.03"
FIELDS = ("DCGM_FI_PROF_SM_ACTIVE", "DCGM_FI_DEV_PCIE_LINK_GEN", "DCGM_FI_DEV_PCIE_LINK_WIDTH")
APPEND = (b"DCGM_FI_PROF_SM_ACTIVE, gauge, Streaming multiprocessor active fraction.\n"
          b"DCGM_FI_DEV_PCIE_LINK_GEN, gauge, Current PCIe link generation.\n"
          b"DCGM_FI_DEV_PCIE_LINK_WIDTH, gauge, Current PCIe link width.\n")
VOLUME = "phorvex-dcgm-counters"
MOUNT = "/etc/phorvex-dcgm"
COLLECTORS = "DCGM_EXPORTER_COLLECTORS"
OVERRIDE_ENV = (COLLECTORS, "DCGM_EXPORTER_CONFIGMAP_DATA")
CM_PREFIX = "phorvex-dcgm-counters-"
HASH_ANNOTATION = "phorvex.ai/dcgm-counters-sha256"
SUPPORT_SCHEMA = "phorvex-dcgm-support-v1"
CLOSURE_SCHEMA = "phorvex-dcgm-closure-v1"
FRESH_SECONDS = 300
SUPPORT_SECONDS = 86400
REVIEW_RV = "RECAPTURE_WITH_ROLLBACK_COMMAND"
MAX_BYTES = 4 << 20
SHA = re.compile(r"[0-9a-f]{64}\Z")


class Refusal(ValueError):
    """A fixed diagnostic safe to show without printing captured input."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def json_bytes(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "nonfinite JSON value"))


def read_bounded(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_BYTES,
                "bounded nonempty regular file required")
        raw = stream.read(MAX_BYTES + 1)
    require(0 < len(raw) <= MAX_BYTES, "file exceeds byte bound")
    return raw


def digest(value):
    require(isinstance(value, str) and SHA.fullmatch(value), "lowercase SHA256 required")
    return value


def read_pinned(path, expected):
    raw = read_bounded(path)
    require(sha(raw) == digest(expected), "input SHA256 drift")
    return json_bytes(raw)


def fresh(value, now=None, seconds=FRESH_SECONDS):
    require(isinstance(value, str) and value.endswith(("Z", "+00:00")), "UTC capture time required")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(stamp.utcoffset().total_seconds() == 0, "UTC capture time required")
    age = ((now or datetime.now(timezone.utc)) - stamp).total_seconds()
    require(-30 <= age <= seconds, "stale or future capture")


def identity(ds):
    require(isinstance(ds, dict) and ds.get("apiVersion") == "apps/v1" and
            ds.get("kind") == "DaemonSet", "full apps/v1 DaemonSet required")
    meta = ds.get("metadata", {})
    require(isinstance(meta, dict) and meta.get("namespace") == NAMESPACE and
            meta.get("name") == DAEMONSET and isinstance(meta.get("uid"), str) and meta["uid"] and
            isinstance(meta.get("resourceVersion"), str) and
            re.fullmatch(r"[1-9][0-9]*", meta["resourceVersion"]) and
            not meta.get("deletionTimestamp"), "DaemonSet identity/UID/RV differs")
    require(isinstance(ds.get("spec"), dict) and isinstance(ds.get("status"), dict) and
            type(meta.get("generation")) is int and meta["generation"] > 0,
            "full DaemonSet spec/status/generation required")
    return {key: meta[key] for key in ("name", "namespace", "uid", "resourceVersion")}


def ownership(ds):
    # This annotation is controller-generated during a normal DaemonSet rollout.
    annotations = copy.deepcopy(ds["metadata"].get("annotations", {}))
    annotations.pop("deprecated.daemonset.template.generation", None)
    return {"ownerReferences": copy.deepcopy(ds["metadata"].get("ownerReferences", [])),
            "labels": copy.deepcopy(ds["metadata"].get("labels", {})), "annotations": annotations}


def named_rows(rows, description):
    require(isinstance(rows, list) and all(isinstance(x, dict) and isinstance(x.get("name"), str)
                                        and x["name"] for x in rows), description + " list required")
    require(len({x["name"] for x in rows}) == len(rows), "duplicate " + description)
    return rows


def baseline(ds):
    ident = identity(ds)
    status = ds["status"]
    desired = status.get("desiredNumberScheduled")
    require(type(desired) is int and desired > 0 and
            type(status.get("observedGeneration")) is int and
            status["observedGeneration"] == ds["metadata"]["generation"] and
            status.get("numberMisscheduled", 0) == 0 and
            all(type(status.get(key)) is int and status[key] == desired for key in
                ("currentNumberScheduled", "updatedNumberScheduled", "numberReady", "numberAvailable")),
            "settled Ready DaemonSet required before forward rendering")
    spec = ds["spec"]
    require(isinstance(spec.get("selector"), dict) and spec["selector"] and
            isinstance(spec.get("updateStrategy"), dict), "full selector/strategy required")
    ps = spec["template"]["spec"]
    containers = named_rows(ps.get("containers"), "container")
    init = named_rows(ps.get("initContainers", []), "init container")
    require(not ps.get("ephemeralContainers"), "ephemeral container collision")
    all_containers = containers + init
    require(len({x["name"] for x in all_containers}) == len(all_containers), "container name collision")
    exporters = [(i, c) for i, c in enumerate(containers) if c["name"] == DAEMONSET]
    require(len(exporters) == 1, "one named exporter required")
    index, exporter = exporters[0]
    require(exporter.get("image") in IMAGES, "exporter image tag/digest differs")
    require(not exporter.get("envFrom"), "unresolved envFrom collectors override")
    env = named_rows(exporter.get("env", []), "exporter environment")
    require(all(e["name"] not in OVERRIDE_ENV for e in env), "existing collectors override")
    command = exporter.get("command", [])
    require(not command or command in (["dcgm-exporter"], ["/usr/bin/dcgm-exporter"],
                                       ["/usr/local/bin/dcgm-exporter"]), "unresolved exporter command override")
    args = exporter.get("args", [])
    require(isinstance(args, list) and all(isinstance(x, str) for x in args), "exporter args required")
    require(not any(x.startswith(("--collectors", "-f", "--configmap-data", "-m")) or
                    any(name in x for name in OVERRIDE_ENV)
                    for x in command + args), "existing collectors argument override")
    volumes = named_rows(ps.get("volumes", []), "volume")
    require(all(v["name"] != VOLUME for v in volumes), "CSV volume collision")
    for container in all_containers:
        mounts = named_rows(container.get("volumeMounts", []), "volume mount")
        paths = []
        for mount in mounts:
            path = mount.get("mountPath")
            require(isinstance(path, str) and path.startswith("/") and not path.startswith("//") and
                    os.path.normpath(path) == path, "canonical absolute mount path required")
            require(mount["name"] != VOLUME and not overlaps(path, MOUNT), "CSV mount collision")
            paths.append(path)
        require(len(set(paths)) == len(paths), "duplicate mount path")
        require(all(v.get("name") != VOLUME for v in container.get("volumeDevices", [])),
                "CSV volume device collision")
    return ident, index, exporter


def overlaps(path, directory):
    left, right = path.rstrip("/") + "/", directory.rstrip("/") + "/"
    return left.startswith(right) or right.startswith(left)


def validate_counters(default, counters):
    require(sha(default) == DEFAULT_SHA256, "captured image default CSV differs")
    require(counters == default + APPEND, "candidate must preserve exact defaults and append only three gauges")
    return sha(counters)


def configmap(counters):
    checksum = sha(counters)
    return {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": CM_PREFIX + checksum[:16], "namespace": NAMESPACE,
        "annotations": {HASH_ANNOTATION: checksum}}, "immutable": True,
        "data": {"counters.csv": counters.decode("utf-8")}}


def inventory(value, name):
    require(isinstance(value, dict) and value.get("apiVersion") == "v1" and
            value.get("kind") in ("List", "ConfigMapList") and
            isinstance(value.get("metadata"), dict) and value["metadata"].get("resourceVersion") and
            not value["metadata"].get("continue") and
            not value["metadata"].get("remainingItemCount") and isinstance(value.get("items"), list),
            "complete namespace ConfigMap API List required")
    names = []
    for obj in value["items"]:
        require(obj.get("apiVersion") == "v1" and obj.get("kind") == "ConfigMap", "ConfigMap inventory kind differs")
        meta = obj.get("metadata", {})
        require(meta.get("namespace") == NAMESPACE and all(isinstance(meta.get(k), str) and meta[k]
                for k in ("name", "uid", "resourceVersion")), "ConfigMap inventory identity required")
        names.append(meta["name"])
    require(len(set(names)) == len(names), "duplicate ConfigMap inventory name")
    require(name not in names, "content-named ConfigMap collision; never adopt existing objects")


def support(receipt, ds, ds_sha256, now=None):
    require(isinstance(receipt, dict) and receipt.get("schema") == SUPPORT_SCHEMA and
            receipt.get("scope") == "independent-capability-only", "capability-only receipt schema required")
    require(isinstance(receipt.get("executor"), str) and receipt["executor"], "support executor required")
    fresh(receipt.get("observedAt"), now, SUPPORT_SECONDS)
    require(receipt.get("daemonsetSHA256") == digest(ds_sha256) and
            receipt.get("daemonsetUID") == ds["metadata"]["uid"], "receipt DaemonSet SHA/UID binding differs")
    exporter = next(c for c in ds["spec"]["template"]["spec"]["containers"] if c["name"] == DAEMONSET)
    require(receipt.get("instanceID") == INSTANCE and receipt.get("amiID") == AMI and
            receipt.get("gpu") == "Tesla T4" and receipt.get("driverVersion") == DRIVER and
            receipt.get("exporterTag") == IMAGE_TAG and receipt.get("exporterDigest") == IMAGE_DIGEST and
            receipt.get("liveExporterImage") == exporter["image"] and
            receipt.get("liveExporterDigest") == IMAGE_DIGEST and
            receipt.get("defaultCountersSHA256") == DEFAULT_SHA256, "support hardware/image/default binding differs")
    probes = receipt.get("probes", {})
    require(isinstance(probes, dict) and set(probes) == {"smActive", "pcieLink"}, "two independent probes required")
    for name, fields in (("smActive", FIELDS[:1]), ("pcieLink", FIELDS[1:])):
        probe = probes[name]
        require(isinstance(probe, dict) and probe.get("fields") == list(fields) and
                probe.get("defaultCountersSHA256") == DEFAULT_SHA256 and probe.get("ready") is True and
                type(probe.get("warningCount")) is int and probe["warningCount"] == 0 and
                type(probe.get("errorCount")) is int and probe["errorCount"] == 0,
                "independent probe fields/readiness/diagnostics differ")
        for key in ("csvSHA256", "metricsSHA256", "logsSHA256"):
            digest(probe.get(key))
        values = probe.get("values", {})
        require(isinstance(values, dict) and set(values) == set(fields), "probe values must cover exact fields")
        for field in fields:
            samples = values[field]
            require(isinstance(samples, list) and 1 <= len(samples) <= 1024, "finite probe samples required")
            for value in samples:
                require(type(value) in (int, float) and math.isfinite(value), "nonfinite probe sample")
                if field == FIELDS[0]:
                    require(0 <= value <= 1, "SM occupancy outside [0,1]")
                elif field == FIELDS[1]:
                    require(value == int(value) and 1 <= value <= 6, "invalid PCIe link generation")
                else:
                    require(value in (1, 2, 4, 8, 16, 32), "invalid PCIe link width")


def additions(spec, index, cm_name):
    """Return exact candidate and only the three additive RFC6902 operations."""
    candidate = copy.deepcopy(spec)
    ps = candidate["template"]["spec"]
    exporter = ps["containers"][index]
    env = {"name": COLLECTORS, "value": MOUNT + "/counters.csv"}
    mount = {"name": VOLUME, "mountPath": MOUNT, "readOnly": True}
    volume = {"name": VOLUME, "configMap": {"name": cm_name, "defaultMode": 292,
        "optional": False, "items": [{"key": "counters.csv", "path": "counters.csv"}]}}
    ops = []
    for obj, key, base, value in (
        (exporter, "env", f"/spec/template/spec/containers/{index}", env),
        (exporter, "volumeMounts", f"/spec/template/spec/containers/{index}", mount),
        (ps, "volumes", "/spec/template/spec", volume)):
        present = key in obj
        obj.setdefault(key, []).append(copy.deepcopy(value))
        ops.append({"op": "add", "path": base + "/" + key + ("/-" if present else ""),
                    "value": value if present else [value]})
    return candidate, ops


def guarded(ds, expected_spec, operations, rv=None):
    return [{"op": "test", "path": "/metadata/uid", "value": ds["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": rv or ds["metadata"]["resourceVersion"]},
            {"op": "test", "path": "/spec", "value": copy.deepcopy(expected_spec)},
            *([] if rv == REVIEW_RV else [{"op": "test", "path": "/metadata", "value": copy.deepcopy(ds["metadata"])}]),
            *copy.deepcopy(operations)]


def render(ds, ds_sha256, configmaps, configmaps_sha256, receipt, receipt_sha256,
           default, counters, captured_at, now=None):
    fresh(captured_at, now)
    for checksum in (ds_sha256, configmaps_sha256, receipt_sha256):
        digest(checksum)
    ident, index, _ = baseline(ds)
    checksum = validate_counters(default, counters)
    support(receipt, ds, ds_sha256, now)
    cm = configmap(counters)
    inventory(configmaps, cm["metadata"]["name"])
    candidate, operations = additions(ds["spec"], index, cm["metadata"]["name"])
    inverse = guarded(ds, candidate, [{"op": "replace", "path": "/spec", "value": ds["spec"]}], REVIEW_RV)
    closure = {"schema": CLOSURE_SCHEMA, "capturedAt": captured_at,
        "acceptance": "pending-lead-kubernetes-attribution-and-serving-proof",
        "inputs": {"daemonsetSHA256": ds_sha256, "configmapsSHA256": configmaps_sha256,
                   "supportReceiptSHA256": receipt_sha256, "defaultCountersSHA256": DEFAULT_SHA256},
        "daemonset": ident, "ownership": ownership(ds), "image": ds["spec"]["template"]["spec"]["containers"][index]["image"],
        "imageDigest": IMAGE_DIGEST, "countersSHA256": checksum, "configMap": cm,
        "originalSpec": copy.deepcopy(ds["spec"]), "candidateSpec": candidate,
        "originalSpecSHA256": sha(canonical(ds["spec"])), "candidateSpecSHA256": sha(canonical(candidate)),
        "rollback": {"reviewOnlyResourceVersion": REVIEW_RV,
                     "requires": "fresh stable UID, exact candidate spec, unchanged ownership and current RV"}}
    return {"dcgm-exporter-profiling.yaml": cm, "daemonset-forward.json": guarded(ds, ds["spec"], operations),
            "daemonset-inverse-review-only.json": inverse, "dcgm-closure.json": closure}


def rollback(current, current_sha256, closure, captured_at, now=None):
    fresh(captured_at, now)
    ident = identity(current)
    digest(current_sha256)
    require(closure.get("schema") == CLOSURE_SCHEMA and closure.get("imageDigest") == IMAGE_DIGEST,
            "closure schema/image differs")
    require(all(ident[k] == closure["daemonset"][k] for k in ("name", "namespace", "uid")), "rollback UID/identity drift")
    original, candidate = closure["originalSpec"], closure["candidateSpec"]
    require(sha(canonical(original)) == closure.get("originalSpecSHA256") and
            sha(canonical(candidate)) == closure.get("candidateSpecSHA256"), "closure spec SHA256 drift")
    cm = closure["configMap"]
    counters = cm["data"]["counters.csv"].encode("utf-8")
    validate_counters(counters[:-len(APPEND)], counters)
    require(cm == configmap(counters) and closure.get("countersSHA256") == sha(counters), "closure CSV ConfigMap drift")
    # Validate the preserved original and reconstruct the candidate; no arbitrary
    # spec can be smuggled into a rollback merely by updating its embedded hashes.
    synthetic = copy.deepcopy(current)
    synthetic["spec"] = copy.deepcopy(original)
    synthetic["metadata"]["generation"] = 1
    synthetic["status"] = {"observedGeneration": 1, "desiredNumberScheduled": 1,
        "currentNumberScheduled": 1, "updatedNumberScheduled": 1, "numberReady": 1,
        "numberAvailable": 1, "numberMisscheduled": 0}
    _, index, exporter = baseline(synthetic)
    require(exporter["image"] == closure.get("image"), "closure original image drift")
    expected, _ = additions(original, index, cm["metadata"]["name"])
    require(canonical(candidate) == canonical(expected) and canonical(current["spec"]) == canonical(candidate),
            "rollback requires exact candidate spec; recapture/review on drift")
    require(ownership(current) == closure.get("ownership"), "rollback ownership metadata drift")
    patch = guarded(current, candidate, [{"op": "replace", "path": "/spec", "value": original}])
    return {"daemonset-inverse.json": patch, "rollback-receipt.json": {
        "schema": "phorvex-dcgm-rollback-v1", "capturedAt": captured_at,
        "daemonset": ident, "currentDaemonsetSHA256": current_sha256,
        "candidateSpecSHA256": sha(canonical(candidate)), "restoredSpecSHA256": sha(canonical(original))}}


def write_artifacts(directory, artifacts):
    # Exclusive output directory; never overwrite another worker's evidence.
    directory.mkdir(parents=False, exist_ok=False)
    for name, value in artifacts.items():
        with (directory / name).open("xb") as stream:
            stream.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode("ascii") + b"\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    prepare = sub.add_parser("render", help="offline forward patch and review-only inverse")
    inverse = sub.add_parser("rollback", help="bind prepared inverse to a fresh exact candidate capture")
    for command in (prepare, inverse):
        command.add_argument("--daemonset", type=Path, required=True)
        command.add_argument("--daemonset-sha256", required=True, help="SHA256 of exact capture file bytes")
        command.add_argument("--captured-at", required=True, help="UTC capture time, at most 300 seconds old")
        command.add_argument("--output-dir", type=Path, required=True, help="new directory with an existing parent")
    prepare.add_argument("--configmaps", type=Path, required=True, help="full gpu-telemetry namespace ConfigMap List")
    prepare.add_argument("--configmaps-sha256", required=True)
    prepare.add_argument("--support-receipt", type=Path, required=True)
    prepare.add_argument("--support-sha256", required=True)
    prepare.add_argument("--default-counters", type=Path, required=True)
    prepare.add_argument("--counters", type=Path, default=COUNTERS_FILE)
    inverse.add_argument("--closure", type=Path, required=True)
    inverse.add_argument("--closure-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        ds = read_pinned(args.daemonset, args.daemonset_sha256)
        if args.mode == "render":
            artifacts = render(ds, args.daemonset_sha256,
                read_pinned(args.configmaps, args.configmaps_sha256), args.configmaps_sha256,
                read_pinned(args.support_receipt, args.support_sha256), args.support_sha256,
                read_bounded(args.default_counters), read_bounded(args.counters), args.captured_at)
        else:
            closure = read_pinned(args.closure, args.closure_sha256)
            artifacts = rollback(ds, args.daemonset_sha256, closure, args.captured_at)
            artifacts["rollback-receipt.json"]["closureSHA256"] = args.closure_sha256
        write_artifacts(args.output_dir, artifacts)
    except Refusal as error:
        parser.exit(2, "DCGM render refused: " + str(error) + "\n")
    except (ValueError, KeyError, TypeError, OSError, OverflowError, StopIteration,
            AttributeError, IndexError, RecursionError) as error:
        # Do not echo captured file contents, environment, or parser values.
        parser.exit(2, "DCGM render refused: " + type(error).__name__ + "\n")
    print("Rendered offline S6-D " + args.mode + " artifacts; live acceptance remains lead-owned.")


if __name__ == "__main__":
    main()
