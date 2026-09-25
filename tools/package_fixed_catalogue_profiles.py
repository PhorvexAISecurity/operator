#!/usr/bin/env python3
"""Package operator-reviewed fixed catalogue profile bytes; offline and create-once.

This tool does not establish current cluster authority or deploy its output.
"""

import argparse
import copy
import hashlib
import json
import re
import stat
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import yaml

SPECS = {
    "mongo": ("config.mongo-exposure-baseline.yaml", "mongoExposure", "mongoExposureFixture", "document-store"),
    "guardrail-static": ("config.guardrail-confidentiality-static.yaml", "guardrailStatic", "guardrailStaticFixture", "vllm"),
    "guardrail-availability": ("config.guardrail-availability-recovery.yaml", "guardrailAvailability", "guardrailAvailabilityFixture", "vllm"),
    "nats-baseline": ("config.nats-exposure-baseline.yaml", "natsExposure", "natsExposureFixture", "phorvex-nats-exposure-fixture"),
    "nats-response": ("config.nats-client-response.yaml", "natsExposure.clientResponse", "natsExposureFixture", "phorvex-nats-exposure-fixture"),
    "pod-token": ("config.pod-bound-api-auth-response.yaml", "podBoundToken", "podBoundTokenFixture", "voice"),
}
UID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
SHA = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IMAGE = re.compile(r"^\S+@sha256:[0-9a-f]{64}$")
PLACEHOLDER = "__SET_EXACT_REVIEWED_MANIFEST_SHA256__"
MAX_PROFILE = 256 * 1024
MAX_MANIFEST = 8 * 1024
MAX_EVIDENCE = 128 * 1024
MONGO_166_RUNS_SHA256 = "15c6bfe59290ffd44ef2ba57f26c09f72e3bfd70ed321daf44a766fdbae1f910"
MONGO_REVIEWED_PARSER_REPAIR = "8b5dd50f6f94255b6c597bd5876f7fbd5d27986d"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_relative(root, relative, limit):
    need(isinstance(relative, str) and relative and not Path(relative).is_absolute(), "input path must be relative")
    path = Path(relative)
    need(all(part not in ("", ".", "..") for part in relative.split("/") ) and "\\" not in relative,
         "input path is not clean")
    current = root
    for part in path.parts:
        current = current / part
        need(not current.is_symlink(), "input path contains a symlink")
    need(current.resolve().is_relative_to(root.resolve()), "input path escapes bundle")
    mode = current.stat().st_mode
    need(stat.S_ISREG(mode) and 0 < current.stat().st_size <= limit, "input is not a bounded regular file")
    return current.read_bytes()


def strict_json(raw):
    def unique(pairs):
        seen = set()
        result = {}
        for key, value in pairs:
            folded = key.casefold()
            need(folded not in seen, "duplicate JSON field")
            seen.add(folded)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            need(isinstance(key, str), "YAML field name must be a string")
            folded = key.casefold()
            need(folded not in seen, "duplicate YAML field")
            seen.add(folded)
        return super().construct_mapping(node, deep=deep)


def strict_yaml(raw):
    return yaml.load(raw, Loader=UniqueLoader)


def has_unfilled_scalar(value):
    if isinstance(value, str):
        return "__SET_" in value
    if isinstance(value, dict):
        return any(has_unfilled_scalar(key) or has_unfilled_scalar(item) for key, item in value.items())
    if isinstance(value, list):
        return any(has_unfilled_scalar(item) for item in value)
    return False


def pod_manifest(raw, build_raw, review_raw, pods_raw, rollout, rollout_sha, overlay):
    manifest = strict_json(raw)
    need(isinstance(manifest, dict) and set(manifest) == {
        "schema", "sourceCommit", "managerImageID", "buildEvidenceRef", "buildEvidenceSHA256",
        "reviewRecordRef", "reviewRecordSHA256"}, "Pod-token manifest fields differ")
    need(manifest["schema"] == "phorvex.manager-source-image.v1" and
         COMMIT.fullmatch(manifest["sourceCommit"]) and IMAGE.fullmatch(manifest["managerImageID"]),
         "Pod-token source/image pin differs")
    need(manifest["buildEvidenceRef"] == "evidence/SOURCE-BUILD.json" and
         manifest["reviewRecordRef"] == "evidence/source-review.json", "Pod-token evidence refs must use fixed portable paths")
    refs = {}
    for kind, data, hash_key in (("build", build_raw, "buildEvidenceSHA256"),
                                 ("review", review_raw, "reviewRecordSHA256")):
        need(SHA.fullmatch(manifest[hash_key]), "Pod-token evidence digest malformed")
        need(digest(data) == manifest[hash_key], "Pod-token evidence bytes changed")
        refs[kind] = strict_json(data)
    need(manifest["buildEvidenceRef"] != manifest["reviewRecordRef"], "source and review refs must differ")
    review, build = refs["review"], refs["build"]
    need(isinstance(review, dict) and set(review) <= {"schema", "approved", "sourceCommit", "managerImageID", "consoleImageID",
                         "buildEvidenceSHA256", "rolloutPodReadSHA256", "rolloutJoinSHA256",
                         "fixtureSourceSHA256", "probeSourceSHA256", "reviewer", "reviewedAtUTC"} and
         b"/home/" not in review_raw and
         rollout["sourceSHA256"] == manifest["buildEvidenceSHA256"] and
         review.get("approved") is True and review.get("sourceCommit") == manifest["sourceCommit"] and
         review.get("managerImageID") == manifest["managerImageID"] and
         review.get("buildEvidenceSHA256") == manifest["buildEvidenceSHA256"] and
         review.get("rolloutPodReadSHA256") == digest(pods_raw) and
         review.get("rolloutJoinSHA256") == rollout_sha and
         review.get("consoleImageID") == rollout["console"] and
         isinstance(review.get("reviewer"), str) and bool(review["reviewer"].strip()) and
         isinstance(review.get("reviewedAtUTC"), str) and bool(review["reviewedAtUTC"].strip()),
         "source review does not bind manifest/rollout")
    need(build.get("run", {}).get("headSHA") == manifest["sourceCommit"] and
         build.get("run", {}).get("jobs", {}).get("manager", {}).get("sourceTagAndManifestListPushConfirmed") is True and
         build.get("run", {}).get("jobs", {}).get("manager", {}).get("manifestListDigest") ==
         manifest["managerImageID"].split("@sha256:", 1)[1], "build record does not bind manager image")
    need(build.get("release", {}).get("sha") == rollout["releaseSHA"] and
         build.get("run", {}).get("jobs", {}).get("console", {}).get("manifestListDigest") ==
         rollout["console"].split("@sha256:", 1)[1], "build record does not bind console image")
    need(overlay["image"]["tag"] == rollout["tag"] and
         overlay["console"]["image"]["tag"] == rollout["tag"], "manager/console desired tags differ from reviewed release")
    return manifest


def verify_pod_read(pods_raw, join, rollout):
    pods = strict_json(pods_raw)
    need(isinstance(pods, dict) and pods.get("schema") == "catalogue-pr330-rollout-read-v1" and
         pods.get("status") == "COMPLETE" and b"/home/" not in pods_raw and
         isinstance(pods.get("projection"), dict), "rollout Pod read differs")
    projection = pods["projection"]
    need(projection.get("cluster", {}).get("uid") == rollout["clusterUID"] and
         [pods.get("startedAtUTC"), pods.get("finishedAtUTC")] == join.get("readWindow"),
         "rollout Pod read cluster/window differs")
    for component in ("manager", "console"):
        deployment = projection.get(component + "Deployment", {})
        actual_pods = projection.get(component + "Pods", [])
        joined = join["components"][component]
        expected_image = rollout[component].split("@sha256:", 1)[0] + ":" + rollout["tag"]
        need(isinstance(deployment, dict) and isinstance(actual_pods, list) and len(actual_pods) == 1 and
             deployment.get("namespace") == "phorvex-system" and
             deployment.get("uid") == joined.get("deploymentUID") and
             deployment.get("generation") == joined.get("deploymentGeneration") and
             deployment.get("replicas") == deployment.get("readyReplicas") == 1 and
             deployment.get("containers") == [{"name": component, "image": expected_image}],
             "rollout Pod read deployment differs: " + component)
        pod = actual_pods[0]
        containers = pod.get("containers", []) if isinstance(pod, dict) else []
        need(pod.get("namespace") == "phorvex-system" and
             pod.get("uid") == joined.get("podUIDs", [None])[0] and
             pod.get("ready") is True and pod.get("phase") == "Running" and pod.get("deleting") is False and
             isinstance(containers, list) and len(containers) == 1 and
             containers[0].get("name") == component and
             containers[0].get("imageID") == rollout[component] and containers[0].get("ready") is True,
             "rollout Pod read incarnation/image differs: " + component)


def overlay_block(console, dotted):
    block = console
    for part in dotted.split("."):
        need(isinstance(block, dict) and part in block, "values overlay omits selected profile: " + dotted)
        block = block[part]
    need(isinstance(block, dict) and type(block.get("enabled")) is bool, "profile enabled must be explicit boolean")
    return block


def optional_block(console, dotted):
    block = console
    for part in dotted.split("."):
        if not isinstance(block, dict) or part not in block:
            return None
        block = block[part]
    need(isinstance(block, dict) and type(block.get("enabled")) is bool,
         "omitted profile enabled value is ambiguous: " + dotted)
    return block


def exact_keys(document, allowed, reason):
    need(isinstance(document, dict) and set(document) <= set(allowed), reason)


def selected_values(source, kinds):
    exact_keys(source, {"phorvex"}, "unrelated root values")
    outer = source["phorvex"]
    exact_keys(outer, {"phorvex"}, "unrelated umbrella values")
    inner = outer["phorvex"]
    allowed_inner = {"image", "console"}
    if "pod-token" in kinds:
        allowed_inner |= {"prometheusUrl", "eventIdentityPolicy", "e2eDetector"}
    exact_keys(inner, allowed_inner, "unrelated stack values")
    exact_keys(inner.get("image"), {"tag"}, "unrelated manager image settings")
    console = inner.get("console")
    exact_keys(console, {"image", "mongoExposure", "guardrailStatic", "guardrailAvailability", "natsExposure", "podBoundToken"},
               "unrelated console values")
    exact_keys(console.get("image"), {"tag"}, "unrelated console image settings")
    if "pod-token" in kinds:
        exact_keys(inner.get("eventIdentityPolicy"), {"enabled"}, "unrelated event identity settings")
        exact_keys(inner.get("e2eDetector"), {"enabled", "targetNamespace"}, "unrelated E2E settings")
        need(inner["eventIdentityPolicy"].get("enabled") is True and
             inner["e2eDetector"].get("enabled") is True and
             inner["e2eDetector"].get("targetNamespace") == "voice" and
             isinstance(inner.get("prometheusUrl"), str) and inner["prometheusUrl"].startswith("http"),
             "Pod-token required fixed-source stack settings differ")
    expected_blocks = {
        "mongoExposure": {"enabled", "configMapName", "profileSHA256"},
        "guardrailStatic": {"enabled", "configMapName", "profileSHA256", "sourceConfigMap", "guardrailJournalName", "kvJournalName"},
        "guardrailAvailability": {"enabled", "configMapName", "profileSHA256", "sourceConfigMap", "guardrailJournalName"},
        "natsExposure": {"enabled", "configMapName", "profileSHA256", "clientResponse"},
        "podBoundToken": {"enabled", "configMapName", "profileSHA256", "scrapeApproved", "scrapeNamespace", "podSelectorLabel", "quarantineCapacityLedgerName"},
    }
    for name, allowed in expected_blocks.items():
        if name in console:
            exact_keys(console[name], allowed, "unrelated profile values: " + name)
    if "natsExposure" in console and "clientResponse" in console["natsExposure"]:
        exact_keys(console["natsExposure"]["clientResponse"], {"enabled", "configMapName", "profileSHA256"},
                   "unrelated NATS response values")
    # Rebuild from a strict allowlist; input blocks for unselected disabled suites
    # are checked below but never copied into the proposed output.
    projected = {"image": {"tag": inner["image"]["tag"]},
                 "console": {"image": {"tag": console["image"]["tag"]}}}
    if "pod-token" in kinds:
        for name in ("prometheusUrl", "eventIdentityPolicy", "e2eDetector"):
            projected[name] = copy.deepcopy(inner[name])
    for kind in kinds:
        if kind == "nats-response":
            continue
        field = SPECS[kind][1]
        projected["console"][field] = copy.deepcopy(console[field])
    if "nats-response" in kinds:
        need("nats-baseline" in kinds, "NATS response requires packaged baseline")
        projected["console"]["natsExposure"]["clientResponse"] = copy.deepcopy(console["natsExposure"]["clientResponse"])
    elif "nats-baseline" in kinds:
        projected["console"]["natsExposure"]["clientResponse"] = {"enabled": False}
    return {"phorvex": {"phorvex": projected}}


class Literal(str):
    pass


yaml.SafeDumper.add_representer(Literal, lambda dumper, value: dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|"))


def verified_mongo_166_evidence(root, profile, expected):
    """Join retained .166 build and original Kubernetes GET bytes for Mongo only.

    The three expected SHA values are separately reviewed caller pins, not values
    copied from the input directory. The named suite still rechecks live UIDs.
    """
    need(all(isinstance(x, str) and SHA.fullmatch(x) for x in expected.values()),
         "Mongo .166 original evidence SHA pins are required")
    copied = {}
    def original(name, limit=MAX_EVIDENCE):
        relative = "evidence/" + name
        raw = read_relative(root, relative, limit)
        copied[relative] = raw
        return raw
    build_raw = original("SOURCE-BUILD-166.json")
    need(digest(build_raw) == expected["source"], "Mongo .166 source-build original SHA differs")
    build = strict_json(build_raw)
    review_raw = original("source-review.json")
    need(digest(review_raw) == expected["review"], "Mongo .166 independent source review SHA differs")
    review = strict_json(review_raw)
    need(build.get("schema") == "catalogue-release-0.4.166-source-build-v1" and
         build.get("run", {}).get("conclusion") == "success" and
         COMMIT.fullmatch(build.get("releaseCommit", "")) and
         COMMIT.fullmatch(build.get("releaseParentBuildSource", "")) and
         build["run"].get("headSHA") == build["releaseParentBuildSource"] and
         review.get("approved") is True and
         review.get("sourceCommit") == build["releaseParentBuildSource"] and
         review.get("buildEvidenceSHA256") == digest(build_raw),
         "Mongo .166 reviewed source/build fields differ")
    source = build["releaseParentBuildSource"]
    repo = Path(__file__).resolve().parents[1]
    git = subprocess.run(["git", "-C", str(repo), "show", "-s", "--format=%H%n%P%n%s",
                          build["releaseCommit"]], capture_output=True, text=True, timeout=15)
    need(git.returncode == 0 and git.stdout.splitlines() ==
         [build["releaseCommit"], source, "release: v0.4.166 [skip ci]"],
         "Mongo .166 release parent/source is not present in reviewed Git")
    parser = subprocess.run(["git", "-C", str(repo), "show", source + ":phorvex/internal/console/runs.go"],
                            capture_output=True, timeout=15)
    ancestor = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                               MONGO_REVIEWED_PARSER_REPAIR, source], capture_output=True, timeout=15)
    need(parser.returncode == 0 and digest(parser.stdout) == MONGO_166_RUNS_SHA256 and
         b"validation.IsDNS1123Subdomain(name)" in parser.stdout and ancestor.returncode == 0,
         "Mongo .166 parser repair/source bytes differ")
    images = {}
    for component, image in (("manager", "phorvex"), ("console", "phorvex-console")):
        row = build["run"].get("jobs", {}).get(component, {})
        log = original(component + "-build.original", 250_000)
        image_id = "753556437180.dkr.ecr.us-east-2.amazonaws.com/" + image + "@sha256:" + str(row.get("manifestListDigest", ""))
        pushed = ("pushing manifest for 753556437180.dkr.ecr.us-east-2.amazonaws.com/" + image +
                  ":sha-" + source + "@sha256:" + str(row.get("manifestListDigest", ""))).encode()
        need(row.get("conclusion") == "success" and row.get("sourceTag") == "sha-" + source and
             SHA.fullmatch(str(row.get("manifestListDigest", ""))) and
             digest(log) == row.get("logSHA256") and row.get("logBytes") == len(log) and
             any(pushed in line and line.rstrip().endswith(b"done") for line in log.splitlines()) and
             review.get(component + "ImageID") == image_id and
             review.get("components", {}).get(component, {}).get("logSHA256") == digest(log),
             "Mongo .166 original build push/image differs: " + component)
        images[component] = image_id
    terminal_raw = original("CPU-TERMINAL.json")
    need(digest(terminal_raw) == expected["rollout"], "Mongo .166 rollout terminal original SHA differs")
    terminal = strict_json(terminal_raw)
    receipt_rows = {r.get("file"):r for r in terminal.get("receipts", []) if isinstance(r, dict)}
    need(terminal.get("schema") == "cpu-console-once-v1" and terminal.get("consolePOSTs") == 0 and
         terminal.get("postSourceComparison") == "STABLE" and
         terminal.get("forwardClose") == "CONFIRMED", "Mongo .166 rollout original status differs")
    after = {}
    for name in ("after-cluster.json", "after-manager-deploy.json", "after-manager-pods.json",
                 "after-manager-rs.json", "after-console-deploy.json", "after-console-pods.json",
                 "after-console-rs.json", "after-projection.json"):
        raw = original(name)
        row = receipt_rows.get(name, {})
        need(row.get("sha256") == digest(raw) and row.get("bytes") == len(raw),
             "Mongo .166 rollout original hash differs: " + name)
        after[name] = strict_json(raw)
    cluster_uid = after["after-cluster.json"].get("metadata", {}).get("uid")
    need(UID.fullmatch(str(cluster_uid)) and cluster_uid == profile["mongoExposureFixture"].get("clusterUID"),
         "Mongo .166 cluster UID differs from original GET")
    projection = after["after-projection.json"]
    need(projection.get("clusterUID") == cluster_uid and projection.get("sourceCommit") == source,
         "Mongo .166 rollout projection/source differs")
    for component in ("manager", "console"):
        dep = after["after-" + component + "-deploy.json"]
        pods = after["after-" + component + "-pods.json"].get("items", [])
        rs = after["after-" + component + "-rs.json"]
        expected_name = "phorvex-phorvex" + ("" if component == "manager" else "-console")
        need(len(pods) == 1 and rs.get("kind") == "ReplicaSet" and
             dep.get("metadata", {}).get("name") == expected_name and
             dep.get("metadata", {}).get("namespace") == "phorvex-system" and
             rs.get("metadata", {}).get("namespace") == "phorvex-system" and
             rs.get("spec", {}).get("replicas") == rs.get("status", {}).get("readyReplicas") == 1 and
             dep.get("metadata", {}).get("uid") and
             dep.get("spec", {}).get("replicas") == dep.get("status", {}).get("readyReplicas") == 1 and
             dep.get("status", {}).get("observedGeneration") == dep["metadata"].get("generation") and
             dep.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [{}])[0].get("image") ==
                 "753556437180.dkr.ecr.us-east-2.amazonaws.com/" + ("phorvex" if component == "manager" else "phorvex-console") + ":0.4.166",
             "Mongo .166 deployment original differs: " + component)
        pod = pods[0]
        status = pod.get("status", {}).get("containerStatuses", [])
        need(pod.get("metadata", {}).get("namespace") == "phorvex-system" and
             len(status) == 1 and status[0].get("imageID") == images[component] and status[0].get("ready") is True and
             pod.get("status", {}).get("phase") == "Running" and not pod["metadata"].get("deletionTimestamp") and
             any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod["status"].get("conditions", [])) and
             any(o.get("kind") == "ReplicaSet" and o.get("uid") == rs["metadata"].get("uid") for o in pod["metadata"].get("ownerReferences", [])) and
             any(o.get("kind") == "Deployment" and o.get("uid") == dep["metadata"].get("uid") for o in rs["metadata"].get("ownerReferences", [])) and
             projection.get(component + "PodUID") == pod["metadata"].get("uid") and
             projection.get(component + "ImageID") == images[component] and
             projection.get(component + "Deployment", {}).get("uid") == dep["metadata"].get("uid"),
             "Mongo .166 Pod/ReplicaSet/image original differs: " + component)
    target_hash, pod = verify_mongo_target(original, profile, expected, cluster_uid, images)
    return ({"releaseSHA":build["releaseCommit"], "sourceSHA256":digest(build_raw),
             "clusterUID":cluster_uid, "tag":"0.4.166", **images}, copied,
            {"sourceCommit":source, "targetReadSHA256":target_hash,
             "rolloutTerminalSHA256":digest(terminal_raw), "mongoPodUID":pod["metadata"].get("uid"),
             "managerPodUID":after["after-manager-pods.json"]["items"][0]["metadata"].get("uid"),
             "consolePodUID":after["after-console-pods.json"]["items"][0]["metadata"].get("uid")})


def verify_mongo_target(original, profile, expected, cluster_uid, images):
    """Reparse original Mongo GET bodies and the separately reviewed CPU node."""
    read_raw = original("mongo/RECEIPT.json")
    need(digest(read_raw) == expected["target"], "Mongo target read original SHA differs")
    read = strict_json(read_raw)
    receipts = read.get("receipts", [])
    labels = {r.get("label"):r for r in receipts if isinstance(r, dict)}
    wanted = ("kube-system-namespace", "document-store-namespace", "mongo-deployment", "mongo-pods",
              "manager-deployment", "manager-pods", "console-deployment", "console-pods", "mongo-service",
              "mongo-endpointslices", "mongo-pvc", "mongo-policy", "mongo-cpu-node")
    need(read.get("status") == "READ_ONLY_CURRENT_PROJECTION" and read.get("callCount") == len(wanted) and
         set(labels) == set(wanted) and read.get("context") == profile.get("context") and
         read.get("projection", {}).get("clusterUID") == cluster_uid,
         "Mongo target read scope/status differs")
    target = {}
    for label in wanted:
        row = labels[label]
        name = row.get("originalFile", "")
        argv = row.get("argv", [])
        need(re.fullmatch(r"[0-9]{2}-[a-z-]+[.]original[.]json", name) and
             isinstance(argv, list) and len(argv) >= 5 and
             argv[0] == "--context=" + profile["context"] and argv[1] == "get" and
             argv[-2:] == ["-o", "json"] and
             row.get("dispatchCount") == 1 and row.get("exitCode") == 0,
             "Mongo target original GET receipt differs: " + label)
        raw = original("mongo/" + name, 750_000)
        need(digest(raw) == row.get("stdoutSHA256") and len(raw) == row.get("stdoutBytes"),
             "Mongo target original GET bytes differ: " + label)
        target[label] = strict_json(raw)
    mongo_ns = target["document-store-namespace"].get("metadata", {})
    mongo_dep = target["mongo-deployment"]
    mongo_pods = target["mongo-pods"].get("items", [])
    mongo_svc = target["mongo-service"]
    slices = target["mongo-endpointslices"].get("items", [])
    policy = target["mongo-policy"]
    pvc = target["mongo-pvc"]
    f = profile["mongoExposureFixture"]
    need(target["kube-system-namespace"].get("metadata", {}).get("uid") == cluster_uid and
         mongo_ns.get("name") == "document-store" and UID.fullmatch(str(mongo_ns.get("uid", ""))) and
         len(mongo_pods) == len(slices) == 1 and mongo_dep.get("metadata", {}).get("name") == "mongo" and
         mongo_dep.get("spec", {}).get("replicas") == mongo_dep.get("status", {}).get("readyReplicas") == 1 and
         mongo_dep.get("status", {}).get("observedGeneration") == mongo_dep.get("metadata", {}).get("generation"),
         "Mongo current namespace/deployment/Pod source differs")
    pod, sl = mongo_pods[0], slices[0]
    cs = pod.get("status", {}).get("containerStatuses", [])
    need(len(cs) == 1 and cs[0].get("imageID") == f.get("mongoImageID") and cs[0].get("ready") is True and
         pod.get("status", {}).get("phase") == "Running" and not pod["metadata"].get("deletionTimestamp") and
         any(c.get("type") == "Ready" and c.get("status") == "True" for c in pod["status"].get("conditions", [])) and
         mongo_svc.get("metadata", {}).get("name") == "mongo" and
         mongo_svc.get("spec", {}).get("selector", {}).get("app") == "mongo" and
         len(mongo_svc.get("spec", {}).get("ports", [])) == 1 and
         mongo_svc["spec"]["ports"][0].get("port") == 27017 and
         len(sl.get("endpoints", [])) == 1 and sl["endpoints"][0].get("targetRef", {}).get("uid") == pod["metadata"].get("uid") and
         sl["endpoints"][0].get("conditions", {}).get("ready") is True and
         any(o.get("uid") == mongo_svc["metadata"].get("uid") for o in sl["metadata"].get("ownerReferences", [])) and
         pvc.get("status", {}).get("phase") == "Bound" and UID.fullmatch(str(pvc.get("metadata", {}).get("uid", ""))),
         "Mongo original image/Service route/PVC differs")
    spec = policy.get("spec", {})
    need(policy.get("metadata", {}).get("name") == "mongo-defense" and
         UID.fullmatch(str(policy.get("metadata", {}).get("uid", ""))) and
         policy["metadata"].get("generation", 0) >= 1 and spec.get("tenant") == "mongo" and
         spec.get("mode") == "active" and spec.get("selector", {}).get("matchLabels") == {"app":"mongo"} and
         spec.get("triggers", {}).get("reactiveOnly") is True,
         "Mongo original policy source differs")
    nodes_raw = original("mongo/ELIGIBLE-NODES.json")
    need(digest(nodes_raw) == expected["node"], "Mongo reviewed CPU node receipt SHA differs")
    nodes = strict_json(nodes_raw)
    names = f.get("allowedNodeNames", [])
    need(nodes.get("status") == "READ_ONLY_COMPLETE" and names == ["ip-172-27-11-9.us-east-2.compute.internal"],
         "Mongo reviewed CPU node allowlist differs")
    node_row = next((x for x in nodes.get("rows", []) if x.get("name") == names[0]), None)
    node_raw = original("mongo/17-eligible-node.original.json", 750_000)
    node = strict_json(node_raw)
    allocatable = node.get("status", {}).get("allocatable", {})
    need(node_row is not None and digest(node_raw) == node_row.get("stdoutSHA256") and
         node.get("metadata", {}).get("uid") == node_row.get("uid") and node["metadata"].get("name") == names[0] and
         node.get("spec", {}).get("unschedulable", False) is False and not node.get("spec", {}).get("taints") and
         all(str(allocatable.get(k, "")) not in ("", "0") for k in ("cpu", "memory", "pods")) and
         any(c.get("type") == "Ready" and c.get("status") == "True" for c in node.get("status", {}).get("conditions", [])) and
         f.get("managerImageID") == images["manager"],
         "Mongo original CPU node or manager image differs")
    return digest(read_raw), pod


def verified_mongo_current_evidence(root, profile, expected):
    """Bind a reviewed current release to CI bytes, projected rollout and Mongo GETs.

    The rollout responses are the retained bounded projections of Kubernetes GETs,
    not raw Kubernetes objects. The Mongo target and node records are raw GETs.
    """
    need(all(isinstance(x, str) and SHA.fullmatch(x) for x in expected.values()),
         "Mongo current original evidence SHA pins are required")
    copied = {}
    def original(name, limit=MAX_EVIDENCE):
        relative = "evidence/" + name
        raw = read_relative(root, relative, limit)
        copied[relative] = raw
        return raw

    build_raw = original("source-current/SOURCE-BUILD.json")
    review_raw = original("source-current/SOURCE-REVIEW.json")
    need(digest(build_raw) == expected["source"] and digest(review_raw) == expected["review"],
         "Mongo current independently reviewed source originals differ")
    build, review = strict_json(build_raw), strict_json(review_raw)
    source, release = build.get("releaseParentBuildSource"), build.get("releaseCommit")
    match = re.fullmatch(r"v(\d+\.\d+\.\d+)", str(build.get("releaseTag", "")))
    need(match is not None, "Mongo current release tag differs")
    version = match[1]
    need(build.get("schema") == "catalogue-release-" + version + "-source-build-installed-join-v1" and
         build.get("releaseTag") == "v" + version and COMMIT.fullmatch(str(source)) and
         COMMIT.fullmatch(str(release)) and
         build.get("buildRun", {}).get("headSHA") == source and
         build["buildRun"].get("conclusion") == "success" and
         review.get("schema") == "mongo-" + version.split(".")[-1] + "-source-review-v1" and
         review.get("approved") is True and review.get("sourceCommit") == source and
         review.get("sourceBuildSHA256") == digest(build_raw),
         "Mongo current source/build/reviewer fields differ")
    repo = Path(__file__).resolve().parents[1]
    git = subprocess.run(["git", "-C", str(repo), "show", "-s", "--format=%H%n%P%n%s", release],
                         capture_output=True, text=True, timeout=15)
    parser = subprocess.run(["git", "-C", str(repo), "show", source + ":phorvex/internal/console/runs.go"],
                            capture_output=True, timeout=15)
    ancestor = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                               MONGO_REVIEWED_PARSER_REPAIR, source], capture_output=True, timeout=15)
    need(git.returncode == 0 and git.stdout.splitlines() ==
         [release, source, "release: v" + version + " [skip ci]"] and parser.returncode == 0 and
         digest(parser.stdout) == MONGO_166_RUNS_SHA256 and ancestor.returncode == 0,
         "Mongo current Git release/source/parser bytes differ")

    metadata = build.get("originalGitHubMetadata", {})
    for field in ("buildRun", "buildJobs", "releaseCommit", "tagObject", "tagRef"):
        item = metadata.get(field, {})
        name = item.get("file", "")
        need(re.fullmatch(r"[a-z-]+[.]json", name) is not None,
             "Mongo current GitHub metadata name differs: " + field)
        raw = original("source-current/" + name, 300_000)
        need(digest(raw) == item.get("SHA256") and len(raw) == item.get("bytes"),
             "Mongo current GitHub original bytes differ: " + field)
        value = strict_json(raw)
        if field == "buildRun":
            need(value.get("id") == build["buildRun"].get("id") and
                 value.get("head_sha") == source and value.get("conclusion") == "success",
                 "Mongo current CI run original differs")
        elif field == "buildJobs":
            jobs = {j.get("name"): j for j in value.get("jobs", []) if isinstance(j, dict)}
            for component, name in (("manager", "build-operator"), ("console", "build-console")):
                need(jobs.get(name, {}).get("id") == build["builds"][component].get("jobID") and
                     jobs[name].get("conclusion") == "success",
                     "Mongo current CI job original differs: " + component)
        elif field == "releaseCommit":
            need(value.get("sha") == release and
                 [p.get("sha") for p in value.get("parents", [])] == [source],
                 "Mongo current release original parent differs")
        elif field == "tagObject":
            need(value.get("sha") == build.get("annotatedTagObjectSHA") and
                 value.get("object", {}).get("sha") == release,
                 "Mongo current annotated tag original differs")
        else:
            need(value.get("object", {}).get("sha") == build.get("annotatedTagObjectSHA"),
                 "Mongo current tag ref original differs")

    images = {}
    for component, image in (("manager", "phorvex"), ("console", "phorvex-console")):
        row = build.get("builds", {}).get(component, {})
        filename = row.get("buildLogFile", "")
        need(filename == ("build-operator.log" if component == "manager" else "build-console.log"),
             "Mongo current build log name differs: " + component)
        log = original("source-current/" + filename, 250_000)
        manifest = row.get("buildManifestDigest", "")
        need(isinstance(manifest, str) and manifest.startswith("sha256:") and SHA.fullmatch(manifest[7:]),
             "Mongo current manifest digest differs: " + component)
        image_id = "753556437180.dkr.ecr.us-east-2.amazonaws.com/" + image + "@" + manifest
        pushed = ("pushing manifest for 753556437180.dkr.ecr.us-east-2.amazonaws.com/" + image +
                  ":sha-" + source + "@" + manifest).encode()
        need(row.get("jobConclusion") == "success" and row.get("sourceTag") == "sha-" + source and
             row.get("installedDigestEqualsBuild") is True and row.get("installedImageID") == image_id and
             digest(log) == row.get("buildLogSHA256") and len(log) == row.get("buildLogBytes") and
             any(pushed in line and line.rstrip().endswith(b"done") for line in log.splitlines()) and
             review.get(component + "ImageID") == image_id,
             "Mongo current CI push/installed image differs: " + component)
        images[component] = image_id

    rollout_raw = original("rollout-current/RECEIPT.json")
    need(digest(rollout_raw) == expected["rollout"] and
         build.get("installedRead", {}).get("receiptSHA256") == digest(rollout_raw) and
         review.get("rolloutReceiptSHA256") == digest(rollout_raw),
         "Mongo current installed rollout receipt differs")
    rollout = strict_json(rollout_raw)
    need(rollout.get("schema") == "cpu-activation-current-rollout-read-v1" and
         rollout.get("status") == "READ_COMPLETE_DEPLOYMENT_METADATA" and
         rollout.get("kubernetesGETs") == 10 and
         all(rollout.get(k) == 0 for k in ("applicationRequests", "tokenRequests", "execs", "writes")),
         "Mongo current installed rollout scope/status differs")
    projection = rollout.get("projection", {})
    responses = rollout.get("originalProjectedResponses", {})
    need(set(responses) == set(projection) and len(responses) == 11,
         "Mongo current projected response set differs")
    commands = {c.get("label"): c for c in rollout.get("commands", []) if isinstance(c, dict)}
    need(set(commands) == set(responses) and len(rollout.get("commands", [])) == len(responses),
         "Mongo current projected GET command set differs")
    for label, record in responses.items():
        need(re.fullmatch(r"[A-Za-z]+", label) and record.get("file") == "responses/" + label + ".json",
             "Mongo current projected response path differs")
        raw = original("rollout-current/" + label + ".json", 300_000)
        command = commands[label]
        need(digest(raw) == record.get("SHA256") and strict_json(raw) == projection[label] and
             command.get("stdoutSHA256") == digest(raw) and command.get("rc") == 0 and
             command.get("dispatches") == 1 and command.get("retry") is False,
             "Mongo current projected original bytes differ: " + label)
    app = projection.get("stackApplication", {})
    app_revision = app.get("syncRevision", "")
    app_ancestor = (subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                                   release, app_revision], capture_output=True, timeout=15)
                    if isinstance(app_revision, str) and COMMIT.fullmatch(app_revision) else None)
    need(app_ancestor is not None and app_ancestor.returncode == 0 and
         app.get("syncStatus") == "Synced" and
         build["installedRead"].get("argoSyncRevision") == app_revision and
         build["installedRead"].get("argoSyncStatus") == "Synced",
         "Mongo current Argo source join differs")
    cluster_uid = projection.get("cluster", {}).get("identity", {}).get("uid")
    need(UID.fullmatch(str(cluster_uid)) and
         profile["mongoExposureFixture"].get("clusterUID") == cluster_uid,
         "Mongo current cluster UID differs")
    for component in ("manager", "console"):
        name = "phorvex-phorvex" + ("-console" if component == "console" else "")
        dep = projection.get(component + "Deployment", {})
        pods = projection.get(component + "Pods", [])
        rs = projection.get(component + "ReplicaSet", {})
        assessed = rollout.get("podAssessments", {}).get(component, {})
        row = build["builds"][component]
        need(len(pods) == 1 and assessed.get("status") == "EXACT_ACTIVE_READY_SELECTED" and
             not assessed.get("validationErrors") and
             assessed.get("selectedActiveReady", {}).get("identity", {}).get("uid") == row.get("podUID") and
             dep.get("identity", {}).get("name") == name and
             dep.get("identity", {}).get("namespace") == "phorvex-system" and
             dep.get("status", {}).get("readyReplicas") == dep.get("status", {}).get("replicas") == 1 and
             dep.get("status", {}).get("observedGeneration") == dep.get("identity", {}).get("generation") and
             dep.get("containers", [{}])[0].get("image") ==
                 "753556437180.dkr.ecr.us-east-2.amazonaws.com/" +
                 ("phorvex" if component == "manager" else "phorvex-console") + ":" + version and
             pods[0].get("identity", {}).get("uid") == row.get("podUID") and
             pods[0].get("ready") is True and pods[0].get("phase") == "Running" and
             pods[0].get("deleting") is False and
             pods[0].get("containers", [{}])[0].get("imageID") == images[component] and
             pods[0]["containers"][0].get("ready") is True and
             rs.get("identity", {}).get("uid") and rs.get("readyReplicas") == 1 and
             len(rs.get("owners", [])) == 1 and rs["owners"][0].get("uid") == dep["identity"].get("uid") and
             any(o.get("uid") == rs["identity"].get("uid") and o.get("controller") is True
                 for o in pods[0].get("owners", [])),
             "Mongo current installed Pod/owner/image differs: " + component)
    need(profile["mongoExposureFixture"].get("managerImageID") == images["manager"],
         "Mongo current profile manager digest differs")
    target_hash, pod = verify_mongo_target(original, profile, expected, cluster_uid, images)
    target_receipt = strict_json(original("mongo/RECEIPT.json"))
    target_names = {r.get("label"): r.get("originalFile") for r in target_receipt.get("receipts", [])}
    for component in ("manager", "console"):
        raw = original("mongo/" + target_names[component + "-pods"])
        pods = strict_json(raw).get("items", [])
        need(len(pods) == 1 and
             pods[0].get("metadata", {}).get("uid") == build["builds"][component]["podUID"] and
             pods[0].get("status", {}).get("containerStatuses", [{}])[0].get("imageID") == images[component],
             "Mongo current later original manager/console Pod source differs: " + component)
    return ({"releaseSHA": release, "sourceSHA256": digest(build_raw),
             "clusterUID": cluster_uid, "tag": version, **images}, copied,
            {"sourceCommit": source, "targetReadSHA256": target_hash,
             "rolloutReceiptSHA256": digest(rollout_raw), "mongoPodUID": pod["metadata"].get("uid"),
             "managerPodUID": build["builds"]["manager"]["podUID"],
             "consolePodUID": build["builds"]["console"]["podUID"]})

def package(args):
    root = args.input.resolve()
    need(root.is_dir() and not args.output.resolve().is_relative_to(root) and not args.output.exists(),
         "input/output directory unavailable")
    need(args.namespace == "phorvex-system", "fixed console namespace differs")
    kinds = list(dict.fromkeys(args.profile))
    need(kinds and len(kinds) == len(args.profile), "select each fixed profile once")
    overlay_raw = read_relative(root, args.overlay, MAX_PROFILE)
    input_values = strict_yaml(overlay_raw)
    overlay = selected_values(input_values, kinds)
    original_console = input_values["phorvex"]["phorvex"]["console"]
    phorvex = overlay["phorvex"]["phorvex"]
    console = phorvex.get("console")
    need(isinstance(console, dict), "console values missing")
    mono166_pins = {"source": getattr(args, "expect_mongo166_source_sha256", None),
                 "review": getattr(args, "expect_mongo166_review_sha256", None),
                 "rollout": getattr(args, "expect_mongo166_rollout_sha256", None),
                 "target": getattr(args, "expect_mongo166_target_sha256", None),
                 "node": getattr(args, "expect_mongo166_node_sha256", None)}
    mono_current_pins = {"source": getattr(args, "expect_mongo_current_source_sha256", None),
                    "review": getattr(args, "expect_mongo_current_review_sha256", None),
                    "rollout": getattr(args, "expect_mongo_current_rollout_sha256", None),
                    "target": getattr(args, "expect_mongo_current_target_sha256", None),
                    "node": getattr(args, "expect_mongo_current_node_sha256", None)}
    mongo_release = "166" if any(mono166_pins.values()) else "current" if any(mono_current_pins.values()) else None
    mono_pins = mono166_pins if mongo_release == "166" else mono_current_pins
    need(not (any(mono166_pins.values()) and any(mono_current_pins.values())),
         "Mongo release original proof pin sets cannot be mixed")
    if mongo_release:
        need(kinds == ["mongo"] and all(mono_pins.values()),
             "Mongo release original proof requires one Mongo profile and five exact SHA pins")
        mongo_profile = strict_yaml(read_relative(root, SPECS["mongo"][0], MAX_PROFILE))
        verifier = verified_mongo_166_evidence if mongo_release == "166" else verified_mongo_current_evidence
        rollout, mongo_originals, mongo_summary = verifier(root, mongo_profile, mono_pins)
        need(phorvex["image"].get("tag") == rollout["tag"] and
             console["image"].get("tag") == rollout["tag"],
             "Mongo manager/console desired tags differ from original release")
        join_raw = build_raw = review_raw = pods_raw = None
    else:
        join_raw = read_relative(root, "evidence/JOIN.json", MAX_EVIDENCE)
        build_raw = read_relative(root, "evidence/SOURCE-BUILD.json", MAX_EVIDENCE)
        review_raw = read_relative(root, "evidence/source-review.json", MAX_EVIDENCE) if "pod-token" in kinds else None
        pods_raw = read_relative(root, "evidence/PODS.json", MAX_EVIDENCE) if "pod-token" in kinds else None
        join = strict_json(join_raw)
        build = strict_json(build_raw)
        need(isinstance(join.get("schema"), str) and UID.fullmatch(join.get("clusterUID", "")) and
             isinstance(join.get("components"), dict), "rollout join target/schema differs")
        need(isinstance(build, dict) and build.get("schema") == "catalogue-pr330-source-build-v1" and
             join.get("sourceSHA256") == digest(build_raw) and
             join.get("releaseSHA") == build.get("release", {}).get("sha") and
             build.get("run", {}).get("deployJob", {}).get("conclusion") == "success",
             "rollout/build receipt join differs")
        need(set(join) <= {"schema", "clusterUID", "components", "readBudget", "readWindow", "releaseSHA", "sourceMergeSHA", "sourceSHA256"} and
             set(build) <= {"schema", "capturedAtUTC", "mergeParents", "pr", "release", "run"} and
             b"/home/" not in join_raw and b"/home/" not in build_raw,
             "unsupported or private rollout/build evidence")
        version = re.fullmatch(r"release: v(\d+\.\d+\.\d+) \[skip ci\]", build.get("release", {}).get("messageSubject", ""))
        need(version is not None and phorvex["image"].get("tag") == version[1] and
             console["image"].get("tag") == version[1], "manager/console desired tags differ from reviewed release")
        rollout = {"releaseSHA": join.get("releaseSHA"), "sourceSHA256": join.get("sourceSHA256"),
                   "clusterUID": join["clusterUID"], "tag": version[1]}
        for component in ("manager", "console"):
            record = join["components"].get(component, {})
            images = record.get("podImageIDs", [])
            need(record.get("allPodsReady") is True and record.get("allImageIDsMatchSourceBuild") is True and
                 record.get("podCount") == record.get("readyReplicas") == 1 and
                 len(images) == 1 and IMAGE.fullmatch(images[0]) and
                 len(record.get("podUIDs", [])) == 1 and UID.fullmatch(record["podUIDs"][0]) and
                 build.get("run", {}).get("jobs", {}).get(component, {}).get("manifestListDigest") ==
                 images[0].split("@sha256:", 1)[1], "rollout incarnation/image differs: " + component)
            rollout[component] = images[0]
        if "pod-token" in kinds:
            verify_pod_read(pods_raw, join, rollout)
    for kind, (_, dotted, _, _) in SPECS.items():
        if kind in kinds:
            continue
        # An omitted profile cannot be activated by this bundle.
        block = optional_block(original_console, dotted)
        if block is None:
            continue
        need(block["enabled"] is False, "enabled profile has no packaged bytes: " + kind)
    configmaps, profiles = [], {}
    for kind in kinds:
        filename, dotted, fixture, namespace = SPECS[kind]
        block = overlay_block(console, dotted)
        need(args.allow_enabled or block["enabled"] is False, "enabled delivery requires explicit --allow-enabled")
        raw = read_relative(root, filename, MAX_PROFILE)
        manifest = None
        manifest_raw = None
        if kind == "pod-token":
            manifest_raw = read_relative(root, "manifest.json", MAX_MANIFEST)
            manifest = pod_manifest(manifest_raw, build_raw, review_raw, pods_raw, rollout, digest(join_raw), phorvex)
            if PLACEHOLDER.encode() in raw:
                need(raw.count(PLACEHOLDER.encode()) == 1, "Pod-token manifest placeholder count differs")
                raw = raw.replace(PLACEHOLDER.encode(), digest(manifest_raw).encode())
            need(block.get("scrapeApproved") is True or block["enabled"] is False,
                 "enabled Pod-token profile lacks scrape approval")
        need(b"/home/" not in raw, "private profile bytes: " + kind)
        profile = strict_yaml(raw)
        need(not has_unfilled_scalar(profile), "unfilled profile scalar: " + kind)
        need(isinstance(profile, dict) and profile.get("namespace") == namespace and
             profile.get("context") not in (None, "", "in-cluster") and
             profile.get("kubeconfig", "") == "" and profile.get("ownedAck") is True and
             profile.get("trialsPerArm") == 1 and isinstance(profile.get(fixture), dict) and
             profile[fixture].get("transport") == "in-cluster", "fixed named profile scope differs: " + kind)
        if kind == "pod-token":
            f = profile[fixture]
            need(f.get("prometheusURL") == phorvex["prometheusUrl"],
                 "Pod-token fixture/manager Prometheus URL differs")
            need(f.get("sourceManifestPath") == "/etc/phorvex-catalogue-pod-bound-token/manifest.json" and
                 f.get("sourceManifestSHA256") == digest(manifest_raw) and
                 f.get("managerImageID") == manifest["managerImageID"] and
                 f.get("clusterUID") == rollout["clusterUID"], "Pod-token profile/manifest binding differs")
            need(f["managerImageID"] == rollout["manager"], "Pod-token manager image differs from rollout")
        if kind == "mongo":
            need(profile[fixture].get("managerImageID") == rollout["manager"] and
                 profile[fixture].get("clusterUID") == rollout["clusterUID"], "Mongo manager/cluster differs from rollout")
        if kind in ("nats-baseline", "nats-response"):
            need(profile[fixture].get("observerImage") == rollout["console"] and
                 profile[fixture].get("clusterUID") == rollout["clusterUID"], "NATS observer/cluster differs from rollout")
        if kind == "guardrail-static" and block["enabled"]:
            need(profile[fixture].get("variant") in ("pgv1", "pgv2", "observe-current"),
                 "enabled static suite requires an exact pgv1/pgv2 pin or observe-current selector")
        if kind == "guardrail-availability":
            f = profile[fixture]
            creator = str(f.get("eventCreator", ""))
            creator_prefix = "system:serviceaccount:phorvex-system:"
            account = creator.removeprefix(creator_prefix)
            creator_ok = (creator.startswith(creator_prefix) and 0 < len(account) <= 253 and
                          all(0 < len(label) <= 63 and
                              re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", label)
                              for label in account.split(".")))
            deployment_name = str(f.get("consoleDeploymentName", ""))
            deployment_ok = (0 < len(deployment_name) <= 253 and
                             all(0 < len(label) <= 63 and
                                 re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", label)
                                 for label in deployment_name.split(".")))
            try:
                audit = urlsplit(str(f.get("auditURL", "")))
                audit_port = audit.port
            except ValueError as exc:
                raise ValueError("availability audit URL is malformed") from exc
            need(f.get("clusterUID") == rollout["clusterUID"] and
                 f.get("managerImageID") == rollout["manager"] and
                 f.get("consoleImageID") == rollout["console"],
                 "availability cluster/manager/console rollout differs")
            need(f.get("sourceConfigMapName") == block.get("sourceConfigMap") == "guardrail-proxy" and
                 f.get("guardrailJournalName") == block.get("guardrailJournalName") and
                 f.get("policyName") == "vllm-defense" and
                 f.get("modelID") == "Qwen/Qwen2.5-7B-Instruct-AWQ" and
                 creator_ok and
                 f.get("consoleURL") == "http://127.0.0.1:8090" and
                 f.get("scopedTokenFile") == "/etc/phorvex-catalogue-v1/token" and
                 f.get("auditCAFile") == "/etc/audit-client/ca.crt" and
                 f.get("auditClientCertFile") == "/etc/audit-client/tls.crt" and
                 f.get("auditClientKeyFile") == "/etc/audit-client/tls.key" and
                 f.get("maxRunSeconds") == 600 and f.get("cleanupSeconds") == 90,
                 "availability fixed route, journal or bounds differ")
            need(UID.fullmatch(str(f.get("podUID", ""))) and
                 UID.fullmatch(str(f.get("serviceUID", ""))) and
                 UID.fullmatch(str(f.get("sourceUID", ""))) and
                 UID.fullmatch(str(f.get("guardrailJournalUID", ""))) and
                 UID.fullmatch(str(f.get("managerPodUID", ""))) and
                 UID.fullmatch(str(f.get("consoleDeploymentUID", ""))) and
                 deployment_ok and
                 "consolePodName" not in f and "consolePodUID" not in f and
                 UID.fullmatch(str(f.get("policyUID", ""))) and
                 IMAGE.fullmatch(str(f.get("podImageID", ""))) and
                 SHA.fullmatch(str(f.get("sourceSHA256", ""))) and
                 type(f.get("policyGeneration")) is int and f["policyGeneration"] > 0 and
                 re.fullmatch(r"run-[1-9][0-9]*", str(f.get("runID", ""))) and
                 audit.scheme == "https" and audit.hostname is not None and
                 audit.hostname.endswith(".phorvex-system.svc") and audit_port == 8445 and
                 not audit.username and not audit.password and not audit.path and
                 not audit.query and not audit.fragment and f.get("auditServerName") == audit.hostname,
                 "availability installed source/identity pin is incomplete")
        profile_sha = digest(raw)
        name = "phorvex-catalogue-" + kind + "-" + profile_sha[:12]
        for key, actual in (("profileSHA256", profile_sha), ("configMapName", name)):
            need(block.get(key, "") in ("", actual), "overlay carries stale " + kind + " " + key)
            block[key] = actual
        data = {filename: Literal(raw.decode("utf-8"))}
        if manifest_raw is not None and kind == "pod-token":
            data["manifest.json"] = Literal(manifest_raw.decode("utf-8"))
        configmaps.append({"apiVersion": "v1", "kind": "ConfigMap",
                           "metadata": {"name": name, "namespace": args.namespace},
                           "immutable": True, "data": data})
        profiles[kind] = {"filename": filename, "sha256": profile_sha, "configMapName": name,
                          "manifestSHA256": digest(manifest_raw) if kind == "pod-token" else None,
                          "enabledInProposal": block["enabled"]}
    if "nats-response" in kinds and overlay_block(console, "natsExposure.clientResponse")["enabled"]:
        need("nats-baseline" in kinds and overlay_block(console, "natsExposure")["enabled"],
             "NATS response requires enabled baseline")
    args.output.mkdir(parents=True, mode=0o700)
    evidence = args.output / "evidence"
    evidence.mkdir(mode=0o700)
    if mongo_release:
        for relative, raw in mongo_originals.items():
            destination = args.output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
    else:
        (evidence / "JOIN.json").write_bytes(join_raw)
        (evidence / "SOURCE-BUILD.json").write_bytes(build_raw)
        if "pod-token" in kinds:
            (evidence / "source-review.json").write_bytes(review_raw)
            (evidence / "PODS.json").write_bytes(pods_raw)
    (args.output / "configmaps.yaml").write_text(yaml.safe_dump_all(configmaps, sort_keys=False, explicit_start=True))
    (args.output / "values-overlay.yaml").write_text(yaml.safe_dump(overlay, sort_keys=False))
    receipt = {"schema": "phorvex.catalogue-profile-package.v1", "status": "OFFLINE_REVIEW_REQUIRED_NOT_DEPLOYED",
               "inputOverlaySHA256": digest(overlay_raw), "profiles": profiles,
               "rolloutImageIDs": {k: rollout[k] for k in ("manager", "console")},
               "configMapsSHA256": digest((args.output / "configmaps.yaml").read_bytes()),
               "valuesOverlaySHA256": digest((args.output / "values-overlay.yaml").read_bytes())}
    if mongo_release:
        receipt.update({"evidenceSchema": "mongo-" + mongo_release + "-originals-v1", "originalPins": mono_pins,
                        "originalJoin": mongo_summary,
                        "copiedEvidenceSHA256": {name:digest(raw) for name,raw in mongo_originals.items()}})
    else:
        receipt.update({"rolloutJoinSHA256": digest(join_raw),
                        "copiedEvidenceSHA256": {"evidence/JOIN.json": digest(join_raw),
                            "evidence/SOURCE-BUILD.json": digest(build_raw),
                            **({"evidence/source-review.json": digest(review_raw),
                                "evidence/PODS.json": digest(pods_raw)} if "pod-token" in kinds else {})}})
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="operator-reviewed input directory")
    parser.add_argument("--overlay", default="values-overlay.reviewed.yaml", help="relative input values fragment")
    parser.add_argument("--profile", action="append", choices=sorted(SPECS), required=True)
    parser.add_argument("--namespace", default="phorvex-system")
    parser.add_argument("--allow-enabled", action="store_true", help="acknowledge reviewed enabled values in input")
    parser.add_argument("--expect-mongo166-source-sha256", help="independently reviewed original .166 build record SHA")
    parser.add_argument("--expect-mongo166-review-sha256", help="independently reviewed source/image approval SHA")
    parser.add_argument("--expect-mongo166-rollout-sha256", help="independently reviewed original rollout terminal SHA")
    parser.add_argument("--expect-mongo166-target-sha256", help="independently reviewed original Mongo GET receipt SHA")
    parser.add_argument("--expect-mongo166-node-sha256", help="independently reviewed eligible CPU node read SHA")
    parser.add_argument("--expect-mongo-current-source-sha256", help="independently reviewed current CI/build installed join SHA")
    parser.add_argument("--expect-mongo-current-review-sha256", help="independently reviewed current source/image approval SHA")
    parser.add_argument("--expect-mongo-current-rollout-sha256", help="independently reviewed current projected rollout SHA")
    parser.add_argument("--expect-mongo-current-target-sha256", help="independently reviewed current Mongo raw GET receipt SHA")
    parser.add_argument("--expect-mongo-current-node-sha256", help="independently reviewed eligible CPU node raw GET SHA")
    parser.add_argument("--output", type=Path, required=True, help="new output directory; never overwritten")
    receipt = package(parser.parse_args())
    print(json.dumps({"status": receipt["status"], "profiles": receipt["profiles"]}, sort_keys=True))


if __name__ == "__main__":
    main()
