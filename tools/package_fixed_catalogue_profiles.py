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
            need(profile[fixture].get("variant") == "pgv1", "enabled static suite requires reviewed pgv1 source")
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
    (evidence / "JOIN.json").write_bytes(join_raw)
    (evidence / "SOURCE-BUILD.json").write_bytes(build_raw)
    if "pod-token" in kinds:
        (evidence / "source-review.json").write_bytes(review_raw)
        (evidence / "PODS.json").write_bytes(pods_raw)
    (args.output / "configmaps.yaml").write_text(yaml.safe_dump_all(configmaps, sort_keys=False, explicit_start=True))
    (args.output / "values-overlay.yaml").write_text(yaml.safe_dump(overlay, sort_keys=False))
    receipt = {"schema": "phorvex.catalogue-profile-package.v1", "status": "OFFLINE_REVIEW_REQUIRED_NOT_DEPLOYED",
               "inputOverlaySHA256": digest(overlay_raw), "profiles": profiles,
               "rolloutJoinSHA256": digest(join_raw), "rolloutImageIDs": {k: rollout[k] for k in ("manager", "console")},
               "copiedEvidenceSHA256": {"evidence/JOIN.json": digest(join_raw), "evidence/SOURCE-BUILD.json": digest(build_raw),
                                        **({"evidence/source-review.json": digest(review_raw),
                                            "evidence/PODS.json": digest(pods_raw)} if "pod-token" in kinds else {})},
               "configMapsSHA256": digest((args.output / "configmaps.yaml").read_bytes()),
               "valuesOverlaySHA256": digest((args.output / "values-overlay.yaml").read_bytes())}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="operator-reviewed input directory")
    parser.add_argument("--overlay", default="values-overlay.reviewed.yaml", help="relative input values fragment")
    parser.add_argument("--profile", action="append", choices=sorted(SPECS), required=True)
    parser.add_argument("--namespace", default="phorvex-system")
    parser.add_argument("--allow-enabled", action="store_true", help="acknowledge reviewed enabled values in input")
    parser.add_argument("--output", type=Path, required=True, help="new output directory; never overwritten")
    receipt = package(parser.parse_args())
    print(json.dumps({"status": receipt["status"], "profiles": receipt["profiles"]}, sort_keys=True))


if __name__ == "__main__":
    main()
