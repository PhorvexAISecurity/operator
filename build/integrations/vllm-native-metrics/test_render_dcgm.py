"""Offline S6-D controls. Execute on the lead's isolated EC2, never a live cluster.

Fixtures carry synthetic receipt evidence hashes; they prove renderer predicates,
not GPU support, Kubernetes attribution, exporter runtime, or live acceptance.
"""
import contextlib
import copy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest

import render_dcgm as dcgm

NOW = datetime(2026, 10, 14, 14, 20, tzinfo=timezone.utc)
STAMP = NOW.isoformat()
COUNTERS = dcgm.COUNTERS_FILE.read_bytes()
DEFAULT = COUNTERS[:-len(dcgm.APPEND)]


def fixture():
    ps = {"containers": [
        {"name": "other", "image": "unchanged/sidecar:original", "args": ["--watch"],
         "env": [{"name": "OTHER", "value": "preserved"}],
         "securityContext": {"readOnlyRootFilesystem": True}},
        {"name": dcgm.DAEMONSET, "image": dcgm.IMAGE_TAG, "imagePullPolicy": "IfNotPresent",
         "args": ["--collect-interval", "30000"],
         "env": [{"name": "DCGM_EXPORTER_KUBERNETES", "value": "true"},
                 {"name": "DCGM_EXPORTER_LISTEN", "value": ":9400"},
                 {"name": "UNRELATED", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}],
         "ports": [{"name": "metrics", "containerPort": 9400, "protocol": "TCP"}],
         "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                       "limits": {"cpu": "100m", "memory": "128Mi"}},
         "securityContext": {"runAsNonRoot": False, "capabilities": {"add": ["SYS_ADMIN"]}},
         "volumeMounts": [{"name": "pod-resources", "mountPath": "/var/lib/kubelet/pod-resources", "readOnly": True}],
         "terminationMessagePolicy": "File", "terminationMessagePath": "/dev/termination-log"}],
        "initContainers": [{"name": "existing-init", "image": "unchanged/init:v1", "args": ["original"]}],
        "volumes": [{"name": "pod-resources", "hostPath": {"path": "/var/lib/kubelet/pod-resources", "type": ""}}],
        "nodeSelector": {"nvidia.com/gpu.present": "true"},
        "tolerations": [{"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoSchedule"}],
        "serviceAccountName": "existing-exporter-account", "automountServiceAccountToken": False,
        "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
        "terminationGracePeriodSeconds": 30, "dnsPolicy": "ClusterFirst", "restartPolicy": "Always"}
    ds = {"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": {
        "name": dcgm.DAEMONSET, "namespace": dcgm.NAMESPACE, "uid": "stable-dcgm-uid",
        "resourceVersion": "10", "generation": 1,
        "labels": {"app": "dcgm-exporter", "app.kubernetes.io/managed-by": "original-owner"},
        "annotations": {"original/annotation": "preserve", "deprecated.daemonset.template.generation": "1"},
        "ownerReferences": [{"apiVersion": "v1", "kind": "OriginalOwner", "name": "owner", "uid": "owner-uid"}]},
        "spec": {"selector": {"matchLabels": {"app": "dcgm-exporter"}},
                 "template": {"metadata": {"labels": {"app": "dcgm-exporter"},
                                           "annotations": {"original/template": "preserve"}}, "spec": ps},
                 "updateStrategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1}},
                 "revisionHistoryLimit": 10},
        "status": {"observedGeneration": 1, "desiredNumberScheduled": 1, "currentNumberScheduled": 1,
                   "updatedNumberScheduled": 1, "numberReady": 1, "numberAvailable": 1, "numberMisscheduled": 0}}
    cms = {"apiVersion": "v1", "kind": "ConfigMapList", "metadata": {"resourceVersion": "200"}, "items": []}
    return ds, cms


def receipt(ds, ds_sha=None, stamp=STAMP):
    probes = {}
    for name, fields in (("smActive", dcgm.FIELDS[:1]), ("pcieLink", dcgm.FIELDS[1:])):
        probes[name] = {"fields": list(fields), "defaultCountersSHA256": dcgm.DEFAULT_SHA256,
            "csvSHA256": "a" * 64, "metricsSHA256": "b" * 64, "logsSHA256": "c" * 64,
            "ready": True, "warningCount": 0, "errorCount": 0,
            "values": {field: [value] for field, value in zip(fields, (0,) if name == "smActive" else (1, 8))}}
    exporter = next(c for c in ds["spec"]["template"]["spec"]["containers"] if c["name"] == dcgm.DAEMONSET)
    return {"schema": dcgm.SUPPORT_SCHEMA, "scope": "independent-capability-only",
            "observedAt": stamp, "executor": "synthetic-offline-fixture", "daemonsetUID": ds["metadata"]["uid"],
            "daemonsetSHA256": ds_sha or dcgm.sha(dcgm.canonical(ds)), "instanceID": dcgm.INSTANCE,
            "amiID": dcgm.AMI, "gpu": "Tesla T4", "driverVersion": dcgm.DRIVER,
            "exporterTag": dcgm.IMAGE_TAG, "exporterDigest": dcgm.IMAGE_DIGEST,
            "liveExporterImage": exporter["image"], "liveExporterDigest": dcgm.IMAGE_DIGEST,
            "defaultCountersSHA256": dcgm.DEFAULT_SHA256, "probes": probes}


def patched(obj, operations):
    """Minimal RFC6902 evaluator for these outputs, independent of renderer logic."""
    obj = copy.deepcopy(obj)
    for op in operations:
        keys = [k.replace("~1", "/").replace("~0", "~") for k in op["path"].split("/")[1:]]
        parent = obj
        for key in keys[:-1]:
            parent = parent[int(key)] if isinstance(parent, list) else parent[key]
        key = keys[-1]
        if op["op"] == "test":
            actual = parent[int(key)] if isinstance(parent, list) else parent[key]
            if json.dumps(actual, sort_keys=True) != json.dumps(op["value"], sort_keys=True):
                raise ValueError("JSON patch precondition failed")
        elif op["op"] == "add":
            if isinstance(parent, list):
                parent.insert(len(parent) if key == "-" else int(key), copy.deepcopy(op["value"]))
            else:
                parent[key] = copy.deepcopy(op["value"])
        elif op["op"] == "replace":
            if key not in parent:
                raise ValueError("missing replacement path")
            parent[key] = copy.deepcopy(op["value"])
        else:
            raise AssertionError("unexpected JSON patch operation")
    return obj


class RendererTests(unittest.TestCase):
    def setUp(self):
        self.ds, self.cms = fixture()

    def exporter(self, ds=None):
        return next(c for c in (ds or self.ds)["spec"]["template"]["spec"]["containers"] if c["name"] == dcgm.DAEMONSET)

    def rendered(self, ds=None, cms=None, support=None, default=DEFAULT, counters=COUNTERS, stamp=STAMP):
        ds, cms = ds or self.ds, cms or self.cms
        bound = support if support is not None else receipt(ds)
        return dcgm.render(ds, dcgm.sha(dcgm.canonical(ds)), cms, dcgm.sha(dcgm.canonical(cms)),
            bound, dcgm.sha(dcgm.canonical(bound)), default, counters, stamp, now=NOW)

    def candidate(self, artifacts=None):
        artifacts = artifacts or self.rendered()
        current = patched(self.ds, artifacts["daemonset-forward.json"])
        current["metadata"].update(resourceVersion="12", generation=2)
        current["metadata"]["annotations"]["deprecated.daemonset.template.generation"] = "2"
        return current

    def rolled_back(self, current=None, closure=None, stamp=STAMP):
        current = current or self.candidate()
        closure = closure or self.rendered()["dcgm-closure.json"]
        return dcgm.rollback(current, dcgm.sha(dcgm.canonical(current)), closure, stamp, now=NOW)

    def test_actual_defaults_exact_prefix_three_gauges_and_manifest(self):
        self.assertEqual(len(DEFAULT), 4460)
        self.assertEqual(dcgm.sha(DEFAULT), dcgm.DEFAULT_SHA256)
        appended = COUNTERS[len(DEFAULT):].decode().splitlines()
        self.assertEqual([line.split(",", 2)[:2] for line in appended], [[f, " gauge"] for f in dcgm.FIELDS])
        cm = self.rendered()["dcgm-exporter-profiling.yaml"]
        self.assertEqual(cm["data"]["counters.csv"].encode(), COUNTERS)
        self.assertEqual(cm, json.loads((dcgm.ROOT / "deploy/monitoring/dcgm-exporter-profiling.yaml").read_bytes()))
        self.assertEqual(cm["metadata"]["name"], dcgm.CM_PREFIX + dcgm.sha(COUNTERS)[:16])
        self.assertIs(cm["immutable"], True)
        self.assertNotIn("ownerReferences", cm["metadata"])
        self.assertNotIn("labels", cm["metadata"])
        self.assertEqual(set(cm["data"]), {"counters.csv"})

    def test_only_three_additions_preserve_every_original_spec_and_metadata(self):
        before = copy.deepcopy(self.ds)
        artifacts = self.rendered()
        candidate = patched(self.ds, artifacts["daemonset-forward.json"])
        self.assertEqual(self.ds, before)
        self.assertEqual(candidate["metadata"], before["metadata"])
        restored = copy.deepcopy(candidate["spec"])
        ps = restored["template"]["spec"]
        exporter = next(c for c in ps["containers"] if c["name"] == dcgm.DAEMONSET)
        self.assertEqual(exporter["env"].pop(), {"name": dcgm.COLLECTORS, "value": "/etc/phorvex-dcgm/counters.csv"})
        self.assertEqual(exporter["volumeMounts"].pop(), {"name": dcgm.VOLUME, "mountPath": dcgm.MOUNT, "readOnly": True})
        volume = ps["volumes"].pop()
        self.assertEqual(volume["configMap"]["items"], [{"key": "counters.csv", "path": "counters.csv"}])
        self.assertEqual(volume["configMap"]["defaultMode"], 0o444)
        self.assertIs(volume["configMap"]["optional"], False)
        self.assertEqual(restored, before["spec"])
        mutations = [op for op in artifacts["daemonset-forward.json"] if op["op"] != "test"]
        self.assertEqual([op["op"] for op in mutations], ["add"] * 3)
        self.assertEqual([op["path"] for op in mutations], ["/spec/template/spec/containers/1/env/-",
            "/spec/template/spec/containers/1/volumeMounts/-", "/spec/template/spec/volumes/-"])
        self.assertEqual(artifacts["dcgm-closure.json"]["candidateSpec"], candidate["spec"])
        self.assertIn("pending", artifacts["dcgm-closure.json"]["acceptance"])

    def test_absent_optional_lists_create_only_additions_and_restore_absence(self):
        del self.exporter()["env"]
        del self.exporter()["volumeMounts"]
        del self.ds["spec"]["template"]["spec"]["volumes"]
        artifacts = self.rendered()
        current = self.candidate(artifacts)
        inverse = self.rolled_back(current, artifacts["dcgm-closure.json"])["daemonset-inverse.json"]
        self.assertEqual(patched(current, inverse)["spec"], self.ds["spec"])

    def test_both_tag_and_exact_digest_forms_are_preserved(self):
        for image in dcgm.IMAGES:
            with self.subTest(image=image):
                self.exporter()["image"] = image
                self.assertEqual(self.rendered()["dcgm-closure.json"]["image"], image)

    def test_explicit_original_executable_and_noncollector_args_preserved(self):
        self.exporter()["command"] = ["/usr/bin/dcgm-exporter"]
        self.assertEqual(self.rendered()["dcgm-closure.json"]["candidateSpec"]["template"]["spec"]["containers"][1]["command"],
                         ["/usr/bin/dcgm-exporter"])

    def test_forward_uid_rv_whole_spec_and_metadata_preconditions(self):
        operations = self.rendered()["daemonset-forward.json"]
        self.assertEqual([op["path"] for op in operations[:4]], ["/metadata/uid", "/metadata/resourceVersion", "/spec", "/metadata"])
        for field in ("uid", "resourceVersion", "ownerReferences", "annotations", "labels"):
            changed = copy.deepcopy(self.ds)
            changed["metadata"][field] = "drift"
            with self.subTest(field=field), self.assertRaises(ValueError):
                patched(changed, operations)
        for field in ("revisionHistoryLimit", "selector", "updateStrategy", "template"):
            changed = copy.deepcopy(self.ds)
            changed["spec"][field] = "drift"
            with self.subTest(field=field), self.assertRaises(ValueError):
                patched(changed, operations)

    def test_inverse_review_template_cannot_apply(self):
        artifacts = self.rendered()
        inverse = artifacts["daemonset-inverse-review-only.json"]
        self.assertEqual(inverse[1]["value"], dcgm.REVIEW_RV)
        with self.assertRaises(ValueError):
            patched(self.candidate(artifacts), inverse)

    def test_fresh_inverse_restores_original_spec_with_current_rv_and_ownership(self):
        artifacts = self.rendered()
        current = self.candidate(artifacts)
        current["status"].update(numberReady=0, numberAvailable=0)  # rollback also works on a failed rollout
        current["metadata"]["resourceVersion"] = "19999"
        inverse = self.rolled_back(current, artifacts["dcgm-closure.json"])["daemonset-inverse.json"]
        self.assertEqual(inverse[1]["value"], "19999")
        restored = patched(current, inverse)
        self.assertEqual(restored["spec"], self.ds["spec"])
        self.assertEqual(restored["metadata"], current["metadata"])
        for field in ("uid", "resourceVersion"):
            changed = copy.deepcopy(current)
            changed["metadata"][field] = "drift"
            with self.subTest(field=field), self.assertRaises(ValueError):
                patched(changed, inverse)

    def test_rollback_uid_spec_and_ownership_drift_refused(self):
        for mutation in (lambda d: d["metadata"].update(uid="replacement"),
                         lambda d: d["spec"]["template"]["spec"]["containers"][1].update(image="other/image"),
                         lambda d: d["spec"]["template"]["spec"]["containers"][1]["args"].append("--new"),
                         lambda d: d["spec"].update(revisionHistoryLimit=99),
                         lambda d: d["metadata"]["labels"].update({"app.kubernetes.io/managed-by": "Helm"}),
                         lambda d: d["metadata"]["annotations"].update({"meta.helm.sh/release-name": "adopted"}),
                         lambda d: d["metadata"].update(ownerReferences=[])):
            current = self.candidate()
            mutation(current)
            with self.subTest(current=current), self.assertRaises(ValueError):
                self.rolled_back(current)
        with self.assertRaises(ValueError):
            self.rolled_back(self.ds)  # baseline isn't the exact candidate

    def test_rollback_reconstructs_candidate_and_rejects_rehashed_extra_change(self):
        closure = self.rendered()["dcgm-closure.json"]
        current = self.candidate()
        for spec in (closure["candidateSpec"], current["spec"]):
            spec["template"]["spec"]["containers"][1]["resources"] = {}
        closure["candidateSpecSHA256"] = dcgm.sha(dcgm.canonical(closure["candidateSpec"]))
        with self.assertRaises(ValueError):
            self.rolled_back(current, closure)
        closure = self.rendered()["dcgm-closure.json"]
        closure["originalSpecSHA256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.rolled_back(closure=closure)
        closure = self.rendered()["dcgm-closure.json"]
        closure["configMap"]["data"]["counters.csv"] += "# unexpected\n"
        with self.assertRaises(ValueError):
            self.rolled_back(closure=closure)

    def test_default_whitespace_and_arbitrary_candidate_changes_refused(self):
        for default, counters in ((DEFAULT + b"\n", COUNTERS), (DEFAULT, COUNTERS + b"\n"),
                                  (DEFAULT, COUNTERS.replace(b"gauge, Current", b"counter, Current")),
                                  (DEFAULT, DEFAULT + dcgm.APPEND.splitlines(keepends=True)[0]),
                                  (DEFAULT, DEFAULT + dcgm.APPEND + b"DCGM_FI_DEV_EXTRA, gauge, extra\n")):
            with self.subTest(default=default[-20:], counters=counters[-50:]), self.assertRaises(ValueError):
                self.rendered(default=default, counters=counters)

    def test_existing_override_even_empty_or_valuefrom_is_refused(self):
        for row in ({"name": dcgm.COLLECTORS, "value": ""},
                    {"name": dcgm.COLLECTORS, "value": "/existing.csv"},
                    {"name": "DCGM_EXPORTER_CONFIGMAP_DATA", "value": "namespace:old-counters"},
                    {"name": dcgm.COLLECTORS, "valueFrom": {"configMapKeyRef": {"name": "old", "key": "csv"}}}):
            ds = copy.deepcopy(self.ds)
            self.exporter(ds)["env"].append(row)
            with self.subTest(row=row), self.assertRaises(ValueError):
                self.rendered(ds=ds)
        self.exporter()["envFrom"] = [{"configMapRef": {"name": "unresolved"}}]
        with self.assertRaises(ValueError):
            self.rendered()

    def test_collectors_flags_and_shell_command_refused(self):
        for args in (["-f", "/old"], ["-f/old"], ["-f=/old"], ["--collectors", "/old"],
                     ["--collectors=/old"], ["DCGM_EXPORTER_COLLECTORS=/old"],
                     ["--configmap-data=namespace:old"], ["-m", "namespace:old"]):
            ds = copy.deepcopy(self.ds)
            self.exporter(ds)["args"] = args
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.rendered(ds=ds)
        self.exporter()["command"] = ["sh", "-c", "dcgm-exporter"]
        with self.assertRaises(ValueError):
            self.rendered()

    def test_mount_collisions_parents_children_and_other_containers_refused(self):
        for path in (dcgm.MOUNT, dcgm.MOUNT + "/counters.csv", dcgm.MOUNT + "/other", "/etc", "/",
                     "/etc/../etc/phorvex-dcgm", "/etc/phorvex-dcgm/", "//etc/phorvex-dcgm"):
            for key, index in (("containers", 0), ("containers", 1), ("initContainers", 0)):
                ds = copy.deepcopy(self.ds)
                ds["spec"]["template"]["spec"][key][index].setdefault("volumeMounts", []).append(
                    {"name": "colliding-mount", "mountPath": path})
                with self.subTest(path=path, key=key, index=index), self.assertRaises(ValueError):
                    self.rendered(ds=ds)
        self.exporter()["volumeMounts"].append({"name": "unrelated", "mountPath": "/etc/phorvex-dcgm-other"})
        self.rendered()  # prefix alone is not a path collision

    def test_volume_and_mount_name_collisions_refused(self):
        ds = copy.deepcopy(self.ds)
        ds["spec"]["template"]["spec"]["volumes"].append({"name": dcgm.VOLUME, "emptyDir": {}})
        with self.assertRaises(ValueError):
            self.rendered(ds=ds)
        self.exporter()["volumeMounts"].append({"name": dcgm.VOLUME, "mountPath": "/somewhere-else"})
        with self.assertRaises(ValueError):
            self.rendered()

    def test_duplicate_names_paths_and_unsettled_forward_refused(self):
        for key in ("containers", "volumes"):
            ds = copy.deepcopy(self.ds)
            rows = ds["spec"]["template"]["spec"][key]
            rows.append(copy.deepcopy(rows[-1]))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.rendered(ds=ds)
        self.exporter()["env"].append(copy.deepcopy(self.exporter()["env"][0]))
        with self.assertRaises(ValueError):
            self.rendered()
        ds, _ = fixture()
        ds["status"]["numberReady"] = 0
        with self.assertRaises(ValueError):
            self.rendered(ds=ds)
        ds["status"]["numberReady"] = 1
        ds["status"]["observedGeneration"] = 0
        with self.assertRaises(ValueError):
            self.rendered(ds=ds)

    def test_image_identity_partial_object_and_deletion_refused(self):
        for image in (dcgm.IMAGE_TAG + "-changed", dcgm.IMAGE_REPO + "@sha256:" + "0" * 64):
            ds = copy.deepcopy(self.ds)
            self.exporter(ds)["image"] = image
            with self.subTest(image=image), self.assertRaises(ValueError):
                self.rendered(ds=ds)
        for key in ("uid", "resourceVersion", "name", "namespace"):
            ds = copy.deepcopy(self.ds)
            ds["metadata"][key] = ""
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.rendered(ds=ds)
        self.ds["metadata"]["deletionTimestamp"] = STAMP
        with self.assertRaises(ValueError):
            self.rendered()

    def test_configmap_collision_even_identical_object_refused(self):
        cm = self.rendered()["dcgm-exporter-profiling.yaml"]
        cm["metadata"].update(uid="existing-cm", resourceVersion="9")
        self.cms["items"].append(cm)
        with self.assertRaisesRegex(ValueError, "never adopt"):
            self.rendered()
        self.cms["items"][0]["data"]["counters.csv"] = "foreign"
        with self.assertRaises(ValueError):
            self.rendered()

    def test_truncated_or_foreign_configmap_inventory_refused(self):
        for mutation in (lambda c: c["metadata"].update({"continue": "more"}),
                         lambda c: c["metadata"].update({"remainingItemCount": 1}),
                         lambda c: c["metadata"].pop("resourceVersion"),
                         lambda c: c.update(kind="SecretList"),
                         lambda c: c["items"].append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
                             "name": "foreign", "namespace": "other", "uid": "cm-uid", "resourceVersion": "4"}})):
            cms = copy.deepcopy(self.cms)
            mutation(cms)
            with self.subTest(cms=cms), self.assertRaises(ValueError):
                self.rendered(cms=cms)

    def test_support_hardware_image_sha_uid_and_scope_binding_refused(self):
        for key in ("schema", "scope", "daemonsetUID", "daemonsetSHA256", "instanceID", "amiID", "gpu",
                    "driverVersion", "exporterTag", "exporterDigest", "liveExporterImage", "liveExporterDigest",
                    "defaultCountersSHA256", "executor"):
            bound = receipt(self.ds)
            bound[key] = ""
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.rendered(support=bound)

    def test_separate_probe_fields_diagnostics_and_source_hashes_required(self):
        bound = receipt(self.ds)
        bound["probes"] = {"combined": bound["probes"]["smActive"]}
        with self.assertRaises(ValueError):
            self.rendered(support=bound)
        for name in ("smActive", "pcieLink"):
            for key, value in (("fields", list(dcgm.FIELDS)), ("defaultCountersSHA256", "0" * 64),
                               ("ready", False), ("warningCount", 1), ("errorCount", 1), ("csvSHA256", ""),
                               ("metricsSHA256", "bad"), ("logsSHA256", "A" * 64)):
                bound = receipt(self.ds)
                bound["probes"][name][key] = value
                with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                    self.rendered(support=bound)

    def test_finite_zero_sm_active_and_valid_link_domains(self):
        self.rendered()  # positive control: zero occupancy is valid
        for value in (0, 0.123, 1):
            bound = receipt(self.ds)
            bound["probes"]["smActive"]["values"][dcgm.FIELDS[0]] = [value]
            self.rendered(support=bound)
        invalid = [("smActive", dcgm.FIELDS[0], v) for v in (True, -0.1, 1.1, "0", float("nan"), float("inf"))]
        invalid += [("pcieLink", dcgm.FIELDS[1], v) for v in (0, -1, 1.5, 7, float("inf"))]
        invalid += [("pcieLink", dcgm.FIELDS[2], v) for v in (0, -1, 3, 8.5, 2147483647)]
        for name, field, value in invalid:
            bound = receipt(self.ds)
            bound["probes"][name]["values"][field] = [value]
            # Call the predicate directly: strict JSON encoding also rejects NaN/Inf.
            with self.subTest(name=name, field=field, value=value), self.assertRaises(ValueError):
                dcgm.support(bound, self.ds, dcgm.sha(dcgm.canonical(self.ds)), now=NOW)
        bound = receipt(self.ds)
        bound["probes"]["smActive"]["values"][dcgm.FIELDS[0]] = []
        with self.assertRaises(ValueError):
            self.rendered(support=bound)

    def test_capture_and_support_freshness_not_bypassable(self):
        for stamp in ((NOW - timedelta(seconds=301)).isoformat(), (NOW + timedelta(seconds=31)).isoformat(),
                      "2026-10-14T14:20:00+01:00", "2026-10-14T14:20:00"):
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                self.rendered(stamp=stamp)
            with self.subTest(rollback=stamp), self.assertRaises(ValueError):
                self.rolled_back(stamp=stamp)
        for stamp in ((NOW - timedelta(days=1, seconds=1)).isoformat(), (NOW + timedelta(seconds=31)).isoformat()):
            with self.subTest(support=stamp), self.assertRaises(ValueError):
                self.rendered(support=receipt(self.ds, stamp=stamp))
        self.rendered(stamp=(NOW - timedelta(seconds=300)).isoformat())

    def test_duplicate_json_and_nonfinite_constants_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"sample":NaN}', b'{"sample":Infinity}', b'{"sample":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                dcgm.json_bytes(raw)

    def test_exact_file_sha_not_canonical_hash_and_symlink_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ds.json"
            raw = json.dumps(self.ds, indent=2).encode()
            path.write_bytes(raw)
            self.assertEqual(dcgm.read_pinned(path, dcgm.sha(raw)), self.ds)
            with self.assertRaises(ValueError):
                dcgm.read_pinned(path, dcgm.sha(dcgm.canonical(self.ds)))
            alias = Path(tmp) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                dcgm.read_bounded(alias)
            path.write_bytes(b"")
            with self.assertRaises(ValueError):
                dcgm.read_bounded(path)

    def test_cli_render_rollback_sha_bindings_and_exclusive_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stamp = datetime.now(timezone.utc).isoformat()
            raw_ds = json.dumps(self.ds, indent=2).encode()
            bound = receipt(self.ds, dcgm.sha(raw_ds), stamp)
            rows = {"ds": raw_ds, "cms": json.dumps(self.cms, indent=2).encode(),
                    "support": json.dumps(bound, indent=2).encode(), "default": DEFAULT, "counters": COUNTERS}
            for name, raw in rows.items():
                (root / name).write_bytes(raw)
            common = ["--daemonset", str(root / "ds"), "--daemonset-sha256", dcgm.sha(raw_ds), "--captured-at", stamp]
            args = ["render", *common, "--configmaps", str(root / "cms"), "--configmaps-sha256", dcgm.sha(rows["cms"]),
                "--support-receipt", str(root / "support"), "--support-sha256", dcgm.sha(rows["support"]),
                "--default-counters", str(root / "default"), "--counters", str(root / "counters"),
                "--output-dir", str(root / "rendered")]
            with contextlib.redirect_stdout(io.StringIO()):
                dcgm.main(args)
            self.assertEqual({p.name for p in (root / "rendered").iterdir()}, {
                "dcgm-exporter-profiling.yaml", "dcgm-closure.json", "daemonset-forward.json", "daemonset-inverse-review-only.json"})
            closure_path = root / "rendered/dcgm-closure.json"
            closure_raw = closure_path.read_bytes()
            closure = json.loads(closure_raw)
            candidate = patched(self.ds, json.loads((root / "rendered/daemonset-forward.json").read_bytes()))
            candidate["metadata"]["resourceVersion"] = "321"
            candidate_raw = json.dumps(candidate, indent=2).encode()
            (root / "current").write_bytes(candidate_raw)
            rollback_args = ["rollback", "--daemonset", str(root / "current"), "--daemonset-sha256", dcgm.sha(candidate_raw),
                "--captured-at", stamp, "--closure", str(closure_path), "--closure-sha256", dcgm.sha(closure_raw),
                "--output-dir", str(root / "inverse")]
            with contextlib.redirect_stdout(io.StringIO()):
                dcgm.main(rollback_args)
            inverse = json.loads((root / "inverse/daemonset-inverse.json").read_bytes())
            self.assertEqual(patched(candidate, inverse)["spec"], closure["originalSpec"])
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                dcgm.main(args)
            self.assertEqual(error.exception.code, 2)  # refuses overwriting existing output
            before = closure_path.read_bytes()
            args[-1] = str(root / "should-not-exist")
            (root / "support").write_bytes(rows["support"] + b"\n")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                dcgm.main(args)
            self.assertEqual(error.exception.code, 2)
            self.assertFalse((root / "should-not-exist").exists())
            self.assertEqual(closure_path.read_bytes(), before)
            rollback_args[-1] = str(root / "bad-closure")
            closure_path.write_bytes(closure_raw + b"\n")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                dcgm.main(rollback_args)
            self.assertFalse((root / "bad-closure").exists())


if __name__ == "__main__":
    unittest.main()
