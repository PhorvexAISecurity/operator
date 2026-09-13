"""Realistic API objects and a kubectl-shaped fake transport, shared by the tests.

The regressions in this suite are about how the pipeline reads reality, so they have to be
driven by objects shaped like the ones the API server actually returns — a Pod with its
ownerReferences, conditions and deletionTimestamp, a NetworkPolicy with a real selector, an
audit record with the field names `phorvex.audit.v2` really emits. A test that hands a check
a two-key dict proves the check can read that dict.

`FakeKubectl` is a transport, not a mock of the functions under test: tests drive
`Cluster` / `Console` / `DetectorSignal` end to end through it, and it answers with rc,
stdout and stderr the way `kubectl` does — including the Forbidden and NotFound messages
whose confusion this whole fix is about.

This module is imported by tests only; unittest discovery ignores it (it is not `test_*`).
"""

import json
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


FORBIDDEN =('Error from server (Forbidden): pods is forbidden: User '
             '"system:serviceaccount:ci:e2e" cannot list resource "pods" in API group "" '
             'in the namespace "voice"')
NOT_FOUND = 'Error from server (NotFound): pods "voice-a" not found'
TIMED_OUT = 'Unable to connect to the server: net/http: request canceled (Client.Timeout exceeded)'


def pod(name, uid=None, owner_uid="rs-voice-1", owner_kind="ReplicaSet", ready=True,
        phase="Running", labels=None, deletion_timestamp=None, containers=("app",),
        restarts=0, terminated=None, namespace="voice", creation="2026-09-10T18:00:00Z"):
    """One Pod as `kubectl get pod -o json` returns it."""
    metadata = {"name": name, "namespace": namespace, "uid": uid or f"uid-{name}",
                "creationTimestamp": creation, "labels": dict(labels or {})}
    if owner_uid:
        metadata["ownerReferences"] = [{"kind": owner_kind, "name": owner_uid,
                                        "uid": owner_uid, "controller": True}]
    if deletion_timestamp:
        metadata["deletionTimestamp"] = deletion_timestamp
    statuses = []
    for container in containers:
        entry = {"name": container, "restartCount": restarts}
        if terminated:
            entry["state"] = {"terminated": dict(terminated)}
        statuses.append(entry)
    status = {"phase": phase, "containerStatuses": statuses}
    if ready is not None:
        status["conditions"] = [{"type": "Ready", "status": "True" if ready else "False"}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": metadata,
            "spec": {"containers": [{"name": c} for c in containers]}, "status": status}


def deployment_stack(name, namespace="phorvex-system", ready=True, phase="Running", restarts=0):
    """Deployment → ReplicaSet → Pod, linked by controller UID like the real thing."""
    def ref(kind, uid):
        return [{"kind": kind, "uid": uid, "name": uid, "controller": True}]
    return [
        {"kind": "Deployment", "metadata": {"name": name, "namespace": namespace, "uid": name}},
        {"kind": "ReplicaSet", "metadata": {"name": f"{name}-rs", "namespace": namespace,
                                            "uid": f"{name}-rs",
                                            "ownerReferences": ref("Deployment", name)}},
        {"kind": "Pod", "metadata": {"name": f"{name}-pod", "namespace": namespace,
                                     "uid": f"{name}-pod",
                                     "ownerReferences": ref("ReplicaSet", f"{name}-rs")},
         "spec": {"containers": [{"name": "manager"}]},
         "status": {"phase": phase,
                    "containerStatuses": [{"name": "manager", "restartCount": restarts}],
                    "conditions": [{"type": "Ready", "status": "True" if ready else "False"}]}},
    ]


def network_policy(name, match_labels=None, match_expressions=None, ingress=None, egress=None,
                   policy_types=("Ingress", "Egress"), namespace="voice"):
    spec = {"podSelector": {}, "policyTypes": list(policy_types)}
    if match_labels:
        spec["podSelector"]["matchLabels"] = dict(match_labels)
    if match_expressions:
        spec["podSelector"]["matchExpressions"] = list(match_expressions)
    if ingress:
        spec["ingress"] = list(ingress)
    if egress:
        spec["egress"] = list(egress)
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": namespace, "uid": f"np-{name}"},
            "spec": spec}


QUARANTINE_LABEL = "amtd.r6security.com/network-policy"


def quarantined(pod_name, namespace="voice", **kwargs):
    """A Pod plus the deny-all policy Phoenix writes for it."""
    policy = f"{namespace}-{pod_name}-policy"
    return (pod(pod_name, namespace=namespace, labels={QUARANTINE_LABEL: policy}, **kwargs),
            network_policy(policy, match_labels={QUARANTINE_LABEL: policy}, namespace=namespace))


def phorvex_policy(name="voice-defense", namespace="voice", uid="policy-uid-1",
                   max_moves=1, mode="Enforce", dry_run=False, declare_budget=True):
    spec = {"mode": mode, "dryRun": dry_run}
    if declare_budget:
        spec["budget"] = {"maxMovesPerTick": max_moves}
    return {"apiVersion": "amtd.r6security.com/v1alpha1", "kind": "PhorvexPolicy",
            "metadata": {"name": name, "namespace": namespace, "uid": uid}, "spec": spec}


def record(**overrides):
    """One audit record with the field names phorvex.audit.v2 actually writes.

    `risk` and `belief` are deliberately absent: audit/contract.go retired them to
    `coverageValue` and `pHold`, and audit/log.go rejects a v2 record that still carries
    `risk`. A fixture that supplies them would test a schema that cannot be deployed.
    """
    base = {
        "schemaVersion": "phorvex.audit.v2", "kind": "phorvex.decision",
        # A live tail, not an archive: P03's staleness threshold is a real check, so the
        # default record has to be as fresh as one the operator just wrote.
        "time": _now(), "tenant": "voice", "namespace": "voice",
        "pod": "voice-a", "node": "ip-10-0-1-5", "action": "noop",
        "selected": False, "feasible": True, "dryRun": False, "actuated": False,
        "engine": "p1-coverage", "coverageValue": 2.5, "cost": 1.0, "net": 2.0, "lambda": 0.5,
        "residual": 0.1, "threatPosture": 0.0, "exposure": 0.2, "pHold": 0.3,
        "assetValue": 12.0, "blastRadius": 0.4, "sloHeadroom": 0.9, "phase": "Warm",
        "reason": "coverage 2.5 at cost 1.0 does not clear the shadow price",
        "r6Counterfactual": "rotate", "blindCost": 3.0,
        "stage": "recon", "nextStage": "exploit", "stageHazard": 0.2,
        "preemptMargin": 0.7, "projectedNextStageSec": 120.0,
        "perDollar": 2.5, "coveredWeight": 2.5, "coveredFacts": 3, "proactiveRate": 2.0,
    }
    base.update(overrides)
    # net = coverageValue − λ×cost unless a test is deliberately breaking the identity.
    if not {"net"} & set(overrides):
        base["net"] = base["coverageValue"] - base["lambda"] * base["cost"]
    return base


# The exact notices internal/console/live.go writes. Each one means records did not reach
# the reader or the source moved underneath it.
ROTATION_NOTICE = ("Audit replaced or truncated; following the current file. "
                   "Retained history is available at /api/live/history.")
READ_FAILED_NOTICE = "Audit stream read failed."
OMITTED_NOTICE = "Audit record exceeds 1 MiB and was omitted from the stream."
REPLAY_LIMIT_NOTICE = ("Replay is limited to 1000 records; use /api/live/history for older "
                       "decisions.")


def source_notice(message=ROTATION_NOTICE):
    """One `event: notice` frame, byte-for-byte as live.go writes it."""
    return b"event: notice\ndata: " + json.dumps({"message": message}).encode() + b"\n\n"


def decision_trace(asset_uid="uid-voice-a", asset_namespace="voice", asset_name="voice-a",
                   policy_uid="policy-uid-1", policy_name="voice-defense", **extra):
    """The subset of model.DecisionTraceV2 this pipeline reads.

    `assetUID` is the target Pod identity that already exists in the deployed schema
    (model/decision_trace.go:354) — it is the one identity here that is not hypothetical.
    """
    return dict({"assetUID": asset_uid, "assetNamespace": asset_namespace,
                 "assetName": asset_name, "policyUID": policy_uid,
                 "policyName": policy_name, "policyNamespace": asset_namespace},
                **extra)


def phoenix_forensics(event_uid="phoenix-emitted-event-uid",
                      event_name="phorvex-rotate-abc12", amtd_name="voice-amtd",
                      amtd_namespace="voice", rule_source="PhorvexE2EDetector"):
    """M-18 model.PhoenixForensics: the SecurityEvent the ACTUATOR CREATED.

    Its own doc comment is explicit that this establishes correlation to Phoenix resources
    only. It is an OUTPUT identity — not the detector event that caused the decision — and
    the tests exist partly to keep the two from being conflated again.
    """
    return {"amtdName": amtd_name, "amtdNamespace": amtd_namespace,
            "eventName": event_name, "eventUID": event_uid,
            "ruleType": "Panic", "ruleThreatLevel": "critical", "ruleSource": rule_source}


def hypothetical_cause_record(cause_event_uid, target_uid="uid-voice-a", **overrides):
    """A record carrying the CAUSING event's identity.

    HYPOTHETICAL. No inspected producer writes `causeEventUID`; M-18 supplies
    `phoenix.eventUID`, which identifies the emitted event instead. This fixture exists
    only to exercise the correlation path, and it must not be cited as an existing or
    planned schema. See attribution.HYPOTHETICAL_INJECTED_EVENT_UID_PATHS.
    """
    return record(causeEventUID=cause_event_uid,
                  decisionTrace=decision_trace(asset_uid=target_uid), **overrides)


def sse(records, heartbeat=True, trailing_partial=False, notices=()):
    """The byte stream the console's /api/live emits."""
    frames = [b": connected\n\n"] if heartbeat else []
    for r in records:
        frames.append(b"data: " + json.dumps(r).encode() + b"\n\n")
    for message in notices:
        frames.append(source_notice(message))
    body = b"".join(frames)
    if trailing_partial:
        body += b'data: {"namespace":"voice","pod":"voice-'
    return body


class FakeKubectl:
    """A kubectl-shaped transport over a small in-memory cluster.

    Routing is on the same substrings the real commands contain, so a test exercises the
    command this pipeline actually builds — including its quoting — rather than a stub of
    the method that builds it.
    """

    def __init__(self, pods=(), inventory=(), network_policies=(), policies=(),
                 logs=None, metrics=None, deny=None, create_response=None, stream=b""):
        self.pods = list(pods)
        self.inventory = list(inventory)
        self.network_policies = list(network_policies)
        self.policies = list(policies)
        self.logs = dict(logs or {})
        self.metrics = metrics
        # substring → (rc, stdout, stderr): how this cluster refuses.
        self.deny = dict(deny or {})
        self.create_response = create_response
        self.stream = stream
        self.commands = []

    def describe(self):
        return "fake kubectl"

    def _pod(self, name):
        return next((p for p in self.pods if p["metadata"]["name"] == name), None)

    def run(self, command, timeout=60):
        self.commands.append(command)
        for needle, answer in self.deny.items():
            if needle in command:
                return answer
        if "get deployments.apps,replicasets.apps,pods" in command:
            return 0, json.dumps({"items": self.inventory}), ""
        if "get networkpolicy" in command:
            return 0, json.dumps({"items": self.network_policies}), ""
        if "get phorvexpolicy" in command:
            return 0, json.dumps({"items": self.policies}), ""
        if " logs " in command:
            name = _quoted_after(command, "logs")
            return 0, self.logs.get(name, ""), ""
        if "get pods " in command:                 # detector target discovery
            return 0, json.dumps({"items": self.pods}), ""
        if "get pod " in command and "jsonpath='{.metadata.uid}'" in command:
            found = self._pod(_quoted_after(command, "get pod"))
            return (0, found["metadata"]["uid"], "") if found else (1, "", NOT_FOUND)
        if "get pod " in command and "-o json" in command:
            name = _quoted_after(command, "get pod")
            if name == "-o":                       # a list read, not a single object
                return 0, json.dumps({"items": self.pods}), ""
            found = self._pod(name)
            return (0, json.dumps(found), "") if found else (1, "", NOT_FOUND)
        if "get pod " in command and "persistentVolumeClaim" in command:
            found = self._pod(_quoted_after(command, "get pod"))
            if not found:
                return 1, "", NOT_FOUND
            owner = (found["metadata"].get("ownerReferences") or [{}])[0].get("kind", "")
            claims = " ".join(v.get("persistentVolumeClaim", {}).get("claimName", "")
                              for v in found.get("spec", {}).get("volumes", []))
            return 0, f"'{owner}|{claims}'", ""
        if "/proxy/metrics" in command or "metrics_url" in command:
            return (0, self.metrics, "") if self.metrics is not None else (1, "", TIMED_OUT)
        if "create -f" in command:
            return 0, json.dumps(self.create_response or {}), ""
        if "delete securityevent" in command:
            return 0, "", ""
        return 1, "", f"fake kubectl has no answer for: {command[:120]}"


DETECTOR_IDENTITY = "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector"


def security_event_response(name, uid="event-uid-fixture",
                            created="2026-09-10T18:30:05Z", identity=DETECTOR_IDENTITY):
    """What the API server returns from CREATE, including the admission stamp."""
    return {"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
            "metadata": {"name": name, "uid": uid, "creationTimestamp": created,
                         "annotations": {"phorvex.ai/creator-identity": identity}}}


def run_offline(directory, records=(), mode="observe", cluster=None, config=None,
                run_id=None, scope_namespaces="target", detector=False,
                post_records=None):
    """Drive the real pipeline end to end with no network and no cluster.

    Everything below `Console.stream_decisions` and `Transport` is the production code
    path: the same framing, the same checks, the same verdict roll-up and the same three
    outputs. Only the two edges the test cannot own — the console's HTTP surface and the
    readiness probe — are supplied here.
    """
    import contextlib
    import io
    from unittest.mock import patch

    import e2e
    import observation as obs
    from capture import StreamCapture
    from run_output import RunOutput

    namespace = "voice"
    cfg = config or {
        "invariants": {"known_actions": ["noop", "rotate"], "known_engines": ["p1-coverage"],
                       "known_phases": ["Warm"], "known_stages": ["recon", "exploit"],
                       "net_identity_tolerance": 0.005, "phoenix_actions": ["rotate"],
                       "law_reason_prefixes": {}, "max_controller_restarts": 10},
        "transport": {"kind": "local"}, "console": {},
        "capture": {"stream_seconds": 1, "post_attack_seconds": 1, "settle_seconds": 0,
                    "max_bytes": 1_000_000, "max_records": 500,
                    "namespaces": scope_namespaces},
        "controller_deployments": ["fixture-controller"],
        "targets": [dict({"name": "fixture", "namespace": namespace,
                          "attack": {"path": "/unused", "body": {}}},
                         **({"detector": {"identity": DETECTOR_IDENTITY,
                                          "selector": "r6th.io/rotation-target=true"}}
                            if detector else {}))],
    }
    transport = cluster or FakeKubectl(
        pods=[pod("voice-a", namespace=namespace)],
        inventory=deployment_stack("fixture-controller"),
        policies=[phorvex_policy(namespace=namespace)])

    def stream(seconds, limits, scope=None, on_connected=None):
        # The live window fires the injection first, exactly as the real capture does, so
        # the records it returns are the ones the reaction could have produced.
        live = on_connected is not None
        if live:
            on_connected()
        capture = StreamCapture(limits, scope)
        body = list(post_records if (live and post_records is not None) else records)
        if body:
            capture.feed(sse(body))
        return capture.finish()

    output = RunOutput(directory, mode, "fixture", run_id=run_id, source_commit="c" * 40)
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(e2e, "Transport", return_value=transport))
        stack.enter_context(patch.object(
            e2e.Console, "wait_preflight",
            return_value=({"ok": True}, {"operator": "0.4.109", "console": "0.4.109"})))
        stack.enter_context(patch.object(e2e.Console, "stream_decisions", side_effect=stream))
        stack.enter_context(patch.object(
            e2e.Metrics, "scrape",
            return_value=obs.Observation.observed({"phorvex_kill_switch_engaged": 0.0})))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return e2e.run(cfg, mode, "fixture", directory, output=output)


def _quoted_after(command, keywords):
    """The next shell word after a run of words, unquoted the way the shell would.

    Splitting with shlex is the point: it proves the pipeline quoted the namespace and pod
    name it passed, instead of matching on the raw string and accepting anything.
    """
    import shlex
    wanted = keywords.split()
    try:
        words = shlex.split(command)
    except ValueError:
        return ""
    for i in range(len(words) - len(wanted)):
        if words[i:i + len(wanted)] == wanted:
            return words[i + len(wanted)]
    return ""
