"""Opt-in authenticated live fixture; never impersonate a production detector.

The bastion performs read-only target discovery under its existing credentials.
Only event create/get/delete use the dedicated, admission-constrained identity.
No tokens, client-supplied creator stamps, or console privilege expansion.
"""

import json
import shlex
import uuid

from transport import TransportError


class DetectorSignal:
    """Creates the fixture event and keeps every identity the API server assigned it.

    What comes back from CREATE is the only place the event's UID exists, and a later
    attribution can be no stronger than the identity recorded here: the event UID and name,
    the exact target Pod (namespace, name and UID) chosen at fire time, and the server's own
    creation timestamp. Reconstructing any of that afterwards would be guesswork.
    """

    def __init__(self, transport, target, run_id=None):
        self.t = transport
        self.namespace = target["namespace"]
        self.identity = target["detector"]["identity"]
        self.selector = target["detector"]["selector"]
        self.name = "phorvex-e2e-" + uuid.uuid4().hex
        self.run_id = run_id
        self.attempted = False
        self.event_uid = None
        self.created_at = None
        self.target_pod = None
        self.target_uid = None

    def _run(self, command):
        rc, out, err = self.t.run(command, timeout=30)
        if rc:
            raise TransportError(f"E2E detector command failed (rc={rc}): {err.strip() or out[:300]}")
        return out

    def fire(self):
        out = self._run("kubectl -n %s get pods -l %s -o json" % (
            shlex.quote(self.namespace), shlex.quote(self.selector)))
        pods = json.loads(out)["items"]
        ready = [p for p in pods
                 if not p["metadata"].get("deletionTimestamp")
                 and p.get("status", {}).get("phase") == "Running"
                 and any(c.get("type") == "Ready" and c.get("status") == "True"
                         for c in p.get("status", {}).get("conditions", []))
                 and not any(o.get("kind") == "AdaptiveMovingTargetDefense"
                             for o in p["metadata"].get("ownerReferences", []))]
        if not ready:
            raise TransportError("no Ready, non-quarantined rotation target for E2E")
        chosen = sorted(ready, key=lambda p: p["metadata"]["name"])[0]
        pod = chosen["metadata"]["name"]
        self.target_pod = pod
        # The UID of the instance we aimed at. A verdict later has to be about this
        # instance, not about whatever carries the name by then.
        self.target_uid = chosen["metadata"].get("uid")
        if not self.target_uid:
            raise TransportError("the chosen E2E target Pod carries no UID")
        event = {
            "apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
            "metadata": {"name": self.name, "labels": {"phorvex.ai/redteam": "true"}},
            "spec": {
                "description": "E2E fixture: container-escape foothold detected on " + pod,
                "targets": [self.namespace + "/" + pod],
                "rule": {"type": "Panic", "threatLevel": "critical", "source": "PhorvexE2EDetector"},
            },
        }
        # A lost response can still mean CREATE succeeded. The caller registers
        # cleanup before fire(), and each attempt gets a unique event name.
        self.attempted = True
        out = self._run("printf %s %s | kubectl --as=%s create -f - -o json" % (
            "%s", shlex.quote(json.dumps(event)), shlex.quote(self.identity)))
        stored = json.loads(out)
        meta = stored.get("metadata", {})
        creator = meta.get("annotations", {}).get("phorvex.ai/creator-identity")
        if creator != self.identity:
            raise TransportError("E2E event lacks the expected admission-stamped creator identity")
        # No UID means nothing downstream can be attributed to this event. Failing here is
        # the fail-closed choice: a run that cannot identify its own injection must not go
        # on to report a defended attack.
        self.event_uid = meta.get("uid")
        if not self.event_uid:
            raise TransportError("the CREATE response carries no event UID; the injection "
                                 "cannot be identified in any later record")
        self.created_at = meta.get("creationTimestamp")
        return {"ok": True, "action": "foothold", "pod": pod, "expect": "policy-gated reaction",
                "event": self.name, "creatorIdentity": creator, "injection": "dedicated-detector",
                "eventName": self.name, "eventUID": self.event_uid,
                "eventCreatedAt": self.created_at,
                "targetNamespace": self.namespace, "targetPod": pod, "targetUID": self.target_uid,
                "runId": self.run_id,
                "message": "Authenticated test event created; security effect is not assumed."}

    def injection_identity(self):
        """What a correlator needs, available before and after fire()."""
        return {"kind": "SecurityEvent", "eventName": self.name, "eventUID": self.event_uid,
                "eventCreatedAt": self.created_at, "identity": self.identity,
                "targetNamespace": self.namespace, "targetPod": self.target_pod,
                "targetUID": self.target_uid, "runId": self.run_id}

    def clear(self):
        if self.attempted:
            self._run("kubectl --as=%s delete securityevent %s --ignore-not-found --wait=false" % (
                shlex.quote(self.identity), shlex.quote(self.name)))
            self.attempted = False
