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
    def __init__(self, transport, target):
        self.t = transport
        self.namespace = target["namespace"]
        self.identity = target["detector"]["identity"]
        self.selector = target["detector"]["selector"]
        self.name = "phorvex-e2e-" + uuid.uuid4().hex
        self.attempted = False

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
        pod = sorted(ready, key=lambda p: p["metadata"]["name"])[0]["metadata"]["name"]
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
        creator = stored.get("metadata", {}).get("annotations", {}).get("phorvex.ai/creator-identity")
        if creator != self.identity:
            raise TransportError("E2E event lacks the expected admission-stamped creator identity")
        return {"ok": True, "action": "foothold", "pod": pod, "expect": "policy-gated reaction",
                "event": self.name, "creatorIdentity": creator, "injection": "dedicated-detector",
                "message": "Authenticated test event created; security effect is not assumed."}

    def clear(self):
        if self.attempted:
            self._run("kubectl --as=%s delete securityevent %s --ignore-not-found --wait=false" % (
                shlex.quote(self.identity), shlex.quote(self.name)))
            self.attempted = False
