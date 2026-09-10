"""Independent verification of what the actuator claims it did.

Nothing here reads a Phorvex field. Every verdict comes from the cluster or from the
attacked workload's own log, because "the system reported success" is exactly the claim
under test.

Two separate questions are answered separately, and conflating them is what produced a
green board over an unobserved cluster:

  verdict      did the claimed EFFECT happen, as far as an authoritative read can tell?
               confirmed / contradicted / unverifiable — and a read that failed is
               `unverifiable`, never `confirmed`. A Forbidden pod list is not an absent pod.

  attribution  can that effect be tied to the action we fired? Observing a replacement
               proves a replacement, not that *our* signal caused it. Without a causal
               identity in the record this stays `unavailable`, and no amount of namespace
               membership upgrades it.

Every verdict also carries the interval it was observed over, so a reader can see that the
observation came after the action rather than assume it.
"""

from datetime import datetime, timezone

import observation as obs

VERIFIABLE = {
    "rotate": "the original Pod UID must be gone AND a Ready successor under the same "
              "controller UID must be observed",
    "quarantine": "a deny-all NetworkPolicy must select this exact Pod UID with no other "
                  "policy additively allowing its traffic",
    "kv-reset": "vLLM must record a command-specific reset line, in this Pod instance's own "
                "log, after the action started",
    "adapter-rotate": "vLLM must record a command-specific adapter load/unload line, in this "
                      "Pod instance's own log, after the action started",
}

CONFIRMED, CONTRADICTED, UNVERIFIABLE = "confirmed", "contradicted", "unverifiable"

# What we can say about cause. `correlated` requires a forensic identity shared by the
# injected event and the decision record; `unsupported` means the deployed audit schema
# has no such field at all, which is a coverage gap rather than a negative result.
CORRELATED, UNSUPPORTED, ATTR_UNAVAILABLE = "correlated", "unsupported", "unavailable"


def _iso(epoch):
    return None if epoch is None else datetime.fromtimestamp(epoch, timezone.utc).isoformat()


class Verdict:
    """One ground-truth result, assembled so no field can be forgotten."""

    def __init__(self, record, namespace, started_at):
        self.action = record.get("action")
        self.namespace = namespace
        self.pod = record.get("pod")
        self.started_at = started_at

    def build(self, verdict, detail, evidence="", read=None, attribution=None,
              attribution_detail="", identity=None):
        observed_at = read.observed_at if read is not None else None
        return {
            "action": self.action,
            "namespace": self.namespace,
            "pod": self.pod,
            "verdict": verdict,
            "detail": detail,
            "evidence": evidence,
            "expected": VERIFIABLE.get(
                self.action, "no independent verification is defined for this action"),
            "attribution": attribution or ATTR_UNAVAILABLE,
            "attributionDetail": attribution_detail,
            "targetIdentity": identity or {},
            "observation": read.to_json() if read is not None else None,
            "observationWindow": {
                "actionStartedAt": _iso(self.started_at),
                "observedAt": _iso(observed_at),
                "intervalSec": (None if (observed_at is None or self.started_at is None)
                                else round(observed_at - self.started_at, 3)),
            },
        }


def no_attribution(record):
    """Default correlator: this audit schema carries no causal identity at all."""
    return UNSUPPORTED, ("the deployed audit schema carries no forensic event identity, so "
                         "no observed effect can be attributed to the injected action")


def parse_k8s_time(value):
    """RFC3339 as the API server writes it, or None — never a guessed epoch."""
    if not value:
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            return None


def verify(cluster, actuated_records, baseline, namespace=None, action_started_at=None,
           log_patterns=None, attribution_of=None, clock_skew_sec=2.0):
    """Return one verdict per actuated decision.

    `baseline` is the identity snapshot for `namespace` only, and it is used whole: the set
    of Pod UIDs that already existed before the action is what makes a *new* successor
    distinguishable from a replica that was there all along. A decision about any other
    namespace is reported unverifiable rather than checked against identities that were
    never captured for it — one namespace's baseline says nothing about another's pods.
    """
    log_patterns = log_patterns or {}
    attribution_of = attribution_of or no_attribution
    # Every Pod UID the namespace held before the action. Not just the target's.
    known_uids = {identity.get("uid") for identity in (baseline or {}).values()
                  if isinstance(identity, dict) and identity.get("uid")}
    out = []
    for r in actuated_records:
        ns, pod, action = r.get("namespace"), r.get("pod"), r.get("action")
        v = Verdict(r, ns, action_started_at)
        attribution, attribution_detail = attribution_of(r)

        def finish(verdict, detail, evidence="", read=None, identity=None):
            return v.build(verdict, detail, evidence, read, attribution,
                           attribution_detail, identity)

        if not ns or not pod:
            out.append(finish(UNVERIFIABLE, "the record carries no namespace or pod"))
            continue
        if namespace is not None and ns != namespace:
            out.append(finish(
                UNVERIFIABLE,
                f"no pre-action identity was captured for namespace {ns}; this run's baseline "
                f"covers {namespace} only"))
            continue

        before = (baseline or {}).get(pod) or {}
        identity = {k: before.get(k) for k in ("uid", "ownerUID", "ownerKind", "namespace")}

        if action == "rotate":
            out.append(_rotate(cluster, ns, pod, before, identity, finish, known_uids,
                               action_started_at, clock_skew_sec))
        elif action == "quarantine":
            out.append(_quarantine(cluster, ns, pod, before, identity, finish))
        elif action in ("kv-reset", "adapter-rotate"):
            out.append(_service_log(cluster, ns, pod, action, before, identity,
                                    action_started_at, log_patterns, finish))
        else:
            out.append(finish(
                UNVERIFIABLE,
                f"no independent check is implemented for \"{action}\" — deliberately not confirmed",
                identity=identity))
    return out


def _rotate(cluster, ns, pod, before, identity, finish, known_uids, started_at,
            clock_skew_sec):
    """A rotation is a replacement, and a replacement has to be seen — not inferred.

    The trap this arm exists to avoid: the original UID being gone is necessary but not
    sufficient. A Deployment with two replicas already has a Ready pod under the same
    controller before anything happens, so "same owner, not the original, Ready" describes
    a surviving sibling exactly as well as a new successor. A successor has to be one the
    baseline did not already contain AND one created inside the observation window.
    """
    if not before.get("uid"):
        return finish(UNVERIFIABLE, "no Pod UID was captured for this target before the action",
                      identity=identity)
    read = cluster.pod_uids(ns)
    if not read.usable:
        # The defect this whole fix exists for: an unreadable inventory used to look
        # exactly like an absent pod, and an absent pod used to mean success.
        return finish(UNVERIFIABLE,
                      "the post-action Pod inventory could not be read, so no replacement "
                      "was observed", read.describe(), read, identity)

    pods = read.value or {}
    now = pods.get(pod)
    if now and now.get("uid") == before["uid"]:
        if now.get("terminating"):
            return finish(UNVERIFIABLE,
                          "the original pod is still terminating; no successor is observable yet",
                          f"uid={before['uid'][:8]} deletionTimestamp={now.get('deletionTimestamp')}",
                          read, identity)
        return finish(CONTRADICTED, "a rotate was reported but the pod still carries its "
                                    "original UID", f"uid={before['uid'][:8]}", read, identity)

    owner = before.get("ownerUID")
    if not owner:
        return finish(UNVERIFIABLE,
                      "the original pod is gone, but no controller UID was captured for it, so "
                      "no successor can be shown to belong to the same workload",
                      f"uid before the action {before['uid'][:8]}", read, identity)

    detail_uid = f"uid before the action {before['uid'][:8]}"
    same_owner = [p for p in pods.values()
                  if p.get("ownerUID") == owner and p.get("uid") != before["uid"]
                  and not p.get("terminating")]
    # A pod whose UID was already in the baseline is not a successor, whatever its name.
    survivors = [p for p in same_owner if p.get("uid") in known_uids]
    candidates = [p for p in same_owner if p.get("uid") not in known_uids]

    if not candidates:
        # Disappearance is not replacement: a deleted Deployment, an evicted node and a
        # successful rotate all remove the original UID. A surviving replica proves the
        # workload still runs; it does not prove the target was replaced.
        return finish(UNVERIFIABLE,
                      "the original pod is gone but no NEW pod under the same controller was "
                      "observed — disappearance beside a surviving replica is not a successful "
                      "replacement" if survivors else
                      "the original pod is gone but no successor under the same controller was "
                      "observed — disappearance is not a successful replacement",
                      f"{detail_uid}; controller {owner[:8]}; "
                      f"{len(survivors)} pre-existing replica(s) survived "
                      f"({', '.join(sorted(p['name'] for p in survivors)) or 'none'})",
                      read, identity)

    if started_at is None:
        return finish(UNVERIFIABLE,
                      "no action start time was recorded, so a new pod cannot be placed "
                      "inside the observation window", detail_uid, read, identity)

    window_start = started_at - clock_skew_sec
    timed, undated = [], []
    for p in candidates:
        created = parse_k8s_time(p.get("creationTimestamp"))
        if created is None:
            undated.append(p)
        elif created >= window_start:
            timed.append(p)
    ready = [p for p in timed if p.get("ready") is True]

    if undated and not ready:
        # An unparseable or absent creationTimestamp is not evidence of when it appeared.
        return finish(UNVERIFIABLE,
                      f"{len(undated)} candidate successor(s) carry no usable creation time, so "
                      f"none can be placed after the action",
                      f"{detail_uid}; undated "
                      + ", ".join(sorted(p["name"] for p in undated)), read, identity)
    if not timed:
        return finish(UNVERIFIABLE,
                      "the only new pods under this controller were created before the action "
                      "started, so none of them is its replacement",
                      f"{detail_uid}; creation times "
                      + ", ".join(f"{p['name']}={p.get('creationTimestamp')}" for p in candidates),
                      read, identity)
    if not ready:
        return finish(UNVERIFIABLE,
                      f"a new same-controller pod exists but is not Ready "
                      f"({', '.join(sorted(p['name'] for p in timed))})",
                      f"{detail_uid}; readiness "
                      + ", ".join(f"{p['name']}={p.get('ready')}" for p in timed),
                      read, identity)
    return finish(CONFIRMED,
                  "the original UID is gone and a Ready pod created after the action, under the "
                  "same controller, is running",
                  f"{detail_uid} → {ready[0]['uid'][:8]} ({ready[0]['name']}, "
                  f"controller {owner[:8]}, created {ready[0].get('creationTimestamp')}, ready)"
                  + (f"; {len(survivors)} pre-existing replica(s) also survived" if survivors else ""),
                  read, identity)


def _quarantine(cluster, ns, pod, before, identity, finish):
    """Configuration evidence, reported as configuration evidence."""
    read = cluster.quarantine_state(ns, pod, expect_uid=before.get("uid"))
    if not read.usable:
        return finish(UNVERIFIABLE,
                      "the pod or its NetworkPolicies could not be read", read.describe(),
                      read, identity)
    state = read.value or {}
    evidence = state.get("evidence", "")
    if read.status == obs.PARTIAL:
        return finish(UNVERIFIABLE, read.reason or "the quarantine target could not be observed",
                      evidence, read, identity)
    if not state.get("policyPresent"):
        return finish(CONTRADICTED,
                      f"a quarantine was reported but NetworkPolicy {state.get('policy')} "
                      f"does not exist", evidence, read, identity)
    if not state.get("identityMatches"):
        return finish(UNVERIFIABLE,
                      "the pod under this name is a different instance than the one observed "
                      "before the action, so the policy cannot be tied to the target",
                      evidence, read, identity)
    if not state.get("active"):
        return finish(CONTRADICTED,
                      "a quarantine was reported but the deny-all policy does not select this pod",
                      evidence, read, identity)
    if state.get("additiveAllowPolicies"):
        # NetworkPolicy is additive: one allow rule elsewhere in the namespace reopens
        # exactly what the deny-all closed.
        return finish(UNVERIFIABLE,
                      "a deny-all policy selects the pod, but "
                      f"{len(state['additiveAllowPolicies'])} other policies additively allow "
                      "its traffic — isolation is not established",
                      evidence, read, identity)
    return finish(CONFIRMED,
                  "a deny-all NetworkPolicy selects this exact Pod UID — configuration "
                  "evidence only; packet-level blocking and CNI enforcement are not probed",
                  evidence, read, identity)


def _service_log(cluster, ns, pod, action, before, identity, started_at, patterns, finish):
    """The workload's own log, bound to the command, the window and the instance."""
    pattern = (patterns or {}).get(action)
    if not pattern:
        return finish(UNVERIFIABLE,
                      f"no reviewed command-specific log pattern is configured for "
                      f"\"{action}\"; a generic match cannot confirm a command",
                      identity=identity)
    if started_at is None:
        return finish(UNVERIFIABLE,
                      "no action start time was recorded, so log evidence cannot be bounded to "
                      "the window in which the command was issued", identity=identity)
    if not before.get("uid"):
        return finish(UNVERIFIABLE,
                      "no Pod UID was captured for this target, so a log read cannot be bound "
                      "to the instance the action was issued against", identity=identity)

    read = cluster.container_log(ns, pod, before["uid"], started_at, pattern)
    if not read.usable:
        return finish(UNVERIFIABLE, "the service log could not be read for this Pod instance",
                      read.describe(), read, identity)
    value = read.value or {}
    matches = value.get("matches") or []
    where = (f"pattern={value.get('pattern')!r} since={value.get('sinceTime')} "
             f"podUID={(value.get('podUID') or '')[:8]} "
             f"lines={value.get('linesRead')}")
    if not matches:
        if read.status == obs.PARTIAL:
            # Absence over a truncated read is not absence. A contradiction here would be a
            # claim about lines nobody looked at.
            return finish(UNVERIFIABLE,
                          "no matching line was found, but the log read did not cover the "
                          "whole window, so its absence proves nothing",
                          f"{read.reason}; {where}", read, identity)
        return finish(CONTRADICTED,
                      f"the action was reported but no line matching the reviewed pattern "
                      f"appears in this instance's log after the action started", where,
                      read, identity)
    return finish(CONFIRMED,
                  "the service itself recorded a matching command in its own log inside the "
                  "observation window",
                  f"{matches[-1][:160]} [{where}]", read, identity)
