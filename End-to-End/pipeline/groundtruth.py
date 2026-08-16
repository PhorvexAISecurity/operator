"""Independent verification of what the actuator claims it did.

Nothing here reads a Phorvex field. Every verdict comes from the cluster or from the
attacked workload's own log, because "the system reported success" is exactly the claim
under test. A move we cannot check is reported as `unverifiable` — never as confirmed.
"""

VERIFIABLE = {
    "rotate": "the pod must come back with a fresh UID",
    "quarantine": "a deny-all NetworkPolicy must actively select the pod",
    "kv-reset": "vLLM must record reset_prefix_cache in its own log",
    "adapter-rotate": "vLLM must record an adapter unload/load in its own log",
}


def _v(action, ns, pod, verdict, detail, evidence=""):
    return {"action": action, "namespace": ns, "pod": pod,
            "verdict": verdict, "detail": detail, "evidence": evidence,
            "expected": VERIFIABLE.get(action, "no independent verification is defined for this action")}


def verify(cluster, actuated_records, baseline_pods):
    """Return one verdict per actuated decision: confirmed | contradicted | unverifiable."""
    out = []
    for r in actuated_records:
        ns, pod, action = r.get("namespace"), r.get("pod"), r.get("action")
        if not ns or not pod:
            out.append(_v(action, ns, pod, "unverifiable", "the record carries no namespace or pod"))
            continue

        if action == "rotate":
            before = (baseline_pods or {}).get(pod, {}).get("uid")
            now = cluster.pod_uids(ns).get(pod, {}).get("uid")
            if not before:
                out.append(_v(action, ns, pod, "unverifiable", "no UID was recorded before the attack"))
            elif now is None:
                out.append(_v(action, ns, pod, "confirmed",
                              "the pod under that name no longer exists — it was replaced",
                              f"uid before the action {before[:8]}"))
            elif now != before:
                out.append(_v(action, ns, pod, "confirmed", "the UID changed",
                              f"{before[:8]} → {now[:8]}"))
            else:
                out.append(_v(action, ns, pod, "contradicted",
                              "a rotate was reported but the UID is untouched", f"uid={now[:8]}"))

        elif action == "quarantine":
            state = cluster.quarantine_state(ns, pod)
            if state is None:
                out.append(_v(action, ns, pod, "unverifiable",
                              "the pod or quarantine policy could not be read"))
            elif state["active"]:
                out.append(_v(action, ns, pod, "confirmed",
                              "the deny-all NetworkPolicy actively selects the pod",
                              state["evidence"]))
            else:
                out.append(_v(action, ns, pod, "contradicted",
                              "a quarantine was reported but the deny-all policy does not select the pod",
                              state["evidence"]))

        elif action in ("kv-reset", "adapter-rotate"):
            needle = "reset_prefix_cache" if action == "kv-reset" else "lora"
            log = cluster.container_log(ns, pod, since="5m", grep=needle)
            if log.strip():
                out.append(_v(action, ns, pod, "confirmed",
                              "the service itself recorded the action in its log",
                              log.strip().splitlines()[-1][:160]))
            else:
                out.append(_v(action, ns, pod, "contradicted",
                              f"the action was reported but \"{needle}\" is absent from the service log"))

        else:
            out.append(_v(action, ns, pod, "unverifiable",
                          f"no independent check is implemented for \"{action}\" — deliberately not confirmed"))
    return out
