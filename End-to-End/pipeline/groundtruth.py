"""Independent verification of what the actuator claims it did.

Nothing here reads a Phorvex field. Every verdict comes from the cluster or from the
attacked workload's own log, because "the system reported success" is exactly the claim
under test. A move we cannot check is reported as `unverifiable` — never as confirmed.
"""

VERIFIABLE = {
    "rotate": "پاد باید UID تازه بگیرد",
    "quarantine": "پاد باید به مالکیت AMTD CR درآید",
    "kv-reset": "vLLM باید reset_prefix_cache را در لاگ خودش ثبت کند",
    "adapter-rotate": "vLLM باید unload/load آداپتور را در لاگ خودش ثبت کند",
}


def _v(action, ns, pod, verdict, detail, evidence=""):
    return {"action": action, "namespace": ns, "pod": pod,
            "verdict": verdict, "detail": detail, "evidence": evidence,
            "expected": VERIFIABLE.get(action, "روش تأیید مستقلی برای این اقدام تعریف نشده")}


def verify(cluster, actuated_records, baseline_pods):
    """Return one verdict per actuated decision: confirmed | contradicted | unverifiable."""
    out = []
    for r in actuated_records:
        ns, pod, action = r.get("namespace"), r.get("pod"), r.get("action")
        if not ns or not pod:
            out.append(_v(action, ns, pod, "unverifiable", "رکورد نیم‌اسپیس یا پاد ندارد"))
            continue

        if action == "rotate":
            before = (baseline_pods or {}).get(pod, {}).get("uid")
            now = cluster.pod_uids(ns).get(pod, {}).get("uid")
            if not before:
                out.append(_v(action, ns, pod, "unverifiable", "UID پیش از حمله ثبت نشده بود"))
            elif now is None:
                out.append(_v(action, ns, pod, "confirmed",
                              "پاد با همان نام دیگر وجود ندارد — جایگزین شده",
                              f"uid پیش از اقدام {before[:8]}"))
            elif now != before:
                out.append(_v(action, ns, pod, "confirmed", "UID عوض شد",
                              f"{before[:8]} → {now[:8]}"))
            else:
                out.append(_v(action, ns, pod, "contradicted",
                              "اقدام rotate گزارش شد ولی UID دست‌نخورده است", f"uid={now[:8]}"))

        elif action == "quarantine":
            owner = cluster.pod_uids(ns).get(pod, {}).get("owner", "")
            if owner == "AdaptiveMovingTargetDefense":
                out.append(_v(action, ns, pod, "confirmed",
                              "پاد از مجموعه‌ی اصلی به AMTD CR منتقل شده", f"ownerKind={owner}"))
            elif owner:
                out.append(_v(action, ns, pod, "contradicted",
                              "قرنطینه گزارش شد ولی مالک هنوز کنترلر اصلی است", f"ownerKind={owner}"))
            else:
                out.append(_v(action, ns, pod, "unverifiable", "مالک پاد خوانده نشد"))

        elif action in ("kv-reset", "adapter-rotate"):
            needle = "reset_prefix_cache" if action == "kv-reset" else "lora"
            log = cluster.container_log(ns, pod, since="5m", grep=needle)
            if log.strip():
                out.append(_v(action, ns, pod, "confirmed",
                              "خودِ سرویس اجرای اقدام را در لاگش ثبت کرده",
                              log.strip().splitlines()[-1][:160]))
            else:
                out.append(_v(action, ns, pod, "contradicted",
                              f"اقدام گزارش شد ولی «{needle}» در لاگ سرویس نیست"))

        else:
            out.append(_v(action, ns, pod, "unverifiable",
                          f"برای «{action}» بررسی مستقلی پیاده نشده — عمداً تأیید نمی‌شود"))
    return out
