# General-Purpose Attack Set — where Phorvex earns its keep

**Why this doc exists:** every catalogue so far tested Phorvex against the *voice app*, whose real risks are semantic (prompt injection), data-plane (transcript/KB theft), and edge (auth/rate-limit) — none of which pod-motion can touch. That's the **worst-case showcase** for an MTD system and made Phorvex look like it misses everything.

But Phorvex is **workload-agnostic** and built for a **different threat model**: the **interactive intrusion** — an attacker who gets *code running inside a pod* and wants to **stay, persist, move, and phone home**. Against *that* threat, on *any* workload, motion is the right tool. This set is that threat model.

## The one law that decides every verdict
> **Phorvex wins exactly when the attacker's payload is EPHEMERAL IN-POD STATE** — a shell, an implant, a miner, a hands-on-keyboard session, a live process. Rotation destroys that state on a clock, whether or not anyone detects it. It loses when the payload is *elsewhere* (data at rest, a stable Service address, a static/cloud credential, a one-shot exfil) — see the voice catalogue for that half.

Threat model (same as the voice work): **assume-breach** — attacker is on the cluster network, recon done. Target = **any pod** (examples use the real tenants: litellm, vllm, chatbot, nats — but nothing here is app-specific).

---

## The set — attacks Phorvex *should* handle (workload-agnostic)

| # | Attack (on any workload) | What motion does | Verdict |
|--:|---|---|---|
| GP1 | **Interactive RCE foothold → dwell** — attacker exploits any pod, gets a shell, works hands-on-keyboard | proactive rotation caps dwell to the interval; forces re-exploitation every cycle | ✅ **KILL / BOUND** — the canonical MTD win |
| GP2 | **In-pod persistence / backdoor** — webshell, cron, dropped implant in the pod's ephemeral filesystem | a fresh pod has none of it; rotation wipes it each cycle | ✅ **KILL** |
| GP3 | **Fileless / in-memory implant** — reflective load, no disk artifact | rotation kills the process; in-memory state is gone | ✅ **KILL** |
| GP4 | **Detected compromise → targeted eviction** — a Falco/EDR emitter fires on a pod | Phorvex rotates that exact pod within seconds (the reactive/`belief` leg) | ✅ **KILL** — when a detector exists |
| GP5 | **Cryptomining / resource hijack** — miner dropped in a compromised pod | rotation kills the miner each cycle → attacker must re-drop → yield capped, cost raised | ✅ **KILL / BOUND** |
| GP6 | **Lateral movement** — compromised pod → scan → hop to a neighbor | rotating the source/target changes its IP/identity → disrupts the hop | ⚠️ **BOUND** — opportunistic; blunted if the attacker uses Service DNS |
| GP7 | **C2 beacon** — long-lived call-home channel from a foothold | identity/pod rotation drops the channel each cycle → forces re-establish | ⚠️ **BOUND** — a beacon on Service DNS re-establishes |
| GP8 | **Interactive recon / environment mapping** — attacker builds a map of pods/identities | rotation makes the map stale → re-recon cost every interval | ⚠️ **BOUND** — the "recon-staleness" value; DNS-blunted |
| GP9 | **Stolen SA-token / pod-identity reuse over time** | identity-rotate would expire the stolen token on a clock | ⚠️ **BOUND *if* identity-rotate is enabled** — today only pod-rotate is on → MISS |
| GP10 | **Stateful workload compromise** — foothold on a DB / training job | feasibility model **quarantines instead of rotating** → contains without destroying data | ✅ **CORRECT-BY-JUDGMENT** — the "don't rotate stateful" win |

**Clean, workload-agnostic wins:** GP1–GP5, GP10. **Bounded (cadence/DNS-dependent):** GP6–GP8. **Needs an actuator not enabled today:** GP9.

---

## The honest caveats (same rigor as the voice work)
- **Service DNS still blunts GP6–GP8.** If the attacker addresses neighbors by Service name (the k8s norm), pod-IP rotation doesn't stale the reach — it only bites when they've pinned to a pod IP or when a foothold's *own* in-pod state is the target (GP1–GP5).
- **GP9 needs identity-rotate**, which isn't in the enabled set — motivating the actuator roadmap again.
- **Speed still matters.** A foothold that achieves its goal in one interval (grab creds and leave) beats the cadence; motion caps *dwell*, not a smash-and-grab. GP1–GP5 assume an attacker who wants to *persist*, which is the realistic APT / ransomware-staging case.

---

## The strategic point (for the boss)
Phorvex isn't "weak" — it's **specialized**. It defends the **interactive-intrusion / dwell threat model** on *any* workload, and it does that well (GP1–GP5, GP10). It does **not** defend the **app-semantic / data-plane / edge threat model** — and the voice app happens to be dominated by *that*.

So the takeaway isn't "Phorvex misses 27 of 32." It's: **match the tool to the threat.**
- Point Phorvex at a workload whose risk is *someone getting in and staying* (a classic internal service, an ML training job, a compromised web backend) → it's the right defense.
- Point it at a workload whose risk is *semantic abuse or data theft through the front door* (the voice bot) → it needs the app team + the new actuators (edge auth, rate-limit, guardrails, cred-rotation, data-layer), which motion can't substitute for.

Both statements are true, and stating both is what makes the evaluation credible.

## Build note
GP1–GP5 map onto the existing `c1-*`/`c2-*` scenario families (see `GENERIC_CATALOGUE_REALISM.md` §A). To showcase Phorvex working, build **GP1 (foothold dwell-cap)** and **GP4 (detected eviction)** first — they're the clean `KILL`s and the fastest way to demonstrate the defense *succeeding*, which every prior demo lacked.
