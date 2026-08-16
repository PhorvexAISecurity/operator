# K1 — kv-reset flagship runbook (Test-queue #1)

**What it proves (the existence test):** the brain picks the *surgical* `kv-reset` (in-process cache flush, pod stays alive, ~$0 norm-cost) over the blunt `rotate` (pod kill, norm-cost 1.0) — and the flush really happens. Pass = Phorvex is provably better than "on detection → rotate." Fail either oracle = a precise, documented gap.

**Mechanism (one paragraph, plain):** we make rotate *infeasible* (policy `minAvailableReplicas: 2` on the 2-replica vLLM — the availability floor only gates rotate/quarantine, so surgical moves survive), enable `kv-reset`, plant attacker state in the vLLM prefix cache, then fire a `SecurityEvent` at the pod. The brain's only feasible in-pod move covering the `session` fact is `kv-reset`.

**Two oracles:**
1. **SELECTION** — Phorvex decision log: `Action=kv-reset`, `engine=p1-coverage` (not rotate — pruned; nothing else is enabled).
2. **EFFECT** — the handler POSTs `/reset_prefix_cache` (forensic: pod annotation `phorvex.ai/kv-reset-epoch` gets set), the planted cache state is verifiably evicted (identical request goes prefix-cache **HIT → MISS** / cache-usage metric drops), **and the pod UID never changes** (surgical, not a kill).

**Honest caveat (from the 2026-08-10 audit):** on stock vLLM APC, cached KV is a pure function of the prompt tokens, so kv-reset cannot "cure" a poisoned *prompt* — the oracle is *verifiable eviction of cached state with zero pod downtime*, which is the real surgical-beats-rotate proof. Literal "injection cured" holds only for hash-collision (K3) or session-KV staging. Don't overclaim either way.

## How to run (all phases execute on the SSH box)

```bash
scp k1.sh hami@87.106.63.105:/tmp/ && ssh hami@87.106.63.105
bash /tmp/k1.sh recon      # READ-ONLY: policies, pods, annotations, CRD version, pod ages
bash /tmp/k1.sh stage      # patch vllm policy: actions=[rotate,kv-reset], minAvailableReplicas=2 (original saved)
bash /tmp/k1.sh poison     # pre-flight /reset_prefix_cache exists; plant crafted prefix; verify HIT
bash /tmp/k1.sh fire       # apply SecurityEvent (source=redteam) at the poisoned pod
bash /tmp/k1.sh verify     # decision log + kv-reset-epoch annotation + UID-unchanged + MISS after reset
bash /tmp/k1.sh rollback   # restore original policy, delete SecurityEvent, kill port-forward
```

**Pre-flight checks that can stop the run (findings in their own right, not Phorvex failures):**
- `/reset_prefix_cache` returns 404 on this vLLM build (live image is v0.7.3 — verified 200 at T12) → endpoint gated/moved; record, adjust `phorvex.ai/kv-reset-path` annotation or vLLM flags.
- vLLM pods younger than `antiOverRotationWindow` → all moves blocked; wait it out (see ATTACKS.md artifacts note).
- No prefix-cache metric on `/metrics` → fall back to the cold/HIT/post-reset **timing** comparison the script already captures.

**Timing expectations:** 5s tick (verify vllm-defense's `tickInterval` live); decision should appear within ~2 ticks of `fire`.

**Record as T12 in ATTACKS_OUTCOMES.md** (template at its bottom): setup = policy patch + planted prefix + SecurityEvent; oracles above; verdict 🟢 only if BOTH selection and effect pass; update the K1 row Outcome in ATTACKS.md.
