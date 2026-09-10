# T0-C live baseline facts (Proposer, 2026-09-03 ~15:45–16:20 UTC, then-deployed `phorvex:0.4.74`; window actually straddled 0.4.73→0.4.74, and 0.4.75 landed 16:38Z — see Fact 1a corrections)

Corpus: PVC `phorvex-phorvex-audit`, reader pod on brain node. Scan covered the whole retained
corpus (all `live.jsonl*`), not a sample. Note mid-window event: brain pod rolled
s22jx → kg4g2 at 15:17:10Z because **node ip-172-27-12-250 was recycled** (NotFound); new brain
node ip-172-27-12-251. Same image (0.4.74) on both sides of the roll.

## Fact 4 — retention (answering first: it bounds everything)

    live.jsonl.4  255 MB  from 2026-09-03T11:09:47Z
    live.jsonl.3  255 MB  from 2026-09-03T12:05:56Z
    live.jsonl.2  255 MB  from 2026-09-03T13:01:55Z
    live.jsonl.1  255 MB  from 2026-09-03T13:59:43Z
    live.jsonl    252 MB  from 2026-09-03T14:57:03Z (active)

**Retention ≈ 4.7 hours** (5 × ~255 MB, rotation ~hourly). "The last 24 h" is not observable from
the PVC. Consequence for the ticket's Task-9 validator: the "100% of the Tier-0 corpus" claim
needs a frozen export taken at a known time — the live PVC alone cannot ground a 100%-of-corpus
claim. 20,044 decision records in the retained window.

## Fact 1a — selected=true record

`01-selected-record-rotate-voice-0.4.73.json` (full JSON, 101 KB): rotate on
`voice/voice-bot-79d7f9464d-hdwlg`, 2026-09-03T12:13:46Z, actuated=true, selectionRound=1,
reason "rotate: strict gain 11.95 > 0". All 5 selections in the corpus are rotate on voice-bot
(12:13, 12:16, 12:22, 13:56, 14:05 — the pod is churning; each lands on a fresh pod).
**Zero selections on vllm** in the retained window (consistent with the T1-A baseline: gate dark,
`reactiveOnly` policy, no foothold).

**⚠ MISLABEL CORRECTION (Skeptic catch, bus 280, fixed 2026-09-03 ~18:05Z):** the captured file
was originally named `...-0.4.74.json` but the record is **0.4.73** — `brainImage=phorvex:0.4.73`,
`gitSHA=727b408e` (PR #97 merge), 1h41m before the 0.4.74 rollout (13:54:43Z), and no `leakage`
key in inputs. File renamed to its true build. The 5-selection count straddles the deploy:
**3× 0.4.73** (12:13 — verified by gitSHA on the captured file; 12:16, 12:22 — same pre-13:54:43Z
window, by deploy-window inference; their records have since aged out of retention) and
**2× 0.4.74** (13:56, 14:05 — post-rollout, pre-0.4.75; same inference). Lesson now enforced for
L3: **a record's `brainImage`/`gitSHA` is the only honest version stamp** — never the file name
or capture time; the L3 band filters on `gitSHA == <T0-C merge>`.

**⚠ SECOND MID-WINDOW DEPLOY (found 2026-09-03 ~17:55Z):** **0.4.75** (PR #99, `6664ad1`,
M-38 quarantine detach-half actuation fix; release `67acdc3`) rolled out at **16:38:17Z** —
during this fix cycle, by a parallel workstream. The retained corpus now straddles 0.4.74/0.4.75
(0.4.73 has aged out). Re-scan at ~17:55Z: 5 selected records, all rotate on voice —
**2× 0.4.74 (`35c12069`) + 3× 0.4.75 (`6664ad19`)**, all verified by gitSHA this time. M-38
touches the actuation path, not the trace path, but any L3 diff must segment on gitSHA.

Selected candidate's economics reconstruct: ECost 0.4436 = 0.4·CNorm(1) + 0.6·CFlow(0.0727) ✓;
netGain 11.946 = marginalCoverage·provenance − lambdaContribution ✓. **But `lambdaRuntime = 0`
while `lambdaConfiguredSeed = 0.4`** — demand(1) ≤ budget(1), the dual update never fires
(M-19/M-22 λ-trap family). The ticket's tier-exit "λ observed non-zero on a tenant whose budget
does not bind" is NOT satisfiable by observation on this fleet today: λ stays 0 everywhere
because no tenant is over budget. Flagging now — the proposal's §4 band must say λ-runtime
remains 0-valued (a *field*, present and numeric, but 0).

## Fact 1b/1c — selectionReason and existingExclusionReason over the retained corpus

    selectionReason:
      existing_generator_exclusion    125,947
      reactive_only_no_direct_foothold 10,350
      selected_strict_positive_gain         5
      (all others — strict_gain_not_positive, not_evaluated_by_current_greedy,
       move_budget_exhausted, partition_other_action_selected — ZERO)

    existingExclusionReason prefixes:
      recon-cover:*          101,300
      availability:*          24,516
      anti-over-rotation:*       131
      conformal-slo:*              0   <- none in corpus
      NaN-category                 0   <- none in corpus

**No conformal-slo or NaN-category exclusion exists in the retained corpus** — the requested
sample record does not exist to be captured. The cost engine's `UnactionableCategory` is only
consulted to *omit* CNorm/CFlow on excluded rows (coverage.go:803-807); the category string
itself is never recorded anywhere. That is a gap the gap map will name.

## Fact 2 — vllm policy's enabled MutatingActions

`kubectl -n vllm get phorvexpolicy vllm-defense`: `spec.actions.enabled = [rotate,
kv-migrate-invalidate]` — **2 of 15 canonical actions**. (Full spec: maxMovesPerTick 1,
antiOverRotationWindow 90s, proactiveFloor 15m, tick 10s, λ=0.5, normSparsity 0.4,
flowDisruption 0.6, costCeiling 1.2, minAvailableReplicas 2, reactiveOnly+eventDriven.)
The record carries rows for exactly those 2 actions and says nothing about the other 13 —
the R-2 hole measured: from the record alone you cannot tell "not-enabled" from
"enabled but never generated".

## Fact 3 — inputs.primed

    primed=true   4,417 / 20,044  (22.0%)
    primed=false 15,627

## Bonus (feeds the gap map) — action-row coverage per tenant vs the canonical 15

    tenant      rows  actions with NO row
    vllm         2    quarantine,debugger,custom-inject,identity-rotate,route-rotate,warm-swap,
                      mig-rebind,kv-reset,endpoint-rotate,model-shard-replace,adapter-rotate,
                      request-drain,guardrail-rotate
    voice        6    quarantine,route-rotate,kv-reset,endpoint-rotate,model-shard-replace,
                      adapter-rotate,request-drain,guardrail-rotate,kv-migrate-invalidate
    litellm     10    quarantine,adapter-rotate,request-drain,guardrail-rotate,kv-migrate-invalidate
    nats/crm/mcp/chroma/ci-reports/mongo  7 each (rotate,quarantine,debugger,custom-inject,
                      identity-rotate,warm-swap,mig-rebind)
    adapter-rotate, request-drain, guardrail-rotate: ZERO rows fleet-wide (no tenant enables them)

    voice policy enabled list (for the selected record's context): [rotate, noop,
    identity-rotate, debugger, custom-inject, warm-swap, mig-rebind] — note "noop" sits in the
    enabled list; it is not a mutating action and gets no row either.
