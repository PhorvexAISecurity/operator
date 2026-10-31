# Explicit offline endpoint study through the brain

The default `brain-replay --snapshots ...` continues to execute legacy baseline
and parameter arms. The two explicit study modes below use the same recorded
owner state, profiles, capability/failure verdicts, grounded recon facts and
non-cost generator as the actual brain. They do not actuate anything.

```sh
brain-replay --snapshots frozen-cohort --export-study-candidates \
  --out candidates.jsonl
brain-replay --snapshots frozen-cohort --endpoint-study observed-trace.json \
  --endpoint-study-config study-config.json --out result.json --summary summary.json
```

`--export-study-candidates` writes `math-lab.study-candidates.v1` JSONL. Each row
first proves that legacy replay exactly reproduces the recorded decisions.
Candidates include all enabled actions with their real first non-cost veto, or
their pre-cost fact cover and remaining selection gates. Gates after a veto were
not evaluated. Preparation does not evaluate legacy cost, substitute zero cost,
or reconstruct discarded actions from final selections. Runtime generation and
its cost/CHi rules remain unchanged.

The supported initial comparison is one namespace, policy UID and workload UID,
with `maxMovesPerTick=1`, positive observed controller `spec.replicas`, and a
homogeneous snapshot source revision. Unsupported scope is refused explicitly.
Every normalized tick ID is its snapshot digest; the original tick ID remains
in the export. Tick time is recorded `decidedAt`, while `captured_at` retains the
sensor snapshot time. The observer may add qualified endpoint membership,
duration samples, interval ledger and declared study settings. It cannot edit
source facts, provenance-adjusted weights, gates, action/Pod identities,
containment, class, or an already-known membership count.

The study uses the brain-owned `internal/cost/endpoint` kernel for both arms and
then executes the brain's shared bounded-greedy gate/selection loop for every
arm. It verifies value and winner parity before emitting `PAIRED_BRAIN_REPLAY`.
The study sums sorted grounded, provenance-adjusted facts deterministically;
its unpriced worth threshold applies before optional `V-lambda*E` ordering.
Negative priced gain alone is not another worth gate. Real reactive, resource,
capability, cooldown and containment predicates still apply. Original mandatory
containment priority is retained; missing recorded priority is unavailable.

The result is **one JSON object**, compatible with the endpoint result schema,
with `baseline_exact_count`, `snapshot_digests` and
`brain_selection_parity`. `counterfactual_actual_charges` and
`counterfactual_verified_facts` remain null. History-aware selection, entropy,
counterfactual spend feedback and verified mitigation are not implemented by
this V2/V3 mode. The standalone `endpoint-v3` CLI remains labelled
`PAIRED_GO_REFERENCE`; its existence alone is not an actual brain benchmark.

## Source identity and explicit proposals

The executable reports its embedded source; `PHORVEX_GIT_SHA` cannot relabel it.
By default a different capture source is refused. A reviewed experimental
proposal can add `--allow-cross-version` to either command. This preserves the
true producer `source_revision`/`replay_git_sha`, separately records
`snapshot_source_revision`, and marks `cross_version` and `observational` true.
Every required baseline must still reproduce exactly. The bot additionally
requires the image-extracted same-source control and local base fidelity;
explicit cross-version use does not replace those controls or prove a live
experimental deployment. Mixed capture revisions are refused.

## Stage measurement and capture

See [the stage observer contract](../../benchmark/stage/README.md) for durable
watch sessions, UID-bound calibration, source bindings and normalization.
Watch-observed Service readiness intervals are not application outages. A
collector-owned calibration rotation is not a brain-issued move. An open move,
watch gap, source/scope change, unrelated rollout, uncertain attribution or
failed durable write cannot become complete spend history. Short explicit
study windows are supported only after observing their entire duration; they
do not establish the original day/month history requirements.

For split-service capture, configure the brain chart's
`phorvex.mathLab.capturePolicies` allowlist and `mathLabStore.existingClaim`.
The chart grants its nonroot process group 65532 access to the mounted PVC only
when capture is enabled. `phorvex.mathLab.captureMaxBytes` bounds retained
snapshots. The manager chart's independent
`phorvex.mathLab.captureCostEvidence=true` flag enables immutable replica
observations through the remote capture request, including with local audit
capture disabled. That replica evidence is not an endpoint interval ledger.
Both capture features default off. Brain images built with the updated service
Dockerfile include `/brain-replay` with exactly the service's linked SHA/version.
