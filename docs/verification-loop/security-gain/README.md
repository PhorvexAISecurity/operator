# Security Gain validation study

This study measures whether the P1 Security Gain matches the effect an action actually has.
The formula under test is:

```text
SecurityGain(i,a) = provenance(i) × Σ weight(k), summed over the facts k the action covers
```

[REPORT.md](REPORT.md) has the results, the answers to the six Math/OR questions and the
limitations. The candidate-level export is
[2026-10-12/candidates.csv](2026-10-12/candidates.csv).

The study runs on the [one-case verification loop](../README.md):

- a private envtest API server;
- the unchanged `ucw-recon` decision engine;
- the native actuator;
- the shipped Python admission boundary;
- a synthetic downstream.

It never touches a shared cluster. The formula, the action-to-fact map, λ/β and every gate
stay unchanged.

## Scenarios

Each scenario fixes which capabilities the attacker has stolen. Every capability is checked
by an oracle that replays the stolen material after the brain's decision.

| `-scenario` | Replicas | Stolen capability | Oracle |
|---|---|---|---|
| `lease` (default) | 1 | Inference lease credential A, with a `TEST_INJECTED` endpoint-lease observation | A reaches the protected synthetic downstream (200 and the call counter advances), or gets an exact 401 with no downstream call |
| `token` | 2 | The target Pod's bound API token, minted by TokenRequest bound to its UID (as the kubelet projects it), plus one trusted typed `pod-bound-api-auth` event | Replaying the bearer at the private API server: authentication (201), or the API server's exact 401 |
| `combined` | 2 | Both of the above, on the same Pod | Both oracles |

With two replicas, rotate passes the availability floor. Each replica runs its own instance
of the shipped admission runtime. Both instances read the same lease policy, so
endpoint-lease-revoke still validates and drains every proxy.

## Arms

Each episode is fresh: a new private API server, new credentials, and one shadow decision by
the brain from the same declared initial state. After that decision, the episode takes one
branch:

| `-arm` | Branch after the decision | Scenarios |
|---|---|---|
| `intervention` | Dispatches the selected `endpoint-lease-revoke` on the reviewed defended path, with its assertions | lease |
| `baseline` | Withholds every action | all |
| `selected` | Dispatches whatever the brain selected, or nothing if it declined | token, combined |
| `cf-rotate`, `cf-endpoint-rotate`, `cf-endpoint-lease-revoke` | Dispatches that native action instead (a counterfactual). The actuator's own gates still apply; the decision layer's gates do not. | all |

Every arm then measures two things:

- **Capabilities.** Each stolen capability, plus legitimate credential B, is probed on every
  serving replica for the hold window.
- **Brain view.** The brain re-observes the workload: which facts it still mints, at what
  weight, and what it would now select.

After a rotate the evicted Pod is gone, because envtest runs no controllers. The harness
creates the ReplicaSet's replacement, labelled as harness-simulated, and re-observes there.

`run_study.py --scenario S` runs seeded, interleaved blocks with one episode per arm in each
block. `analyze.py` reads any number of study directories.

## Reproduce

Linux amd64, Go 1.26.1, Python 3 and the envtest assets from the
[verification-loop README](../README.md#reproduce-the-experiment) are required. Run from the
operator repository root:

```sh
(cd phorvex && go build -o "$LOOP_WORK/verification-loop" ./cmd/verification-loop)
for s in lease token combined; do
  python3 build/test-harness/security-gain-validation/run_study.py \
    --binary "$LOOP_WORK/verification-loop" --repo-root "$(pwd -P)" \
    --python "$LOOP_WORK/venv/bin/python" --assets "$LOOP_ASSETS" \
    --git-sha "$(git rev-parse HEAD)" --scenario "$s" --out "$LOOP_WORK/study-$s" --blocks 10 --hold 20s
done
python3 build/test-harness/security-gain-validation/analyze.py "$LOOP_WORK"/study-* --out "$LOOP_WORK/analysis"
python3 -m unittest discover -s build/test-harness/security-gain-validation
```

## Reading `candidates.csv`

There is one row for each candidate in each episode's real decision state, including `noop`.
Rows from different episodes are never merged into one decision state.

**Predicted columns** come straight from the unchanged brain's trace for that episode.
`predicted_security_gain` is `grossFullValue`, that is provenance × Σ covered weights.

- `selectable` is false when the decision layer excludes the action, for example on the
  availability floor or the conformal cost ceiling. `blocking_gate` names the gate.
- `predicted_weight_on_measured_capabilities` is the part of the gain that rests on facts
  whose capability this scenario instantiates.

**Measured columns** are filled only on the row for the action the episode executed
(`executed_in_episode=yes`). Each has a `*_status` companion that holds one of:

- `MEASURED`
- `ESTIMATE`
- `CENSORED`, which gives a lower bound
- `PARTIAL`
- `NOT APPLICABLE`
- `UNAVAILABLE`, followed by the reason

An unavailable value is never written as zero.

**Attack outcome:**

- `attack_success_with_action` is the fraction of the scenario's instantiated capabilities
  still usable in the last 3 s of the window.
- `attack_success_no_action` is the same fraction from the scenario's baseline episodes,
  which start from the same initial state but run as separate episodes.
- `estimated_risk_reduction` is the difference between the two.
- `capability_outcomes` and `time_to_capability_removal_s` give the outcome per capability.
  A bearer stays accepted for the API server's authentication-cache lifetime after its Pod
  is gone.

**Fact invalidation.** This is judged on the facts attributed to the attack (marked `*` in
`post_branch_fact_keys`):

| Column | Meaning |
|---|---|
| `confirmed_invalidated_keys` | The fact is no longer minted and the capability was removed |
| `false_invalidated_keys` | The fact is no longer minted, but the capability is still usable |
| `uncredited_removals` | The capability was removed, but the fact is still minted |
| `unmeasured_cleared_keys`, `kinds_reminted_on_new_identity` | Structural kinds that have no instantiated capability here |
