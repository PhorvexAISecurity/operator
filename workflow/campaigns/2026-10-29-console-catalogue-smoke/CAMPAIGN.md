# Console catalogue 13-family staging smoke

## Question and scope

Determine whether one exact authoritative ID in every family of the reviewed
192-ID catalogue can complete the strict Console evidence contract on the
reviewed merged release. The environment is Phorvex staging/dev only. The
population is exactly the 13 IDs below, launched sequentially through the
authenticated Console with `triggerMode=reactive` and `executionMode=active`.

| Family | Exact ID |
| --- | --- |
| agent-action | `AML.T0053` |
| controller-stop | `AML.T0074` |
| credential | `AML.T0035` |
| datastore | `AML.T0070` |
| identity-sa-rotate | `AML.T0012` |
| image | `aml.t0010` |
| network-edge | `AML.T0096` |
| node-recycle | `AML.T0105` |
| pod-rotate | `MS-DE-clear-container-logs` |
| quarantine | `AML.T0025` |
| sensitive-output | `AML.T0069` |
| serving-kv | `AML.T0080` |
| serving-rate | `AML.T0024` |

These IDs are the first exact members of their profiles in the generated,
validated `catalogue-family-profiles.yaml`; no alias or normalized ID is valid.
The active window is capped at 12 hours. Existing staging capacity and the
normal reviewed release path are the cost ceiling.

## Scientific design

`hypotheses.yaml` pre-registers one hypothesis per family. The sample unit is
one newly created exact Console run. Each run requires an independently
captured legitimate/raw baseline, a fresh run-bound signal, a selected and
feasible decision, accepted receipt, family physical oracle, raw/baseline/final
Prometheus evidence, postflight inventory, exact cleanup, and a PASS from the
strict offline verifier. Screenshots are supporting attachments only.

The positive control is the family profile's legitimate/raw baseline and
fresh-signal observation. A baseline that is already protected, a stale event,
or an unrelated decision is non-discriminating and cannot pass.

## Safety boundary

- Production, production namespaces, production images and production Argo
  Applications are prohibited.
- Release and profile changes flow through reviewed Git and Argo. No hidden
  direct drift is allowed.
- Only one family profile is enabled at a time. Its previous run cleanup is
  verified before profile replacement.
- Fixture pruning is limited to catalogue-labelled, chart-owned objects after
  owner-reference and namespace checks; unknown ownership stops the campaign.
- No secret value is logged. Prometheus access uses deployment-managed
  configuration and Secrets.
- The campaign stops immediately on uncontained behavior, source/image drift,
  cleanup failure, cross-namespace effects, or loss of exact evidence binding.
- `codex-integration` owns the mutation/cleanup ledger. `hamihoriyat` is the
  independent PR/campaign reviewer; missing independent review remains a hold.

## Rounds

Round 1 contains the release baseline and the 13 sequential family attempts.
Failed attempts are immutable evidence. Only demonstrated in-scope staging
defects may be fixed and rerun, with a new run ID and preserved earlier result.

## Findings

Any discovered product or staging defect is promoted through intake; this
campaign does not edit Master Issues directly.
