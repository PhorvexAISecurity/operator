# M1b source, activation and rollback

M1b prepares compatibility plus the full active closure. Stage 3 does not merge
or activate it. Hami approved the engine release window; that approval does not
establish network isolation, runtime publication or native vLLM telemetry.
All commands below are stage 3b commands for the lead after independent review.
Never copy source, environments, archives or clients to `phorvex-gw`. Use the
existing authorized off-gateway Kubernetes client. No Secret/token contents,
runner changes, NATS, vLLM pod/scrape or retention writes are part of this runbook.

## Owners, source closure and current prerequisites

The gateway Deployment and its original Service are externally/manually owned.
`install.sh`, `render.py` and `render_output.py` locate that owner; do not rerun
installation, adopt the Deployment into Helm or replace its immutable source.
The stack wrapper, `deploy/helm/phorvex-stack/templates/litellm-gateway-metrics.yaml`,
owns the new source/profile, Service, ServiceMonitor, NetworkPolicy and exact-name
Console read Role. Its JSON inputs are in `files/litellm-m1b/`. No dependency
chart changes or repackaging are necessary; the current EPSS package stays intact.
`values-eks.yaml` switches the complete active Console closure. Generic values
remain disabled. New source/profile and metrics objects carry
`helm.sh/resource-policy: keep` and explicit Argo
`argocd.argoproj.io/sync-options: Prune=false,Delete=false`. This preserves
their identities during rollback for explicit guarded cleanup.
[Argo sync options](https://argo-cd.readthedocs.io/en/stable/user-guide/sync-options/#no-prune-resources)
document the resource-level pruning control. Do not blanket-sync/prune existing Argo drift.

`deploy/monitoring/litellm-m1b/metrics-closure.json` is the authoritative prepared
closure: full source/runtime/profile hashes, baseline UIDs/spec hash and input
hashes. The only active source-bound profile is `litellmLive`. Its ten stable
fields are retained except source and gateway image; the complete JSON hash and
content name are recomputed. Live Console mounts independently confirmed that
profile and `LITELLM_OUTPUT_ENABLED=false`. No installed output-policy or output
source/profile exists in this baseline. If an output extension becomes installed,
stop and inventory its full closure: migration requires its existing policy to
be exactly version 2, revision 0 and empty, with no prepared operation. Never
clear an active policy, rules, grants, journals or trial to make that gate pass.

Both complete reviewed sources remain approved:

- Legacy `4bf046ce690c280da4b4f0f613ac52d2b4511285454f18c25b2e144b574d5cc1`,
  with the original exact Python base image, or the reviewed source-free runtime.
- Metrics `f550b9890b20da4b02b68fac5c102a99a0313e6f419dc41dd0c409b2bdd165c1`,
  with only the exact published source-free runtime in `image-contract.json`.

Engine, Console, actuator and recovery observe the approved source, derive its
content name, verify immutable bytes and actual Pod command/env/read-only volume
bindings, then join current Service, policy and Pod lifetimes. An arbitrary
valid-looking hash/prefix, old volume with new annotation, mixed replicas, image
mismatch or stale journal/observation fails closed. Keep old immutable CMs and
approval through convergence and rollback. Removing them is a separate change.

The 2026-10-14 baseline has two external prerequisites:

1. `aws-eks-nodeagent --enable-network-policy=false`: NetworkPolicy objects do
   not enforce privacy. Hami must separately enable and prove enforcement on
   relevant nodes. No kube-system change is authorized by M1b. Require a fresh
   owner-produced allowed/denied data-plane witness before rollout; repeat those
   controls against both actual gateway replicas afterward.
2. Native vLLM target `:8001` is DOWN, connection refused. The existing healthy
   `phorvex.physics.bridge` already records native completions into
   `http_requests_total` with correct `namespace="vllm"`/serving-pod labels.
   Hami must make that source healthy in his release. Gateway scraping cannot
   satisfy this prerequisite. ReqRate source queries and bridge stay unchanged.

The historical runtime image was absent from ECR during stage 3. The lead
republished the exact source-free recipe on isolated Spot EC2, and its published
old/new protocol tests passed on the real digest in `image-contract.json`.
`runtime-publication.json` and `actual-image-receipt.json` retain the separate
publication and successful protocol receipts, with full hashes in the v3
contract. The manual executor has no GitHub run ID; historical run IDs prove
nothing about this publication. Recheck availability and match these receipts
before activation. No image/profile pin may be guessed or inferred from a tag.

## Before merge and the compatibility release

Run native/race/envtest, chart, real PromQL and published-image controls on
isolated Spot EC2 or CI; compare exact failure sets with fresh main (no new
failure is the authorized gate). Commands are recorded in the worker handoff.
Preserve actual receipts and independent review. Hold catalogue fires and require
no prepared client/output journal operation throughout migration. A prepared
receipt is bound to old Pod/source lifetimes; it must resolve before rollout.

Before merging the active values, establish runtime and network prerequisites,
Hami's healthy native scrape, idle owners and the preserved P0 evidence. Record
absence of the three named metrics objects and new immutable CMs; a name collision
requires review rather than adoption. M1b's ordinary engine/Console release creates
new CMs and inert scrape objects (the Service selector requires a label no old Pod
has). It does not alter the external gateway. The new Console profile refuses
legacy gateway snapshots until the later manual rollout converges; catalogue
fires remain held during that interval. The engine still recognizes legacy source.

After the release pipeline completes, record actual manager and Console Ready
Pod UIDs/imageIDs and ECR/OCI source identities. Verify both were built from the
merged compatibility source; do not hand-edit their release tags/digests. This
must happen before enabling the external gateway listener. Do not treat a CI
source check or a rendered Deployment as release proof.

## Fresh preparation and fail-closed preflight

Use a private off-gateway evidence directory. `m1b_inputs` contains freshly
captured nonsecret Deployment/Service/source/clients/profile/NetworkPolicy/label
snapshots in the same format as stage 3 inputs. Existing credential references
are allowed; only the independently verified exact installed inert
`litellm/OPENAI_API_KEY=sk-placeholder-replace-me` literal is allowed. Unknown
credential literals are refused. The old profile CM remains readable after the
new active values release. Capture it as `profiles.json` for baseline checking.

```sh
set -euo pipefail
m1b_inputs="$M1B_EVIDENCE/fresh-inputs"
m1b_candidate="$M1B_EVIDENCE/fresh-candidate"
m1b_prepared=deploy/monitoring/litellm-m1b
python3 -B build/integrations/litellm-gateway-runtime/verify_reuse.py
python3 -B build/test-harness/fixtures/litellm-live/prepare_metrics_activation.py \
  --inputs "$m1b_inputs" --values deploy/helm/phorvex-stack/values-eks.yaml \
  --baseline-bindings "$m1b_prepared/previous-console-bindings.json" \
  --output "$m1b_candidate"
python3 -B build/test-harness/fixtures/litellm-live/guard_metrics_activation.py \
  --closure "$m1b_prepared/metrics-closure.json" --inputs "$m1b_inputs" \
  --runtime-receipt build/integrations/litellm-gateway-runtime/actual-image-receipt.json \
  --network-config "$M1B_EVIDENCE/network-enforcement-config.json" \
  --network-proof "$M1B_EVIDENCE/network-allowed-denied-proof.json" \
  --prometheus "$M1B_EVIDENCE/prometheus-preflight.json"
```

The guard rejects UID/spec/source/profile drift, missing actual-image evidence,
disabled enforcement, stale network/native-source evidence and active output
state. Its required network receipt schema is
`phorvex-litellm-network-enforcement-proof-v1`: fresh `utc`, `allowed=true`,
`denied=true`, distinct actual `allowedPodUID`/`deniedPodUID`, verified
`prometheusPodLabels`, and the underlying retained `evidenceSHA256`. That receipt
must come from a real owned data-plane witness, never hand-filled booleans.
The runtime receipt schema is the actual-image workflow's existing
`phorvex-litellm-gateway-runtime-reuse-receipt-v1`.

Compare freshly derived source/profile names/full hashes and metrics specs with
the merged chart JSON. Record post-release source/profile CMs' actual UIDs and
verify immutable bytes match. Match selected Prometheus labels and selectors,
full current NetworkPolicy inventory and actual node enforcement. The new policy
preserves the original declared serving/status TCP ports 4000/4001/4002 from all
previous peers; only 4003 is limited to the intersection of monitoring namespace
and the observed Prometheus pod labels. Existing policies must not allow 4003.

Re-render only to refresh the Deployment resourceVersion after proving the same
baseline UID/full spec. Any template, source, Service, profile, owner or replica
change requires review of a new baseline; never remove JSON `test` operations.

## External gateway activation and readback

The released chart already created the five source/scrape objects. Do not apply
them again under a conflicting manual field manager. Record their real identities
using an existing off-gateway loopback proxy (the proxy process holds credentials
privately; no credential export). Use a separate terminal for:

```sh
kubectl proxy --address=127.0.0.1 --port=18081
```

After comparing those actual specs with the merged chart and confirming compatible
engine/Console release, idle catalogue and resolved journals:

```sh
python3 -B build/test-harness/fixtures/litellm-live/guard_metrics_resources.py record \
  --port 18081 --receipt "$M1B_EVIDENCE/metrics-object-authority.json"
kubectl patch deployment litellm -n litellm --type=json \
  --patch-file "$m1b_candidate/deployment-metrics-json-patch.json"
kubectl rollout status deployment/litellm -n litellm --timeout=5m
kubectl get pods -n litellm -l app=litellm -o json > "$M1B_EVIDENCE/gateway-pods-after.json"
kubectl get endpointslices -n litellm -l kubernetes.io/service-name=litellm -o json \
  > "$M1B_EVIDENCE/serving-endpoints-after.json"
```

The patch tests actual UID/resourceVersion/full spec, then changes only the
reviewed gateway runtime/source, metrics env/downward identity/port and opt-in
label. It preserves the backend image/env, serving Service, policy/Secret
references and existing output bindings. Two Ready source/runtime-converged Pods
and exact serving EndpointSlice membership are required. Existing engine
operations refuse mixed-source rollout. Run actual allow/deny network controls
on both replicas and confirm unchanged admission/status access. Exposition may
contain only bounded namespace/pod, fixed `target="litellm"`, method/route/status/
outcome and histogram `le`, plus ordinary scrape labels; no URL/prompt/token/ID.

For queries use an existing off-gateway Prometheus connection, or a bounded local
forward in a separate terminal:

```sh
kubectl port-forward -n monitoring service/kube-prom-stack-kube-prome-prometheus 19090:9090
```

```sh
m1b_prom=http://127.0.0.1:19090
m1b_query() { curl --fail --silent --show-error --get \
  --data-urlencode "query=$1" "$m1b_prom/api/v1/query"; }
m1b_query 'http_requests_total{namespace="litellm",target="litellm"}'
m1b_query 'http_request_duration_seconds_bucket{namespace="litellm",target="litellm"}'
m1b_query 'sum by (pod) (rate(http_requests_total{namespace="litellm"}[1m]))'
m1b_query '1000 * histogram_quantile(0.99, sum by (pod, le) (rate(http_request_duration_seconds_bucket{namespace="litellm"}[5m])))'
m1b_query 'min_over_time(up{namespace="litellm",service="phorvex-litellm-gateway-metrics"}[10m])'
m1b_query 'sum by (pod) (increase(http_requests_total{namespace="litellm",target="litellm"}[10m]))'
m1b_query 'sum by (pod) (increase(http_request_duration_seconds_count{namespace="litellm",target="litellm"}[10m]))'
m1b_query 'up{job="vllm"}'
m1b_query 'vllm:request_success_total{namespace="vllm"}'
m1b_query 'sum by (pod) (rate(http_requests_total{namespace="vllm"}[1m]))'
```

These are the exact unchanged engine ReqRate/p99 queries, substituted separately
for each namespace. Require targets continuously UP for at least ten minutes,
advancing matching gateway counter/count populations under authorized ordinary
traffic and correct current gateway Pod names. p99 remains unavailable at
insufficient observations. Verify vLLM native and generic bridge match their
completion population, with actual vLLM Pod labels. Do not add duplicate bridge
rules, combine the populations or relabel gateway Pods/namespace as vLLM. Both
configured LiteLLM model aliases currently route to the fixed vLLM service;
that routing fact does not confer per-serving-pod attribution on admission
counters. No caller selects a metrics target. Preserve unrelated owner state and
exclude manager-written operation/serving-effect journals from config-drift
comparisons. Acceptance stays incomplete if native vLLM ReqRate is absent.

## Rollback without losing legacy authority or history

Hold fires, resolve any prepared operations and verify current source/runtime
and metrics UIDs/specs still match this activation. Do not roll back another
owner's later edits. First restore the recorded original external gateway
using the exact rollback patch from the activation directory:

```sh
kubectl patch deployment litellm -n litellm --type=json \
  --patch-file "$m1b_candidate/deployment-metrics-rollback-json-patch.json"
kubectl rollout status deployment/litellm -n litellm --timeout=5m
```

The patch tests original owner UID and the full exact candidate spec before
restoring the previous template, original source name/runtime and env/ports.
Check both Ready legacy Pods and serving endpoints. If admission/defaulting
changed the candidate spec, freshly compare it and review a new exact rollback
patch rather than dropping guards. New and old sources remain approved.

The lead prepares a reviewed Git revert of the exact M1b activation commit
from fresh main, preserving subsequent release pins, EPSS and Hami's changes.
The offline starting point is the exact recorded activation commit, leaving
legacy compatibility available:

```sh
git revert --no-commit "$M1B_ACTIVATION_COMMIT"
```

Before committing that revert, preserve subsequent manager/Console release
pins and independently review its file delta; it is not permission for a
blanket live Helm rollback. Restore `previous-console-bindings.json` and disable
`litellmGatewayMetrics`; verify the full preceding profile hash/mount and source
read authority. Do not
roll back the engine/Console binaries merely to undo gateway telemetry. The
compatible release supports the legacy profile after restoration. Immutable
source/profile CMs and metrics objects are retained by the explicit pruning
and deletion controls.
After Git/Helm ownership converges to disabled metrics and no later writer exists,
remove only the three recorded metrics objects, with API UID/resourceVersion
preconditions and exact spec/metadata comparisons:

```sh
for m1b_kind in ServiceMonitor Service NetworkPolicy; do
  python3 -B build/test-harness/fixtures/litellm-live/guard_metrics_resources.py delete \
    --port 18081 --kind "$m1b_kind" --receipt "$M1B_EVIDENCE/metrics-object-authority.json"
done
```

Keep old/new immutable CMs, protected journals, policy state, Secret references,
TSDB history/PVCs, P0 archives and Hami's vLLM/retention release. Close only the
bounded local proxy/forwards created for this window; leave gateway disk unchanged.
Record rollback source/profile/image/Pod/Service identities and bounded legacy
admission/auth/redaction/streaming continuity evidence. No rollback was run in
source preparation.
