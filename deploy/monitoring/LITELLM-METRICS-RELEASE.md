# LiteLLM metrics release and rollback

Source preparation only. No command below was executed in stage 1. M1a leaves active pins and metrics disabled. M1b records the exact merged candidate and baseline before any write. The reserved isolated AWS executor is not provisioned/verified by this PR.

## Stage 2 / M1b commands — prepared only, not executed

Preconditions: lead publication/review and green exact-head CI; Hami's merged
vLLM release; verified merged-source runtime reuse receipt; idle owner window;
all active profile/runtime/source bindings inventoried; preserved P0 originals;
actual Prometheus selectors, monitor selection, full ingress/egress inventory
and CNI enforcement proved. Historical evidence reported enforcement off;
this preparation does not repair it. Stop dependent activation if these gates
are absent. No new gateway artifacts on any apply/rollback step.

From the later reviewed merged source, on the VPS or already approved CI:

```sh
python3 -B build/integrations/litellm-gateway-runtime/verify_reuse.py
# After M1a is merged; dispatch and wait for its successful receipt, never now:
gh workflow run verify-litellm-gateway-runtime.yml --ref main
```

Use fresh reviewed **nonsecret** input files; paths below are placeholders for
that later recorded baseline. No Secret values or literal key/token env values
belong in these snapshots. Output policy input is required only when applicable.

```sh
cfx_m1b_inputs=/path/to/reviewed/nonsecret-owner-inputs
cfx_m1b_candidate=/path/to/reviewed/merged-m1b-render
python3 -B build/test-harness/fixtures/litellm-live/render_metrics.py \
  --enable-metrics \
  --deployment-original "$cfx_m1b_inputs/deployment.json" \
  --profiles-original "$cfx_m1b_inputs/profiles.json" \
  --networkpolicies-original "$cfx_m1b_inputs/networkpolicies.json" \
  --prometheus-pod-labels "$cfx_m1b_inputs/prometheus-labels.json" \
  --output-policy-original "$cfx_m1b_inputs/quiescent-output-policy.json" \
  --output "$cfx_m1b_candidate"
```

M1b records the generated source name, every profile name/full SHA and runtime
receipt in its reviewed active binding PR. Do not run install.sh prepare/switch
or overwrite old immutable ConfigMaps. Serialize the active values/Console
binding release with the gateway upgrade and catalogue idle window; do not
activate a partial closure or blanket-sync unrelated Argo drift. Re-fetch and
re-render if main or owner snapshots change. Rendered patches are candidates,
not permission to apply unmerged inputs.

The following commands are for an already authorized **off-gateway** Kubernetes
client, using only reviewed merged artifacts after the preflight above. Record
absence/prior state and resulting names/UIDs. A collision or stale patch stops
this release; do not adopt another owner's object. The original serving
Service and old policies are not modified:

```sh
kubectl create -f "$cfx_m1b_candidate/gateway-metrics-source-configmap.json"
python3 - "$cfx_m1b_candidate" <<'PY' | kubectl create -f -
import json,sys
from pathlib import Path
root=Path(sys.argv[1]); closure=json.loads((root/'metrics-closure.json').read_text())
items=[json.loads((root/(p['configMapName']+'.json')).read_text()) for p in closure['profiles']]
print(json.dumps({'apiVersion':'v1','kind':'List','items':items}))
PY
kubectl apply --server-side --field-manager=phorvex-litellm-metrics \
  -f "$cfx_m1b_candidate/metrics-networkpolicy.json"
kubectl patch deployment litellm -n litellm --type=json \
  --patch-file "$cfx_m1b_candidate/deployment-metrics-json-patch.json"
kubectl rollout status deployment/litellm -n litellm --timeout=5m
kubectl apply --server-side --field-manager=phorvex-litellm-metrics \
  -f "$cfx_m1b_candidate/metrics-service.json"
kubectl apply --server-side --field-manager=phorvex-litellm-metrics \
  -f "$cfx_m1b_candidate/metrics-servicemonitor.json"
```

Acceptance remains pending: both replicas use the reviewed source/image/profile
closure; ordinary admission/auth/redaction/streaming behavior unchanged; isolated
network allowed/denied controls pass; target up for at least 10 minutes; counter,
histogram counts and intended gateway namespace/pod ingest advance; vLLM native
and bridge populations checked separately. No production test traffic now.

Rollback restores the immediately preceding active binding closure via a
reviewed revert PR and the guarded original gateway template. Lead handles the
binding PR; do not revert Hami's release or unrelated later values. An offline
starting point for that PR, with the exact recorded M1b activation commit:

```sh
git revert --no-commit "$cfx_m1b_activation_commit"
```

After owner/revision/UID preflight in the rollback window:

```sh
kubectl patch deployment litellm -n litellm --type=json \
  --patch-file "$cfx_m1b_candidate/deployment-metrics-rollback-json-patch.json"
kubectl rollout status deployment/litellm -n litellm --timeout=5m
# Before each delete, require the recorded M1b UID/spec and no later owner change:
kubectl delete servicemonitor phorvex-litellm-gateway-metrics -n monitoring
kubectl delete service phorvex-litellm-gateway-metrics -n litellm
kubectl delete networkpolicy phorvex-litellm-gateway-metrics -n litellm
```

The guarded patch rejects another owner's changed template. If admission
webhooks/defaulting make it stale, freshly compare and review a new patch;
never remove guards. Restore all prior profile/source bindings; retain old and
new immutable ConfigMaps, Secret references, TSDB/history, PVCs and Hami's
vLLM release. Keep old pods/source uninstrumented after rollback; no data delete.

