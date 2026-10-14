# Monitoring source of record

The `kube-prom-stack` release in `monitoring` (kube-prometheus-stack 88.5.3) is not managed by
Argo CD, and until 2026-09-29 these two pieces existed only on the cluster.

| File | Live object |
| --- | --- |
| `additional-scrape-configs.yaml` | Secret `monitoring/kube-prom-stack-kube-prome-prometheus-scrape-confg`, key `additional-scrape-configs.yaml` (the release's `prometheus.prometheusSpec.additionalScrapeConfigs`) |
| `phorvex-apps-dashboard.json` | ConfigMap `monitoring/phorvex-apps-dashboard`, key `phorvex-apps.json`, label `grafana_dashboard=1` |

## LiteLLM gateway metrics preparation

Stage 5 prepares bearer-authenticated admission counters/histograms on exact
GET-only port 4003. The active EKS chart remains disabled with legacy Console
bindings. The prospective source/profile/ClusterIP Service/ServiceMonitor/NetworkPolicy
closure is in `litellm-m5`; frozen `litellm-m1b` files remain historical compatibility
artifacts. Tokens are generated once inside the cluster, consumed by Secret mounts
and selectors, and verified later only by sanitized generator records plus
PartialObjectMetadata UID/resourceVersion readbacks.

The [release runbook](LITELLM-METRICS-RELEASE.md) requires a real cross-namespace
auth witness, the compatible release, actual-image/source proof and fresh native
readbacks. Valid auth passes protection with CNI disabled, without claiming
network enforcement. The explicit supervisor correction selects A: fresh native
DOWN/empty reports separate Stage 6 acceptance and permits gateway activation
when its own checks pass. Legacy network mode keeps its native hard gate. The
[coverage record](APP-METRICS-COVERAGE.md) defines populations, fixed labels,
acceptance limits and remaining app gaps. Existing Stage 4 alerting, 14d/15GB,
PVCs and unrelated monitoring configuration are preserved.

## Applying

Run from a directory holding both files, with cluster-admin `kubectl`:

```sh
kubectl -n monitoring create configmap phorvex-apps-dashboard \
  --from-file=phorvex-apps.json=phorvex-apps-dashboard.json --dry-run=client -o yaml \
  | kubectl label --local -f - grafana_dashboard=1 -o yaml \
  | kubectl -n monitoring apply -f -
```

Prometheus reloads the scrape config within about two minutes, and the Grafana sidecar picks up
the dashboard on its next poll. The label must be part of the applied manifest: the existing
object's last-applied record contains `grafana_dashboard=1`, so an `apply` without it removes the
label and the Grafana sidecar stops loading the dashboard (this happened once on 2026-09-29). Persist scrape changes through the serialized, focused Helm procedure below;
a Secret-only patch is overwritten by the next release upgrade.

## 2026-09-30 changes

- **"Apps attacked" no longer counts proactive moves.** The candidate-coverage gauge
  (`phorvex_pod_risk_score`) rises whenever the brain covers exposure, attack or not. With no
  event at all, vLLM's value reached 3.8 every 20–40 minutes on 2026-09-29 (31 episodes in 12
  hours), each time with a proactive kv-reset or request-drain. The 15-minute window therefore
  showed vllm as attacked most of the day. Voice and LiteLLM showed the opposite: their event is
  consumed within one 10 s manager tick, so the value was back at 0 before the 30 s scrape. In the
  latest defended Voice-memory and LiteLLM runs Prometheus recorded 0 for the whole window, even
  though the actuation counter moved.
- The manager now exports `phorvex_security_events_first_seen_total{namespace,trust}`, counted
  once per SecurityEvent UID when first ingested (Phorvex's own events excluded). It is pre-created
  at 0 for each policy namespace. "Apps attacked" and "Apps under attack" use
  `increase(...{trust="trusted"}[15m])`. A counter cannot be missed between scrapes, and it counts
  only real events. The coverage panel stays, retitled to say it includes proactive moves. Needs a
  manager image with this counter; before that the two stats read 0.

## 2026-09-29 changes

- **Native vLLM metrics:** the old PodIP:8001 job cannot reach the engine bound to
  loopback. Stage6's authenticated restartable init sidecar exposes only GET
  `/metrics` on 9102; the serving boundary on 8000 retains its existing routes.
  The checked-in sidecar/source/ServiceMonitor describe the candidate.
  Installation and the obsolete scrape's removal require the gates below; these
  files do not by themselves prove an installed listener or healthy target.
- **Dashboard.** "Apps attacked" and "Apps under attack" use the 15-minute peak of the candidate
  coverage, because the attacked app's value drops back to 0 within seconds of the defense. The
  defense panels add the brain's selected decisions and the actuation attempts by outcome. Token
  throughput reads `vllm:generation_tokens_total` and `vllm:prompt_tokens_total`; `nim_tokens_total` is now defined by the existing physics bridge from generation tokens;
  native scraping supplies its input.

M1b source preparation adds the active immutable gateway/profile and private
scrape closure to the stack chart. The external gateway stays manually owned;
[the release runbook](LITELLM-METRICS-RELEASE.md) orders its guarded rollout after
compatible engine/Console release and actual runtime/network proof. Old source
approval and ConfigMaps remain available for rollback. Gateway admission
telemetry retains LiteLLM namespace/pod and fixed target; native vLLM ReqRate
continues through the existing bridge. The observed disabled network enforcement
and DOWN native vLLM scrape are separate owner prerequisites, not claimed fixes.

## A1 — prepared private-DM alerting (stage 2 only)

A1 is an opt-in overlay for **kube-prometheus-stack 88.5.3 / Alertmanager v0.34.0**.
It contains only `alertmanager.*`; deploy it with `--reuse-values` after Hami's
retention/scrape release is complete and idle. The earlier scrape-config apply
instructions above do not apply to A1. Do not add retention, scrape configuration,
selectors, `defaultRules`, or `additionalPrometheusRulesMap` to this overlay.
There is no full-values export or monitoring Argo ownership change.

| File | Purpose / owner |
| --- | --- |
| `alertmanager-config.yaml` | Native receiver/routing config source, embedded in the overlay |
| `kube-prom-stack/values-alerting.yaml` | Helm overlay; Alertmanager CR, Service and Prometheus alerting endpoint |
| `phorvex-runtime-health.rules.yaml` | Separate manual `monitoring/phorvex-runtime-health` PrometheusRule; record UID and merged source at apply |
| `render-values.py` | Offline config embedding, overlay scope guard and promtool spec export |
| `provision-telegram-secret.py` | Explicit stage-2-only stdin Secret creation/rotation; never run in stage 1 |
| `tests/` | Dummy Python contracts, Prometheus series fixtures and isolated CI tool checks |

The approved destination is `@phorvex_cluster_alerts_bot` → Milad's private DM.
Git stores only file references to Secret `monitoring/phorvex-telegram-alerts`,
keys `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`, mounted beneath
`/etc/alertmanager/secrets/phorvex-telegram-alerts/`. The provisioner reads only
`~/.config/phorvex-alerts/telegram-bot.env`, requires an owned regular mode-0600
file, validates literal token/chat keys and a positive signed-64-bit private-chat
ID, and checks the approved username if `TELEGRAM_BOT_USERNAME` is present.
No shell evaluation, literal credential arguments, temporary Secret manifest,
credential logging or client-side Secret apply is used. Both creation and rotation
use field manager `phorvex-alerts-provisioner`, avoiding a first-rotation ownership
conflict. Failed/conflicting writes stop without force-conflicts or automatic deletion.

The root receiver discards unlabelled/default alerts; Watchdog and InfoInhibitor
are discarded first. Only `phorvex_cluster="dev",severity=~"warning|critical"`
routes to Telegram. Grouping uses cluster/alertname/namespace, waits 60s, regroups
at 10m and repeats at 6h. Critical inhibits warning for the same cluster, namespace
and alertname. Engine scrape loss inhibits its Math Lab metric-coverage warning.
Messages use English plain text (`parse_mode: ""`), show at most five objects with
bounded label lengths, exclude annotations/logs, and send resolved notifications.

One internal ClusterIP replica requests 50m CPU / 64Mi memory with a 256Mi memory
limit; no ingress or PVC is added. Alertmanager state is ephemeral: restart loses
silences and notification deduplication state, so a bounded repeat can follow.
HA/persistent storage needs a separate later decision.

The retained 2026-10-13 audit supplies these **historical identities**, which must
be revalidated in stage 2: deployments `phorvex-system/phorvex-phorvex`,
`phorvex-system/phorvex-phorvex-console`, `voice/voice-bot`, `mcp/mcp-server`;
engine job `monitoring/phorvex-operator` with namespace `phorvex-system`; PVC
`monitoring/prometheus-kube-prom-stack-kube-prome-prometheus-db-prometheus-kube-prom-stack-kube-prome-prometheus-0`.
The manual rules cover replica deficits for 5m, all engine targets down/absent for
5m, PVC <20% warning / <10% critical for 10m (positive capacity required), Math Lab
>90% of the configured one-GiB budget for 5m, any snapshot eviction in 1h, and any
write failure in 15m. Only the known engine's missing store gauge, while its scrape
is healthy, gets a scoped coverage warning after 10m. Review eviction severity
explicitly after P0 and durable archival succeed.

The audit has no Console scrape target or reliable archive-lag metric. Console
replicas are covered; Console scrape and archive-lag rules await a verified monitor
and S2 health metrics. File-count/queued-capture gauges cannot prove archive lag.
There is no vLLM rule before Hami verifies final labels, no NATS expression, no
unowned app missing-telemetry rule, no request p99 alert and no zero-limit memory
ratio. Missing series in an uninstrumented app do not imply failure.

Light checks from the repository root (Python with PyYAML):

```sh
python3 -B -m unittest discover -s deploy/monitoring/tests -p 'test_*.py' -v
python3 -B deploy/monitoring/render-values.py --check
python3 -B deploy/monitoring/render-values.py --rules > /tmp/cfx-a1-rules.yaml
# When the native receiver source changes, write to a different file first:
python3 -B deploy/monitoring/render-values.py > /tmp/cfx-a1-values.yaml
# Review, then copy into kube-prom-stack/values-alerting.yaml and remove temp files.
```

`.github/workflows/monitoring-alerting.yml` adds focused checks without changing
existing checks. CI downloads checksum-verified Alertmanager 0.34.0 and Prometheus
3.14.0 (the pinned chart's tool versions), renders chart 88.5.3 with Helm 3.19.0,
runs `amtool check-config`, actual route/template checks and `promtool check/test
rules`. It tests real inhibition on loopback with **all receiver integrations
removed**, so no Telegram message is sent. Run that integration script only in CI
or already approved isolated AWS; never run monitoring runtimes or heavy tests on
the VPS. A passing offline render is not a reconstruction of live Helm values or
proof of DM delivery.

Stage-2 apply procedure (commands below are **pending**, never stage-1 actions):

1. Require merged/reviewed source, green exact-head CI, P0 preservation and Hami's
   completed retention/scrape release. Revalidate names/labels, CR selectors and
   receiver version. Record the deployed Helm revision from release Secret
   names/status labels only, Prometheus CR generation and the **entire nonsecret
   spec**, scrape Secret resourceVersion, PVC UID/PV/Bound state, and other touched
   nonsecret objects. Never export full Helm values or release/scrape Secret data.
   Run gateway `df -h /` before/after; no new gateway artifacts or Helm binary.
2. On the VPS or approved isolated EC2, use checksum-verified Helm 3.19.0 and a
   private short-lived kubeconfig prepared by the existing authorized access path
   in PLAN §4 (token never in logs/argv/Git). Render the overlay alone:

   ```sh
   helm template kube-prom-stack prometheus-community/kube-prometheus-stack --version 88.5.3 \
     -n monitoring --kube-version 1.36.0 -f deploy/monitoring/kube-prom-stack/values-alerting.yaml
   ```

3. Only in the approved stage-2 window, provision without tracing:

   ```sh
   python3 deploy/monitoring/provision-telegram-secret.py create --execute
   # Rotation instead of creation, when authorized:
   python3 deploy/monitoring/provision-telegram-secret.py rotate --execute
   ```

   Verify the credential Secret with only these safe metadata projections:

   ```sh
   ssh -o BatchMode=yes phorvex-gw "kubectl get secret phorvex-telegram-alerts -n monitoring -o jsonpath='{.metadata.name} {.metadata.resourceVersion} {.type}'"
   ssh -o BatchMode=yes phorvex-gw 'kubectl get secret phorvex-telegram-alerts -n monitoring -o go-template='\''{{if index .metadata.annotations "kubectl.kubernetes.io/last-applied-configuration"}}present{{else}}absent{{end}}'\'''
   ```

   Require `absent`. Unexpected last-applied presence is credential exposure: stop,
   resolve through controlled rotation/removal without printing its value, then
   verify absence. Never `describe` or export JSON/YAML/annotations for this Secret.
4. Run Helm **off the gateway**, retaining all current release overrides:

   ```sh
   helm upgrade kube-prom-stack prometheus-community/kube-prometheus-stack --version 88.5.3 \
     -n monitoring --reuse-values -f deploy/monitoring/kube-prom-stack/values-alerting.yaml \
     --wait --timeout 10m
   ```

   Compare every Prometheus spec field except `.spec.alerting` to the recorded
   baseline; retention, retentionSize, storage, scrape reference and selectors
   must match exactly, and scrape Secret resourceVersion/PVC identity must be
   unchanged. Check other touched nonsecret objects. Unexpected changes require
   immediate rollback to the recorded **post-retention** revision.
5. Verify Alertmanager Ready/reload, active Prometheus endpoint, discovered count
   ≥1, and no failed-notification increments **before** applying the manual rule.
   Record its prior absence or merged spec and UID/provenance; a name collision
   requires review before changing an existing object. Then stream the rule:

   ```sh
   ssh -o BatchMode=yes phorvex-gw kubectl apply --server-side \
     --field-manager=phorvex-monitoring-rules -n monitoring -f - \
     < deploy/monitoring/phorvex-runtime-health.rules.yaml
   ```

   Notifications require the later approved notification window. Delivery remains
   unverified until one labelled temporary canary produces an English firing and
   resolved private DM, with recorded cleanup deadline/deletion and a quiet noise
   watch. No canary or external message is part of stage 1.

Rollback uses the same off-gateway access, preserving TSDB/PVCs and the Telegram
Secret. Helm rollback does not remove the manual rule. For a newly created rule:

```sh
ssh -o BatchMode=yes phorvex-gw kubectl delete prometheusrule phorvex-runtime-health -n monitoring
helm rollback kube-prom-stack <recorded-post-retention-revision> -n monitoring --wait --timeout 10m
```

If the rule replaced a recorded existing object, restore its prior merged spec
with the same server-side field manager instead of deleting it. Verify endpoint,
non-alerting Prometheus spec, scrape resourceVersion and PVC identity after rollback.
Revert the corresponding Git overlay/rule changes through review. For excessive
noise, disable the Telegram route first in a reviewed native-config change; retain
the external Secret. Never roll back Hami's retention/scrape release or delete a PVC.

## Stage6 — authenticated native vLLM metrics

The native sidecar preserves the two regular serving containers, guardrail source,
loopback engine bind, serving Service and protected lease/drain records. It runs
as a restartable init container after the drain-ledger init, using the published
Python image pinned by digest. Scrape failure has no serving probes. It forwards
only authenticated, bodyless GET `/metrics` to literal loopback:8001 with a
three-second deadline, two workers and a one-MiB upstream limit. Model and control
routes are unavailable through 9102.

The independent immutable Secret `phorvex-vllm-native-metrics-token-v1`, key
`token`, exists in both vllm and monitoring only after in-cluster provisioning.
ServiceMonitor credentials resolve in monitoring. No token bytes belong in Git,
Helm values, argv or evidence. The fixed provisioner creates exclusive empty
slots, gives its bounded Job exact-name patch authority, and records only generator
provenance and matching PartialObjectMetadata UID/resourceVersion receipts.

The offline renderer and token tools are documented in
[the integration runbook](../../build/integrations/vllm-native-metrics/README.md).
`vllm-native-metrics.yaml` contains the source ConfigMap, ClusterIP Service and
ServiceMonitor; the external Deployment remains manually owned. The metrics
Service selects app=vllm plus the metrics opt-in independently of serving=true.
The monitor preserves actual namespace/pod/node, sets container=vllm and job=vllm,
and disables redirects.

Apply order: merge reviewed source after exact-head self-hosted CI and isolated
EC2 workflow comparison; capture fresh objects, shared Helm state, namespace
annotations and catalogue holds; provision/prove the pair and source; record the
next 15-minute UTC maintenance slot; engage a UID/RV-guarded namespace dry-run
brake and hold catalogue producers; prove the current Pod idle and startup
headroom; apply the reviewed UID/RV/full-spec-guarded Deployment patch. Preserve
replicas=1/maxSurge=0/maxUnavailable=1. Record actual endpoint loss/restoration;
start the prepared inverse if serving is not restored within ten minutes.
Restore the prior brake after serving/source/lease/auth proof, keeping affected
catalogue entries unavailable until reviewed recapture.

After serving and cross-namespace 401/200 proof, apply the Service/ServiceMonitor.
Scope overlap checks by service=phorvex-vllm-native-metrics. Remove only the old
vllm job through a serialized off-gateway chart 88.5.3 Helm upgrade with
`--reuse-values` and an overlay containing only additionalScrapeConfigs. Prove
unrelated jobs match the current release before this write. Secret-only scrape
changes are not persistent Helm ownership.

Acceptance requires native gauge/counter/E2E/TTFT families, a single current-Pod
target, ten minutes of UP (at least 19 samples, all 1, no sample or window-edge gap
above 45 seconds), healthy bridge rules, preserved serving/source/lease/journals,
and every active exact engine query below. Finite nonnegative zero rates are
valid. P99/mean-sojourn/TTFT quantiles require actual completions; absent traffic
leaves statistical acceptance pending. Do not clamp NaNs or manufacture traffic.

Prepare the inverse from the immediate baseline before activation. Rebind it to
fresh candidate UID/RV/spec before applying; any drift requires new review.
Restore the original template under the maintenance brake, verify one Ready
serving endpoint and protected policy/journal bytes, and recapture any affected
Pod-incarnation profile. Restore only Stage6's scrape change from current Helm
values, retaining unrelated jobs, Stage5 additions and Stage4 alerting/storage.
Delete only recorded Stage6 objects after consumers disappear, with UID/RV/owner
checks. Retain or metadata-guard-delete the pair after all references disappear;
clean temporary generator/probe privileges. Preserve TSDB and historical receipts.

S6-D independently tests the same exporter digest and driver on an isolated T4.
Its approved CSV preserves every default field and adds only validated SM/link
fields. Exporter rollback restores only the captured DaemonSet collector
projection/configuration; it never rolls vLLM. Start that inverse if existing
DCGM queries/readiness fail to recover within two minutes or serving degrades.
Missing test capacity is pending, not evidence of unsupported hardware.

### Engine signal coverage

Before results below were queried on 2026-10-14 for Pod
`vllm-6cc84d486f-8jtwz`. Installation and after results are pending; unsupported
statuses require actual exporter/driver diagnostics. T1 is measured outside the
serving Pod; T1* is steerable outside measurement requiring the 281 clipping or
leave-one-out treatment. T2 is reported by the serving Pod and may only lower
cost under PHORVEXSEC-281. Authentication does not change that tier or cost use.

TokensPerSec retains the existing generation-only bridge
`nim_tokens_total ← vllm:generation_tokens_total`; no default/query override and
no prompt-token addition. ReqRate is successes only and P99 is engine-completion
latency. Branch B applies without an explicit selection: both remain T2 interim
with the 281 polarity caveat. Gateway series retain actual litellm labels. The
T1 per-site gateway mapping is an open decision; branch A requires explicit
selection plus verified single-backend attribution and independent review.

| Signal | Exact engine query | Tier | Before UTC/value | After / status |
| --- | --- | --- | --- | --- |
| `reqRate` | `sum by (pod) (rate(http_requests_total{namespace="vllm"}[1m]))` | T2 | 2026-10-14T14:06:20.380912+00:00; empty vector | pending activation/verification |
| `p99Ms` | `1000 * histogram_quantile(0.99, sum by (pod, le) (rate(http_request_duration_seconds_bucket{namespace="vllm"}[5m])))` | T2 | 2026-10-14T14:06:21.717747+00:00; empty vector | pending activation/verification |
| `connCount` | `sum by (pod) (container_network_tcp_usage_total{namespace="vllm"})` | T1* | 2026-10-14T14:06:23.154816+00:00; 40 | pending activation/verification |
| `bytesIn` | `sum by (pod) (rate(container_network_receive_bytes_total{namespace="vllm"}[1m]))` | T1* | 2026-10-14T14:06:24.539546+00:00; 1865.9762596899225 | pending activation/verification |
| `bytesOut` | `sum by (pod) (rate(container_network_transmit_bytes_total{namespace="vllm"}[1m]))` | T1* | 2026-10-14T14:06:26.087826+00:00; 2310.7134205426355 | pending activation/verification |
| `gpuUtil` | `avg by (pod) (DCGM_FI_DEV_GPU_UTIL{namespace="vllm"}) / 100` | T1* | 2026-10-14T14:06:27.418644+00:00; 0 | pending activation/verification |
| `tokensPerSec` | `sum by (pod) (rate(nim_tokens_total{namespace="vllm"}[1m]))` | T2 | 2026-10-14T14:06:28.810004+00:00; empty vector | pending activation/verification |
| `inFlightMean` | `avg_over_time((sum by (pod) (vllm:num_requests_running{namespace="vllm"}) + sum by (pod) (vllm:num_requests_waiting{namespace="vllm"}))[5m:])` | T2 | 2026-10-14T14:06:30.110173+00:00; empty vector | pending activation/verification |
| `completionRate` | `sum by (pod) (rate(vllm:e2e_request_latency_seconds_count{namespace="vllm"}[5m]))` | T2 | 2026-10-14T14:06:31.420587+00:00; empty vector | pending activation/verification |
| `meanSojournSec` | `sum by (pod) (increase(vllm:e2e_request_latency_seconds_sum{namespace="vllm"}[5m])) / sum by (pod) (increase(vllm:e2e_request_latency_seconds_count{namespace="vllm"}[5m]))` | T2 | 2026-10-14T14:06:32.880078+00:00; empty vector | pending activation/verification |
| `queueDepth` | `sum by (pod) (workload_queue_depth{namespace="vllm"}) or sum by (pod) (vllm:num_requests_waiting{namespace="vllm"}) or sum by (pod) (nv_inference_pending_request_count{namespace="vllm"})` | T2 for the native fallback | 2026-10-14T14:06:34.250280+00:00; empty vector | pending activation/verification |
| `vramUsedMiB` | `sum by (namespace, pod) (DCGM_FI_DEV_FB_USED)` | T1* | 2026-10-14T14:06:35.613092+00:00; 11868 | pending activation/verification |
| `vramFreeMiB` | `sum by (namespace, pod) (DCGM_FI_DEV_FB_FREE)` | T1* | 2026-10-14T14:06:36.932166+00:00; 3226 | pending activation/verification |
| `smActive` | `avg by (namespace, pod) (DCGM_FI_PROF_SM_ACTIVE)` | T1* | 2026-10-14T14:06:38.304304+00:00; empty vector | pending activation/verification |
| `pcieBytes` | `sum by (namespace, pod) (rate(DCGM_FI_PROF_PCIE_RX_BYTES[1m]) + rate(DCGM_FI_PROF_PCIE_TX_BYTES[1m]))` | T1* | 2026-10-14T14:06:39.661150+00:00; 164.4 | pending activation/verification |
| `pcieLinkGen` | `max by (namespace, pod) (DCGM_FI_DEV_PCIE_LINK_GEN)` | T1 discovery | 2026-10-14T14:06:41.255749+00:00; empty vector | pending activation/verification |
| `pcieLinkWidth` | `max by (namespace, pod) (DCGM_FI_DEV_PCIE_LINK_WIDTH)` | T1 discovery | 2026-10-14T14:06:42.662492+00:00; empty vector | pending activation/verification |
| `syscallRate` | Deliberately absent from DefaultPromQueries | Unsupported/inactive | No query | No engine consumer; no fabricated zero |
