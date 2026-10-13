# Application request metrics coverage

M1a prepares LiteLLM admission metrics; it does not activate them. Active stack
values, runtime image digests, catalogue profiles and source ConfigMap bindings
remain unchanged. Source inspection and localhost tests are evidence for the
candidate only. No live scrape, deployment or seven-day history is claimed.

## Populations and identity

| Boundary | Population | Identity and scope |
| --- | --- | --- |
| LiteLLM admission gateway | Each parsed external HTTP request once at terminal response: admission denial, auth failure, validation failure, upstream error/timeout, success, full streamed EOF or observed disconnect. Health/status/metrics traffic excluded. | Actual gateway `namespace` and `pod` from the Downward API; fixed `target="litellm"`, the existing admission Service. No serving-pod attribution. |
| vLLM engine | Native engine completion/success/latency/token populations after Hami's release. Admission denials need not reach this boundary. | Hami's actual serving pod and namespace `vllm`. Read-only acceptance remains pending. |

Keep gateway and engine counts separate. Do not sum their counters or join a
gateway pod to an unresolved vLLM Service endpoint. Engine ingest already sums
`http_requests_total` by `pod` for a requested namespace and computes p99 from
`http_request_duration_seconds_bucket` by `(pod, le)`. This candidate supplies
those real gateway labels without an ingest-query change. Its latency includes
failed/denied responses as well as completed work. At low traffic p99 remains
unavailable; a histogram is not proof of sufficient observations.

The existing `phorvex.physics.bridge` maps native vLLM success/latency/tokens to
generic ingest metrics. Its missing-request-telemetry E1 benefit is confined to
namespace **vllm**. It neither supplies LiteLLM admission telemetry nor removes
other cost/safety vetoes. No bridge or vLLM scrape/runtime edits are included.

## Counter and histogram contract

`http_requests_total` and `http_request_duration_seconds_{bucket,count,sum}`
share one terminal accounting path. Durations use a monotonic clock from
handler arrival through response flush, including full streamed EOF or the
observed I/O failure/disconnect. `_count` and `+Inf` match the counter. There is
no invented queue depth or active-request gauge. A failure after delivered
headers retains the delivered status class and a bounded terminal outcome;
no second response is written for telemetry.

Labels are `namespace`, `pod`, `target`, `method`, `route`, `status_class`,
`outcome`, plus histogram `le`. Namespace/pod are validated process identities.
Other categories have fixed sets:

- Methods: GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS, other.
- Routes: /v1/chat/completions, /v1/completions, /v1/embeddings, /v1/models, other.
- Status classes: 1xx, 2xx, 3xx, 4xx, 5xx, none (no delivered final headers).
- Outcomes: completed, upstream_error, timeout, disconnect, internal_error.
- Finite bucket bounds in seconds: .005, .01, .025, .05, .1, .25, .5, 1, 2.5,
  5, 10, 30, 60, 120, 300, 600; plus +Inf.

No request/client/operation ID, raw URL/query, prompt, response text, token,
auth-derived hash, policy state or customer content enters this registry.
Unrecognized caller methods/paths collapse to `other`; query values are never
retained. Identity is fixed for a process. Series are created only on observed
terminal categories: at most 8 × 5 × 6 × 5 = **1,200 combinations**, each with
20 time series including the counter, or **24,000 series per pod** in the
conservative full cross-product. Typical traffic uses a small subset; pod churn
adds historical series. Measure the realized series count before accepting
retention forecasts.

## Scrape and network contract

Default `PHORVEX_LITELLM_METRICS_ENABLED=0` opens no metrics socket. Explicit `1`
requires `POD_NAMESPACE` and `POD_NAME`; the listener uses **4003**, separate
from LiteLLM 4000, admission 4001 and authenticated status 4002. Relevant
baseline source contains no 4003 use. The renderer also rejects a 4003 port
already declared by any container. Unadvertised runtime listeners still need
owner verification at M1b preflight.

The listener accepts only the exact raw `GET /metrics` target, no body, no
query/path/absolute-URL variants, no redirect, and no API/status proxy. Request
line/header bounds and a five-second read timeout constrain scrape requests.
It never reads auth credentials or protected status state. The prepared Service
is ClusterIP, with a named metrics port and an opt-in pod selector. The
ServiceMonitor lives in monitoring, selects only this Service in litellm,
scrapes every 30s, times out at 5s, and uses discovery's real namespace/pod
labels (`honorLabels=false`) plus the fixed target. No master key or token is
used for scraping.

The prepared NetworkPolicy permits TCP 4003 only from the **intersection** of
namespace monitoring and the supplied, freshly verified Prometheus pod labels.
NetworkPolicies are additive: an older broad allow would defeat this boundary.
The renderer requires reviewed ingress policies which already preserve 4001
and protected 4002 access and do not permit 4003. Unsupported selectors or
unresolved ports stop rendering. It preserves those policies, auth and the
existing Service route. M1b must prove the complete policy inventory, actual
Prometheus labels, monitor selection, egress and CNI enforcement; historical
PHORVEXSEC-281 evidence reported enforcement off, so effective isolation is
**unverified and a release gate**. No CNI/cluster remediation is included.

## Runtime/source ownership and activation

The existing gateway runs reviewed, ConfigMap-mounted standard-library Python
on the published source-free Python runtime pinned in
`build/integrations/litellm-gateway-runtime/image-contract.json`. M1a updates
only that contract's candidate gateway source hash and the verification
workflow's matching hash. Image digest, base, recipe and original publication
provenance are unchanged; there is no guessed image pin or new image build.

`build/test-harness/fixtures/litellm-live/render_metrics.py` prepares the
installed gateway upgrade only with `--enable-metrics`. It emits a new immutable
content-named source ConfigMap, guarded Deployment JSON patch, new immutable
source-bound catalogue profiles, a closure record and the three monitoring
objects. All supplied profiles retain their existing image and other fields.
The patch preserves the upstream container, mounts, auth bindings and serving
route. Active output trials prevent source migration: an output-enabled
snapshot requires a quiescent version-2 revision-0 empty output policy. Never
reset a live trial to satisfy that guard. An image outside the reviewed reuse
contract requires separate runtime convergence first.

M1b must inventory **all** enabled source-bound profiles, verify the merged
runtime reuse receipt, then activate the derived source/profile bindings in a
separate reviewed release. Do not run the older installation/switch scripts as
an upgrade or overwrite an old immutable ConfigMap. Both gateway replicas must
converge on the reviewed source/runtime before acceptance. Source-independent
output seed profiles stay under their existing ownership; any source-bound
policy/rule migration beyond a quiescent policy needs separate review.

After Hami's vLLM merge and an idle owner release window, require target up for
at least 10 minutes, terminal counters/histogram counts advancing under
authorized ordinary traffic, real gateway identities, unchanged enforcement,
and isolated allow/deny network controls. Keep every production observation
pending until run. Remove only the new monitor/Service/NetworkPolicy and restore
the immediately previous gateway source/profile/runtime closure through a
reviewed rollback; preserve collected history and Hami's release.

## Remaining coverage

| Source | Status and next step |
| --- | --- |
| LiteLLM gateway | Candidate implemented and localhost tested; runtime-image, network and live ingest acceptance pending M1b. |
| vLLM | Hami owns native release. Verify existing bridge and native completion count/latency under ordinary traffic; no changes here. |
| ALB target groups | Recommended future outside-pod source for console, voice-bot-public, ci-reports, grafana and argocd. CloudWatch RequestCount, TargetResponseTime and HTTPCode_Target_5XX need an exporter and separately scoped read-only IAM. ALB averages do not establish histogram p99. |
| Voice | Request/session/stream lifetime and error populations lack verified caller-facing monitoring. Owner instrumentation and bounded labels remain follow-ups. Historical voice snapshots are not recovered by these metrics. |
| MCP | Tool-call request/latency/error population and scrape path remain unverified. Owner follow-up. |
| CRM | Caller-facing request/refund latency and error population remain unverified. Owner follow-up. |
| Chroma / ci-reports / Mongo | Define caller-facing populations separately. Health/database metrics alone do not establish HTTP request p99. |
| NATS | Excluded; no exporter, scrape, inspection, benchmark or change. |

## Retention sizing recommendation for Hami

Historical plan measurements on 2026-10-13 around 19:07–19:14 UTC: blocks
2,309,776,880 B over approximately 5.047d, 2,721.21 float samples/s, WAL
265,893,660 B, head chunks 46,363,577 B, current head 105,722 series and 24h
maximum 139,694; 20Gi PVC. These are historical compaction snapshots, not a
fresh live measurement or steady-state benchmark.

Recommend **14d / retentionSize 15GB**, with the existing PVC unchanged, for
Hami's release. Prometheus interprets that size as 15 GiB and accounts for WAL
and head while deleting persistent blocks to enforce the bound. Estimated block
growth is 0.458 decimal GB/day: 14d at that rate is approximately 6.41 GB /
5.97 GiB; at twice the rate approximately 11.94 GiB before variable overhead.
Current WAL/head is approximately .29 GiB. Reserve at least another 1 GiB for
head/WAL/compaction variation and leave filesystem headroom. The 15 GiB bound
is 75% of a 20 GiB claim; no new capacity is proposed.

After native and gateway metrics ship, remeasure samples/s, realized series,
churn, block/WAL/head bytes, filesystem headroom, oldest retained timestamp and
size-retention events. Added series can shorten the effective 14d horizon;
retain seven days only after seven days of qualified collection. An increase
cannot recover previously deleted samples. No retention values or Helm release
are changed by M1a.

Exact future preparation, apply and rollback commands are in [LITELLM-METRICS-RELEASE.md](LITELLM-METRICS-RELEASE.md); none has run in stage 1.
