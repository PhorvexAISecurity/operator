# Application request metrics coverage

Stage 5 adds authenticated LiteLLM admission metrics support. Active EKS values
remain disabled and retain the legacy Console source/profile. Prospective m5
artifacts and isolated checks establish candidate support, not live collection.
Default decision B keeps native vLLM a hard activation gate; its 2026-10-14
DOWN/empty observations block provisioning/S5b until independently repaired.
No vLLM scrape/query/rule, CNI, retention, account, tenant or NATS changes are made.

## Source and release contract

The approved versions remain distinct: legacy source `4bf046ce690c…`, frozen
auth-free M1b `f550b9890b20…`, and auth source `91af283097af…`. The complete
source/profile/runtime bindings and full hashes are in
[the m5 closure](litellm-m5/metrics-closure.json). Legacy may use its original
reviewed base image or the published runtime; metrics versions require the exact
source-free runtime. Unknown/mixed hashes, base-runtime auth, wrong actual image,
command, env, readonly mounts, Pod/Service/policy lifetime or stale observations
fail native compatibility. Frozen m1b artifacts are preserved byte-for-byte.

S5a support ships the shared compatible engine/Console contract with production
metrics off. Its v4 image contract and actual-image v2 receipt separate historical
publication from the exact newly tested mounted source commit/hash. S5b follows
only after real compatible release identities, idle/journal gates, source/runtime
integrity, real auth witness and native acceptance. The externally owned gateway
rolls out through UID/resourceVersion/full-spec-tested forward and inverse patches.
The wrapper owns only immutable source/profile, exact-name ConfigMap read grants,
Service/ServiceMonitor/NetworkPolicy. Existing serving ownership remains unchanged.

## Populations and labels

| Boundary | Counted population | Identity |
| --- | --- | --- |
| LiteLLM admission gateway | Parsed application requests once at terminal response: admission/auth/validation failures, upstream error/timeout, success, full stream EOF or observed disconnect. Health/status/metrics traffic excluded. | Actual gateway namespace and Pod; fixed `target="litellm"`. No attribution to backend serving Pods. |
| Native vLLM engine | Its native completion/success/latency/token populations, supplied by the existing native target and generic bridge. Gateway denials may never reach it. | Actual serving Pod, namespace `vllm`; separate acceptance. |

Gateway counter and duration histogram share one terminal accounting path using
a monotonic clock through response flush/stream termination. Counter = histogram
count = +Inf per label population. Failures after headers retain delivered status
class and bounded terminal outcome; no telemetry response rewrites. No queue-depth
or active-request gauge is invented. Do not sum gateway/native counters together.

Labels are namespace, Pod, target, method, route, status_class, outcome and
histogram le. Process identity is validated. Other values use fixed enums:

- Methods: GET, POST, HEAD, PUT, PATCH, DELETE, OPTIONS, other.
- Routes: /v1/chat/completions, /v1/completions, /v1/embeddings, /v1/models, other.
- Status classes: 1xx, 2xx, 3xx, 4xx, 5xx, none.
- Outcomes: completed, upstream_error, timeout, disconnect, internal_error.
- Seconds buckets: .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60,
  120, 300, 600 and +Inf.

Prompts, response text, raw URL/query, client/request/operation IDs, credentials
and auth-derived hashes never enter labels or exposition. Unknown methods/routes
collapse to other. At most 8 × 5 × 6 × 5 = 1,200 terminal combinations with 20
series each: conservative bound 24,000 series per Pod. Typical observed categories
are fewer; Pod churn adds historical series. Measure realized cardinality before
forecasting retention. Scrapes and denied metrics auth never create app traffic.

## Authenticated scrape and evidence

Disabled opt-in binds no metrics socket and opens no token file. Enabled startup
validates exactly 64 lowercase hexadecimal bytes before any listener starts.
The independent token is projected gateway-only at
`/etc/phorvex-litellm-metrics/token`, whole readonly directory, explicit 0440,
nonoptional single key, fsGroup 10001. No subPath or backend mount is allowed.
Only exact bodyless GET `/metrics` with one valid bearer header returns 200;
absent/wrong/duplicate/malformed parsed auth gets an empty 401. Other paths,
raw-target variants, methods and bodies remain rejected without upstream access.
Responses close, success uses Prometheus text and no-store, and credentials never
enter argv/logs/error bodies/evidence or protected-status authorization.

The Service is internal ClusterIP, named port 4003, opt-in gateway selector.
ServiceMonitor is in monitoring, selects that Service in litellm, scrapes 30s/5s,
uses `honorLabels=false`, real discovery namespace/Pod plus fixed target, and a
nonoptional monitoring-namespace authorization Secret selector with redirects off.
No literal credentials, arbitrary headers, bearer-token file or fallback are used.

One token is generated inside a bounded Job and stored in two immutable Secrets.
The generator emits only sanitized post-patch UID/resourceVersion/immutable/pair
records. Later reads are PartialObjectMetadata only and must match both UID **and**
resourceVersion exactly; unchanged versions anchor immutable/data without reading
those fields outside the cluster. Last-applied/provenance/pair drift fails. Metadata
alone does not prove equal token bytes: the real cross-namespace witness and actual
Prometheus scrape establish compatibility. Generator/witness cleanup uses recorded
identities; no Secret is removed while a consumer or target remains.

A v2 auth proof binds actual witness/probe UIDs/nodes/specs/image/source/helper CMs,
both credential generations, concrete template/protection and monitoring specs.
Auth/metadata/native readbacks expire after 30 minutes and reject future UTC.
Generator records remain immutable-generation anchors without age expiry. The
metrics-only witness has no upstream configured; full-program isolated fixtures
supply substantive zero-upstream-call controls. Real live proof repeats controls
against both gateway replicas and their ClusterIP.

NetworkPolicy remains defense in depth. Valid bearer protection is accepted with
CNI disabled/standard and does not assert enforcement. Existing broad metrics
ingress is recorded in auth mode; unresolved selectors/ports or serving/status
reachability loss still require review. Historical v1 network mode still requires
enabled/strict CNI and fresh allowed/denied controls. Neither a policy object nor
a Secret reference alone is proof of protection. No network bypass is available.

## Acceptance limits

Require two Ready intended replicas and exact source/profile/runtime/projection
closure, healthy ordinary serving/status behavior, correct monitor membership,
no scrape/auth/reload failures and ten minutes after final convergence. Raw gateway
up ranges need ≥19 samples per target at 30s, every value 1 and no adjacent/window
edge gap above 45s. Native has independent sustained-health and exact finite,
nonnegative engine ReqRate for its current serving Pod. Zero observed rate is
valid; empty vectors fail. Default B requires native acceptance before activation.

Require nonempty counter/bucket/count/sum populations, per-label accounting
agreement and ordinary authorized traffic increments. Exact engine LiteLLM ReqRate
uses namespace litellm; native query uses namespace vllm. Gateway traffic cannot
fill an empty native vector. Preserve the generic bridge and source queries.
Insufficient histogram observations cannot establish p99. No seven-day history,
all-rotate-veto removal or fleet-wide coverage is claimed by candidate support.
Stage 5 completes only when gateway and native acceptance both pass.

Rollback first restores the reviewed preceding legacy template (removing 4003,
metrics env/label/token projection), then disables/restores exact metrics/auth and
three Console bindings through a focused values change. Retain compatible code,
latest shared releases, old/new immutable CMs/read grants and TSDB history.
UID/RV/spec/owner guards delete only the three metrics objects; metadata-only
credential cleanup follows consumer absence and Operator/Prometheus reconciliation.
No rotation mode or opt-in-0 auth-source compatibility state is introduced.

## Remaining coverage and retention

| Source | Remaining work |
| --- | --- |
| LiteLLM gateway | Default-off authenticated support; native dependency and real release/provisioning/live acceptance remain separate gates. |
| vLLM | Native-target owner must restore scrape/completion population; no source or query repair is in Stage 5. |
| ALB target groups | Future outside-Pod source for console, voice-bot-public, ci-reports, grafana, argocd; CloudWatch exporter and separate read-only IAM. Averages do not establish histogram p99. |
| Voice / MCP / CRM | Caller-facing request/session/tool/refund populations need owner instrumentation and bounded labels. |
| Chroma / ci-reports / Mongo | Health/database metrics alone do not establish caller HTTP p99. |
| NATS | Excluded. |

Preserve Stage 4 Alertmanager acceptance and configured 14d/15GB/PVC identities.
Historical 2026-10-13 sizing recorded roughly 0.458 decimal GB/day block growth;
14d was about 5.97 GiB, twice that 11.94 GiB before variable overhead. The 15 GiB
bound is 75% of the existing 20 GiB claim. These are historical estimates, not new
measurements. After metrics ship, remeasure samples/s, cardinality/churn,
block/WAL/head/filesystem use and oldest timestamp. Added series can shorten the
history horizon; increased retention cannot recover deleted samples. Stage 5 does
not change retention/storage, EPSS, Alertmanager or unrelated Argo configuration.

Preparation, proof, activation and rollback details are in
[the release runbook](LITELLM-METRICS-RELEASE.md).
