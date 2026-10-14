# Authenticated native vLLM metrics

Stage 6 uses an independent Python stdlib process in a Kubernetes **native init
sidecar**. `metrics.py` listens on `0.0.0.0:9102` and issues only the fixed
`GET http://127.0.0.1:8001/metrics` request. It does not import the guardrail,
lease, drain, or model runtime. The existing two regular serving containers and
five-file boundary remain under their original ownership.

## Listener contract

| Input or failure | Result |
| --- | --- |
| Exact `GET /metrics` with one `Authorization: Bearer <token>` | Native response bytes, after bounded upstream validation |
| Missing, wrong, duplicate, or malformed credentials | Empty 401; no upstream request |
| Other path, query, encoded path, or absolute URL | Empty 404; no upstream request |
| Other method | Empty 405; no upstream request |
| Request body, transfer encoding, ambiguous length, upgrade, malformed HTTP, or exceeded byte bounds | Empty 502; no upstream request |
| Upstream refusal, non-200 (including redirects), malformed/truncated response, unsupported encoding, or oversized body | Empty 502; no upstream content returned |
| Deadline exceeded or both workers occupied | Empty 503 |
| Invalid/unreadable/missing token or failed bind | One fixed `metrics_listener_disabled` event, listener closed, process alive |

The credential file is `/etc/phorvex-vllm-metrics/token`. It must contain exactly
64 lowercase hexadecimal ASCII bytes (256 random bits), without a newline or
whitespace. Loading reads at most 65 bytes and performs no trimming. Credential
comparison uses `hmac.compare_digest`. The HTTP credential grammar is exactly
`Bearer ` followed by those 64 bytes; one conventional space after the header
colon is permitted. Credential failure on the metrics route is 401; path and
method rejection precede credential checking for otherwise well-formed requests.

A fixed pool contains **two** HTTP workers. Admission counts queued and active
connections together, caps them at two, and has a four-connection OS accept
backlog. Excess accepted connections get a fixed 503 from the accept loop without
creating a worker. Each admitted connection has one absolute **three-second**
deadline covering request parsing, upstream connection/headers/body, and success
transmission. A fixed error write has a separate 50ms ceiling so expired clients
can receive a 503 without retaining a worker indefinitely. These are execution
bounds under normal scheduling, not scheduling guarantees under resource starvation.

Request lines are limited to **2KiB including CRLF**; aggregate headers are
limited to **8KiB including the final blank CRLF**, excluding the request line.
HTTP/1.0 and HTTP/1.1 are accepted; folded headers are rejected. A single exact
`Content-Length: 0` is allowed. The upstream status line and aggregate headers
have the same byte bounds. Uncompressed Content-Length, chunked, and EOF-framed
responses are supported, with a **1MiB decoded body ceiling**. The complete body
is validated and buffered before any success is sent, so oversize/truncation
cannot leak a partial upstream response. Chunk trailers are bounded and discarded.

Every reply closes the connection and sets `Cache-Control: no-store`. Successful
responses declare Prometheus plain text. No upstream headers, client headers,
Authorization, cookies, forwarded identity, proxy authorization, or engine/admin
credential are copied. Literal loopback TCP bypasses all HTTP proxy environment
variables. Redirects are rejected before reading their bodies. There is no model,
health, admin, status, or control route and no request URL/header/body logging.

The token is loaded before bind and is held for the process lifetime. Disabled
startup does not retry or exit deliberately; repair requires the reviewed
sidecar/source rollout or inverse. Engine absence at startup or a later engine
outage affects only individual scrapes. **Do not attach startup, readiness, or
liveness probes to this sidecar or run the auth proof as a serving probe.** Image
pull, nonoptional mount, native-sidecar lifecycle, and OOM failures can still
impact Pod startup; Python process independence does not prove those Kubernetes
behaviors.

## Deployment and scrape integration

The pinned runtime is:

```text
753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:cb16b9b573dea616b184263915f7cb259f39e012650d8ad398456e0e6c91a108
```

Run `python3 -B /opt/phorvex/metrics.py`. Append `phorvex-vllm-metrics` after the
existing drain-ledger init with `restartPolicy: Always`; port name is
`engine-metrics`, TCP 9102. UID/GID and Pod fsGroup are 10001; root, source, and
token mounts are read-only. Drop capabilities, disable privilege escalation,
use RuntimeDefault seccomp, and request 10m CPU/16Mi with limits 100m CPU/64Mi.
Mount only the separate immutable metrics source and the whole nonoptional token
directory (token mode 0440). Do not use token subPath or mount a service-account,
lease, engine/admin, TLS, or drain-ledger credential. Verify projected-file
readability with the actual UID/fsGroup on isolated EC2/EKS.

`render.py` and its companion tests are maintained by the renderer owner. It
consumes fresh SHA-pinned captures and token **metadata**, emits guarded forward
and inverse Deployment patches, and renders a source ConfigMap named
`phorvex-vllm-native-metrics-<first12-of-source-sha>`, a ClusterIP Service, and a
ServiceMonitor. Any change to `metrics.py` requires regeneration of its source
ConfigMap, full closure hash, and reviewed patches. Do not apply old generated
source after a listener revision.

The Service selects `app=vllm` and the metrics opt-in label independently of
`serving=true`. The ServiceMonitor in `monitoring` references the independent
immutable `phorvex-vllm-native-metrics-token-v1` Secret/key `token` in that namespace;
the listener references its matching pair in `vllm`. Scrape every 30s with a 5s
scrape timeout, disabled redirects, and `honorLabels: false`. Keep native sample
names, actual namespace/Pod/node metadata, and `container=vllm`. Derive node from
`__meta_kubernetes_pod_node_name`. Token generation/provisioning is owned by the
companion helpers; credentials never enter Git, Helm values, argv, or receipts.

The revised plan starts native work immediately without waiting for Stage 5.
Serialize only colliding release/object writes. Provision the token pair and
immutable source before the explicitly recorded singleton maintenance window;
prepare the current-template guarded inverse first. Prove restored serving,
source, lease continuity, and auth before activating the scrape; remove the old
loopback job only after the new target is healthy. A failed acceptance does not
justify weakening the credential boundary. Apply only the reviewed fresh inverse
on serving failure or unresolved metrics failure within the planned window.

See [the monitoring runbook](../../../deploy/monitoring/README.md) for the full
per-signal matrix, maintenance, observation, and rollback gates. This listener
preserves the existing generation-only `nim_tokens_total` bridge; it does not add
prompt tokens to throughput. Native request/latency series remain T2 and the
request-success counter excludes failures/aborts. Revised-plan default branch B
keeps that interim with the PHORVEXSEC-281 lower-cost-only caveat. A gateway T1
mapping needs explicit selection and separate reviewed attribution; do not relabel
Stage 5 traffic as vLLM. Independent DCGM capability work does not block native
scraping and needs its own isolated diagnostic/rollback evidence.

## Offline renderer and rollback CLI

Forward rendering requires the complete original capture directory and token
metadata, each with age **0..1800 seconds**. `captures.json` has exactly `schema`,
`capturedAt`, and `sha256`; its schema is
`phorvex-vllm-native-metrics-captures-v1`. The SHA map contains exactly
`deployment.json`, `pod.json`, `replicaset.json`, `service.json`,
`endpointslices.json`, `source.json`, `policy.json`, `journal.json`,
`drain-journals.json`, `inventory.json`, and `token-metadata.json`. These are full
original objects/lists and metadata-only token evidence; the renderer makes no
API calls. Run from this integration directory:

```sh
python3 -B render.py \
  --inputs /path/frozen-originals \
  --output /path/forward-review
sha256sum /path/forward-review/metrics-closure.json
```

Retain the original directory, all forward artifacts, and the recorded **exact
closure file SHA256**, including its newline. The forward closure binds the raw
manifest and every input file SHA, original capture UTC, canonical input-object
hashes (`inputsCanonicalSHA256`), original/candidate spec and template hashes,
metrics source and generated source-manifest hashes, token metadata/pair, helper
provenance, and generated artifact hashes. Before forward activation, regenerate
and review these artifacts with the current renderer; older completion/pins and
closures lacking `inputsCanonicalSHA256` are superseded. `metrics.py` is unchanged
by this rollback fix, so its existing content-named source ConfigMap is unchanged.

The initial inverse tests the original RV and is review-only. To rebind it, capture
a **full current candidate Deployment** separately and record its capture UTC
when the file is collected, plus its exact file SHA256. Use that capture time,
never the original capture UTC, Deployment creation time, or render time. Supply
**all five** rollback flags together:

```sh
python3 -B render.py \
  --inputs /path/frozen-originals \
  --output /path/rollback-review \
  --rollback-deployment /path/candidate-deployment.json \
  --rollback-sha256 '<EXACT_CANDIDATE_FILE_SHA256>' \
  --rollback-captured-at '<CANDIDATE_CAPTURE_UTC>' \
  --rollback-closure /path/forward-review/metrics-closure.json \
  --rollback-closure-sha256 '<RECORDED_FORWARD_CLOSURE_FILE_SHA256>'
```

| Flag | Exact requirement |
| --- | --- |
| `--rollback-deployment` | Full `vllm/vllm` Deployment JSON; nonempty regular file, no symlink, at most 32MiB; original stable UID and exactly the full forward candidate `/spec`. |
| `--rollback-sha256` | Exactly 64 lowercase hex characters; SHA256 of the candidate file's exact bytes. |
| `--rollback-captured-at` | Separately recorded ISO 8601 UTC with `Z` or zero UTC offset, at most 64 characters; age 0..1800 seconds, inclusive; future or timezone-free values refused. |
| `--rollback-closure` | Original forward `metrics-closure.json`; nonempty regular file, no symlink, at most 1MiB. A previously rebound rollback closure is refused. |
| `--rollback-closure-sha256` | Exactly 64 lowercase hex characters; must match the forward closure file and the SHA recorded before activation. |

Rollback preserves original capture/token timestamps and gives those frozen
records **no age limit**. Their exact file hashes and manifest must still match
the explicit forward closure; rewriting UTC, rehashing a modified capture, or
substituting token metadata is refused. Frozen token records pass the existing
low-level whitelist/identity checks, including namespace, name, UID/RV, pair,
provenance, readiness and immutable generator records. No helper freshness
behavior changes and no refreshed token UTC is synthesized. The entire
regenerated forward closure must match before the inverse is rebound.

The rebound inverse still tests **UID, current RV, and the entire candidate
`/spec`**, then restores the exact original template. Status-only RV churn after
capture requires another candidate capture and render; any spec drift requires
reviewed reconciliation. The output closure records `rollback.captureSHA256`,
`capturedAt`, `resourceVersion`, and `forwardClosureSHA256`, with
`requiresCurrentDeploymentCapture=false`. Review/apply only
`deployment-metrics-rollback-json-patch.json` for rollback; the re-emitted forward
and monitoring artifacts do not authorize another rollout or scrape activation.

All input reads retain their byte bounds (manifest 16KiB, each original file
32MiB, original files total 64MiB). Duplicate JSON fields, nonfinite values,
credentials in captures, missing flags, stale candidate UTC, hash/identity/spec
drift, and changed source/helper closure refuse before output creation. Output
must be a new directory; an existing one is never refreshed. Rendering exits 0
with a nonsecret review-only summary on success, or 1 with a fixed refusal on
validation failure. Flag abbreviations are disabled.

Offline renderer controls use synthetic captures and no listener, socket, API,
image, or serving process:

```sh
python3 -B -m unittest -v test_render
```

The lead must rerun the actual-image suites against these exact changed files on
isolated EC2; the previous worker completion and actual-image pins do not cover
this renderer revision. All existing lifecycle, CI, review and activation gates
remain pending until separately recorded.

## One-shot in-cluster auth proof

`verify_metrics_auth.py` is a temporary **Job in monitoring**, separate from the
serving Pod. It refuses any projected namespace other than `monitoring` before
making a request and targets only
`phorvex-vllm-native-metrics.vllm.svc.cluster.local:9102`. It reads the monitoring
Secret's token from the same fixed file path; there are no target, credential, or
URL command-line/environment options, API calls, or Kubernetes RBAC requirements.

The 18 sequential cases cover missing/wrong/duplicate/malformed credentials,
valid auth, authenticated model/control/health/query/trailing-slash paths, five
unsupported methods, request body, and transfer encoding. Each exchange has an
absolute 3s bound including DNS resolution (Linux SIGALRM on the main thread),
8KiB aggregate response headers, and a 1MiB response bound. The valid response
must contain actual samples for running/waiting, success, prompt/generation,
E2E bucket/count/sum, and TTFT bucket/count/sum; HELP/TYPE comments do not satisfy
this check. Missing families leave proof unsuccessful. It neither generates
inference traffic nor proves finite PromQL values or sustained target health.

It prints one JSON receipt (`phorvex.vllm-native-metrics-auth.v1`) with fixed case
names, status/expected status, byte counts, fixed family-presence booleans, and a
SHA256 of the successful metrics body. It never prints token bytes, a token hash,
request URLs/headers, metrics contents/labels, exception text, or engine error
bodies. Precondition/network/protocol failures emit fixed nonsecret events and
exit 1; full success exits 0. Worst-case exchange time is 18 × 3s; a 90s Job
deadline also bounds the proof process. Capture Job/Pod identity, runtime/source
hashes, execution UTC, and cleanup receipts separately without Secret data.

The lead must create a reviewed immutable ConfigMap containing only the final
`verify_metrics_auth.py` bytes, use its content-derived name below, and execute
only during authorized isolated validation or cluster acceptance. Example Job
(the source ConfigMap name is a placeholder to replace with its reviewed hash):

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: phorvex-vllm-native-metrics-auth-proof
  namespace: monitoring
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 90
  template:
    spec:
      automountServiceAccountToken: false
      restartPolicy: Never
      securityContext:
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: auth-proof
          image: 753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:cb16b9b573dea616b184263915f7cb259f39e012650d8ad398456e0e6c91a108
          command: [python3, -B, /opt/phorvex/verify_metrics_auth.py]
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
          resources:
            requests: {cpu: 10m, memory: 16Mi}
            limits: {cpu: 100m, memory: 64Mi}
          volumeMounts:
            - {name: source, mountPath: /opt/phorvex, readOnly: true}
            - {name: token, mountPath: /etc/phorvex-vllm-metrics, readOnly: true}
            - {name: namespace, mountPath: /etc/phorvex-vllm-metrics-probe, readOnly: true}
      volumes:
        - name: source
          configMap:
            name: phorvex-vllm-native-metrics-probe-REVIEWED_SOURCE_SHA12
            optional: false
            defaultMode: 0444
            items: [{key: verify_metrics_auth.py, path: verify_metrics_auth.py}]
        - name: token
          secret:
            secretName: phorvex-vllm-native-metrics-token-v1
            optional: false
            defaultMode: 0440
            items: [{key: token, path: token}]
        - name: namespace
          downwardAPI:
            defaultMode: 0444
            items:
              - path: namespace
                fieldRef: {fieldPath: metadata.namespace}
```

The Service proof does not independently check public port 8000 `/metrics=404`
or external PodIP:8001 refusal. The lead must retain separate bounded reads of
those boundaries, serving/lease continuity, source/image hashes, current-Pod
labels, all coverage-matrix queries, and the scoped ten-minute sustained-UP
series. Remove the temporary Job/source after recording its bounded receipt,
using captured identity/ownership guards. No serving-coupled probes are added.

## Isolated validation only

No runtime test, socket fixture, process, image pull, or probe is authorized on
the shared VPS or gateway for this worker. Listener runtime tests default to
skipped unless `PHORVEX_STAGE6_ISOLATED_TESTS=1` is explicitly set. The offline
renderer controls above do not execute the listener. On isolated EC2, from this
directory, run:

```sh
PHORVEX_STAGE6_ISOLATED_TESTS=1 python3 -B -m unittest -v test_metrics
```

The suite uses synthetic tokens, ephemeral loopback ports, independent subprocess
serving/metrics fixtures, an upstream trap, and real HTTP wire inputs. It covers
auth grammar/constant-time comparison, privacy, routes/methods/body/header limits,
redirects, refusal/truncation/encoding, exact/oversized body framing, two-worker
admission/recovery, trickled client/upstream deadlines, DNS bounds, closed-startup
process survival, engine start/outage/recovery, and continued serving after
metrics removal. Test-only monkeypatches choose ephemeral ports and credential
fixtures; production has no such options. These checks need execution, not just
syntax inspection.

Run the same suite in the actual pinned image on isolated EC2, using a read-only
source bind mount, UID/GID 10001, a writable temporary `/tmp`, `python3 -B`, and
loopback-only/no external network. Separately test the exact production command,
fixed ports, 0440 projected-token readability, 64Mi memory budget, and native
restartable-init-sidecar lifecycle on isolated EKS. Preserve a new receipt for
this exact mounted program/image; old gateway image evidence is insufficient.
Static compile/AST inspection may be performed locally without importing or
executing these programs. Runtime and actual-image outcomes remain pending until
the lead records those isolated results.
