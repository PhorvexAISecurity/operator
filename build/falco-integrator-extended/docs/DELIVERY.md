# Falco webhook delivery contract (V3-M164)

The webhook acknowledges a Falco alert only after the corresponding `SecurityEvent`
was **persisted by the Kubernetes API in this request** or was **read back as a
proven identical retry**. It never acknowledges an attempted-but-failed Create.
This is retry-safe API delivery; it is not exactly-once actuation and it makes no
claim about whether Falco's `http_output` retries a failed POST.

## Request contract

* `POST /` with a Falco JSON alert (`json_output: true`, `json_include_output_property: true`).
  Any other method: `405` with `Allow: POST`.
* Body limit 1 MiB (`413`). Malformed JSON, trailing data or an unparsable `time`: `400`.
* Required identity, validated **before any API write** (`400` otherwise):
  * `time` (non-zero RFC 3339, nanosecond precision preserved),
  * `rule`,
  * `output_fields["k8s.ns.name"]` (DNS-1123 label) and `output_fields["k8s.pod.name"]` (DNS-1123 subdomain).
* Normalization (priority → threat level, rule → type, severity-proxy anomaly score,
  audit metrics) is unchanged from Phase 7; see `cmd/normalize.go`.

## Event identity

```
canonical  = CanonicalJSON(request body)          # keys sorted, number literals verbatim, no whitespace
digest     = sha256("falco/v1\n" + canonical)     # detector-prefixed, versioned domain
name       = "falco-" + hex(digest)[:40]          # metadata.name, valid DNS-1123 label (46 chars)
fingerprint= "sha256:" + hex(digest)              # annotation amtd.r6security.com/delivery-fingerprint
```

* Identity covers the **complete request body** (every field Falco sends, including
  unsupported `output_fields`, `tags`, `output` text and the exact `time` string). Two
  alerts that differ in any content are different events, even in the same pod and
  second; a byte-for-byte or key-reordered/whitespace-reformatted resend of the same
  alert is the same event.
* Intentionally excluded: HTTP headers, receipt time, remote address, and any
  semantic normalization of values (e.g. `+01:00` vs `Z` spellings of the same instant
  are different content — Falco always emits UTC `Z`).
* The object carries `amtd.r6security.com/delivery-identity: falco/v1`. Bump the
  version if the preimage changes so names from different schemes never coincide.
* `SecurityEvent` is a **Cluster-scoped** CRD: the object has no `metadata.namespace`;
  the logical target stays in `spec.targets[0] = "<namespace>/<pod>"`.

## Delivery and readback

1. `POST /apis/amtd.r6security.com/v1beta1/securityevents` with the request context
   bounded by `SECURITYEVENT_API_TIMEOUT` (Go duration, default `10s`). One attempt;
   no retry loop.
2. `2xx` whose returned object **is this event** (same name, both delivery
   annotations, byte-identical serialized `spec` including `anomalyScore`, `metrics`
   and `evidence`) → **accepted**. A nil error alone is not proof.
3. `2xx` whose returned object is not this event (empty body, another object's
   name, a missing annotation, a pruned or different spec) → at most **one**
   bounded `GET .../securityevents/<name>`:
   * readback identical → **accepted** with `reason: readback_verified`;
   * readback differs → **conflict** (`reason: create_mismatch`) — the object stored
     under this name is not what was delivered (e.g. a schema that prunes the
     optional fields); nothing is adopted or rewritten;
   * readback fails → **failed** (`reason: create_unverified`).
4. `409 AlreadyExists` → the same bounded `GET`. The stored object is accepted as a
   **duplicate** only if its name, both delivery annotations and its serialized
   `spec` are exactly this delivery. Otherwise it is a **conflict**
   (`readback_mismatch`): nothing is adopted, overwritten or patched.
5. Any other rejection, a deadline, a transport error, or a readback that fails
   (forbidden, not found, timeout) → **failed**. Cancelled requests are failed as
   `canceled`; if the Create had actually landed, the next retry resolves it via the
   readback path.

Bounds: at most two API calls per event, so one request takes at most
2 × `SECURITYEVENT_API_TIMEOUT` of downstream time (plus body read). The caller's
disconnect cancels in-flight calls (`canceled`). Falco's `http_output` has no
retry queue; a non-2xx is an honest refusal, not a guarantee of redelivery.

### Schema prerequisite

The strict comparison is intentional: a SecurityEvent CRD that does not declare
`spec.anomalyScore`, `spec.metrics` and `spec.evidence` (the Phoenix chart copy did
not until V3-M164 synchronized `charts/phoenix/templates/crds/securityevents_crd.yaml`
with `config/crd/bases`) makes the API server prune what the detector wrote. Such a
server is never acknowledged as full delivery: the first request is a `409 conflict`
(`create_mismatch`) and retries stay `409` (`readback_mismatch`). Install the
synchronized CRD; do not expect the integrator to drop fields to match a stale
schema. The regression `TestSecurityEventChartCRDMatchesGeneratedSchema` in
`build/phoenix-extended/api/v1beta1` keeps chart, vendored archive and generated
schema identical.

## Response contract

Every reply is `application/json`:

```json
{"status":"accepted|duplicate|conflict|failed|invalid",
 "event":"falco-<40 hex>", "deliveryFingerprint":"sha256:<64 hex>",
 "reason":"<machine token>", "message":"<bounded, credential-free text>"}
```

| HTTP | `status` | Meaning |
|---|---|---|
| 200 | `accepted` | persisted in this request and the returned object is this event (`reason: readback_verified` when the Create response was unusable and a readback confirmed it) |
| 200 | `duplicate` | already stored and verified identical by readback |
| 409 | `conflict` | the object stored under this name is not this payload (`reason: readback_mismatch` after AlreadyExists, `create_mismatch` after a 2xx whose readback differs, e.g. a pruning schema); retrying the same payload will not succeed until the stored object is removed or the schema is fixed |
| 503 | `failed` | `api:<Reason>` (Forbidden, TooManyRequests, InternalError, …), `timeout`, `transport`, `readback_failed`, `create_unverified`, `canceled`, `shutting_down` |
| 400 | `invalid` | `invalid_input`, `unreadable_body` |
| 405 / 413 | `invalid` | `method_not_allowed` / `body_too_large` |

A non-2xx status is an honest refusal to acknowledge; it does not by itself make
Falco retry (`http_output` has no retry/queue guarantee).

## Deployment prerequisites

* RBAC: the integrator now needs `get` on `securityevents` in addition to `create`.
  The shipped `deploy-falco-integrator/deploy.yaml` ClusterRole already grants
  `get, list, create`; the Helm chart in `helm/falco-backend` ships no RBAC (it
  relies on the namespace's default ServiceAccount being bound separately) — grant
  `get` there if it was not already.
* Image: the fix lives in this module (`build/falco-integrator-extended`), which the
  running `phoenixop/falco-integrator:0.0.1` upstream image does not contain. Build
  with the repository `build/` directory as context
  (`docker build -f build/falco-integrator-extended/Dockerfile build/`) because the
  module replaces `github.com/r6security/phoenix` with `../phoenix-extended`, then
  point the deployment image at the pushed digest.
