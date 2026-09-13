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
2. `201` → **accepted**.
3. `409 AlreadyExists` → `GET .../securityevents/<name>` (same bound). The stored
   object is accepted as a **duplicate** only if its name, both delivery annotations
   and its serialized `spec` are exactly this delivery. Otherwise it is a **conflict**:
   nothing is adopted, overwritten or patched.
4. Any other rejection, a deadline, a transport error, or a readback that fails
   (forbidden, not found, timeout) → **failed**. Cancelled requests are failed as
   `canceled`; if the Create had actually landed, the next retry resolves it via the
   readback path.

## Response contract

Every reply is `application/json`:

```json
{"status":"accepted|duplicate|conflict|failed|invalid",
 "event":"falco-<40 hex>", "deliveryFingerprint":"sha256:<64 hex>",
 "reason":"<machine token>", "message":"<bounded, credential-free text>"}
```

| HTTP | `status` | Meaning |
|---|---|---|
| 200 | `accepted` | persisted in this request |
| 200 | `duplicate` | already stored and verified identical by readback |
| 409 | `conflict` | name exists with different content (`reason: readback_mismatch`); retrying the same payload will not succeed until the stored object is removed |
| 503 | `failed` | `api:<Reason>` (Forbidden, TooManyRequests, InternalError, …), `timeout`, `transport`, `readback_failed`, `canceled`, `shutting_down` |
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
