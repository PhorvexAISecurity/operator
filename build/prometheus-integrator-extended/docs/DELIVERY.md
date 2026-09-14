# Prometheus (Alertmanager) webhook delivery contract (V3-M164)

The webhook acknowledges an Alertmanager notification only when **every** alert in
the batch was **persisted by the Kubernetes API in this request** or **read back as a
proven identical retry**. It never acknowledges an attempted-but-failed Create and
never reports a partially delivered batch as delivered. This is retry-safe API
delivery; it is not exactly-once actuation and it makes no claim that a non-2xx
status guarantees an Alertmanager retry.

## Request contract

* `POST /` with the Alertmanager webhook payload (`version: "4"`). Any other method:
  `405` with `Allow: POST`.
* Body limit 1 MiB (`413`). Malformed JSON, non-object alerts or an unparsable
  `startsAt`: `400`.
* The **complete batch is validated before the first API write**; any problem rejects
  the whole request with `400` and no event is created:
  * `truncatedAlerts != 0` → `reason: truncated_batch` (configure `max_alerts: 0`; an
    incomplete batch cannot be acknowledged as delivered),
  * empty `alerts` → `reason: empty_batch`,
  * per alert (`reason: invalid_input`, listing `alerts[i]: …`): `startsAt` (non-zero,
    nanosecond precision preserved), `fingerprint`, `labels.alertname`,
    `labels.namespace` (DNS-1123 label), `labels.pod` (DNS-1123 subdomain).
* Alert `status` (`firing`/`resolved`) is not filtered and adds no resolution
  handling: a notification whose content (minus the lifecycle members below) is not
  already stored is delivered through the unchanged normalizer, whatever its status —
  including a first notification that is already `resolved`. Normalization (`type`,
  `threatlevel`, anomaly score provenance, label metrics) is unchanged from Phase 7;
  see `cmd/normalize.go`.

## Event identity

```
canonical  = CanonicalJSONWithout(alerts[i], "status", "endsAt")   # the alert object minus two top-level lifecycle members; keys sorted, numbers verbatim
digest     = sha256("prometheus/v1\n" + canonical)
name       = "prometheus-" + hex(digest)[:40]      # metadata.name, valid DNS-1123 label (51 chars)
fingerprint= "sha256:" + hex(digest)               # annotation amtd.r6security.com/delivery-fingerprint
```

* Identity is the **alert's content** — `labels`, `annotations`, `startsAt` (full
  nanosecond precision), `generatorURL`, `fingerprint` and any other member
  Alertmanager sends — **except the two top-level lifecycle members `status` and
  `endsAt`**, which Alertmanager rewrites over an alert's life (repeat notifications
  advance `endsAt`; resolution flips `status`) without the alert being a new episode.
  Nested members with those names (e.g. a `status` label) remain identity-bearing.
  Batch position, the batch's `groupKey`/`receiver`/`externalURL`/common labels and
  receipt time are never part of the identity, so a whole-batch retry — including
  reordered entries — maps each alert to the same stored event.
* Consequently: a repeat notification with an advanced `endsAt`, and the `resolved`
  notification of a stored firing alert, are **verified duplicates** (one stored
  event, acknowledged `duplicate`). Two alerts that differ in anything else
  (different rule, one nanosecond of `startsAt`, a different logical namespace, a
  label or annotation) are different events, even in the same pod and second.
* Baseline behaviour, for the record: before V3-M164 the name was
  `prometheus-<pod>-<startsAt unix seconds>`, so repeats and resolutions collided with
  the firing event's name and were swallowed as `AlreadyExists` (acknowledged 200),
  while genuinely distinct alerts in the same pod and second collided too. The new
  identity keeps the first effect deliberately and removes the second.
* Intentionally excluded from identity: top-level `status` and `endsAt`, the
  batch-level fields above, HTTP headers, receipt time and remote address. The
  identity scheme is `prometheus/v1`; it was defined with these exclusions before
  any deployment used it.
* The object carries `amtd.r6security.com/delivery-identity: prometheus/v1`.
* `SecurityEvent` is a **Cluster-scoped** CRD: no `metadata.namespace` is sent; the
  logical target stays in `spec.targets[0] = "<namespace>/<pod>"`.

## Delivery and readback (per alert, in batch order)

1. `POST /apis/amtd.r6security.com/v1beta1/securityevents`, bounded by
   `SECURITYEVENT_API_TIMEOUT` (Go duration, default `10s`) per call. One attempt per
   alert; no retry loop.
2. `2xx` whose returned object **is this event** (name, both delivery annotations,
   byte-identical serialized `spec` including `anomalyScore`/`metrics`/`evidence`)
   → **accepted**. A nil error alone is not proof.
3. `2xx` whose returned object is not this event (empty body, foreign name, missing
   annotation, pruned or different spec) → at most **one** bounded exact-name `GET`:
   identical readback → **accepted** (`reason: readback_verified`); differing
   readback → **conflict** (`create_mismatch`, e.g. a schema that prunes the optional
   fields — never adopted or rewritten); failed readback → **failed**
   (`create_unverified`).
4. `409 AlreadyExists` → the same bounded `GET`. Accepted as a **duplicate** only if
   name, both delivery annotations and the serialized `spec` are exactly this
   delivery; otherwise **conflict** (`readback_mismatch`) — nothing is adopted or mutated.
5. Any other rejection, deadline, transport error or failed readback → **failed**.
   Once the request context is cancelled, remaining alerts are reported `failed`
   with `reason: canceled` and are not attempted.

Bounds: alerts are delivered serially with at most two API calls each, so a batch
of N alerts takes at most **N × 2 × `SECURITYEVENT_API_TIMEOUT`** of downstream
time (default 20 s per alert) plus body read; there is no separate batch budget.
Size Alertmanager's `webhook_configs[].timeout`/`max_alerts` and `group_interval`
accordingly. The caller's disconnect cancels in-flight calls and skips the rest
(`canceled`). Alertmanager retries 5xx on its own schedule and gives up after its
notification retry limit; a `503` here is an honest refusal, not a redelivery
guarantee.

### Schema prerequisite

The strict spec comparison is intentional. A SecurityEvent CRD lacking
`spec.anomalyScore`/`metrics`/`evidence` (the Phoenix chart copy did not declare
them until V3-M164 synchronized `charts/phoenix/templates/crds/securityevents_crd.yaml`
with `config/crd/bases`) makes the API server prune what the integrator wrote; such a
server is never acknowledged as full delivery (first request `409 conflict`
`create_mismatch`, retries `409` `readback_mismatch`). Install the synchronized
CRD; the regression `TestSecurityEventChartCRDMatchesGeneratedSchema` in
`build/phoenix-extended/api/v1beta1` keeps chart, vendored archive and generated
schema identical.

## Response contract

Every reply is `application/json`:

```json
{"status":"accepted|failed|conflict|invalid",
 "counts":{"total":N,"accepted":a,"duplicate":d,"conflict":c,"failed":f},
 "items":[{"index":0,"fingerprint":"<alertmanager fingerprint>",
           "outcome":"accepted|duplicate|conflict|failed",
           "event":"prometheus-<40 hex>","deliveryFingerprint":"sha256:<64 hex>",
           "reason":"…","message":"…"}],
 "reason":"…","message":"…"}
```

| HTTP | `status` | Meaning |
|---|---|---|
| 200 | `accepted` | every alert accepted (per item `reason: readback_verified` when the Create response had to be confirmed by readback) or verified duplicate |
| 503 | `failed` | at least one alert failed (`api:<Reason>`, `timeout`, `transport`, `readback_failed`, `create_unverified`, `canceled`); accepted alerts stay stored and a whole-batch retry re-verifies them as duplicates while retrying the failures |
| 409 | `conflict` | no failures, but at least one alert's stored object is not this payload (`readback_mismatch` after AlreadyExists, `create_mismatch` after a 2xx whose readback differs, e.g. a pruning schema) |
| 400 | `invalid` | `invalid_input`, `truncated_batch`, `empty_batch`, `unreadable_body` — nothing written |
| 405 / 413 | `invalid` | `method_not_allowed` / `body_too_large` |
| 503 | `failed` | `shutting_down` — not attempted |

Alertmanager retries webhook notifications on 5xx and drops them on 4xx; this
integrator does not control that policy and a 503 is only a refusal to acknowledge.

## Deployment prerequisites

* RBAC: the integrator now needs `get` on `securityevents` in addition to `create`.
  This repository ships no deployment manifest for the Prometheus integrator; grant
  `get, create` on `securityevents.amtd.r6security.com` to its ServiceAccount.
* Image: the fix lives in this module (`build/prometheus-integrator-extended`). Build
  with the repository `build/` directory as context
  (`docker build -f build/prometheus-integrator-extended/Dockerfile build/`) because
  the module replaces `github.com/r6security/phoenix` with `../phoenix-extended`,
  then point the deployment image at the pushed digest.
