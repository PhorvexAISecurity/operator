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
* Alert `status` (`firing`/`resolved`) is not filtered — as before, each notification
  content becomes an event. Normalization (`type`, `threatlevel`, anomaly score
  provenance, label metrics) is unchanged from Phase 7; see `cmd/normalize.go`.

## Event identity

```
canonical  = CanonicalJSON(alerts[i])              # the alert object only; keys sorted, numbers verbatim
digest     = sha256("prometheus/v1\n" + canonical)
name       = "prometheus-" + hex(digest)[:40]      # metadata.name, valid DNS-1123 label (51 chars)
fingerprint= "sha256:" + hex(digest)               # annotation amtd.r6security.com/delivery-fingerprint
```

* Identity is the **alert's complete content** (`status`, `labels`, `annotations`,
  `startsAt`, `endsAt`, `generatorURL`, `fingerprint`), not its batch position, the
  batch's `groupKey`/`receiver`/`externalURL`/common labels, or receipt time. A
  whole-batch retry — including reordered entries — therefore maps each alert to the
  same stored event. Two alerts that differ in any content (different rule, one
  nanosecond of `startsAt`, a different logical namespace, `firing` vs `resolved`)
  are different events, even in the same pod and second.
* Repeat notifications (`repeat_interval`) whose alert content is unchanged are
  verified duplicates, not new events; any content change is a new event.
* Intentionally excluded: batch-level fields listed above, HTTP headers, receipt
  time and remote address.
* The object carries `amtd.r6security.com/delivery-identity: prometheus/v1`.
* `SecurityEvent` is a **Cluster-scoped** CRD: no `metadata.namespace` is sent; the
  logical target stays in `spec.targets[0] = "<namespace>/<pod>"`.

## Delivery and readback (per alert, in batch order)

1. `POST /apis/amtd.r6security.com/v1beta1/securityevents`, bounded by
   `SECURITYEVENT_API_TIMEOUT` (Go duration, default `10s`) per call. One attempt per
   alert; no retry loop.
2. `201` → **accepted**.
3. `409 AlreadyExists` → `GET .../securityevents/<name>` (same bound). Accepted as a
   **duplicate** only if name, both delivery annotations and the serialized `spec`
   are exactly this delivery; otherwise **conflict** — nothing is adopted or mutated.
4. Any other rejection, deadline, transport error or failed readback → **failed**.
   Once the request context is cancelled, remaining alerts are reported `failed`
   with `reason: canceled` and are not attempted.

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
| 200 | `accepted` | every alert accepted or verified duplicate |
| 503 | `failed` | at least one alert failed (`api:<Reason>`, `timeout`, `transport`, `readback_failed`, `canceled`); accepted alerts stay stored and a whole-batch retry re-verifies them as duplicates while retrying the failures |
| 409 | `conflict` | no failures, but at least one alert's name exists with different content (`readback_mismatch`) |
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
