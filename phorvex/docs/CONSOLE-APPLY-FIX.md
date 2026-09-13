# Console apply-fix: request identity and approval outcomes

This documents the `/api/apply-fix/*` contract after M-166. It is deliberately narrow: how a
request is identified, what one approval call can return, and what the console does and does
not guarantee. Identity and grants are in `CONSOLE-AUTH.md`; the allowlist and safety gate are
unchanged.

## Request identity

A submission is an **immutable record** keyed by the verified tenant plus the caller-chosen `id`,
stamped with a server-issued **generation**. The generation embeds an unpredictable identity of
the running console instance and a per-instance sequence, so it is unique per submission and
cannot match anything after a restart. Tenant, namespace, requester, reason, delta and the
gate-approved candidate are fixed for that generation; the server copies the delta and the
candidate's mutable data at submit, so nothing the caller does afterwards changes the snapshot
or its `deltaHash`.

`POST /api/apply-fix/submit` — body `{"id", "delta", "reason", "tenant"?}`; the tenant is the
grant-resolved one (`?tenant=` or body, both only as a selection among granted tenants).

| Response | Meaning |
|---|---|
| `200 {"status":"pending-approval","id","tenant","generation","existing":false,"note"}` | New record, awaiting a distinct approver. |
| `200 {..., "existing":true, "status":<state>}` | An identical submission (same tenant/id/namespace/requester/reason/delta) already exists; its generation and current state are returned. The stored request is consulted **before** the allowlist and the current gate — an accepted request is never re-judged, so a gate that later refuses (or is unavailable) cannot rewrite an accepted, possibly applied, outcome. Only a new record is gated. |
| `409` | The tenant already has a record under this `id` with **different** content. Records are never overwritten; a finished record is a tombstone, so an id is never recycled for new content. |
| `422` | Allowlist or safety-gate rejection (unchanged). |
| `503` | The request store is at its finite limit (`DefaultMaxApplyFixRecords`, per console process, open and finished records together). Nothing is evicted; choose a new console or wait for a restart. |
| `403` / `429` / `501` | Tenant scope, quota, write-path not enabled (unchanged). |

The same `id` in two different tenants is two independent records.

## Approval

`POST /api/apply-fix/approve` — body `{"id", "generation", "tenant"?}`. `generation` is
**required** and must be exactly the one the pending listing (or the submit response) reported;
there is no id-only approval. The tenant is resolved from the grant exactly as for a submit: a
principal granted several tenants or the wildcard must name one, and the body/query tenant can
select among granted tenants but never widen them. A principal granted only tenant A can never
reach tenant B's record, whatever id or generation it sends. The approver is the verified subject
and must differ from the requester (two-key).

Under the manager lock, exactly one valid approval moves the record `pending → applying`. With
that claim held — and outside the lock — the server checks that the tenant's base policy still
derives the same candidate, re-runs the safety gate on the exact snapshot, and invokes the
applier **once**. The attempt then ends in one terminal state that is never reopened. The gate
and the applier each receive their own copy of the snapshot (at submit, preview and approval), so
a gate callback cannot alter what is retained or what is applied.

Every approve response carries `status` (what *this call* did), `state` (the record's lifecycle
state afterwards), `id`, `tenant`, `generation`, `approver`, `retry` and, on failure, `error`.
**Only `status: "applied"` means the applier accepted the candidate.** The HTTP code is a
transport convenience; the dashboard reads `status`.

| HTTP | `status` | `state` | Applier called by this call? | Meaning |
|---|---|---|---|---|
| 200 | `applied` | `applied` | yes (once) | The applier returned success for this generation. |
| 200 | `applied`, `retry: true` | `applied` | **no** | Same approver repeated an already-successful approval; the retained outcome is returned, the applier is not re-invoked and no second `apply-fix.applied` audit record is written. |
| 409 | `in-progress` | `applying` | no | Another approval holds the claim and its callback is still running (`approver` says who). |
| 409 | `conflict` | terminal | no | The generation already reached a terminal state under a different approver. |
| 409 | `stale-generation` | unchanged | no | The generation does not match this tenant/id — an old listing, a foreign tenant's generation, or a previous console instance. |
| 409 | `stale` | `stale` | no | The tenant's base policy changed since submit so the delta would now derive a different candidate. Applying the old snapshot would write fields nobody approved; resubmit against the current policy. |
| 422 | `refused` | `pending` | no | Two-key violation: approver equals requester. The request stays open for a distinct approver. |
| 422 | `rejected` | `rejected` | no | The safety gate refused the immutable candidate at approval. Terminal. |
| 501 | `applier-unavailable` | `pending` | no | No applier is wired in this deployment (the shipped console is record-only). Nothing was applied, no `apply-fix.applied` record is written, and the request stays pending — regardless of the `applierMode` label. |
| 500 | `failed` | `failed` | yes (once) | The applier returned an error or panicked. **Its effect is unknown** — the write may have landed. The generation is terminal and is never retried; a retry by the same approver returns this same outcome without touching the applier. Reconcile the cluster, then submit a new request if still wanted. |
| 404 | `not-found` | — | no | No record under this tenant/id. |
| 400 | — | — | no | Missing `id` or `generation`. |

Audit events: `apply-fix.submitted` (with `generation`), `apply-fix.applying` (claim taken),
`apply-fix.applied`, `apply-fix.apply.error`, `apply-fix.apply.unavailable`,
`apply-fix.rejected.{allowlist,gate,twokey,stale,conflict,capacity}`. A successful generation
produces exactly one `apply-fix.applied`.

`GET /api/apply-fix/pending` lists the **open** records (`pending` or `applying`) in submission
order, each with `generation`, `state` and, while applying, `approver`. The top level carries
`applierMode` (the deployment's label) and `applierWired` (whether an applier actually exists —
the value an approval acts on).

## What this does and does not guarantee

- **At most one applier attempt per generation, within one console process.** The request store
  is process memory, not a durable or replicated ledger. After a restart every earlier generation
  is refused; a resubmission gets a new generation and needs a fresh approval. Two console
  replicas do not coordinate; a multi-replica persistent approval service is a separate design.
- **A successful callback is the applier's acceptance by its own contract**, not proof of what the
  cluster holds. The console does not claim an atomic or exactly-once physical cluster write; the
  CRD applier's own verify/rollback behaviour is documented with it.
- The stale-base check compares the whole data content of the recomputed candidate with the
  approved snapshot; it does not make the base policy and the write a single transaction.
- The shipped console wires **no** applier: every approval answers `applier-unavailable` until a
  deployment injects one (`REAL-ENV-VALIDATION.md` §2).
