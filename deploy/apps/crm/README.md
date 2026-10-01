# Live mini-CRM app + refund deny-guard

The `crm` namespace runs the mini-CRM (`app.py`, FastAPI, backed by the shared
Mongo in `document-store`). It is deliberately **unauthenticated** — `POST /refunds`
trusts any caller and does not check order ownership — so a direct cross-record
refund always succeeds. Per the reviewed fixture contract
(`build/test-harness/fixtures/crm/CONTRACT.md`) that is a *functional capability*,
not an attack/defense win; the designed defense is the agent-level
`voice-refund-pair-deny` (the confused-deputy path).

`app.py` here is the live `crm-code` ConfigMap plus one backward-compatible change:
a **refund deny-guard**. Before issuing a refund the handler re-reads an
operator-owned deny-list; if the order is revoked it fails closed (403). The guard
is read per request so a ConfigMap update reaches every serving Pod. An absent,
empty or malformed guard leaves the original behaviour unchanged (fail-open), so
the voice confused-deputy demo is unaffected until an order is explicitly revoked.

`test_refund_guard.py` drives the real handler and proves: cross-record refund
lands with an empty guard; the same order is denied once revoked; an unrelated
order still refunds; and an absent guard fails open.

## Scale and apply (live; these mutate the shared crm app, so run them yourself)

```sh
# already done: 2 replicas
kubectl -n crm scale deploy crm --replicas=2

# guard ConfigMap (OFF by default)
kubectl apply -f deploy/apps/crm/crm-refund-guard.yaml

# update the app code and mount the guard, then roll
kubectl -n crm create configmap crm-code \
  --from-file=app.py=deploy/apps/crm/app.py --dry-run=client -o yaml | kubectl apply -f -
kubectl -n crm patch deploy crm --type=json -p '[
 {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"crm-guard","configMap":{"name":"crm-refund-guard"}}},
 {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"crm-guard","mountPath":"/etc/phorvex-crm-guard","readOnly":true}}]'
kubectl -n crm rollout status deploy crm
```

Revoke / restore an order's refunds (what the actuator automates):

```sh
kubectl -n crm create configmap crm-refund-guard \
  --from-literal=denied.json='{"denied_order_ids":["OR-5002"]}' --dry-run=client -o yaml | kubectl apply -f -
# restore: set it back to {"denied_order_ids":[]}
```

## The actuator (reviewed next step, not yet wired into the live operator)

A native `crm-refund-revoke` action — same shape as `litellm-client-revoke` and
`voice-refund-pair-deny` — would, on a trusted CRM refund-abuse SecurityEvent, add
the abused `order_id` to `crm-refund-guard` and read it back from every serving CRM
Pod. It must be wired into the brain candidate set, native dispatch, the capability
gate and RBAC (named ConfigMap get/update verbs), then enabled in `crm-defense`.
Enabling a new actuator type is done through the reviewed fix loop because a wrong
registration wedges the operator (see the startup-preflight RBAC note); it is
intentionally **not** hot-applied here.
