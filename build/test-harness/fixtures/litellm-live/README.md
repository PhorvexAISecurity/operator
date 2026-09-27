# LiteLLM Live client policy trial

This package integrates a scoped admission gateway into the **existing**
`litellm/litellm` Service path. It requires an owner-reviewed rollout. Merely
rendering these files does not deploy it or establish a defense result.

The existing two LiteLLM Pods keep their real model-serving process on local
port 4000. Each Pod gains a gateway on 4001 and an operator-authenticated
status listener on 4002. The existing Service stays at port 4000 and its
`targetPort` changes to 4001, so real authorized clients still traverse the
installed workload. Only run-owned synthetic tokens derived from a private
trial seed are recognized by the gateway; they are exchanged for the upstream
master key inside the Pod. Each Fire derives a fresh attacker/control pair.
The append-only policy retains earlier revocations, so a second Fire can use
a new credential while the first remains denied. Other callers retain the
upstream auth behavior for this gateway's supported request paths. Existing
large or streaming responses are relayed in constant memory; non-owned POST
requests have an explicit 64 MiB bound.

`render.py` has two stages:

1. Provide the private trial seed's SHA-256, the exact reviewed digest-pinned
   Python 3.11 gateway image, and the installed `gpt-4o-mini` alias. It emits an
   immutable one-file source ConfigMap, an immutable clients ConfigMap, an
   empty revision-zero append-only policy ConfigMap, a fixed protected
   journal ConfigMap, and a dedicated PhorvexPolicy
   proposal. The policy selects only Pods bearing the rollout's
   `phorvex.ai/litellm-live=true` label, is event-driven/reactive-only, and
   leaves rotate and quarantine enabled alongside client revoke. The reader
   gives defense credit only if the brain actually chooses client revoke.
   No raw trial seed, client token, or master key is written to these objects.
2. After the policy ConfigMap exists, supply its UID and read-only originals
   for the current Deployment and Service. The renderer emits JSON patches
   for those **existing** objects and label the reviewed Pods for the dedicated
   policy. The patches require the owner to create a
   `phorvex-litellm-master-key` Secret (`master-key`),
   `phorvex-litellm-trial-seed` Secret (`seed`), and
   `phorvex-litellm-status-token` Secret (`token`) first. The console needs
   the same seed and status token bytes in read-only Secrets in
   `phorvex-system`. A literal existing
   master-key env value is replaced by a Secret reference; it is never copied
   into renderer output. The status port must be restricted to the operator
   and console identities by reviewed network policy.

After rollout, create a private reviewed console profile matching
`liteLLMLiveProfile` in `phorvex/internal/console/litellm_live.go`. Pin stable
source/clients/seed SHA-256 digests, reviewed `gatewayImage`, policy name,
model alias, audit source identity, exact console service-account creator,
and `maxRunSeconds:900`. The console captures current Pod UIDs, backend and
gateway runtime image IDs, Service/Deployment/namespace UIDs, ConfigMap UIDs,
and policy UID/generation afresh for each Fire; it binds those to the event and
before/after evidence. An ordinary Pod rollout does not require profile edits.
Hash the literal profile bytes and enable `phorvex.console.litellmLive` with
that hash, profile ConfigMap name, trial seed Secret, status Secret, and fixed
protected journal name. Console mounts those inputs read-only; the manager
must mount the same status token for native
readback. The event creator must be trusted by admission for the typed
LiteLLM observation. Keep the chart toggle off until all bindings pass.

Only `ai2-unbounded-consumption` and `ai2-query-extraction` are included.
Both require real accepted original requests and usage before a labeled
`TEST_INJECTED` event, a normal selected `litellm-client-revoke` action,
protected terminal journal, activation on both exact Pods, a denied replay
with no new upstream attacker completion, and a successful benign completion.
The query case verifies bounded distinct queries; it does not claim replica
quality. Invalid bearer rejection is a negative control, not a defense.

Offline checks:

```sh
python3 -m unittest discover -s build/test-harness/fixtures/litellm-live -p 'test_*.py' -v
```
