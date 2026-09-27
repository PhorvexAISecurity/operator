# LiteLLM Live client policy trial

This package integrates a scoped admission gateway into the **existing**
`litellm/litellm` Service path. It requires an owner-reviewed rollout. Merely
rendering these files does not deploy it or establish a defense result.

The existing two LiteLLM Pods keep their real model-serving process on local
port 4000. Each Pod gains a gateway on 4001 and an operator-authenticated
status listener on 4002. The existing Service stays at port 4000 and its
`targetPort` changes to 4001, so real authorized clients still traverse the
installed workload. Only the two review-owned synthetic client tokens are
recognized by the gateway; they are exchanged for the upstream master key
inside the Pod. All other callers retain the upstream auth behavior.

`render.py` has two stages:

1. Provide attacker/control token SHA-256 values, the exact reviewed
   digest-pinned gateway image, and one installed model alias. It emits an
   immutable one-file source ConfigMap, an immutable clients ConfigMap, an
   inactive revision-zero policy ConfigMap, and a dedicated PhorvexPolicy
   proposal. The policy selects only Pods bearing the rollout's
   `phorvex.ai/litellm-live=true` label, is event-driven/reactive-only, and
   leaves rotate and quarantine enabled alongside client revoke. The reader
   gives defense credit only if the brain actually chooses client revoke.
   No client token or master key is written to these objects.
2. After the policy ConfigMap exists, supply its UID and read-only originals
   for the current Deployment and Service. The renderer emits JSON patches
   for those **existing** objects and label the reviewed Pods for the dedicated
   policy. The patches require the owner to create a
   `phorvex-litellm-master-key` Secret (`master-key`) and
   `phorvex-litellm-status-token` Secret (`token`) first. A literal existing
   master-key env value is replaced by a Secret reference; it is never copied
   into renderer output. The status port must be restricted to the operator
   and console identities by reviewed network policy.

After rollout, create a private reviewed console profile matching
`liteLLMLiveProfile` in `phorvex/internal/console/litellm_live.go`. Pin the
new Pod UIDs, the reviewed digest-pinned `gatewayImage`, both backend/gateway
runtime image IDs, Service/Deployment/namespace
UIDs, source/clients/policy ConfigMap UIDs and SHA-256 digests, policy UID and
generation, the two owned token hashes, model alias, audit source identity,
the exact console service-account creator, and `maxRunSeconds:900`. Hash the
literal profile bytes and enable `phorvex.console.litellmLive` with that hash,
profile ConfigMap name, exact attacker/control token Secret names, status
Secret, and deterministic protected journal name. Console mounts those
inputs read-only; the manager must mount the same status token for native
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
