# M100 and M106 bounded deployment handoff

This directory is a public, nonsecret deployment bundle for two bounded development tests:

- **M100** loads an authenticated current-version observation, then an authenticated completed-loss observation, into a dedicated durable history volume.
- **M106** enables one preregistered, reporting-only scoped outcome observer backed by a dedicated evidence volume.

Both features remain disabled in `values-eks.yaml`. Nothing in this directory creates a fixture automatically. Apply changes through the existing GitOps workflow after reviewing a full render against the current Argo source. These controls do not establish fleet-wide loss coverage, attack prevention, or general external probe authority.

## Current readiness

M100 requires the three already-provisioned observer TLS Secrets to remain present, unexpired, and bound to a freshly pinned target, Policy, protected bytes, and mTLS endpoint. The example files contain no certificate or key data.

The checked-in `secure-transfer-pin.json` binds the freshly re-rendered M106 policy, Deployment, target Pod, session authority, source Secret UIDs, destination namespace UID, exact content hashes, and certificate horizon. The old target-bound config was rejected and is not included. The transfer pin expires at 2026-09-23T18:00:00Z; any target, Policy, owner, Secret, namespace, or expiry drift requires another complete render and pin. DevOps can deliver the private bytes entirely through Kubernetes and does not need access to the preparation server.

## Files

| File | Purpose |
| --- | --- |
| `m100-deployment-pin.json` | Fresh nonsecret M100 workload, Policy, projection, transport, Secret-metadata, and certificate pin. |
| `values-m100-phase-a-current.json` | Fresh exact values: enable durable history and run the current-inventory observer. |
| `values-m100-phase-b-loss.json` | Preserve the Phase A creator trust and run the loss observer. |
| `values-m100-disable.yaml` | Disable both observers and the manager history reader after evidence retention. |
| `values-m106.yaml` | Enable one scoped observer using the reviewed destination Secret and PVC names. |
| `values-m106-disable.yaml` | Disable the scoped observer. |
| `pvc-*.yaml` | Dedicated 1 GiB RWO claims. They do not reuse audit or each other's storage. |
| `rbac-m106-fixture.yaml` | Minimum event-producer and native-rotate access for the owned fixture only. |
| `secure-transfer-pin.json` | Fresh executable nonsecret M106 source/destination UID, authority, expiry, and content-hash pin. |
| `secure-transfer-pin.example.json` | Template for a later full M106 render. |
| `scripts/transfer_secret.py` | Read-only `check` and explicit `apply`; Secret bytes never enter stdout, logs, Git, or a local file. |
| `scripts/verify_bundle.py` | Static and Helm-render checks for this bundle. |

## Prerequisites

1. Check out the exact reviewed commit of this repository. Use the current Argo Application source (`deploy/helm/phorvex-stack`, `values.yaml`, then `values-eks.yaml`) as the baseline. Do not use `helm get values` as desired-state authority.
2. Install Python 3, Helm, and a `kubectl` context authorized for the normal deployment workflow.
3. Confirm Argo is synchronized and record the Application revision. Record manager and console Deployment, Pod, container, and image identities before each phase.
4. Confirm each fixture namespace, target Pod, stable workload owner, Policy UID/generation, Service, and protected ConfigMap or session endpoint from the live API. Stop on drift.
5. Render before submitting a GitOps change:

```sh
HELM=${HELM:-helm}
$HELM template phorvex deploy/helm/phorvex-stack \
  --namespace phorvex-system \
  -f deploy/helm/phorvex-stack/values.yaml \
  -f deploy/helm/phorvex-stack/values-eks.yaml \
  -f deploy/helm/phorvex-stack/examples/math-observers/values-m106.yaml \
  -f deploy/helm/phorvex-stack/examples/math-observers/values-m100-phase-a-current.json \
  > /tmp/phorvex-m100-a.yaml
```

The M106 layer in this example preserves an already reviewed M106 rollout while M100
moves between phases. Omit it only when M106 is disabled in the captured pre-state.
Use the same ordered layers for Phase B and prove that the rendered manager Pod template
is byte-identical across the two M100 phases.

The checked-in JSON overlays and `m100-deployment-pin.json` are the fresh nonsecret current fixture pin. Revalidate every UID, generation, endpoint, digest, and certificate expiry immediately before deployment. The `.example.yaml` files and `m100-deployment-pin.example.json` are templates for a later fixture; render them outside Git with `scripts/render_m100_values.py`.

The `evidence` paths in the exact M100 pin name externally retained campaign artifacts;
their digests preserve provenance, but those private review files are intentionally not
part of this public repository. Deployment authority comes from repeating the live API,
mTLS, and hash checks described here, not from the local path strings.

## M100 phase order

### Phase A: current inventory

1. Revalidate the existing CA and current-client Secret metadata and certificate validity without printing Secret data. Verify the target Pod UID, Policy UID/generation, projected ConfigMap key/path, protected asset/version/property, rule digest, and mTLS manifest endpoint.
2. Create `pvc-m100-loss-history.yaml` through the deployment workflow. Refuse a same-name existing claim unless its UID/spec/ownership are already pinned for this run.
3. Merge `values-m100-phase-a-current.json` into the current GitOps values. Preserve every unrelated value.
4. Review the full render. The chart supplies the observer ServiceAccount, a `securityevents.create` ClusterRole, and target-namespace get-only access to the exact resource kinds needed for authority checks.
5. Sync normally. Require the manager to become Ready and the current-inventory Job to finish once. Validate the emitted event's authenticated creator, target/Policy authority, TTL, protected identity, and admitted current observation. Job success by itself is insufficient.

### Phase B: completed loss

1. Start before the Phase A observation TTL expires. Resolve `expectedBytes` and `expectedSHA256` from the exact protected bytes without printing them.
2. Render Phase B. The manager Deployment `spec.template` must be byte-identical to Phase A. Phase A pretrusts the loss observer; Phase B retains the current observer identity explicitly, so changing Jobs/RBAC does not require a manager restart.
3. Merge and sync `values-m100-phase-b-loss.json`. Require one loss-observer Job and validate authenticated creator, exact disclosed bytes, history admission, and the resulting representation. Preserve unknown or partial outcomes.

### M100 rollback

Merge `values-m100-disable.yaml` through GitOps. Confirm observer Jobs/RBAC are gone and the manager no longer has loss-history arguments or mount. Archive the required history evidence before deleting the PVC. Remove only test-owned TLS Secrets by exact UID under their owner's cleanup plan. Never delete shared audit data or serving journals.

## M106 secure material delivery

A fresh reviewed renderer creates two immutable source Secrets in the already-owned fixture namespace:

- `phorvex-m106-config-transfer-v5`: type `Opaque`, exact key `startup.json`;
- `phorvex-m106-tls-transfer-v5`: type `Opaque`, exact keys `ca.crt`, `tls.crt`, `tls.key`.

Each source Secret must carry label `phorvex.ai/secure-transfer=m106-v5`, annotation `phorvex.ai/expires-at` no more than 22 hours ahead and before certificate expiry, and annotation `phorvex.ai/transfer-destination` with the exact destination. Root publishes only a nonsecret pin containing namespace UIDs, Secret UIDs, expiry, and decoded SHA-256 per key.

DevOps first performs a read-only check:

```sh
python3 deploy/helm/phorvex-stack/examples/math-observers/scripts/transfer_secret.py check \
  --pin deploy/helm/phorvex-stack/examples/math-observers/secure-transfer-pin.json \
  --kubectl "$(command -v kubectl)" \
  --receipt /tmp/m106-transfer-check.json
```

After reviewing that receipt, DevOps explicitly materializes the destinations:

```sh
python3 deploy/helm/phorvex-stack/examples/math-observers/scripts/transfer_secret.py apply \
  --pin deploy/helm/phorvex-stack/examples/math-observers/secure-transfer-pin.json \
  --kubectl "$(command -v kubectl)" \
  --receipt /tmp/m106-transfer-apply.json
```

The helper pins both namespace UIDs and source Secret UIDs, expiry, immutable flag, marker, destination, type, exact key set, and content hashes. It preflights both destinations as absent before writing either. It sends data to `kubectl create -f -` through stdin and requests only `-o name`; it stores and prints only metadata and hashes. An existing destination is always a refusal. An ambiguous create is reconciled by exact content hashes and source annotations and is never replayed blindly. Transfer-source deletion remains with the fixture owner.

The accepted destination names are `phorvex-system/phorvex-m106-scoped-outcome-v4` and `phorvex-system/phorvex-m106-scoped-outcome-v4-tls`. They must remain absent until this transfer.

## M106 rollout and rollback

1. Require the fresh renderer's target, Policy, owner, session responses, workload digest, TLS names, certificate validity, and startup JSON to pass their producer controls. A stale target blocks the rollout.
2. Run transfer `check`, then `apply`. Record destination UIDs without recording data.
3. Create `pvc-m106-scoped-outcome.yaml` and `rbac-m106-fixture.yaml`. Confirm the fixture ServiceAccount and manager ServiceAccount identities before applying RBAC.
4. Merge `values-m106.yaml` into current GitOps values. Its detector list is a full Helm list replacement: confirm it is the current `values-eks.yaml` allowlist plus exactly the fixture detector. Preserve all other Argo settings.
5. Review the full render. The manager change must be limited to the scoped config flag, two read-only Secret mounts, one dedicated writable evidence mount, and the retained detector allowlist. Sync normally.
6. Require the manager log `scoped outcome observer enabled` with source `scoped-synthetic-process-session`. Readiness is insufficient. Run the separately reviewed no-operation, native receipt, scoped label, rejection, and recovery controls.

Rollback by restoring the exact captured values that preceded the M106 overlay. If the
overlay was merged into `values-eks.yaml`, remove its fixture detector and restore the
prior actuator as well as disabling `scopedOutcome`; `values-m106-disable.yaml` only
disables the scoped mounts and flag. After the manager is Ready with that exact prior
actuator/detector state and evidence is archived, delete the two destination Secrets,
fixture RBAC, and PVC only with recorded UID preconditions. The fixture owner separately
removes transfer Secrets and fixture objects. Do not clear serving-operation receipts.

## Stop conditions

Stop before a rollout on any placeholder, expired certificate, stale UID/generation, changed Argo base, changed Helm allowlist, existing destination Secret, PVC/RBAC collision, incomplete render, or unavailable secure pin. During a run, stop on manager/console replacement, observer authority mismatch, unplanned manager restart between M100 phases, M106 producer startup refusal, or evidence-storage failure. Retain failed results; do not turn unavailable evidence into a pass.
