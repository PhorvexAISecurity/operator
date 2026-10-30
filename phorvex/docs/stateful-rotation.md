# Stateful rotation

Plain `rotate` evicts a Pod and lets its controller replace it. On a stateful Pod that
is a blind delete of single-writer state, so `stateful-integrity` keeps it infeasible
there, and quarantine is the only containment. The stateful rotation family adds three
rotation mechanisms for StatefulSet members. Each one is admitted only under a contract
the StatefulSet owner declares. The brain picks among them, and quarantine, from live
conditions.

| Action | Class | Pre-eviction step | Replacement keeps | Invalidates |
|---|---|---|---|---|
| `stateful-replica-rebuild` | A: replicated | release the member's claims (UID-bound delete) | nothing local; re-seeds from peers | identity, memory, session, **persisted volume state** |
| `stateful-snapshot-rotate` | B: single writer | ready CSI `VolumeSnapshot` of every claim | the same claims | identity, memory, session (same as `rotate`) |
| `stateful-checkpoint-handoff` | C: volume-less | application commits a checkpoint | the restored checkpoint | identity, memory (session is carried) |

Every class also retires the old Pod's API credential (`podBoundKubeAPIAuthPotential`).

## How the brain chooses

Selection uses the existing optimizer unchanged. The inputs are:

- **Cover** (`internal/recon/profile.go`): what a class invalidates. Only replica-rebuild
  covers `persistentVolumeState`. The fact is minted only for a member with claims whose
  owner declares peer-resync.
- **Cost** (`internal/cost/action_flow.go`): `C_norm` is one workload replacement.
  `C_flow` is `0.10 + unavailableFraction × sat(declaredSeconds / 1800)`. The unavailable
  fraction is `1/ready` for a replicated set and `1` for a single writer. The seconds are
  the declared resync bound for replica-rebuild and the recovery bound otherwise. This is
  availability multiplied by time.
- **Admission** (`internal/statefulrotation/admit.go`, through the feasibility law
  `stateful-rotation-admission`): the class must be declared, the observation complete,
  the target Ready, and the owner not mid-rollout with every member Ready. A replicated
  set must keep its quorum with the target out. The set must also have settled: no member
  may have become Ready within the declared resync bound (or the recovery bound when the
  owner does not declare peer-resync). Each class adds its own volume
  preconditions (A: non-leader member, claims from `volumeClaimTemplates`, Bound; B: the
  snapshot class exists and claims are Bound; C: no claims). The policy availability floor
  and PodDisruptionBudget rules apply as they do for `rotate`.

`internal/decision/stateful_rotation_selection_test.go` runs the real engine with every
class enabled, under both recon profiles:

| Situation | Selected |
|---|---|
| healthy replicated member (3/3, quorum 2) | `stateful-replica-rebuild` |
| the replicated leader | `stateful-snapshot-rotate` |
| degraded set (2/3) or rollout in progress | `quarantine` (state kept) |
| single writer, policy `minAvailableReplicas: 0` | `stateful-snapshot-rotate` |
| single writer, policy `minAvailableReplicas: 1` | no move (every replica-removing move breaches the floor) |
| volume-less pair with a checkpoint | `stateful-checkpoint-handoff` |
| high disruption price (λ=3), 1-minute resync | `stateful-replica-rebuild` |
| high disruption price (λ=3), 30-minute resync | `stateful-snapshot-rotate` |
| no contract | `quarantine`; plain `rotate` is never selected |

## Owner contract

The contract is declared as annotations on the **StatefulSet**, never on the Pod. A
malformed value fails the whole contract closed.

| Annotation | Value | Enables |
|---|---|---|
| `phorvex.ai/stateful-quorum` | integer 1–15 | quorum headroom for every class |
| `phorvex.ai/stateful-replica-rebuild` | `peer-resync` (requires quorum) | class A |
| `phorvex.ai/stateful-leader-label` | `key=value` | class A never rebuilds the matching member |
| `phorvex.ai/stateful-snapshot-class` | VolumeSnapshotClass name | class B |
| `phorvex.ai/stateful-checkpoint-port` / `-checkpoint-path` / `-restore-path` | port, absolute paths | class C |
| `phorvex.ai/stateful-recovery-seconds` | 1–3600 (default 300) | Ready bound; confirmation window, cost, and the settle time without peer-resync |
| `phorvex.ai/stateful-resync-seconds` | 1–3600 (default 3600) | peer catch-up bound; class A cost and the settle time with peer-resync |

A replicated database that allows rebuild, plus a snapshot restart for its primary:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: pg
  annotations:
    phorvex.ai/stateful-quorum: "2"
    phorvex.ai/stateful-replica-rebuild: peer-resync
    phorvex.ai/stateful-leader-label: role=primary
    phorvex.ai/stateful-snapshot-class: ebs-csi-snapclass
    phorvex.ai/stateful-recovery-seconds: "120"
    phorvex.ai/stateful-resync-seconds: "600"
spec:
  replicas: 3
  volumeClaimTemplates:
  - metadata: {name: data}
    # ...
```

The class C endpoints form an application contract. `POST <checkpoint-path>` must commit
the state to the application's own durable store, then answer
`{"checkpointId": "...", "sha256": "<64 hex>"}`. `GET <restore-path>` on the replacement
must answer with the checkpoint it restored. Phorvex treats both responses as untrusted
data and only compares them.

## Enabling

1. The backend must be `native` or `hybrid` (`phorvex.actuator`), with the tenant
   namespace listed in `phorvex.actuatorNamespaces`.
2. Set `phorvex.statefulRotation.enabled: true` in the manager chart (or in the actuator
   and sensor service charts). This grants PersistentVolumeClaim get/delete and
   VolumeSnapshot get/create per actuator namespace, plus cluster VolumeSnapshotClass get.
   Enable it before any policy enables a stateful action, or startup preflight refuses to
   start.
3. Add the actions you accept to the policy's `spec.actions.enabled`.
4. Annotate the StatefulSet with its contract.

## Dispatch and failure behaviour

The native handler (`internal/actuator/stateful_rotation.go`) re-reads the live target,
re-observes its StatefulSet and claims, and re-admits the class with the same law the
brain used. It then binds the exact selecting-policy epoch and grace cap, which is the
same path as `rotate`, and runs these steps in order:

1. **Dry-run the Eviction.** PodDisruptionBudget admission is proven before anything is
   prepared.
2. **Prepare.**
   - A: release the claims.
   - B: create the snapshots and wait (bounded) until every one is `readyToUse`.
   - C: the checkpoint.
3. **Evict** under UID/resourceVersion preconditions.
4. **Observe** (bounded by the declared recovery time, at most 90s) that the
   replacement member is Ready, then the class's continuity property:
   - A: fresh claims, Bound.
   - B: the same claims.
   - C: the restored checkpoint digest equals the committed one.

Failure outcomes:

- **Refusal before any mutation** (admission, policy, PDB, failed checkpoint):
  `NoEffect=refused`, and the member is untouched.
- **Stop after a preparatory mutation** (released claims, created snapshots):
  `MutationKind=partial`, with the touched objects and the snapshot rollback reference
  retained. The member keeps running. Released claims are recreated empty, and the member
  re-seeds from its peers on its next restart.
- **Replacement or continuity not observed in the window**: the result says
  `unconfirmed`. It never claims success.

Repeated actions on the same member are damped by the pod-identity anti-over-rotation
clock. That clock is per Pod, so it does not stop the brain from moving straight on to a
sibling. A readiness probe also does not prove that a rebuilt member has caught up with
its peers. The owner settle time closes that gap. Every class on the set is refused until
the youngest member has been Ready for the declared resync bound (or the recovery bound
without peer-resync), measured from the latest `Ready` transition among the owner's
Pods. If the members cannot be listed, the observation is incomplete, and every class is
refused. A set is therefore rotated one member at a time, with each replacement given its
declared catch-up time first.

## Restoring from a class B snapshot

Snapshots are named `phorvex-pre-rotate-<hash>` and labelled
`phorvex.ai/stateful-target-uid=<old Pod UID>`. The result's `RollbackRef` lists them.
A restore is an operator procedure, not an automatic step, because it requires stopping
the writer:

1. Scale the StatefulSet to exclude the ordinal (or stop the application).
2. Delete the ordinal's claim and recreate it, with the same name, using
   `dataSource: {kind: VolumeSnapshot, apiGroup: snapshot.storage.k8s.io, name: <snapshot>}`.
3. Scale back. The StatefulSet reattaches the restored claim.

## Monitoring

The actuator records exactly one outcome for every dispatch:

| Metric | Labels | Meaning |
|---|---|---|
| `phorvex_stateful_rotations_total` | `namespace`, `action`, `outcome` | `confirmed` (replacement Ready and class continuity observed), `unconfirmed` (evicted; not observed within the bound), `partial` (stopped after a preparatory mutation, member kept), `refused` (no effect), `error` (effect unknown) |
| `phorvex_stateful_rotation_recovery_seconds` | `action` | seconds from the accepted Eviction to a confirmed member |

The brain's choices appear in the existing `phorvex_decisions_total`,
`phorvex_candidates_excluded_total` and `phorvex_actuation_failures_total` series
under the stateful `action` values. Each environment's "Phorvex services" dashboard
has a **Stateful rotation** section for all of them.

Staging runs the sample in `deploy/demo/`. `nats-demo.yaml` is a 3-member NATS
JetStream cluster declaring classes A and B, with an exporter sidecar and a seeded R3
`DEMO` stream. `nats-demo-defense` (in `policy.yaml`) enables only the stateful family;
it is event-driven and also proactive (floor 1h). The **"Phorvex stateful rotation —
NATS demo"** dashboard (`nats-demo-dashboard.yaml`) shows each member's copy of `DEMO`,
the members' volume identity (a rebuild adds a new volume, a snapshot rotation keeps
it), and the rotations, decisions and recovery times.

## Live verification

`internal/decision/stateful_live_test.go` (build tag `live`) runs the production chain on
one real member: `statefulrotation.Observe`, the unmodified coverage engine, and the native
actuator. It authenticates as a ServiceAccount limited to the fixture namespace, and models
the held foothold as the engine's proactive trigger (every exposure clock past the floor).
The fixtures are in `config/samples/stateful-rotation/`. They include a 3-node NATS
JetStream cluster with an R3 stream of 1000 messages (classes A and B), and a volume-less
checkpoint worker (class C).

```sh
kubectl apply -f config/samples/stateful-rotation/
KUBECONFIG=<fixture-sa-kubeconfig> PHORVEX_LIVE_NAMESPACE=phorvex-stateful-e2e \
  PHORVEX_LIVE_POLICY=stateful-e2e PHORVEX_LIVE_POD=nats-e2e-2 \
  PHORVEX_LIVE_EXPECT=stateful-replica-rebuild \
  go test -tags live ./internal/decision -run TestLiveStatefulRotation -v
```

Results on EKS `phorvex-dev-eks` (Kubernetes 1.36, EBS CSI, 2026-10-29):

| Run | Brain selected | Outcome |
|---|---|---|
| `nats-e2e-2`, healthy set | `stateful-replica-rebuild` | 16s. New claim UID, member Ready, 1000/1000 messages re-synced from peers |
| `nats-e2e-1`, resync 1800s, λ=2.2 (A up to λ=2) | `stateful-snapshot-rotate` | first dispatch `partial` (EBS snapshot ready after ~65s > the then 60s wait; member kept). Retry reused the ready snapshot: same claim reattached, 1000/1000 messages |
| `checkpoint-worker-1` | `stateful-checkpoint-handoff` | checkpoint at counter 666 committed. Replacement restored the same digest and continued from 666 |
| `nats-e2e-0`, rollout pending (`partition=3`) | no move | admission refused every class while the revisions differed |

## Limits

- The flow-cost prior and the recovery and resync bounds are declarations and expert
  priors, not measurements (`[ESTIMATE-UNVALIDATED]`). Calibrate them on your own
  workloads.
- Class A trusts the application to re-seed a member that has empty claims. Declare
  `peer-resync` only for systems that do this, such as Patroni replicas, etcd/Raft members
  re-added by their operator, or Kafka/Elasticsearch replicas.
- Snapshot-rotate needs the CSI snapshot API (the `VolumeSnapshot` CRDs, the snapshot
  controller and a `VolumeSnapshotClass`). On EKS that means the `snapshot-controller`
  add-on and a class for `ebs.csi.aws.com`. Without them the class is not admitted. On
  EKS, measured EBS snapshots became `readyToUse` about 60–70s after creation. The
  handler waits up to 120s. If a snapshot is slower, the member is retained as `partial`,
  and a later dispatch reuses the same snapshot.
- A Pod is observed only when it is a rotation target. A failed read leaves the
  observation incomplete, and the family inadmissible.
