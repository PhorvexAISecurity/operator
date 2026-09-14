# Identity-bound Pod deletion on the AI actuation paths (M-69)

`warm-swap`, `model-shard-replace` (single shard and TP/PP group) and `mig-rebind` retire
Pods by deleting them. A Pod **name** is not an identity: the workload owner respawns a
replacement under the same namespace/name, so a Delete addressed by name can kill a Pod
nothing ever selected — a delayed retry of an already-completed move, or a Delete issued
after the observed object was replaced mid-handler. Native `rotate` has always bound its
Delete to the observed UID (+ResourceVersion); the AI paths now carry the same contract.

## The guarantee

1. **Trigger identity is checked before any mutation.** The runner captures the selected
   Pod's UID from its own snapshot into `Request.TargetUID`. Each destructive AI handler
   reads the trigger Pod and refuses — in native rotate's shape: not emitted, reason in the
   `Note`, no error — when the request carries no identity (`target-uid-unavailable`), the
   observed object carries none (`observed-uid-unavailable`), or they differ
   (`target-uid-mismatch`). Nothing is flipped, relabeled or deleted on refusal.
2. **Every Delete names the observed object.** The Delete carries the UID of the Pod object
   that planned that retirement as an API-server-enforced precondition (`deleteObservedPod`,
   `handlers_ai_identity.go`). Only the UID is pinned: the handlers legitimately relabel the
   old leader `retiring` first, so a pre-relabel ResourceVersion would always be stale.
   - single cutover: the leader object read at the start of the move;
   - TP/PP group: each old leader's list object, and the trigger keeps the identity
     verified in step 1 — a same-name object listed under another UID is a replacement
     and is neither relabeled nor deleted;
   - mig-rebind: the pod object read at the start of the move.
3. **A rejected Delete is a non-success that tells the truth.** The API server answers a
   UID mismatch with a Conflict; the handler surfaces it as an error wrapping
   `errPodReplaced` and describes the partial state as it is (shadow(s) promoted, the name
   relabeled `retiring`, which old leaders were and were not retired). No rollback or
   atomic cutover is claimed, no rewarm is provisioned, and `mig-rebind` never calls
   `Repartition` after a rejected eviction. The runner retains the reported
   `ObjectsTouched` without crediting the move.
4. **NotFound stays "already gone".** With a UID precondition, NotFound means no Pod of that
   name exists at all — a same-name replacement would be a Conflict, not NotFound — so the
   observed object is genuinely gone and the existing already-retired handling is truthful.

## What is verified where

- `handlers_ai_identity_test.go` (fake client): refusals on all four paths, the
  precondition every Delete carries, honest non-success on a rejected Delete, repartition
  count 0 after a rejected eviction.
- `m069_apiserver_test.go` (local `envtest` kube-apiserver, skipped without
  `KUBEBUILDER_ASSETS`): the observed Pod is replaced by a same-name object immediately
  before the handler's own Delete; the replacement survives and the move is a
  non-success; unchanged identities still retire. The serving-stack and MIG callbacks are
  local fakes — no GPU effect is proven.

## Out of scope

Pre-delete drain failure, GPU zero-context verification, group-wide transactions and
ownership reconstruction (M-70), trusted node-exec (M-81) and the crash-resume reaper in
`warmswap_resume.go` (which deletes only Pods it itself listed as `retiring`) are unchanged.
