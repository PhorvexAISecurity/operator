# M-80 reconciliation at Tier7 source `669197bf025a446a87ed2923c04dbaa2237ca077`

## Disposition

**Source-fixed by Tier6 M83; no further product change is justified from the current M-80 text.**

The issue describes the pre-M83 `Available(ctx,node)` contract, which admitted a non-nil exec seam plus a Running agent without invoking GPU tooling. That method no longer exists. Commit `64b46198fdf3147225dac4cd9c8e9ae725cbf54b` (`fix: bind MIG reconfiguration to kubelet allocation`), followed by timeout correction `295102baa4676677c55a0890a335015e4b1c3c70`, is contained in the exact reviewed source. The selected native and hybrid capability producer now performs a real, non-mutating PodResources plus `nvidia-smi` probe, while the handler repeats uncached evidence and validates full MIG geometry before its first workload mutation.

## Producer and consumer trace

- `phorvex/internal/capability/gate.go:304-321` is the consumer: the selected actuator's `SupportsAction` result gates the action before scoring. Hybrid delegates MIG to native in `phorvex/internal/actuator/hybrid.go:61-69`.
- `phorvex/internal/actuator/native.go:54-93` is the current producer. For `mig-rebind` it requires a wired transport, exact operator-owned profile, fresh Pod UID/node/resource, a prepared trusted node agent, and `BindAllocation` success.
- `phorvex/internal/actuator/mig_authority.go:125-140` makes the probe real and non-mutating: it reads kubelet PodResources through the helper and executes `nvidia-smi -L` in the configured GPU tooling container. `parseNVIDIAInventory` rejects empty, malformed, duplicate, or GPU-less output (`:88-122`). `bindAllocation` requires exactly one target MIG device, maps it to one physical GPU, and rejects unknown aliases, duplicate device tuples, extra target NVIDIA allocations, and any co-allocation on the same physical GPU (`:142-201`).
- The old wiring-only failure is therefore discriminated. A Running/Ready pod with a non-nil exec seam but a wrong container or missing/broken `nvidia-smi` fails the real exec and makes `SupportsAction` false. A working `nvidia-smi` with MIG disabled/no MIG inventory, or inventory that does not contain the kubelet-assigned MIG ID, also fails. Mere pod lifecycle is insufficient.
- `phorvex/internal/actuator/gpu_stack_p4set.go:381-419` additionally binds namespace, node, Pod UID, DaemonSet UID/controller, configured ServiceAccount, both named containers, readiness, and live lifecycle. Every helper/tool exec revalidates that identity (`:440-483`). Thus an absent configured container fails preparation, while a present-but-incapable container fails the command.

## Cache and effect-boundary reconciliation

- Only capability-probe contexts may use the cache (`phorvex/internal/actuator/gpu_stack_p4set.go:316-327,440-483`). It is keyed by node + DaemonSet UID + agent Pod UID, has a two-second TTL, prunes expired entries on reads and writes, and independently caps allocation and inventory maps at 32 entries (`:238-314`). Overflow skips caching rather than growing memory.
- The handler does not inherit the locally derived capability context. It prepares again and performs uncached `BindAllocation` and `Capture` before mutation (`phorvex/internal/actuator/handlers_ai.go:465-489`). `Capture` executes UUID query, `nvidia-smi mig -lgip`, `-lgi`, and `-lci`, verifies the target profile exists, and accepts only one complete, internally consistent geometry (`phorvex/internal/actuator/gpu_stack.go:272-312,409-538`). This catches missing MIG command support, MIG-disabled/empty state, unsupported partial compute instances, malformed tables, and target-profile absence before route relabel or Pod delete.
- The handler rereads Pod identity/configuration and allocation evidence before recovery intent and route removal (`handlers_ai.go:491-510`), then again before UID-bound eviction (`:538-551`). After allocation release it recaptures and compares geometry before destroy (`:560-573`). Each destructive GPU step calls `mutationGuard`, which rechecks recovery ownership, uncached allocation authority, and the same physical GPU UUID (`handlers_ai.go:577-583`; `gpu_stack.go:579-617`).

## Existing controls and counterexample coverage

- `phorvex/internal/actuator/mig_capability_test.go:18-62` proves two capability calls use real helper plus `nvidia-smi -L` evidence and share only the bounded capability cache; `:64-85` rejects stale Pod UID and missing profile; `:88-115` proves the 32-entry limit and expired-identity pruning.
- `phorvex/internal/actuator/nodeexec_identity_test.go:114-141` rejects missing configured containers and other untrusted agent identities. `:262-321` proves revalidation before the first and every later exec.
- `phorvex/internal/actuator/mig_authority_test.go:30-81` covers positive binding and foreign/unknown/duplicate/ambiguous allocations; `:84-99` rejects physical-parent drift.
- `phorvex/internal/actuator/mig_recovery_test.go:79-155` proves UUID-bound, target-profile-aware complete geometry and rejects ambiguous, partial, and zero-exit malformed inventory.
- `phorvex/internal/actuator/mig_podresources_integration_test.go:151-190` exercises the real Unix kubelet PodResources server -> shipping helper -> handler path with repeated authority reads and UUID-bound destructive commands; `:192-243` proves foreign sibling and false tenant-annotation refusals remain pre-effect.

The narrow local-proof gap is test coverage, not source behavior: there is no single focused `SupportsAction` negative whose trusted agent is Running/Ready and contains the configured container but whose `nvidia-smi -L` exec returns “binary absent” or malformed/no-MIG output. The current call graph deterministically returns false through `allocationEvidence`, and handler geometry negatives cover the deeper MIG command/table cases. If a permanent M-80-specific witness is desired, the minimal change is one test-only table in `mig_capability_test.go` for exec error, GPU-only/no-MIG inventory, and malformed inventory, paired with the existing positive control. No new probe or product logic is needed.

## Proof limits

- This reconciliation is static at the pinned source. Per instruction, no Go tests or shared-cluster operations were run; `workflow.py doctor` exited successfully.
- Local tests use fake Kubernetes clients or a real Unix gRPC PodResources producer, but mock the SPDY exec/GPU command endpoint. They prove invocation, parser/refusal logic, cache bounds, ordering, and effect boundaries, not installed driver/NVML behavior.
- Live proof still requires an authorized MIG-capable node: render/deploy the opt-in agent with its pinned GPU tooling image, show a bad container or missing `nvidia-smi` excludes the action without workload mutation, show MIG-disabled/no-profile states refuse before mutation, then show a valid allocation/profile reaches a read-only probe. A destructive repartition/control remains separate L3 work and must verify actual CUDA quiescence, allocation release, geometry change/readback, and recovery. No live waiver is implied.
