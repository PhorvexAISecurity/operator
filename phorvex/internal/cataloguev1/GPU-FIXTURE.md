# Limited v1 owned GPU request-drain fixture

`limited-v1-vllm-request-drain` runs one benign functional control against a dedicated, externally prepared ordinary-GPU vLLM fixture. It does not target the stock business vLLM Service, invoke the manager, or measure a security defense. The result is unscored and its security outcome is `not-measured`.

The trusted server runtime must supply all of these values. None may come from the browser or launch request:

- an executable copy of the reviewed static test-harness binary and its fixed working directory;
- one mounted, bounded harness config for scenario `c2-vllm-request-drain`, defender `d-nomtd`, one trial, `ownedAck: true`, and `gpuFunctionalFixture.operation: request-drain` in `direct` mode;
- the exact prepared namespace and namespace UID, node/Pod/controller/Service/container/image/model/source identities, zero restart count, port 8000, and container start time;
- a private projected bearer-token file used only by the harness to reach the fixed in-Pod drain proxy;
- a mounted kubeconfig/context pinned to the same cluster. The harness uses its existing kubeconfig safety guard; it has no in-cluster fallback and receives no arbitrary API destination;
- RBAC limited to the reviewed fixture reads and Pod port-forward required by the existing harness. Fixture creation, GPU allocation and cleanup remain the external supervisor's responsibility.

The console worker copies the config into its private run directory and changes only `outDir`. It invokes exactly:

```text
<configured harness> -config <private run config> -negative-control=false -adaptive=false
```

There is no shell command, Python helper, retry, resume mode, business-Service fallback or user-selected scenario. The output directory must be empty before dispatch. The worker accepts exactly one metric row and runs the shared `metricvalidity` evaluator plus the fixed fixture, operation, source, protocol-attempt, reopen and receipt-digest checks. It preserves that metric byte-for-byte for the console outcome reader.

A functional pass requires the harness's exact in-flight anchor, acknowledged drain, abort/quiescence evidence, acknowledged reopen, fresh post-reopen inference and verified teardown. A valid complete row whose oracle is false is a functional failure. Missing, malformed, multi-row, identity-mismatched or cleanup-unverified output is a test failure and unsafe to retry.

The child is placed in its own process group with a parent-death signal. Ordinary caller cancellation gives the harness a bounded interval to finish its own reopen and teardown. If the worker must terminate the group, it cannot claim cleanup. Reconciliation never replays the drain or starts the harness again; it accepts only the exact retained run config and a complete, shared-contract-valid metric proving reopen and cleanup. Otherwise it returns `UNVERIFIED-NO-REPLAY` with `unsafeToRetry: true` for operator-owned fixture recovery.
