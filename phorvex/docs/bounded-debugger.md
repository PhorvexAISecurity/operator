# Bounded debugger inspection

The native `debugger` action submits one ephemeral container to the selected Pod. Its
image is the pinned BusyBox digest, command is exactly `sleep 300`, stdin and TTY are
disabled, and it targets the Pod's first ordinary container. This creates a five-minute
diagnostic window. The process starts only after the runtime pulls and starts it; an API
submission is not evidence that it is running. Inspect the Pod's
`status.ephemeralContainerStatuses` and proceed only while `phorvex-debugger` is
`Running` with a valid start time inside the five-minute window. `Waiting`,
`Terminated`, missing status, and an invalid or expired running timestamp are
unavailable states. Pod status can lag the node, so a recent `Running` observation
still requires an operator to confirm the runtime supports the intended inspection.

An authorized operator can inspect or attach through their existing Kubernetes access.
The automatic brain's permission to submit `pods/ephemeralcontainers` does not grant
`pods/exec` or attach permissions. No automatic interactive shell or arbitrary command is
submitted. `TargetContainerName` requests the runtime's supported target process view;
PID visibility depends on the container runtime and is not guaranteed on every cluster.

The ephemeral container spec cannot be removed or changed in place. Once its five-minute
process exits, another session requires a fresh Pod and a new selection; repeated action
against the same name reports the actual state instead of injecting another container.
The debugger is diagnostic availability, not a defense effect or attack mitigation. The
admission policy enforces its fixed profile, and the runtime verifier rejects an older or
mismatched policy epoch.
