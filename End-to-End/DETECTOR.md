# Authenticated Voicebot E2E fixture

The Voicebot CI target injects a real SecurityEvent using a dedicated identity,
not the console's ServiceAccount. M-94 correctly rejects the old console identity:
it is not a trusted detector. Do not bypass that check or allowlist the console.
The deployed console still supplies the live audit stream, health, and version;
this target tests detector-to-actuator behavior, **not** the console attack endpoint.
Other targets retain their existing console injection paths.

Enable `phorvex.e2eDetector.enabled` with an explicit `targetNamespace` in the
Phorvex subchart (the EKS parent overlay enables it for `voice`). The chart creates
`<release>-phorvex-e2e-detector`, admits it to the detector allowlist, and grants
only SecurityEvent create/get/delete. No persistent token is created. CI uses its
existing bastion credentials to impersonate this identity; it is not granted any
new impersonation privileges.

SecurityEvents are cluster-scoped. A fail-closed ValidatingAdmissionPolicy and
binding additionally restrict this identity to `phorvex-e2e-*` events, one pod
target in the configured test namespace, and source `PhorvexE2EDetector`. The
policy applies to deletion as well as creation. Install and validate this policy
and binding **before** granting the role or enabling trust.

Each run creates a fresh named event (never reapplies a stale CreationTimestamp),
requires the admission-stamped identity in the API response, and clears that exact
event on completion or exceptions, including interrupted capture. Cleanup errors
fail the run. SIGKILL/host loss cannot execute cleanup: inspect leftover
`phorvex-e2e-*` events after an interrupted runner, and delete only the recorded
event for that run. GitHub's `phorvex-e2e-live` concurrency group must remain intact.

Before a live run, verify operator/console readiness, the admission policy's
type-check status, denied out-of-namespace server-side dry-run probes, and the
absence of any pod-delete permission for this identity. Keep existing safety
policies, A05 assertions, unresolved M-34 weights, and scoring admission unchanged.
Run during an approved window: the actual operator may rotate a Voicebot pod.
