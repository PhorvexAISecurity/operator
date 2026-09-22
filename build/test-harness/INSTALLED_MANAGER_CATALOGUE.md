# Installed-manager catalogue control

`c2-installed-manager-session` is a benign functional benchmark for an already
installed Phorvex manager. It creates a disposable two-replica CPU session
service in the harness-owned namespace and compares three separately configured
arms:

- `d-nomtd` observes the fixed window without a coordinated action.
- `d-r6blindtimer` changes the owned PodDisruptionBudget from 2 to 1 and sends
  one UID/resourceVersion-preconditioned Pod delete with a 30-second grace.
- `d-phorvex-installed` attaches to the installed manager. It does not install a
  CRD or start a controller. It observes an exact minAvailable 2 refusal, retires
  that policy, changes the native PodDisruptionBudget to 1, and creates a fresh
  minAvailable 1 policy for the eligible window.

Run each arm as a distinct one-trial invocation. Do not combine their results or
reuse a namespace. The target label is placed only on one original live Pod and
is absent from the Deployment template, so a replacement cannot be selected
again. The 90-second target warmup, fixed disruption aversion, one-move budget,
30-second grace cap, five-second policy tick, and finite observation windows are
part of the benchmark and must not be tuned after an outcome is known. A fully
attributed non-selection is a valid no-op measurement.

## Installed fixture pins

An installed arm requires `installedManagerFixture` in the target config. Pin
the current manager Deployment, ReplicaSet, Pod, container name, exact spec
image, immutable image ID, start time, restart count, service account, OCI
revision, decision-trace schema, and the PhorvexPolicy CRD UID/resourceVersion.
The exact observed runtime image string is also `expectedBrainImage`; do not
replace a tag observed in the decision trace with an inferred digest spelling.

Build `cmd/installed-audit-observer` from the same reviewed source tree and pin
its SHA-256 in `observerBinarySHA256`. Configure the existing authenticated audit
HTTPS origin, expected TLS server name, and absolute local CA/client certificate
paths. These paths and their contents are private runtime inputs and must not be
copied into benchmark output. Pin the parameter manifest ID/hash and set explicit
bounded reader limits: timeout 5–30 seconds, bytes 8–64 MiB, and rows 64–1024.

The installed arm creates one owned namespace-scoped Role for only core
`pods/eviction:create` and binds it to the pinned manager service account. This
grant cannot use `resourceNames` because the installed capability gate asks a
nameless SubjectAccessReview. The harness proves nameless and exact-target access
inside the fixture namespace and denial in a distinct unowned namespace. It
does not alter a shared ClusterRole or any business namespace.

## Receipts and claims

The observer reads the existing mTLS audit transport with a pinned cursor and
projects only allowlisted fields. Each phase binds policy UID/generation,
parameter epoch, decision and target UID, manager source, source byte ranges and
hashes. An emitted rotate must also bind handler, exact object, Pod
resourceVersion, and effective grace. The control phase is accepted only with a
typed availability refusal `{ready:2, removed:1, minAvailable:2}`. Missing or
mixed rich trace, source gaps, exceeded bounds, dispatch errors, and ambiguous
effects remain invalid or unknown; a later no-op cannot erase an earlier failed
attempt.

Decision and dispatch receipts do not prove application effect. The scenario
independently retains every successful or failed shared-Service request, original
Pod absence or retention, owner-stable replacement, old process-state survival
or loss, and fresh-state recovery. HTTP 404 is a known `application-response`,
not a session-success label. This scenario is `BenignControl=true`: it has no
ATT&CK, security-efficacy, avoided-breach, ROI, or security-per-cost credit.
Measured functional cost, availability, protocol, session, and cleanup evidence
remain reportable.

## Cleanup and result handling

Policy objects are retired before the exact-UID RoleBinding and Role. The target
label, PodDisruptionBudget, Services, Deployment, and producer Pod are cleaned
with bound identities; runner cleanup and namespace absence remain independent
checks. Preserve partial observer receipts when a later source read fails, but
never reinterpret an invalid summary as no action.

This source defines the benchmark and refusal boundaries. It does not claim that
an installed manager selected, dispatched, or achieved a rotation until a
separately pinned live run retains the corresponding audit and application
receipts.
