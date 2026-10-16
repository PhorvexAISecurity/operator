# Installed-manager catalogue control

`c2-installed-manager-session` is a benign functional benchmark. It creates a
disposable two-replica CPU session service in the harness-owned namespace and
compares two separately configured arms:

- `d-nomtd` observes the fixed window without a coordinated action.
- `d-r6blindtimer` changes the owned PodDisruptionBudget from 2 to 1 and sends
  one UID/resourceVersion-preconditioned Pod delete with a 30-second grace.

The third arm, `d-phorvex-installed`, attached to an already installed Phorvex
manager and read its authenticated audit through `cmd/installed-audit-observer`.
That arm, its `installedManagerFixture` configuration and the observer were
removed; they remain in `PhorvexSecurity/operator@65af1c99`
(`build/test-harness/defenders/d_phorvex_installed.go`,
`phorvex/cmd/installed-audit-observer`). The scenario keeps the coordinator
receipt keys of its v1 evidence schema, and every remaining coordinator must
leave them empty.

Run each arm as a distinct one-trial invocation. Do not combine their results or
reuse a namespace. The target label is placed only on one original live Pod and
is absent from the Deployment template, so a replacement cannot be selected
again. The 90-second target warmup, 30-second grace cap and finite observation
windows are part of the benchmark and must not be tuned after an outcome is
known. A fully attributed non-selection is a valid no-op measurement.

## Receipts and claims

Dispatch receipts do not prove application effect. The scenario independently
retains every successful or failed shared-Service request, original Pod absence
or retention, owner-stable replacement, old process-state survival or loss, and
fresh-state recovery. HTTP 404 is a known `application-response`, not a
session-success label. This scenario is `BenignControl=true`: it has no ATT&CK,
security-efficacy, avoided-breach, ROI, or security-per-cost credit. Measured
functional cost, availability, protocol, session, and cleanup evidence remain
reportable.

## Cleanup and result handling

The target label, PodDisruptionBudget, Services, Deployment, and producer Pod
are cleaned with bound identities; runner cleanup and namespace absence remain
independent checks.

This source defines the benchmark and refusal boundaries. It makes no claim
about what an installed manager would select, dispatch, or achieve.
