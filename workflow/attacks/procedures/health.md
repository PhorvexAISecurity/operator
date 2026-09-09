# P-HEALTH — read-only baseline

Run `attacks preflight` with the explicit context and tenant namespaces. Check
operator and target readiness, images/digests, and the listed policies and modes.
Kill-switch, backend and enrollment checks belong to the selected attack
prerequisites; this baseline does not certify them. Missing source SHA is recorded unknown. No logs,
Secret values, pod exec, policy edits or attack injection are needed.

`attacks observe-health --plan <path> --by <executor>` repeats preflight and
records PASS only if the operator remains ready at the planned image/digest and the selected namespaces
contain targets with ready containers.
A live observation that drifted from the plan is FAIL, not current verification.
This proves deployment health only; it does not prove an attack was defended.
