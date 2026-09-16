# Startup authorization admission

Before the manager registers policy controllers or starts recovery, it lists every
`PhorvexPolicy` through the uncached API reader and checks the manager ServiceAccount's
permissions with `SelfSubjectAccessReview`. The check has a finite deadline and refuses
startup when policy inventory is incomplete, a required review is denied, or the API cannot
return a known answer.

The permission plan follows `PHORVEX_ACTUATOR`. Native actions check their namespaced Pod,
Service, NetworkPolicy, owner, and protected journal operations. Phoenix-routed actions check
cluster-scoped SecurityEvent access and namespaced AMTD preparation. Hybrid checks the route
that will receive each action. Quarantine also checks the namespace/pod/event inventory and
protected capacity ledger used before every backend. Optional MIG agent checks are included
only when node execution is enabled.

Dry-run policies do not add actuation requirements. An installation with no policies may
start and reports that it checked zero active policies; it does not describe nonexistent
permissions as verified. Startup admission is one observation. Runtime capability checks
remain active for later policy or RBAC changes and retain their existing unknown-result
behavior.

`phorvex.actuatorNamespaces` creates tenant Roles for the manager ServiceAccount that the
chart creates under `serviceAccountName` (or its release-scoped default). Active native or
hybrid policies in an unlisted namespace therefore fail startup instead of beginning
reconciliation with missing grants. The protected
operator-namespace ConfigMap Role remains separate from tenant mutation Roles. Code execution
and the optional MIG agent stay disabled unless their separate grants and configuration are
enabled.
