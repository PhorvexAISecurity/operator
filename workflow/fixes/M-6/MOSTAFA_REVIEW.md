# M6 — recorded contract choices

**Status:** engineering review passed; **Mehrdad (human_owner) approved all three recommendations**, as
recorded by Claude in [the approval record](evidence/decision/human-decision-2026-09-08.md). No separate
Mostafa signature is asserted.
Approval is for the selected contract and subsequent implementation after independent agreement; deployment,
execution grants, action enablement and persisted live injections remain separately authorized steps.

M6 limits the two ephemeral-container actions (`debugger` and `custom-inject`) at Kubernetes admission and
keeps them unavailable when the applicable protection cannot be verified. It does not claim these actions
are effective defenses or protect the separate `pods/exec` path.

| Decision | Recommended choice | Practical effect |
|---|---|---|
| **SEC-1: allowed execution** | **Option A:** keep debugger command/args empty and enforce that at admission. Use the captured BusyBox digest, non-root UID/GID 65534, restricted securityContext, exact action names, and exact custom-inject command. Installer/admin owns the profile. | Arbitrary images, commands, privileges, environment additions and mounts are rejected. Debugger functionality/lifetime is not improved or claimed. |
| **SEC-2: protected scope** | Protect installer-labelled namespaces; allow only the designated manager SA with approved payloads. No emergency exceptions in the initial contract. | Other identities' ephemeral-container debugging in protected namespaces is denied, including routine administrator debug unless the contract is explicitly changed. Debugging in unlabelled namespaces remains governed by other controls; Phorvex itself cannot inject there. |
| **PO-1: initial support/degraded behavior** | Start with one Phorvex release per cluster, linux/amd64 image, Kubernetes 1.36.2 as the validation target. Keep code-exec unavailable on missing/unknown/unsupported protection while other defenses continue. | No broader compatibility claim before testing. Use D=2s, TTL=30s, polling=10s and reporting≤40s as the proposed bounded L4 acceptance targets, not a universal latency guarantee. |

All three recommended choices were selected without a contract change. Multiple-release support or
administrator-debug exceptions would require a subsequent amendment and corresponding tests.

**Evidence:** 62 authorization queries and API discovery confirmed the proposed named policy/binding cannot
currently be read by the manager. The implementation therefore includes a separate minimal read-only grant;
that grant does not enable injection. Existing `pods/exec` permissions remain explicitly outside M6.
The live deployment is now 0.4.98; original analysis and current source/deployment observations are separately
pinned in the [full decision package](03-decision.md).

Approval record: SEC-1 **APPROVED** · SEC-2 **APPROVED** · PO-1 **APPROVED** — actual approver Mehrdad,
recorded by Claude. Implementation follows independent agreement; live changes remain separately gated.
