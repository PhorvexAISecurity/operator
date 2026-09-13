# Tier 1 deployment assessment

> **15:52 UTC update:** PR179 has since merged; the observed Pod still runs0.4.112. See [the timestamped update](UPDATE-1552.md). The original-window findings below retain their original pins and timing.

Status: REPORTED_WITH_GAPS; Tier 1 remains open for repair and acceptance.

This is a bounded continuation of the September 10 readiness assessment after
the owner's September 13 deployment notice. It is not a new exhaustive audit,
a replacement master register, or permission to begin Tier 2.

- Lead and live observer: codex-lead.
- Independent reviewer: claude-tier1-auth-review, Claude Opus 5, high effort.
  Its initial source investigation and plan review are separate from the lead's
  live observations; review of this assessment packet passed after corrections; see
  [independent review](auth-integration/ASSESSMENT-REVIEW-R2.md) and
  [lead disposition](LEAD-DISPOSITION.md).
- Source: `6ed7d3135e97de68eaf8ebb607ddab4833d22d20`.
- Running operator source: `58363a1796cd03c3f7834c5814f85799df95b56f`.
- Running image identities: [report](REPORT.md) and
  [container receipt](evidence/deployed-containers.json).
- Scope and ceilings: [SCOPE.md](SCOPE.md).
- Coverage and limits: [COVERAGE.md](COVERAGE.md).
- Observations and per-fix acceptance: [REPORT.md](REPORT.md).
- External prerequisites: [DEVOPS-HANDOFF.md](DEVOPS-HANDOFF.md).
- Evidence integrity: [manifest](evidence/manifest.json).

No issue is closed or assigned L3 PASS by this packet. Seven implementation
merges are present in the running source; M161/PR179 is absent. M136 has an
authenticated-caller integration follow-up, T1-E2E-AUTH, with a separate signed
plan and worker implementation. Its local source review does not provision the
live principal or substitute for successful live controls.

The next owner action is legitimate console access provisioning and completion
of the outstanding Tier 1 PRs/deployments. The lead then repeats identity checks
and completes each registered acceptance experiment within its authorized scope.
