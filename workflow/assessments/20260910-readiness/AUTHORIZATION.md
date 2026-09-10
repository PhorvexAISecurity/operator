# User authorization and completion boundary

The user explicitly requested a fresh, code-verified master issue list and Anatomy
V3, discovery of missed defects, and remediation through parallel Claude workers.
The latest instruction requests both V3 artifacts and at least all first-tier PRs
before stopping to await deployment. This authorizes investigation, deduplicated
issue filing/reconciliation, lead-approved implementation, tests, branch pushes
and reviewed PR delivery. Routine work requires no renewed permission.

Use Claude Opus5 with max reasoning for every new worker invocation and resume.
Codex leads/plans/reviews; Claude implements. No implementation author may approve
their own implementation. Never add co-author or AI/assistant commit attribution.

The user and DevOps own merge and deployment. Agents must not merge, deploy, change
shared infrastructure, or run unscoped live attacks. Read-only dev observations
are authorized. Each completed tier waits for all members to be deployed and
verified before implementation of the next tier. Source/PR delivery is not live
closure, and no proof of an entirely bug-free system is claimed.

This campaign retains unknowns and models/research requests rather than silently
calling them solved or accepting their risk on the user's behalf.
