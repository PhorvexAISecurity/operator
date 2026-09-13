# Tier delivery policy

User instruction2026-09-13: continue the current Tier2 delivery, then from Tier3 onward deliver one PR per tier and one commit per issue. DevOps requested this to reduce GitHub runner load from many simultaneous PRs.

Tier2 keeps its existing issue PRs and explicit merge dependencies. Starting with Tier3, workers still implement in isolated worktrees and the lead independently reviews each issue. Do not open individual worker PRs. Assemble accepted changes on one tier branch, one attributable issue commit each, preserve review/test provenance and source equivalence, and validate the combined tree before publishing one tier PR. Fix review failures before publication; later repair commits should be folded into their owning issue commit before final delivery when safe and communicated. Never fabricate attested source hashes while consolidating history. Retain original review objects/artifacts using the workflow's verified provenance mechanism.

Per-issue evidence and acceptance conditions remain required. A passing combined suite does not substitute for an issue's actual producer, baseline and positive controls. Run required combined CI; avoid redundant individual PR-triggered jobs. State which issue commits are contained in the exact tested tier head.

Stop when the tier PR is review-ready with required checks passing or clearly identified infrastructure blockers. Owner/DevOps merges and deploys. Lead verifies the deployed composition and each member live before advancing. One PR does not authorize merge/deploy or weaken any evidence gate.
