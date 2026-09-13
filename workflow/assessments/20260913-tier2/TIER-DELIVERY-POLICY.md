# Tier delivery policy

User instruction2026-09-13: continue the current Tier2 delivery, then from Tier3 onward deliver one PR per tier. The user subsequently clarified: keep local issue branches, merge all completed issue branches into one local tierN branch, and retain any number of commits. This supersedes the earlier one-commit-per-issue preference. DevOps requested this to reduce GitHub runner load from many simultaneous PRs.

Tier2 keeps its existing issue PRs and explicit merge dependencies. Starting with Tier3, workers still implement in isolated worktrees and the lead independently reviews each issue. Do not open individual worker PRs. After every issue branch is independently accepted, create a local tierN branch and merge those issue branches into it. Preserve their commits and review/test provenance; there is no squash or commit-count requirement. Resolve composition conflicts and validate the entire resulting tree before opening the single tier PR. Fix review failures before publication. Retained merge ancestry must keep original reviewed source objects reachable; never fabricate attested source hashes.

Per-issue evidence and acceptance conditions remain required. A passing combined suite does not substitute for an issue's actual producer, baseline and positive controls. Run required combined CI; avoid redundant individual PR-triggered jobs. State which issue commits are contained in the exact tested tier head.

Stop when the tier PR is review-ready with required checks passing or clearly identified infrastructure blockers. Owner/DevOps merges and deploys. Lead verifies the deployed composition and each member live before advancing. One PR does not authorize merge/deploy or weaken any evidence gate.
