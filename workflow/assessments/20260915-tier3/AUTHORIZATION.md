# Tier 3 scheduling and delivery authorization

On September 15 the owner instructed: “verify what is possible right now and
start tier 3. it will be several hours before I'll have access to our devops
and don't want to waste time”. This explicitly permits Tier 3 implementation
before every outstanding Tier 2 live control is complete. It supersedes the
scheduling hold in the earlier Tier 2 report, not its recorded observations.

The lead completes available read-only checks and carries forward unavailable
Tier 1/2 controls as pending. No issue or tier is marked live-verified merely
to advance scheduling. Recheck affected source dependencies against fresh main.
This is a Tier 3 start override, not a blanket waiver for all later tiers.

Lead codex-lead investigates, signs each fix plan, independently reviews worker
implementations, runs appropriate validation and delivers one combined Tier 3
PR. Workers use GPT-5.6 Sol. Keep local branches/worktrees per issue, compose
accepted issue branches into local `tier3`, preserve commits, and open no
individual issue PRs. Commit count is unrestricted. Never add coauthor,
Co-authored-by or assistant/AI attribution to commit messages; convey this rule
to every worker and check messages before commit/push.

Source investigation, isolated local tests, implementation, evidence, commits,
branch push and reviewed PR delivery reuse operations/AUTONOMY.md. Owner/DevOps
retain merge, deployment, infrastructure, CI administration and access grants.
No shared mutation, attack, credential issuance or GPU actuation is added by
this scheduling instruction. Existing bounded live scope may be reused only
for its covered targets/actions. Source gaps remain the lead/workers' task.

Fresh source main: `3906776ffcd04d6c44357f7adbc6809b49c6dfb2`.
Last observed manager source: `b1db5bdab328dc9c006e45c9171c3e7e35330285`,
release 0.4.116. Coordinator starts from the preserved Tier 2 source/evidence
composition at `98cef23e`; product source contains fresh main. No new CI or
deployment action is authorized. Prior [live evidence](../20260914-tier2-live/REPORT.md)
and [owner handoff](../20260914-tier2-live/DEVOPS-HANDOFF.md) remain valid within
their recorded times and limits.
