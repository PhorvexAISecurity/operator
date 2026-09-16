# Tier 8 scheduling and delivery authorization

On September 16 the owner explicitly requested Tier8 source work after Tier7 merged, periodic deployment observation while away, and one conclusive live verification campaign for Tiers6–8. The owner reiterated “ok then start tier 8”. This changes scheduling, not acceptance: retain per-issue verdicts and all outstanding earlier live controls. No merge, deployment, shared infrastructure mutation or production approval is delegated.

Tier8 starts at merged Tier7 source `38f1f18c6211e059217320af9168427a111de8b3`, which contains Tier6 `669197bf025a446a87ed2923c04dbaa2237ca077`. PR218 merged into tier6 after PR217 had merged to main; corrective PR219 now targets main and carries exactly the reviewed Tier7 source. Do not omit Tier7 by starting Tier8 from the older main. Reconcile the delivery target again before publishing Tier8; avoid another stranded stacked merge.

Lead codex-lead signs current-source plans, assigns the existing GPT-5.6 Sol high workers, reviews independently, and composes one Tier8 PR from local issue branches. No coauthor or assistant/AI attribution in commits. One heavy test owner at a time, GOMAXPROCS=2, GOFLAGS=-p=1, disk-backed temporary storage. Already repaired historical issues are reconciled, not reimplemented.

Five-minute read-only rollout monitoring is authorized through a local user timer and the existing lead session. It records source/digest/health observations and does not equate rollout with behavioral verification. DevOps retains deployment, RBAC and infrastructure administration. The central live backlog remains authoritative for missing controls, including real MIG hardware and M92's unimplemented source gap.
