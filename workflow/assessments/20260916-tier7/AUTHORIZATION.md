# Tier 7 scheduling and delivery authorization

On September 16 the owner requested: “can't you start tier 7 while he deploys tier 6? we are tight on bugdge” and asked for a durable list of unverified live controls. This authorizes Tier7 source work now and the linked live-verification backlog. It supersedes the scheduling barrier for this tier only. Pending Tier6/earlier live acceptance, merge/deployment ownership and production HOLD remain unchanged.

Lead codex-lead reconciles each historical issue against actual code, signs plans, independently reviews workers and composes one tier7 PR. Continue the authorized GPT-5.6 Sol high workers; reuse existing sessions and tests where applicable. Never add Co-authored-by, coauthor or assistant/AI attribution to any commit. Keep local issue branches and independently accepted evidence; no issue PRs.

At intake, fetched main is `b82a6b5d5e0841b3ab855f50f3f8b44cdc06f97a`; Tier6 PR217 is open with source `669197bf025a446a87ed2923c04dbaa2237ca077`. Tier7 is based locally on that exact reviewed Tier6 composition to avoid duplicating already fixed code. This is a source dependency, not proof that Tier6 is merged or deployed. Reconcile main before final PR publication and preserve the correct PR base if Tier6 is still unmerged.

DevOps retains merge, deployment, CI administration, grants and shared infrastructure. Existing read-only observation is allowed; no new shared-cluster mutation, restart, injection or hardware drill is authorized. Local isolated controls remain allowed. The [live-verification backlog](../LIVE-VERIFICATION-BACKLOG.md) preserves every known missing acceptance category and links the exact prior tier contracts.

Use one heavy build/API-test owner at a time, disk-backed temporary storage, GOMAXPROCS=2 and GOFLAGS=-p=1. Source investigations can run in parallel. Do not rewrite an already repaired issue merely to fill its historical tier slot.
