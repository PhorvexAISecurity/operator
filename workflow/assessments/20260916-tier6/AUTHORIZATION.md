# Tier 6 scheduling and delivery authorization

On September 16, after the lead explicitly reported that Tier 5 was deployed but not fully live-verified and Tier 6 had not started, the owner instructed: **“start tier 6”**. This authorizes Tier 6 source fixes now while the remaining Tier 5 and earlier live obligations stay open. It supersedes the scheduling barrier for Tier 6 only, not the required evidence for closure or a production milestone.

Lead codex-lead investigates and signs plans; GPT-5.6 Sol workers with high reasoning implement on local issue branches. Lead independently reviews and tests every fix and requests repairs until accepted. Merge accepted local issue branches into local tier6 and publish one combined PR. No individual issue PRs. Commit count unrestricted. Never add Co-authored-by, coauthor or assistant/AI attribution to commit messages; direct every worker accordingly.

The owner/DevOps retain merge, deployment, ArgoCD, CI administration, shared infrastructure and grants. No shared cluster mutation, attack injection or restart scope is added. Existing read-only live observation can continue. Prior live evidence and missing fixtures remain explicit; do not call a deployment or source test a full live PASS. Tier 6's PR delivery is the stopping point until its deployment, subject to further owner instructions.

Fresh product baseline: 21b9ddac0ab788faee88c24488b0ff530019526c, including PR215 console session/scan recovery. Last independently observed running manager source: 65806a61f472835f3c5c4492ab88e059f74157b9, image0.4.119; these are separate pins. Production HOLD remains.

Use disk-backed temporary storage, GOMAXPROCS=2, GOFLAGS=-p=1 and a single heavy test owner to avoid resource exhaustion. Source review and implementation may run concurrently; tests coordinate through the lead.
