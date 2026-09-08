# M6 bootstrap handoff / workflow PR

Authorized by Mehrdad on 2026-09-08: commit/push the workflow changes; when the M6 PR is ready,
open the docs/workflow PR too. Do not open the workflow PR early or infer merge permission.
Coordinator owns this follow-up; it is part of the active delivery, not a request for another approval.

Current record: /home/mehrdad/operator-workflow/workflow/fixes/M-6.
Product branch: parallel/contract-m006-code-exec-admission in /home/mehrdad/operator-m006.
Shared runtime bus: Git common directory / phorvex-workflow/bus.

1. Finish M6 implementation, independent incident/P3 review, and open its authorized PR.
2. Open the workflow PR from docs/workflow with final validation and current record snapshots.
3. After authorized merges put both code and framework on main, fetch and incorporate main into the
   retained M6 branch. Never discard later local verification evidence with a hard reset.
4. Pause record writers; compare/import any newer M6 artifacts and record their hashes. Its own
   workflow/fixes/M-6 then becomes authoritative; notify Claude and Codex with the new workflow_root.
5. Re-arm both runners and the supervised bridge from that worktree before retiring the bootstrap
   checkout. Continue separately authorized deployment and L3/L4 on the same issue branch.
6. Publish later verification/closure records through an evidence follow-up PR; the original merged
   code PR does not contain those later commits. Preserve all code/deployment/decision pins.

Future issue branches use their own local fix directory from the start. No assistant-attribution
trailers are permitted in Git commits.
