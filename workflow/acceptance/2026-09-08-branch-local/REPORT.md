# Branch-local workflow and publishing cleanup

User authorized committing/pushing docs/workflow now, and opening its PR when M6's PR is ready.
The next named issue should own code and workflow/fixes/<id> in the same branch/worktree. After its
code PR merges, retain that branch, incorporate main, and continue live evidence there; publish later
records with an evidence follow-up PR. Shared runtime transport does not make fix records shared.

Implemented a Git-common-directory bus with source-worktree metadata, runtime identity registration,
and layout diagnostics. The active bus migrated under /home/mehrdad/operator/.git/phorvex-workflow/bus
with all 81 pre-cutover message/ack hashes preserved. Legacy inbox/archive aliases keep current monitors
working. The supervised Codex bridge restarted successfully; no messages or thread identities were reset.
Migration receipt is in bus-migration.json. New worktrees resolve the same bus and retain separate records.

The current bootstrap exception is deliberate: M6 product implementation is already underway in
operator-m006, so its record remains in operator-workflow until the framework lands on main. Both
writers coordinate a hash-preserving import into operator-m006/workflow/fixes/M-6 after merging main.
Do not retire the bootstrap checkout until both runners/service paths are re-armed from the issue branch.
This transition is specified in operations/WORKTREES.md and fixes/M-6/WORKTREE_HANDOFF.md.

Git preference saved in global Codex instructions/memory and repository instructions: no Co-authored-by
trailers or similar assistant attribution in commits. Configured human author is retained.

Validation: all 77 tests passed, including cross-worktree shared bus resolution, branch-local record
isolation, message workflow_root, shared identity registration/path validation, existing bus recovery,
and autonomous PR/evidence gate regressions. Deep doctor: zero errors, thirteen existing release/anatomy
and historical-fixture warnings. git diff --check passed. Publishable workflow content was checked for
large files and recognizable credential patterns; no new credential findings or files over 10 MB.
