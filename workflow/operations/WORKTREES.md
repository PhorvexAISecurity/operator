# One issue branch owns code and fix evidence

After this framework is on main, create an issue branch/worktree from reviewed main
and work entirely there: code, `workflow/tools`, and `workflow/fixes/<fix-id>`.
Commit the issue's evidence with its code; do not maintain a second authoritative
record in a workflow-only checkout. Keep generated index/issue views synchronized.

The runtime bus is shared under the repository's Git common directory
(`phorvex-workflow/bus`), outside commits. `bus.py layout` shows its location.
Register any new identity with `bus.py register --agent <id>`. Messages include
the sender's `workflow_root`; use that checkout's tools/status for its fix.
Two agents working one issue share that issue worktree's record. They do not each
create a competing copy. Read the latest revision before writing.

After the code PR merges, retain the issue worktree. Fetch main and merge it into
that branch (or fast-forward when possible); never reset away verification evidence
or silently rebase published history. Continue incident/deployment/L3/L4 records
in the same `workflow/fixes/<id>`. Code-merge status is historical; an evidence-only
follow-up PR synchronizes later verification and closure back to main. It does not
pretend the already-merged PR includes later evidence. Merge/deploy permissions
still follow separately recorded scope.

Concurrent issue branches may conflict in generated indexes/registers: reconcile
their underlying status/entry records, preserve both issues, then regenerate views.
Do not resolve a conflict by replacing another issue's directory wholesale.

## Current bootstrap exception: M6

The in-progress M6 code is in `operator-m006`; its current record remains in
`operator-workflow` until the framework lands, to avoid a mid-write relocation.
When M6 reaches PR_READY/IN_PR, open the requested docs/workflow PR as well.
After those merges, incorporate main into the retained M6 branch, pause both
writers briefly, import any newer M6 evidence with hashes, and designate its local
`workflow/fixes/M-6` as authoritative. Notify/re-arm both runners from that checkout
before retiring the bootstrap checkout or updating its service executable path.
Do not duplicate the whole framework into the M6 product PR during bootstrap.
