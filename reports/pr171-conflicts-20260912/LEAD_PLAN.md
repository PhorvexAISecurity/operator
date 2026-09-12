# Signed lead plan: PR171 conflict resolution

Signed root, 2026-09-12. The user requested updating existing PR171, not merging
the GitHub PR. Implementer: pr171_conflict_worker; independent reviewer: root.

Exact parents:

- PR171: `f5f75cd9d672240a5a1d7900f28951cfe234ff10`.
- Main: `528f3341f180e47fb687f3e86f3fabeba8713222`.
- Target: `main`; remote branch: `parallel/record-m018-phoenix-forensic-fields`.

The synthetic merge finds one content conflict, the generated
`workflow/fixes/INDEX.yaml`. Rebuild it from the union of authoritative status
records. Preserve all historical signed M-18 evidence byte-for-byte. Do not choose
one entire index side or rewrite another fix record.

Git auto-merges `phorvex/internal/actuator/phoenix.go`,
`phorvex/internal/runner/manager.go`, and the generated master issue view. Inspect
both-parent semantics. Preserve M-18's server-assigned Phoenix Event UID/name and
AMTD identifiers across successful and partial-failure audit records, stale-field
clearing, per-decision ownership and owner-view redaction. Preserve main's M-21
validated actuator selection/support behavior and the merged E2E capture/stub
fixes. Report any semantic contradiction rather than dropping either side.

Create a normal merge with these exact parents. Validate both-parent ancestry,
clean conflict state, generated index equality to the union of parent records and
workflow sync checks. Run focused actuator, runner, audit and console tests,
including every M018/M-18 and M021 test, plus the full relevant packages. Run the
workflow harness and chart parity/render checks when selected by the combined
change. Use isolated kube settings and no live cluster. Preserve existing skips
and report them honestly. Commit a bounded resolution report with exact commands.

Do not push, force-update, change PR metadata, merge the GitHub PR, deploy, or
perform live cluster writes. Root independently reviews the frozen candidate,
rechecks GitHub tips, and publishes the existing branch only if unchanged.
