# M6 continuation

State: IN_PR. Product PR: https://github.com/PhorvexSecurity/operator/pull/143
Reviewed head: `9eb14271625620aef6b6184386764e29f0d71ea3`.
Independent incident/P3 and implementer offline checks PASS. Baseline RED and head
GREEN ran through real handlers on isolated Kubernetes 1.36.2; see evidence/incident.md.

Current roles: Claude implements; codex-m006 independently reviews/verifies and
coordinates. Current record root remains this bootstrap workflow checkout.

Next: coordinator opens the companion docs/workflow PR. Neither PR is merge or
shared deployment authorization. L3/L4 are REQUIRED and PENDING; old unsigned
verification display strings are not waivers. The signed required-level contract
and checks govern acceptance.

After separately authorized merges, follow WORKTREE_HANDOFF.md: incorporate main
into the retained issue branch, preserve/import latest records, switch both agents
and monitor paths to its own workflow directory, then continue authorized live
verification. No hard resets or evidence loss.

Resume with `python3 workflow/tools/workflow.py brief M-6 --agent <assigned-id>`
and drain `python3 workflow/coordination/bus.py list --agent <assigned-id>`.
Runtime bus is shared under the Git common directory; follow each message's
workflow_root. Do not create another agent or change roles.

Superseded working notes: evidence/coordination/resume-history-through-rev53.md.
