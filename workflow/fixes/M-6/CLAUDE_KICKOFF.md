We are starting M-6: code-exec admission protection. Work with Codex through the NEW workflow; K3 is not assigned to this cycle. M79 is parked.

Start here:
  cd /home/mehrdad/operator-workflow
  Read workflow/AGENTS.md and workflow/operations/FIX.md.
  python3 workflow/tools/workflow.py doctor
  python3 workflow/tools/workflow.py brief M-6 --agent claude

Canonical requirements and baseline:
  workflow/fixes/M-6/TICKET.md
  workflow/fixes/M-6/00-intake.md
  workflow/fixes/M-6/BASELINE.md

Your identity is claude. You own the proposal and implementation: Go, admission/CEL manifests, Helm/RBAC packaging, tests and rollout documentation.
Codex's identity is codex-m006. Codex owns the cluster baseline, independent security/operational review, approved cluster operations, live verification and coordination. Codex has already sealed its independent 02A. Neither agent approves its own implementation. Mostafa owns the ticket's SEC-1/SEC-2/PO-1 decisions.

Product changes go in the prepared worktree:
  /home/mehrdad/operator-m006
  branch: parallel/contract-m006-code-exec-admission
Coordination and evidence stay in /home/mehrdad/operator-workflow/workflow; do not create another authoritative workflow copy in the product worktree.

Your first action: inventory the exact requests both actions emit, read the current baseline, and write workflow/fixes/M-6/01-proposal.md. Include concrete options/recommendations for Mostafa, acceptance criteria and attributable allow/deny tests. Follow the stage gates before implementation. Baseline and proposal work can proceed while decisions are open; do not enable code-exec, grant execution permissions or deploy enforcement without the required approved contract/scope.

For M6, use ONLY workflow/coordination/bus.py. File-bus communication with codex-m006 is authorized. From the workflow checkout:
  python3 workflow/coordination/bus.py list --agent claude
  python3 workflow/coordination/bus.py monitor --agent claude --interval 10 --existing

Run the monitor through your background-task facility while active; re-arm after restart. Read notified M6 messages with bus.py read <path>, handle them, then bus.py ack --by claude <path>. The monitor reports files; it does not change state or start an idle agent.

When the proposal is ready:
  python3 workflow/coordination/bus.py send --from claude --to codex-m006 --fix M-6 --role skeptic --state-from DESIGNING --request CRITIQUED --subject "M6 proposal ready" --ref fixes/M-6/01-proposal.md --needs-reply --body "Proposal ready for independent critique; see the artifact."

Keep messages to artifact references and next actions. STATUS.yaml owns state; re-read brief and use revision-checked commands. Preserve unrelated edits. Require the new incident-evidence gate before P3 and actual API-server enforcement evidence before closure. Do not use the legacy campaign bus for M6 or require the human to relay our subsequent messages.
