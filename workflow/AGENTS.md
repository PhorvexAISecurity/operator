# Agent entrypoint

This harness works through files and explicit roles, not model names or chat
memory. The current user request controls scope and authorization.

1. Classify the task using `OPERATIONS.md`; read **one** matching runbook.
2. Run `python3 workflow/tools/workflow.py doctor` once per work session.
   Report relevant failures; an unrelated historical gap does not prohibit
   useful work on your authorized task.
3. For a fix, run `brief <fix-id> --agent <your-assigned-id>`. Read only its
   listed stage, issue, source locus, and artifacts. If unassigned, the
   coordinator records your role first. Do not infer a role from “Claude,”
   “Cursor,” or an earlier ticket.
4. Complete the work owned by your role, record evidence, then hand off.
   Continue through authorized steps you own; stop at a different owner,
   a concrete blocker, or an action outside recorded approval scope.

## Hard boundaries

- The skeptic derives independently **before** reading the proposal, diff,
  implementation commits, or related messages. Seal `02A` using `seal --by`.
  Read only the baseline source until sealed. Role alternation is optional;
  independent derivation and independent review are mandatory.
- The proposer/implementer cannot sign critique, P3, or final review. The
  implementer cannot sign live verification of their own change.
- A `PASS` string is insufficient: `record-check` binds signer, artifact hash,
  and source/deployment pin. Missing evidence stays unavailable or blocked.
- Never equate Selected, Dispatched, Emitted, Executed, Confirmed, or
  Attack-mitigated. A null result requires a positive control.
- Before P3, independently reproduce the incident through the real producers
  of the fix's inputs; sign `incident`. A mocked final flag is not that proof.
- Use `transition --expect-revision <brief-revision>`; stale work must be
  reread. Commands serialize the complete read/validate/write transaction.
- Reuse explicit authorization already given. Record its reference and scope
  (e.g. `pr_open`, `deploy`); do not ask again for that scope. Uncovered merge,
  deployment, attack, waiver, or accepted-risk decisions remain human gates.
- Generated register/anatomy files are read-only. Edit their authorities and
  regenerate. Notifications carry references; they do not change state.

## Context and handoff

Do not preload the master register, full anatomy, archives, raw corpora, or bus
history. Use `brief` and targeted source reads; expand only for a demonstrated
dependency. `WORKFLOW.md` is the compact protocol reference, not required
startup reading. `MANIFEST.yaml` locates authorities when needed.

Handoff: **fix/operation ID · state + revision · next owner/action · artifact
references · source/deployment pins · blockers**. Send no proposal content to
an unsealed skeptic. Record status before notifying; do not send messages
unless communication is authorized.

Use isolated worktrees for product changes. Preserve unrelated edits. A
harness-only task may update its existing development worktree. Historical
records are evidence, not proof of current deployment or permission.
