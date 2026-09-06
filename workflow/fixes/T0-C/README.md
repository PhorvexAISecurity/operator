# fixes/T0-C — B-5/R-2/R-9 · "record the complete decision path" (Tier 0)

Fix-loop cycle 2. **Roles this cycle (alternated per FIX_LOOP §1): K3 = Proposer, Claude = Skeptic.**
Lead/decider remains Claude (Mehrdad's instruction). Branch `t0/record-complete-decision-path`
cut from `origin/main` @ `515c56a` (release v0.4.74, == deployed `phorvex:0.4.74`).

Standing rules (Mehrdad, 2026-09-02): (1) no agent names or Co-Authored-By/Generated-with in
commit messages or PR text; (2) nothing under `fixes/` is ever committed — the record lives here,
untracked. Repo receives only commits that address the ticket.

Lifecycle caveat: no dev cluster. TESTED offline → PR → DevOps merge+deploy → K3 L3 on the
cluster → verdict. If red, back to PROPOSED with a new commit + PR.

Ticket text: `TICKET.md` (verbatim from the boss, 2026-09-03). Note the ticket was written against
the anatomy at `fb52e6c`; `DecisionTraceV2` (T0-D, `c53258d`, 2026-08-30) landed after that and is
live at 0.4.74 — the gap map must be against the CURRENT record, not the ticket's quotation.

Files (same schema as T1-A): 01-proposal (K3) · 02-critique (Claude; §A blind derivation written
BEFORE opening 01) · 03-decision · 04-diff.patch · 05-evidence · 06-verdict · STATUS · verify.sh.
