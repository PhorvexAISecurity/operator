# Brain recommendation assessment

- Status: REPORTED_WITH_GAPS. Report and independent correction review complete;
  empirical adoption experiments remain explicitly unrun.
- User scope: recommendation document for the overall brain, scorer, availability
  cost, physics, context, optimization and confirmed actuation, with reasoning and
  examples; complete the separate PR182 for review/merge alongside tier 1.
- Mode: follow-up to V3, with prior source/issue/audit exposure declared. This is
  not a blind from-scratch system assessment.
- Lead/author: codex-lead, current Codex session; exact model variant not asserted.
- Source auditors: claude-brain-cost and claude-brain-context, explicit
  `claude-opus-5`, requested effort `high`; reported model agrees. Both finished
  R1 and bounded R2 corrections. No source auditor is the final report approver.
- Independent final reviewer: claude-brain-final, explicit `claude-opus-5`,
  requested effort `high`, reported model `claude-opus-5`; final R2 **PASS**.
  See [final verdict](review/FINAL-REVIEW-R2.md) and [worker receipts](review/worker-receipts.json).
- Source: freshly fetched main `528f3341f180e47fb687f3e86f3fabeba8713222`;
  branch `docs/brain-math-recommendations`. Source fingerprints in
  [source.json](evidence/source.json).
- Historical V3 source: `dbf5fa4321b35651e8142cb2c13d4f28f8c6dcca`.
- Observed deployment: retained read-only 2026-09-12 07:43 UTC identity check,
  manager `0.4.109`, digest
  `sha256:e384b100ddef9bc611971dbea1337ec43a994a36188671aced3b4355aa9470df`;
  36 dev decisions identify the V3 source. Identity only, not fix or recommendation
  acceptance. Originals are in the Git-common private `postdeploy-20260912/` runtime.
- Live phase: no new recommendation experiment run. Earlier passive observation
  and identity limits are preserved. No new production parameter or algorithm,
  cluster mutation, merge, deployment or infrastructure change is made by this report.
- Validation: 113 workflow tests pass; doctor has zero errors and 17 historical
  warnings. Nine named source tests (12 cases) pass in four packages. All 19
  worker probes independently pass in the lead worktree on synthetic inputs.
  Report examples include 3,645 enumerated ordinary selection cases. Links,
  source fingerprints and all 17 immutable V3 research IDs pass delivery checks.
- Register reconciliation: [lead dispositions and retained candidates](review/LEAD-DISPOSITION.md).
  Canonical states/IDs and the tier schedule are unchanged. Tier 1 remains at its
  deployment/live-acceptance barrier; this does not start tier 2.
- Deliverables: [REPORT.md](REPORT.md), [retained brief](SCOPE.md),
  [coverage and gaps](COVERAGE.md), source audits and reproducible evidence.
- Lead disposition: accepted for recommendation-document publication after R1/R2
  correction review. Final report SHA256: `02534565b0a8f9cc12cc2f4726f688097ebcece4d15248741dad34521bb02224`.
- Next: owner review/merge of PR182. Implement recommendations only through their
  normal fix/review, deployment and live-acceptance gates; keep empirical claims qualified.

Never add co-author or AI/assistant attribution to commit messages. This was
conveyed to every peer and the publication commit message is checked before pushing.
