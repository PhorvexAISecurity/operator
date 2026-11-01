# Round 4 independent review

Reviewer: stage-review. Verdict: the real code branch of H2 and exact three-arm replay are supported; final operational and source gates are independently accepted.

The sole preregistered retry used the identical original request and produced a new actual model candidate 4b01653a26c163911122f03de94ca8386d1cd6f6 on ef94. The first attempt remains FAILED. Raw test streams independently show baseline 465 passed and retry candidate 509 passed, with the same two inherited opt-in skips and no failures. The original TestExactRuntimeMatrix blob and its 500ms subprocess deadline are unchanged and pass in both retry arms. A success after pausing owned refresh is not proof that contention caused the first failure.

The exact 2,517-byte incremental source bundle has SHA256 885ca6eedb0b757bd0a5610161d527f35585117a6e41571841add34898caecda and verifies against prerequisite ef94. Its candidate parent and two added pure helper files match the actual patch; no active selector references the helper. The replay binaries' actual embedded versions and hashes were checked independently on the host. Capture control, local base and candidate exactly matched every one of the 64 actual source/image-bound snapshots. All 576 funnel, 13,824 gate and 561 cost rows match across arms apart from arm identity. Zero changed decisions is expected for an unused helper and does not demonstrate integrated V2 activation.

The actual four Telegram deliveries match report, CSV, patch and test hashes. The final ZIP cb49697cddebf1630087ce4e21fb52d89ca227713e9e3043b25f1734f2ddd7d9 contains 14 terminal job records, preserves the original failure and 30-day refusal, and omits no pending result. Incoming Telegram ingestion was not claimed. A generic inherited 'recorded production' label in raw reports does not override the concrete stage namespace, policy, source and image provenance; raw results remain unchanged.

The retry completed in approximately 23 minutes, within the 45-minute preregistered ceiling. It issued no physical mutation and did not alter unrelated processes. Restoration of bot polling and the owned refresh timer is independently reviewed separately. A later real observation gap affects newly generated endpoint datasets, not this already frozen code replay; no gap is bridged.

Evidence: peer-review/code-retry/raw-test-log-audit.json, candidate-bundle-review.json, actual-cohort-binary-control.json and replay-delivery-review.json. Final coherent ec310 preflight, owned cleanup and fresh post-retry refresh recovery are independently accepted in the closure receipts below.

## Final closure evidence

Final review recorded after the original conditional draft. The exact ec310 recipe-2 preflight passes all 18 selected gates, plus 7 dedicated L1 and 19 dedicated L2 top-level tests. Independent strict validation binds the current product tree, source-attested CI plan, canonical diff and every raw job log. Formal non-author P3 is PASS and the fix is PR_READY; PR publication, remote CI and merge remain distinct.

Operational handover and cleanup are accepted. The automatic post-gap refresh produced 64 new snapshots with 663.16–978.50 seconds of real covered history, with no gap bridging or old-cohort reuse. Runtime identities and remote temporary-auth/scratch cleanup are independently checked. The actual source bundle, journals, cohorts and results remain retained. Local delivery-only authentication is a separate lead-owned publication task, not a runtime dependency.

Hash-bound receipts under workflow/fixes/BENCH-STAGE/evidence/peer-review:

- final-source-acceptance.json — SHA256 fb082b9f2e0be672bf559835adb043294724d08e6bb6fde2336b2afea23563af.
- final-handover/operational-review.json — SHA256 4ff58dee166905fa966e63665af0066fc36b6511c70262657524895862e5f0ab.
- final-handover/recovery-independent-review.json — SHA256 870a39bf1087a356b9af9ed6cadca6d67e57281654014ea65b7f3147e6e6c648.

Final cleanup and intentional retention are detailed in ../../cleanup-final.md. Original round manifests and failed/blocked receipts are unchanged.
