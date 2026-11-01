# Round 4 independent review draft

Reviewer: stage-review. Verdict: the real code branch of H2 and exact three-arm replay are supported; overall closure is conditional on final operational and source gates.

The sole preregistered retry used the identical original request and produced a new actual model candidate 4b01653a26c163911122f03de94ca8386d1cd6f6 on ef94. The first attempt remains FAILED. Raw test streams independently show baseline 465 passed and retry candidate 509 passed, with the same two inherited opt-in skips and no failures. The original TestExactRuntimeMatrix blob and its 500ms subprocess deadline are unchanged and pass in both retry arms. A success after pausing owned refresh is not proof that contention caused the first failure.

The exact 2,517-byte incremental source bundle has SHA256 885ca6eedb0b757bd0a5610161d527f35585117a6e41571841add34898caecda and verifies against prerequisite ef94. Its candidate parent and two added pure helper files match the actual patch; no active selector references the helper. The replay binaries' actual embedded versions and hashes were checked independently on the host. Capture control, local base and candidate exactly matched every one of the 64 actual source/image-bound snapshots. All 576 funnel, 13,824 gate and 561 cost rows match across arms apart from arm identity. Zero changed decisions is expected for an unused helper and does not demonstrate integrated V2 activation.

The actual four Telegram deliveries match report, CSV, patch and test hashes. The final ZIP cb49697cddebf1630087ce4e21fb52d89ca227713e9e3043b25f1734f2ddd7d9 contains 14 terminal job records, preserves the original failure and 30-day refusal, and omits no pending result. Incoming Telegram ingestion was not claimed. A generic inherited 'recorded production' label in raw reports does not override the concrete stage namespace, policy, source and image provenance; raw results remain unchanged.

The retry completed in approximately 23 minutes, within the 45-minute preregistered ceiling. It issued no physical mutation and did not alter unrelated processes. Restoration of bot polling and the owned refresh timer is independently reviewed separately. A later real observation gap affects newly generated endpoint datasets, not this already frozen code replay; no gap is bridged.

Evidence: peer-review/code-retry/raw-test-log-audit.json, candidate-bundle-review.json, actual-cohort-binary-control.json and replay-delivery-review.json. Final source preflight, owned cleanup and fresh post-retry refresh recovery still gate campaign closure.
