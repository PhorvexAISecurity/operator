# Independent resident-transport review

Reviewer `/root/agentic_reviewer`; independent of the runner, observer/gate and supervisor authors. Source checkout ca69456b17299aa742c5ea9275fb5e6ae9cccfa4. Recorded 2026-10-10T13:36:20.996518+00:00. No mutation lease, serving requests, staged artifacts or events were created by this review.

**Current disposition: FINAL_READY for supervisor freeze and independent read-only check-live, on the final source pins below.** This supersedes the blocked resident snapshot for code readiness. Actual current transport acceptance, serving baseline, observation/native effect, cleanup, fresh reproduction and architecture acceptance remain unproved. No mutation lease is granted.

## Retained pre-fix disposition

**BLOCKED for live readiness on runner f9e78ec5...** Two narrow defects remain: bulk audit segment-prefix download precedes the first timed native journal poll, and malformed stop input raises only inside a helper thread while the main helper can exhaust its request plan and exit successfully. The earlier cold schedule failure and its superseded code acceptance remain intact in REVIEW-TRANSPORT-FEASIBILITY.md and REVIEW-PREFLIGHT-FINAL.md. Repairs must change source pins and be reviewed before read-only check-live. This report contains no live PASS.

The resident implementation removes per-request SSH startup by preserving a fixed helper source, exact request plans, nonce-bound streamed original replies and actual HTTP UTC/monotonic timestamps. Host API reads preserve original inner GET envelopes; normalization uses each channel's independently measured offset. Five nonce samples use full RTT/2 +5ms, reject wall clock steps, and require each channel <=100ms; max(A-node,B-node)+API must fit200ms. The physical gate still widens the entire conservative dispatch bracket by200ms and requires a single actual B32 flight to contain it. No service time is subtracted and exact native endpoints remain unmeasured. Cold startup and warm GET measurements support attempting the scoped schedule; actual model latency and containment remain unproved until physical originals exist.

Timed journal polling now excludes cold observer logs; only absent, independently pinned prior completed or exact current prepared receipt may advance the conservative lower bound. Per-request budgets, actual counts distinct from reserved intents, six paired retests anchored to the first actual A start, native receipt ownership, unchanged source/declared configuration, and before-cleanup evidence remain strict. Lost load ACK is not replayed; unresolved native operation or cleanup retains reconciliation responsibility. Exact resource/fixture cleanup, EOF channel closure and independent final seals remain necessary.

## Authoritative API verification and corrected inference

The independent read-only CRD GET at2026-10-10T13:28:23.094841–13:28:24.672339Z exited0. Installed `securityevents.amtd.r6security.com` is cluster scoped, served+storage `v1beta1`, UID c82dd949-1a63-4ce5-bdff-437ac35f856e. The observer's original event API was correct. The runner incorrectly used the separate PhorvexPolicy group. My initial inference from policy GroupVersion was insufficient; root and the source reviewer identified that distinction before any observer group edit or stimulus. The authoritative capture corrects the inference explicitly. The new selected schema fixture matches this independent original exactly, including string anomalyScore. Runner paths now match the event CRD, while policies retain phorvex.ai/v1alpha1.

Ten independent local unittest methods passed on observerd529718..., gate8ea9a3..., testsb332344... with exit0. They include exact cluster GET/POST/DELETE paths and body types, producer/runner route consistency, wrong event API/kind rejection, original event reconciliation, failed ordinary traffic, budgets/cadence, prior receipt pinning, exact inventories and cleanup seal rejection. Additional reviewer-authored offline probes pass nonce/order/short-batch rejection, callback-error terminal drainage, exact own repeat stop, full RTT/2+5 threshold, wall-step rejection, and request/timestamp normalization retaining raw originals. Four embedded helper bodies compile. These tests are synthetic and do not establish physical recovery or runtime outcomes.

The malformed-stop regression executes original HTTP helper control flow with only request() replaced by a pure fake. Wrong nonce produced a thread AssertionError but90 responses, normal done and exit0; the original helper hash and exact transformation boundary are preserved. The bounded correction must propagate a stop parse/nonce error to the main helper, stop further requests, preserve originals and fail closed. A valid owned stop and clean exhaustion must still close without an orphan reader.

## Bounded documentation review

The current RUNBOOK cleanup mapping is sound: original outcome/retests are durably immutable before cleanup; independent adjudication can follow bounded safety cleanup against those bytes. Cleanup earns no defense credit. Honest failed outcomes may release only after independent safe-state confirmation; unresolved operation/ownership/absence holds the lease. The six prompts, role separation, typed handoffs, stages and failure routing form a portable guide rather than an implemented LangGraph service.

ARCHITECTURE-V3 remains a candidate, preserves the failed cold schedule and requires actual transport feasibility. README is a usable portable entrypoint. The interim LIVE-TRIAL-REPORT accurately leaves physical baseline, native effect, retests, cleanup, fresh reproduction and architecture acceptance NOT RUN/NOT ESTABLISHED. It distinguishes declared configuration, audit-source provenance and incomplete binary attestation. Formal SLO remains UNKNOWN. No material prose blocker was found in these pinned bytes.

## Retained input and evidence pins

| Path | SHA256 |
| --- | --- |
| build/test-harness/verification-workflow/live_adapter/run_episode.py | `b5be9d155f9004c517d2399e5f5f6ada2f10b2bc402afb7846c2f169f8c93ea5` |
| build/test-harness/verification-workflow/live_adapter/README.md | `bc8857ce0bab88bbd470595f1d05d9b6f95e619abe3d00c2a4eb369701143d06` |
| build/test-harness/verification-workflow/live_adapter/observer.py | `d529718a498b341cd5c38b1670b40112cdbefe5c303f681ab81bba97edef2eaa` |
| build/test-harness/verification-workflow/live_adapter/gate.py | `8ea9a3e3e4ce2fd027323d90591c0a97d96e0578620b79acf6aebe5d7e8451ae` |
| build/test-harness/verification-workflow/live_adapter/test_live_adapter.py | `b3323447eae019f2456e48b7d762abc4e633e2315736465a52e764cd5a981fe8` |
| build/test-harness/verification-workflow/live_adapter/securityevent-api-fixture.json | `164348256d9a945dc150fb89ce21aaed657498e78bbe317ba2c847fd5871a7db` |
| docs/verification-loop/agentic/RUNBOOK.md | `843e8e4eb299d20ce18ed6de0beb09d818b674014856f935b4db9cb9c40d645e` |
| docs/verification-loop/agentic/ARCHITECTURE-V3.md | `bf864c5acb2683b734e0750f5a70faa898d8ee60e6e4ac08c7611686e2d64687` |
| docs/verification-loop/agentic/README.md | `3e3d89d1d28d2260f829f2f34c9132a1014936ace07602b23d61922ee6f7d725` |
| docs/verification-loop/agentic/experiments/live-v2/LIVE-TRIAL-REPORT.md | `459694376c56be08b38704b35182df2dec70c91e7a3decdfbacbd8f47a2c1f67` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-schema-preflight/securityevent-crd.original.json | `ec5af2e07a05679ef351c21d371b688dd74c6ffe4648ac4281b167f7c1d77e37` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-schema-preflight/receipt.json | `b0fc74b793c91a399db2c374edc3c8a796a1a8bf6393a53e4ca46216b93ae81d` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/adverse_checks.py | `4e2346a269a758c93ee1b594ab0b271c1fdf6f02e2d909cb87a0ebb571d59dfe` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/adverse-results.json | `54f219eb17b4787f7d92af0ac0fa2a6e00fe762208a70822d09389e35446688c` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/helper_stop_check.py | `61be7960024b50a73c48495d80e2a271c092085618179ac624bcaa93fbefedc7` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/helper-stop-result.json | `52b68741497769326b92f67f9e8b5c97dc77eb49aac7c1abda707a70183ac79f` |

Next owner: runner author corrects only the two concrete defects; independent reviewer reruns affected adverse checks and pins the final stationary source. Supervisor then seals current inputs for the independent verifier's read-only runtime check. Physical work still requires separate frozen scope and explicit lease; future architecture acceptance requires both fresh physical episodes and independently accepted evidence/cleanup.

## Final stationary repair and acceptance

Recorded 2026-10-10T13:39:59.219749+00:00. Runner b5be9d155f9004c517d2399e5f5f6ada2f10b2bc402afb7846c2f169f8c93ea5 defers bulk audit prefix retrieval until the first completed raw journal read is durable and the B loop has stopped/joined. The timed poll contains warm exact journal GETs and bounded polling waits; cold observer receipts and audit attribution follow the captured bracket. A stop parse/nonce/size/active-EOF error now stops the loop, joins its reader, emits a nonce-bound terminal error and exits2; Resident records and rejects that error without replay.

The exact original-control-flow regression (only HTTP request() replaced by a pure offline fake) now rejects wrong nonce with exit2 after2 responses. The six-case matrix independently rejects wrong nonce, malformed JSON, oversized stop and active EOF; valid own stop and complete90-request exhaustion return done/exit0 without reader errors. The original failing helper result remains unchanged. Sixteen additional adverse/syntax checks passed again against final bytes. Ten unittest methods passed independently at2026-10-10T13:38:03.662151–13:38:04.000676Z, exit0, with all source hashes equal before and after. No network, helper CLI or physical traffic was used by these local checks.

Freezing allow_failed_outcome_cleanup_unload=true is within the existing bounded safety branch: only after durable outcome, no ambiguous effect, absent/completed native state, quiescent observer and exact current UID/owner/digests; at most one exact owned unload followed by absence readback, never replay or defense credit. Unresolved native/acknowledgement/ownership/absence still blocks release. Positive case acceptance remains dependent on immutable precleanup denial, full legitimate traffic, entire-bracket overlap and all retests, independently adjudicated later.

No remaining material code blocker was found in the final scoped candidate. Acceptance is conditional on freezing these exact sources with independently observed configuration/authority/schema originals and passing the current read-only clock/transport check before any mutation lease. A failed physical predicate must remain INCOMPLETE or failed under the original oracle; no widened timing/budget or alternative action earns a pass.

### Final accepted sources and supporting pins

| Path | SHA256 |
| --- | --- |
| build/test-harness/verification-workflow/live_adapter/run_episode.py | `b5be9d155f9004c517d2399e5f5f6ada2f10b2bc402afb7846c2f169f8c93ea5` |
| build/test-harness/verification-workflow/live_adapter/README.md | `bc8857ce0bab88bbd470595f1d05d9b6f95e619abe3d00c2a4eb369701143d06` |
| build/test-harness/verification-workflow/live_adapter/observer.py | `d529718a498b341cd5c38b1670b40112cdbefe5c303f681ab81bba97edef2eaa` |
| build/test-harness/verification-workflow/live_adapter/gate.py | `8ea9a3e3e4ce2fd027323d90591c0a97d96e0578620b79acf6aebe5d7e8451ae` |
| build/test-harness/verification-workflow/live_adapter/test_live_adapter.py | `b3323447eae019f2456e48b7d762abc4e633e2315736465a52e764cd5a981fe8` |
| build/test-harness/verification-workflow/live_adapter/securityevent-api-fixture.json | `164348256d9a945dc150fb89ce21aaed657498e78bbe317ba2c847fd5871a7db` |
| docs/verification-loop/agentic/RUNBOOK.md | `843e8e4eb299d20ce18ed6de0beb09d818b674014856f935b4db9cb9c40d645e` |
| docs/verification-loop/agentic/ARCHITECTURE-V3.md | `bf864c5acb2683b734e0750f5a70faa898d8ee60e6e4ac08c7611686e2d64687` |
| docs/verification-loop/agentic/README.md | `3e3d89d1d28d2260f829f2f34c9132a1014936ace07602b23d61922ee6f7d725` |
| docs/verification-loop/agentic/experiments/live-v2/LIVE-TRIAL-REPORT.md | `459694376c56be08b38704b35182df2dec70c91e7a3decdfbacbd8f47a2c1f67` |
| docs/verification-loop/agentic/experiments/live-v2/MEASUREMENT-PLAN.md | `237aa8e3df7b3ecc8efb8f6484dee82ca66caffd12aac9fdd2e7b95e575c00aa` |
| docs/verification-loop/agentic/experiments/live-v2/PRECHECK.json | `b43550707583eb35c3b01f5d98457aeab71d853abbef608601435e5a5584048a` |
| docs/verification-loop/agentic/experiments/live-v2/CASE-PROPOSAL.json | `45ccb9b3a5e979944f81fce6e1510303c5ad8305221eaf6cc75020c78e0fc3d6` |
| docs/verification-loop/agentic/experiments/live-v2/PLANNING-ADDENDUM-1.md | `f83546f8f1400c14064c6d83a44184a7b159beedafe9c778f87224db89464a5e` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/adverse_checks.py | `4e2346a269a758c93ee1b594ab0b271c1fdf6f02e2d909cb87a0ebb571d59dfe` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/adverse-results.final.json | `fc2adeeade9740a4a372efcd80c7f6db20da92fc8262f2a914d89146215c9f38` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/helper_stop_check.py | `61be7960024b50a73c48495d80e2a271c092085618179ac624bcaa93fbefedc7` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/helper-stop-result.json | `52b68741497769326b92f67f9e8b5c97dc77eb49aac7c1abda707a70183ac79f` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/helper-stop-result.fixed.json | `239c0b3d1d366d62ad841d32c666ccc9e948064c6c4cfa782f15de1b455033e2` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/helper_control_matrix.py | `c727845000d9cdb50fbb651e49a4130cfe5a63d957b2cc169cfde6fc9ae28784` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/helper-control-matrix.json | `2c83f29e5d8b770f3f1e12e37121b881fd586847e6b149d1a963213b823b4e5e` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/unittest-final.json | `4290b78219d50546eb9e350c96edd82211e7f4a2aaee362349f7fe680b1b7353` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-schema-preflight/securityevent-crd.original.json | `ec5af2e07a05679ef351c21d371b688dd74c6ffe4648ac4281b167f7c1d77e37` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-schema-preflight/receipt.json | `b0fc74b793c91a399db2c374edc3c8a796a1a8bf6393a53e4ca46216b93ae81d` |

Next owner: supervisor seals these sources/current expected pins; independent verifier performs and preserves the read-only check-live with closure evidence. Only a separate explicit frozen lease permits the first physical episode. Independent fresh reproduction remains mandatory before architecture adjudication.

The exact failed helper body is also preserved. It was reconstructed from final source with the recorded pre-fix snippets and its SHA256 equals the digest measured during the original failing check; it was not executed again. The provenance makes that reconstruction explicit. Final helper bytes are preserved separately.

| Artifact | SHA256 |
| --- | --- |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/HTTP_HELPER.failed.py | `b9fe5b816d551601bbbc377cd010b3e7db19f0497dc5cb2b0b15f41672072e87` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/HTTP_HELPER.final.py | `e469037fd1de6d905483d0e9290fc4d9da84e872223cf47967e905f43290245b` |
| .git/phorvex-workflow/agentic-loop-live-v2/reviewer-resident-preflight/helper-source-provenance.json | `052058be26ed062e16b8dd5a809cb8f4cda2ef5846b6f55b3eb42456473d2a8f` |
