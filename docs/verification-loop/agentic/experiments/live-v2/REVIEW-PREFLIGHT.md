# Live V2 independent preflight review

**Disposition: BLOCKED for execution; scoped case is legitimate in principle.** Reviewer `/root/agentic_reviewer`, 10 October 2026 UTC; checkout `ca69456b17299aa742c5ea9275fb5e6ae9cccfa4`. This is an initial review of planning documents and in-progress adapter code, not final code acceptance. No serving request, stimulus, event creation or cluster mutation was performed.

The declared `OBSERVATIONAL_TEST_DETECTOR` route is acceptable: a separate, independently reviewed observer reads real authenticated inventory and emits through its own allowlisted ServiceAccount; the installed manager decides naturally and the real inference route supplies an independent effect oracle. Setup admin enrollment is separate from the inference-only caller's capability. The harmless zero-delta fixture proves removal of the declared unapproved model route, not malicious answers, attacker enrollment or prevention of privileged reload. Discovery correctly preserves the legacy detectors' authentication/vector/retirement failures. This mode must not be renamed production autodetection.

## Material findings and precise corrections

| ID | Finding | Required correction / next owner |
| --- | --- | --- |
| LIVE-PF-001 | Current gate processes named one-token groups and can ignore a failed B32 sample. Independent local check with an added B32 503 still returns LIVE_CASE_PASS. | Integration engineer: validate every recorded request, including all failures; implement separate B1/B32 request, generated-token and latency rules; enforce total requested tokens, request counts and episode/response deadlines. Freeze current revised budgets in all inputs. |
| LIVE-PF-002 | Native overlap is not proved by report-defined dispatch timestamps or simple intersection with a polling bracket. Current protected receipt has no actual dispatch start/end pair. Event timestamps may be quantized and clocks differ. | Case/integration engineer: collect authenticated raw endpoints that conservatively bound this exact native effect; freeze skew/precision handling. A B request containing the entire widened outer bracket can prove overlap. Merely intersecting it cannot. Keep exact endpoints explicitly unmeasured; missing containment is incomplete. |
| LIVE-PF-003 | Gate accepts captured, rehashed receipts with changed creator, endpoint/binding, legacy-mode or event-created-time fields. Actual policy generation/effective manager profile and post-effect inventory are insufficiently bound. | Integration engineer: bind protected receipt version/authority, original journal/API object, event identity/age, target/policy/config, serving endpoint/SA/security mode and manager audit/source/process identity to trusted freeze inputs. Capture inventory after effect and hold: owned adapter absent, base and unrelated membership retained. Unknown whole-binary attestation stays disclosed. |
| LIVE-PF-004 | The synthetic positive has only two A retests across10s and passes, despite planned2s cadence/at least five. Cleanup time is an unbound report field; null can pass. | Integration/case engineer: enforce actual retest count/span/cadence, unique request identity, A/B pairing and same runtime before cleanup; bind cleanup phase/intent/readback separately. Persist verdict before any cleanup unload and prohibit cleanup effects from defense credit. Final acceptance needs exact-resource cleanup and lease release evidence. |
| LIVE-PF-005 | Observer reconciliation checks creator/type/target but not observation-mode/inventory hash in validate_event; existing or lost-ACK event must remain tied to the actual observed read. No completed driver transport review exists. | Integration engineer: validate mode/hash and run/episode ownership on POST response and exact GET; retain original observed receipt and create intent. Case engineer: deliver noninjecting run_episode adapter, bounded credentials/transports, one setup load and no automatic mutation retry. Reviewer then checks source and tests independently. |
| LIVE-PF-006 | Draft CASE mentions rotate as an alternative, but current gate supports adapter-rotate and fixed Pod UID only. Current PRECHECK pins superseded CASE63e28... while latest CASE is d84693.... | Supervisor/case engineer: freeze adapter-rotate-only certification for this adapter, with another natural choice reported unsupported rather than forced or “wrong”; alternatively implement/review actual replacement branch. Preserve stale proposals and regenerate affected handoffs against final bytes. |
| LIVE-PF-007 | Exact authenticated audit/native capture and effective process configuration are still unbound. Existing audit-tail capture contains a read error, not a usable decision. Scope/adapter/gate/lease are not frozen. | Case engineer/verifier/supervisor: demonstrate readable capture interface without stimulus, retain original audit cursor/source and protected journal transport, freeze accepted code/CASE/current identities, then grant an exclusive episode lease. No live execution until those prerequisites and final independent review pass. |

The current source flags `forced_selection` and `tester_unload_before_verdict` are declarations; actual operation/transport evidence must support them. Candidate output cannot provide its own trusted expected pins. Formal SLO remains UNKNOWN/UNVERIFIED: sampled continuity cannot grant formal actuator or production approval.

## Independent executable evidence

At **2026-10-10T11:59:19.550493Z**, local synthetic-only probes used stable gate SHA `b95d25a9ffac136ce5521a8eff6a4b3ef4a2a15cc55f49ebacd7977fbb1dd14c`, with the author's specimen/run_gate helper. Each mutation rewrote captured fields and recomputed their refs, so acceptance was challenged beyond stale hash detection. All returned `LIVE_CASE_PASS`:

- added recorded B32-during request with503;
- declared request/token caps1 and episode1s/response0.01s, exceeded by the specimen;
- changed receipt creator, serving binding, endpoint, legacy flag and event time;
- only two A retests spanning10s rather than the declared cadence.

The unmodified specimen also passed. These are observed gate false accepts, not live defense results. Detailed adverse regression requirements were sent directly to the engineer. No final author test suite has yet been certified by this reviewer.

## Reviewed snapshots and next step

Hashes below were sampled at 12:00:07.854101Z; inputs remain drafts. Current CASE budget revisions were subsequently read and checked; PRECHECK's stale contract dependency must be refreshed before freeze.

| File | SHA-256 |
| --- | --- |
| SCOPE.md | `147e9cfa74084ac35924b6afc2c72decfa1f3cb1c37bb77389fff7f7acf6424e` |
| DISCOVERY.md | `a0a16a76ea6dd420f6182fb53bbbb184ae1a86e959f64e4f2b75ab28e4e7d131` |
| CASE-PROPOSAL.json | `d8469317cf1f4b04a74b9c639221ba141b4df1a2b0af769068b58bc26f878c8a` |
| MEASUREMENT-PLAN.md | `6664c1312e2a6224af3cf010d325fec20831baf5be36213ef89acbf76eef9809` |
| PRECHECK.json | `106d3077917a0b105afb11c21ed6bcca2f8cf7f82d2c5e3531852a6e12064ca4` |
| observer.py | `11e37d919aba33af4172be277255e085a6ff0b4174334f4f28586b0a2c16dff1` |
| gate.py | `b95d25a9ffac136ce5521a8eff6a4b3ef4a2a15cc55f49ebacd7977fbb1dd14c` |
| test_live_adapter.py | `4e2539a260f4afb3d2c057a7c54a7fd4f1e9950e2758cb053f6ab780ee90ac5c` |

Adapter paths are under `build/test-harness/verification-workflow/live_adapter/`; document paths are in this directory. Protected authority inspection used adapter_evidence.go `dde97ce7...`, adapter_rotate.go `0464db36...`, operation_journal.go `b7242bf7...` and reviewed zeroLoRA helper vllm_lora_probe.go `9c560e7e...`; full local source pins are already in proposal/precheck except operation_journal, whose full hash is `b7242bf77b78545cb3dfa5c74e93d80469b5d207bcb6cd2029d58f4fc39f3f3a`.

Next owners are the integration and case engineers for these specific corrections, then the supervisor/verifier for final contract and capture binding. The reviewer will rerun the completed local adverse suite and independently challenge its corrected gates. A changed code/plan revision must retain this failed initial review. Corrected preflight does not itself establish a live chain or authorize a serving episode.

## Bounded preregistration review

I reviewed the root-authored campaign question and H1 preregistration. They correctly require two independent fresh episodes, successful pre-observer capability, authentic observational production, correlated native effect, inventory/base controls, ten-second precleanup retests and cleanup. The conservative-bracket containment requirement is appropriate; exact native endpoints remain unmeasured. Formal SLO, legacy detector and privileged reload exclusions are explicit. Initial historical template pins are disclosed as superseded drafts, not deployment evidence. No material scientific-design objection remains at this scope; the code, transport and freeze blockers above still apply. Production/config changes remain excluded. Adapter-rotate-only certification must be made consistent in final CASE and gate; another naturally selected action stays unsupported rather than being forced.

Preregistration pins sampled at 2026-10-10T12:03:20.221987Z: CAMPAIGN.md `460bd463f3d4d5e17ba16de32f2db01e5706832b121d54065e166cd717265eca`; hypotheses.yaml `d43a65cdde2f103bb7010738fc98f9dcbafa6b777fac8ec953b8207080b53091`. Both remain planning inputs, not measured outcomes; refresh affected pins if they change before final review.


## Corrected tools: independent review, 12:11 UTC

The eight supplied local unittest methods passed independently on a stationary snapshot at **2026-10-10T12:11:01.951967Z** (exit0). Observed SHA-256 before and after the additional synthetic probes agreed:

| File | SHA-256 |
| --- | --- |
| observer.py | `d529718a498b341cd5c38b1670b40112cdbefe5c303f681ab81bba97edef2eaa` |
| gate.py | `2fc617952bd38545586ffe6029aa61be1a7607d3bd2cc45319322398301645fb` |
| test_live_adapter.py | `0292336657ef7e411e4424af4972c30675d09d6c95fcc0ad5d218241adad985a` |

Corrections now validate every legitimate request, budgets/deadlines, protected secure-required receipt version8 and authority, raw journal/API identity, whole conservative execution-bracket containment, post-effect inventory, six varied A retests over ten seconds, and separate cleanup acceptance. The retained prior completed journal is allowed only when independently captured/pinned, older than the new event and bound to the same adapter/target/policy/native authority; journals are not manually deleted. Declared Pod configuration is explicitly distinct from unknown effective process configuration and whole-binary attestation. Observer GET/lost-ACK reconciliation now binds actual inventory SHA and observation mode.

Additional independent probes confirmed rejection of extra failed B, an unknown probe group, exceeded A and episode caps, wrong completion epoch, adapter source reload material, forged receipt creator, version4 in secure-required mode, two-only retests and premature cleanup. A response deadline of1s legitimately accepts the synthetic response finishing0.6s after observer release; that is not a false acceptance. These checks use local synthetic records, recompute their accepted capture refs, and do not establish live defense behavior.

A new observed continuity defect was sent to the engineer and fixed before the stationary snapshot above: moving every B-retest to the final checkpoint originally passed, despite absent early B continuity. The revised code requires distinct B request identities between paired A and the next A, and the final pair within its request budget. The independent same mutant now rejects at enforcement. Intermediate code changed during an earlier probe; that earlier run does not certify a stationary revision.

Remaining blockers and precise owners:

| ID | Evidence / consequence | Correction / owner |
| --- | --- | --- |
| LIVE-PF-008 | Stationary gate above returns LIVE_CASE_PASS for hash-bound cleanup started12s/finished13s whose resource absence read actually starts20s/finishes21s. Cleanup can therefore claim completion before its own evidence. | Integration engineer: bound every cleanup readback to the cleanup start/end with strict supplied clock uncertainty; require timed owned-artifact/readback capture and reject invalid uncertainty. Preserve this failed revision. |
| LIVE-PF-009 | Runner draft `687650d88cae48db343b3f7054fc125e06f00737bc486984b44bb1eed7f34998` sets self.event only after response completion. A failure after real observer creation but before that assignment can skip event cleanup. Current cleanup capture also lacks the full artifact/runtime/resource seal expected by finalize_cleanup. | Case engineer: reconcile only the deterministic owned event using actual creator/UID/target/adapter/mode/inventory binding on failure; capture artifact absence, final runtime and complete owned-resource set with actual times for independent cleanup sealing. Unresolved ownership retains the lease. Driver integration remains under review. |
| LIVE-PF-007 (open) | Planning is scientifically scoped but final exact capture interfaces, independent declared-configuration binding, accepted runner source, refreshed case/precheck and freeze/lease are not yet complete. | Supervisor/verifier: retain original authenticated audit data/cursors, independently observe expected pins, refresh affected artifacts, and supply immutable execution freeze after final review. Runtime remains prohibited until explicit frozen lease. |

The root-authored ARCHITECTURE-V3 candidate correctly separates proposal, execution freeze, capture seal and cleanup seal. Its mode, role independence, exact effect oracle, failure routing, retained journals and declared-attestation limits are consistent with this bounded experiment. It is a candidate: no live-chain outcome, production detector certification, service implementation, cross-host lease enforcement or formal SLO acceptance is established by these local checks. The live case remains legitimate in principle and **BLOCKED for execution** pending the specific integration/cleanup/freeze corrections above.


### Cleanup correction verified, 12:12 UTC

LIVE-PF-008 is resolved on observer `d529718a498b341cd5c38b1670b40112cdbefe5c303f681ab81bba97edef2eaa`, gate `b115b48924d1f19aaa479bfdc2e5d112e573efb08b6cca5676bd7a3d1ae6befa`, tests `de0c018e381deb20e0ed7960e546edfa9cd256a7ff60bb0e2a98f2a4e90f8223`. Eight supplied local tests pass independently (exit0). At **2026-10-10T12:12:16.796476Z**, my separate probes confirmed the same hashes before/after: valid timed cleanup passes, late resource and artifact readbacks both reject, and uncertainty values -1, boolean True and1001 reject. Every cleanup capture must now fit the declared interval with strictly bounded uncertainty. This closes the observed cleanup gate false accept without rewriting its failed revision above.

Observer/gate local code review is **ACCEPTED for the narrow supervised observational test adapter** on these exact bytes. This is component acceptance only. The completed runner, original capture interface and refreshed execution freeze remain prerequisites; LIVE-PF-009 and LIVE-PF-007 remain open. No live execution is authorized or performed by this review.


## Final runner review and bounded snapshot checks, 12:53–12:57 UTC

Completed runner `5ccf0c4d0bf67fdc2b51d3018b11fa15809df4f146029378965ad7d344b87e05` and its README `c9f9c262f20d5e50ed46d934edb8a3c2623c6c3e53aef48637d7b200ed454c7b` address failed-path deterministic event reconciliation, producer quiescence, actual owner-file bytes/hash, timed exact artifact absence, complete cleanup resource/runtime captures, and hold scheduling anchored to the first measured A start. Source-derived native authority matches the installed handler's compact Go struct member order. The driver preserves original audit receipts and cursor, opens its own previously free SSH forwarding port, terminates the remote child on EOF, and cancels only its exact forwarding map. Cleanup failure remains unresolved; the runner emits neutral capture status and cannot supply its own trusted acceptance seal. A/B roles share the disclosed inference credential.

At **2026-10-10T12:55:06.919603Z**, four embedded helpers compiled locally. Separate temporary-ledger probes confirmed durable intent, exact terminal cache and rejection of changed result bytes, rebound episode, concurrent owner and interrupted RUNNING state. Runner hash matched before/after; no network or cluster operation occurred.

Further bounded findings were reported directly:

- **LIVE-PF-010 (inventory drift):** gate b115 accepted a rehashed unrelated model added after effect/posthold (12:53:48.145845Z). Gate `25699d05b9441cf2efbb5b290cb0daec709228c1e0faec9a58991f350430ea6c` with tests `05167b32b046b4d54e7f69c0b7d7d1f16d784efc07fa9259550da7ac69383ed0` corrects this: exact frozen baseline IDs, observed baseline plus owned adapter, and after/posthold exactly baseline. All nine supplied tests passed independently. My four additional rehashed additions reject at every inventory checkpoint, with hashes stable at12:56:19.059543Z. Current real base-only inventory makes unrelated preservation vacuous, explicitly; unexpected drift still invalidates the case. Case author is enforcing baseline equality before staging/load.
- **LIVE-PF-011 (clock correlation):** runner inventory observed_at originally retained remote UTC while probes subtract measured node offset before comparison to the local execution bracket. Case author is normalizing inventory timestamps and preserving raw remote timestamps/offset; no timing oracle is relaxed.
- **LIVE-PF-003 provenance remainder:** gate25699 still accepts a rehashed decisionTrace.gitSHA equal to wrong-installed-source (12:57:10.524522Z). Runner already checks this exact field; the deterministic gate must also compare it, including missing rejection, to the independently frozen manager_audit_git_sha. Integration engineer owns the targeted correction.

The read-only audit-preflight SUMMARY `4a29615d0809880fef5679f1338db92123ed3b2369eb9ffb57378cc61a2d277b` now has20 independently hash-validated evidence refs. Its original31,077-byte snapshot capsule contains the captured header with source3051797426ce51265bf2757561bffded3bb69268, vllm policy UID/generation59, ucw-recon and sensed-context; header is present in the original bytes. Sampled effective process evidence is available historically, while this driver's declared-config claim remains accurate and future run evidence still required. The accepted separate64MiB raw audit cap is distinct from the owned8MiB fixture cap and must fail closed on exhaustion. This resolves the original unreadable audit transport prerequisite at the captured read-only evidence level; it does not establish a fresh physical chain.

Final runner/code acceptance awaits only these precise source/schema updates and their stationary readbacks. Original failures remain preserved. No serving stimulus was executed in this review.
