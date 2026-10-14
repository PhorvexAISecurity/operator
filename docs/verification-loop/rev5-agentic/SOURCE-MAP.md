# Rev5 requirements and design decisions

The complete boss package is bundled in `source/rev5/`. Its hashes are in `source/MANIFEST.json`. The extracted DOCX text is a reading aid; it does not replace the original DOCX. External framework currency and cited repository behavior have not been independently revalidated by creating this package.

| Requirement | Authoritative source | Implementation location |
| --- | --- | --- |
| Library-first selection, human-reviewed new entries | Handoff README; DOCX Appendix B/C; WS2 Rev5 | Selector/binder prompts and S1–S2 |
| Math/scope review and build-time framework refresh before build | Handoff README two review gates | S0: library_review_ref and library_refresh_ref matched to admitted bytes |
| Frozen brain, isolated twin, read-only customer | DOCX section 2; WS5 | Architecture authority and tool permissions |
| Scan sizing, facts and cover | WS1; DOCX section 4 | Analyst, scheduler, evidence profile |
| C1–C6, untrusted scanned text | WS2/WS3; DOCX section 6 | Reality gate and binder |
| Proposal/critique/ranking; minority preservation; diverse personas and mixed underlying models | WS4; DOCX section 9.1–9.2 | Critic/ranker, worker/model plan and recorded limitations |
| G1–G3, S1–S4, exact trace | WS3/WS5; DOCX sections 7–10 | Named G2 components, metrics, audit, register |
| Mandatory scenario battery before actuator WIN | DOCX section 7.1 Stage 5; WS3 section 2 Stage 5 | S7 expected-outcome manifest and checks.scenario_battery |
| Scoped actuator design and engineering handoff | DOCX section 3.4 and Appendix B | SD/SE and designer prompt |
| Shadow learning and governed calibration | WS6; DOCX section 11 | Final evidence record; no automatic brain tuning |
| Reviewed library buckets and actuator status; all-technique framework matrix | WS8 and CSV/YAML; DOCX Appendix B section 8 addition | Library admission and S10 classification/applicability/evidence matrix |

Where retained Rev4 workstreams describe agents authoring attacks, Rev5 DOCX plus WS2 Rev5 override that wording. Do not carry forward old live-cluster execution or automatic brain-repair instructions from historical campaigns.

## Known source ambiguities

1. The library's 148 bucket-1 entries include 15 marked needs-build and 26 partial implementations. Treat bucket and actuator status as separate claims. The mandatory library review resolves eligibility; no automatic declaration of existing coverage.
2. Appendix B narrows design admission to bucket 3, while several bucket-1/2 rows need implementation. Preserve the scope classification and request review for such gaps; do not silently reroute them into a forbidden design branch.
3. WS5 describes simulated dispatch, while G1/G2/S1 require measured effects. This package separates decision replay from physical execution and exposes claim scope. Physical equivalence, timing, and isolation need actual adapter evidence.
4. A library entry is not an executable fixture. Fixture/probe contracts must be supplied and reviewed. Template parameters may be fitted; agents cannot author new attack steps.
5. Fixture establishment alone does not demonstrate natural detection. Observation mode and state-to-input provenance are required fields.
6. Phase 1 may complete with S2–S4 unknown. This package's FULL closure requires measured S2–S4; other results retain the appropriate limited profile.
7. WS3's mandatory battery includes negative integrity scenarios (NaN fail-closed, reactive-only and SLO rejection), but also says every trace must be a selected/pass reason. These cannot both hold literally. The reviewed manifest therefore specifies each scenario's expected positive, rejection or integrity assertion; all required assertions must pass before WIN. Positive actuator proof still requires selection and G1–G3. Required archetypes are plain, stateful, neighbors, gpu*, sensitive-output and vector-*; unsupported/unrun scenarios are unknown, not silently omitted. This is an explicit interpretation of the conflicting source wording, not a waived battery.
8. Rev5 says a declined proposal leads to another actuator while also freezing the deterministic brain. Identical state/policy/action-set/capability inputs cannot make proposer ordering change the selection. This package deduplicates evaluations by epoch/tick/input hash, retains complete action accounting, and permits reevaluation only after a genuine observed transition or reviewed implementation epoch. A no-passing-selected-response finding does not prove that unselected actuators were physically tested or universally ineffective. Agents cannot force selection, hide competing actions or adjust policy for a desired answer.
9. G2 cites exact-zero co-tenant byte streams using the brain-isolation tests, while physical availability is also required. This package records both: exact-zero deltas for compared co-tenant brain/state byte streams and separately measured service availability/disruption for every affected workload and co-tenant. It does not interpret naturally changing service output bytes as a frozen trace, nor substitute decision isolation for physical availability. The bound proof, realized ledger hold and feasibility laws remain named required components.

Before execution or dependent build work, use the source package's required Zeinab math/scope library review and build-time framework refresh, with separate receipts bound to the admitted library hash/version. Existing owner decisions can satisfy these when concrete and applicable; do not invent an approval or ask again for a recorded one. Current work creates a handoff, not a new cluster campaign.

## Source diversity requirement and harness limits

DOCX section 9.2 requires diverse personas AND a mix of underlying models. S0 records the available model roster, actual assignment identities/model IDs and the planned proposer/critic/auditor separation. Use multiple available underlying models where the harness supports that choice. Separate sessions using one model can establish author/executor separation; they do not satisfy the mixed-model decorrelation requirement. A single-model harness must expose SINGLE_MODEL_LIMITATION in its worker plan and final report, retain the deterministic gates and independent sessions, and make no claim that model errors were decorrelated. Report unavailable diversity rather than inventing models or repeatedly requesting routine approvals. A strict Rev5 model-diversity claim remains unsatisfied until a real mixed-model run occurs.

## Additional orchestration decisions

Transactional case revisions, immutable task envelopes, resource fencing, one fresh independent repeat, N/C/E concurrency limits, the fixed milestone completion indicator, and detailed blocker/PR history are this package's V1 operational choices. Bounded defended-state reservations are distinct from short fenced operation leases, and the trusted local coordinator is the root harness session rather than an assumed installed service. These choices need pilot validation and concurrency testing. They do not waive source requirements or imply that hundreds of workers have been tested.
