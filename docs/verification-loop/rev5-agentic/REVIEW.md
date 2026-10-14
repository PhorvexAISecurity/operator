# Rev5 agentic V1 review and validation

Review date: 13 October 2026. Scope: a portable architecture/handoff package and its local progress utility. This review did not start a cluster campaign, change Phorvex or customer applications, deploy an actuator, or certify physical defense.

## Source and scope

The complete boss Rev5 handoff is bundled under `source/rev5`; `source/MANIFEST.json` pins its 15 files and the original ZIP digest. The DOCX, WS1–WS8, library files and source catalogue remain readable without this server or the preceding conversation. Source package classifications and old code citations are not claims about a current deployment. Build-time source refresh and named library scope review remain required campaign inputs.

The handoff includes roles and prompts, per-stage prerequisites/outputs/failure routes, typed task/return envelopes, tool contracts, concurrency/resource rules, progress schemas, examples and startup commands. Physical experiment adapters and distributed scheduling are contracts awaiting implementation/binding; only local progress/check tooling is supplied here.

## Independent reviews and corrections

Four specialist review tasks were configured with GPT-6.1 Sol. Their responsibilities were source fidelity, harness portability, register implementation/testing, and a final independent documentation review. Source/portability reviewers first inspected independently; a separate final reviewer checked the revised architecture. Register code was inspected by a reviewer who did not implement it. Displayed role names alone were not used as evidence of separate reviews.

| Finding | Correction |
| --- | --- |
| Initial WIN preceded the mandatory scenario battery | All required positive, expected-rejection and integrity assertions now gate the first WIN; later winner challenges remain separate |
| Alternative-actuator queue could imply forcing a frozen brain | Decision deduplication, full action accounting and genuine changed-input/epoch reentry; no invented physical testing of excluded actions |
| G2 lacked source-specific proofs | Separate feasibility/SLO components, ZERO/BOUNDED proof, realized ledger hold, exact-zero co-tenant state isolation and physical availability |
| Challenge/resource handling could skip admission or release held state | New instances rebind/readmit; defended-state reservations and mutation leases have distinct bounded reconciliation rules |
| Required source admission/publication omitted | Separate library review/refresh receipts and final per-framework classification/applicability/evidence matrix |
| Native Codex dispatch/state ownership was unclear | Explicit root coordinator, actual tool procedure, no nested fan-out, typed null-case campaign tasks and clean-context auditors |
| Root loaded contradictory worker instructions | COMMON explicitly distinguishes the sole coordinator from delegated role workers |
| Roster and consensus were too implicit | Scan-derived G/Val/conditional Des, pinned P1 parameters, deterministic rank aggregation and role handoffs are explicit |
| Parallelism meant model processes rather than throughput | Primary case_parallelism counts ACTIVE case workflows; worker budget and physical concurrency remain separate |
| Register could admit incomplete or nonsensical success | All pre-WIN prerequisites, finite numeric measurements, removed capability, named battery assertions and G2 component guards |
| Changed pins could relabel old acceptance as current | Dependent evidence becomes stale; reacceptance requires a new review reference and later acceptance time |
| Concurrent updates could compete for case slots | Transactional case-cap admission and revision checks, tested with multiple processes |
| Agent subtotal looked like total activity | Renderer labels case-worker jobs and exposes total active agents as UNKNOWN without root/shared task observations |

Evidence-bearing minority obligations, unknown measurements, stale history, failed retests and follow-up PRs are retained. Single-model sessions provide role separation, but do not meet the source's mixed-model decorrelation requirement; that limitation is explicit for an all-Sol rehearsal.

## Local checks

Final local result: **34 tests passed**. The package checker passed with **15 pinned source files**, **3 schema/template pairs**, **5 synthetic cases**, and all checked local links valid. These checks also passed from the isolated PR checkout based on main `b90a5a53`.

The reproducible commands from this package root are:

```sh
python3 tools/check_package.py
python3 -m unittest discover -s tests -v
```

The checker verifies source bytes, required portable files, bundled schemas/templates, synthetic case records and local Markdown links. Its standard-library schema reader supports the constructs used in this package and fails on unsupported keywords; it is not a general-purpose JSON Schema implementation. The task/return contracts were additionally checked using Draft 2020-12 JSON Schema with format checking.

The tests exercise actual local SQLite concurrency, revision rollback, case-slot admission races, stale dependencies/review reuse, branch growth, physical-versus-replay labeling, measurement/battery gates, append-only attempt/PR/deployment/retest history, synthetic exports, source tampering and copied-package validation. Passing these checks establishes local bookkeeping behavior, not producer honesty or physical enforcement.

A legacy workspace doctor run reported a pre-existing malformed historical campaign YAML record and historical warnings. That record is outside this change and was preserved. It is not counted as a passing validation check for this package.

## Codex handoff smoke test

A fresh Codex subagent was dispatched through the real collaboration tool with a typed campaign-scoped CRITIC task, `fork_turns: none`, and requested model `gpt-6.1-sol`. Its input was an explicitly synthetic concurrency proposal: 10 admitted case workflows, seven worker jobs plus the root, and a separate one-experiment limit. No cluster adapter or credential was supplied.

The worker returned a SUBMITTED Critique envelope. The coordinator independently checked task and return schemas, real canonical worker identity, case/campaign/revision fields, pins, and the original input hash. All checks passed. The worker could not independently observe its serving model and correctly reported UNKNOWN; the dispatcher records the requested model separately. This validates one concrete dispatch/return path, not an end-to-end verification competition.

## Limits and next validation

No real case is claimed completed by this package. The five included case examples, including the one labelled DEFENDED, are synthetic and conspicuously marked. Local SQLite is not an authenticated multi-host state or resource gateway. No test here proves hundred-agent capacity, twin fidelity, live cleanup, natural detection, or a physical defense.

The first runtime validation must bind reviewed fixtures and real adapters, complete one scoped competition, then exercise two-case conflicts/recovery before increasing physical overlap. Larger case parallelism can use bounded worker waves immediately where the harness supports them; hundreds of simultaneous workers require an actual broker and capacity measurements. Scope and evidence gates remain unchanged when concurrency increases.
