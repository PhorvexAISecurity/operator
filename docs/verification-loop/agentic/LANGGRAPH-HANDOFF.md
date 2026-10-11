# LangGraph implementation handoff

**Current source architecture: [WORKFLOW-V5.md](WORKFLOW-V5.md), for the boss's
Revision 4 package.** Its [architecture and prompts](REVIEW-ARCHITECTURE-V5.md)
and [requirements map](REVIEW-SOURCE-REQUIREMENTS-V5.md) are independently accepted
for source conformity. Full physical-loop completion remains **NOT_ESTABLISHED**;
source review does not accept implementation, runtime admission or deployment.
No LangGraph service is claimed.

## Current V5 transfer requirements

Port only independently supported contracts and behavior, preserving V5's complete
competition rather than the historical single-case sketch below:

- S0–S10 persistent competition lineage, immutable artifacts and separate durable
  operation/lease truth; current budgets and failed history survive revisions.
- ACTUATOR enabled-response proposals; conditional ACTUATOR-DESIGN spec-only
  deliberation; separately authorized ENGINEER implementation, independent source
  review and normally selected, newly pinned competition re-entry.
- Typed current winningActuators input, every-round quarantine refresh, applicable
  minority/battery coverage, winner-conditioned re-attack and registered regressions.
- Unchanged native brain/graph/trace semantics, exact per-round/tick/asset wrapper,
  separate integrity/fidelity/selection/effect/competition status and original joins.
- G1 actual capability/graph removal, G2 formal action proof plus full affected,
  system and co-tenant obligations/ledgers, matched predecision G3 and physical S1.
  All seven fields stay present; Phase1 is narrower than measured Phase2 completion.
- Independent fresh physical reproduction, exact safety cleanup, truthful counts,
  and customer shadow records without automatic live learning promotion.

Bind each logical tool to a reviewed implemented descriptor, or record MISSING;
a graph/checkpoint cannot certify external effects. Logical role jobs, runnable
tasks and active workers are distinct. The current owner model preference is
GPT-6.1 Sol; multiple actors do not prove underlying-model diversity. Current
source/runtime, scopes, numerical limits and independent execution admission
must be rebound before physical work.

Use [PROMPTS-V5.md](PROMPTS-V5.md) for current assignments. V4 documents and their
source-local adapters retain their original evidence scope; implementation folder
names do not override V5 authority. The compiler/manual transform has separate
review, and empirical workflow acceptance precedes service transfer.

## Historical V2 implementation sketch

Everything below is the earlier outline: its four-role graph, illustrative pool
size, state fields, tool names and build order are not sufficient current V5
contracts. Preserve it as history. Do not silently implement its old defaults or
omit current design/engineering, winner/refresh, metric or completion duties.

This specification separates the architecture evaluated with Codex workers from
the future runnable service. The service has not been implemented here. The
standard-library pilot gate exercises the key contracts; it does not contain an
LLM backend, LangGraph scheduler, persistent twin or production tool server.

## Components

1. A campaign scheduler selects cases, enforces global budgets and runs a bounded
   pool. Begin with two active cases; increase only when their mutation resources
   are disjoint and worker/evidence throughput improves.
2. A case graph implements V2 with four routine roles and conditional specialists.
   Agent nodes receive bounded typed inputs and return structured proposals.
3. Deterministic adapters validate contracts, references, measurements and routes.
   They own acceptance criteria. The existing deterministic Phorvex engine stays
   outside all LLM calls, using its normal inputs and native interfaces.
4. An artifact store retains immutable source manifests, plans, execution inputs,
   raw evidence, reviews and reports by hash. Only references enter graph state.
5. A durable operation/lease store reconciles physical side effects separately
   from graph checkpoints. It must outlive workers and enforce atomic ownership.

The graph should use typed state, nodes and conditional edges, as supported by
the official [Graph API](https://docs.langchain.com/oss/python/langgraph/graph-api).
Checkpointed threads preserve workflow state; see the official
[persistence documentation](https://docs.langchain.com/oss/python/langgraph/persistence).
Neither mechanism independently attests to physical enforcement.

## State contract

```python
# Interface sketch, not an implemented LangGraph service.
class CaseState(TypedDict):
    run_id: str
    case_id: str
    contract_revision: int
    contract_sha256: str
    source_manifest_sha256: str
    observation_mode: str
    runtime_lifecycle: str
    accepted_inputs: dict[str, ArtifactRef]
    task_records: dict[str, TaskRecord]
    episode_records: dict[str, EpisodeRecord]
    measurement_records: dict[str, MeasurementRecord]
    review_records: dict[str, ReviewRecord]
    budget: Budget
    next_stage: str
    terminal_disposition: str | None
```

Artifacts, tasks, episodes and reviews are distinct objects. Each task carries
role/actor, attempt ID, dependencies, status and error class. Each episode carries
contract/code/runtime pins, owner lease, tool inputs, operation ID, command exit,
timestamps, cleanup and immutable evidence references. Measurements retain raw
verdict plus threat/attribution/task dimensions. Reviews bind precisely the code
and evidence reviewed, with authorship separation.

Reducers merge records by immutable record ID. Repeated identical IDs/hashes are
idempotent; conflicting values are errors. Do not append duplicate chat messages
as the state authority or let simultaneous model outputs overwrite one case's
outcome. Accepted dependency pointers change only through validated transitions.
Concurrent read-only analyses can share source artifacts; a single supervisor
owns transition decisions and each environment has one mutation lease.

## Nodes and logical tools

| Node/tool | Input | Output and preconditions |
| --- | --- | --- |
| `case_engineer` | Approved scope, current scan or compatible inventory, source manifest | Proposed typed case, realistic baseline and observation contract; cannot set acceptance |
| `freeze_case` | Reviewed proposal and runtime adapter capabilities | Immutable contract/hash; rejects unsupported claims/options |
| `validate_handoff` | Supervisor assignment and agent output | Verified role/task/contract/source binding plus file hashes; rejects self-review and stale dependencies |
| `preflight` | Frozen case, actual tools and runtime pins | Structured setup result; rejects missing/wrong assets before physical mutation |
| `run_episode` | Approved adapter, episode ID, explicit options, lease and source pins | Private execution evidence and cleanup; subprocess arguments are constructed by the adapter, not arbitrary model shell |
| `measure_episode` | Raw evidence, contract and control type | Specific threat/legitimate probes, stage facts and outcome dimensions; never trusts a summary flag alone |
| `route_failure` | First failed stage, error class, control identity and budget | Deterministic next owner/action, targeted rework or terminal unavailable state |
| `defense_engineer` | Demonstrated gap and accepted source/evidence | Repair/new-actuator patch and effect/authority/availability/recovery contract; conditional activation |
| `review_patch` | Authored code/oracle, authors and hashes | Independent findings; cannot certify its own artifact |
| `reattack` | Live lease, defended-state reference and reviewed probe plan | New measured capability attempt; only available with a supporting adapter |
| `independent_reproduce` | Accepted candidate contract/code and new private lease | Fresh positive report and comparison; never resumes an already destroyed fixture |
| `finalize_case` | Required episode joins, measurements, review and remaining gaps | Scoped report/regression candidate, or exact unresolved prerequisites |

Every mutating tool requires authorization scope and a lease. Read-only source,
inventory and evidence tools have no physical mutation authority. Artifact writes
are restricted to the task's directory. Enforce these capabilities in adapters;
the Codex pilot's role instructions are not a production sandbox.

## Routing and retries

Use normal edges for the happy path and deterministic conditional edges for
stage failures. Model recommendations are advisory inputs to that router.
Expected failure controls join the control results; they do not activate defense
engineering. Unknown fields or unsupported enum values fail closed.

Assign a new attempt ID after correcting a prerequisite. A new contract/source
requires a new trial. Distinguish retry of a read-only tool, fresh physical
reproduction, exact-input brain replay, and reconciliation of an interrupted
mutation. They are not interchangeable operations.

Before executing a side effect, durably record its operation ID and input hash.
On restart:

- Terminal matching input: return retained evidence, labelled cached, without
  performing the side effect again.
- Same ID, changed input: reject; a new ID is necessary.
- Prepared, never started: acquire the lease and begin if prerequisites hold.
- Running or ambiguous: reconcile actual readback and worker/lease status.
  No automatic blind retry or assumption that a failed worker made no changes.
- Ephemeral fixture already destroyed: preserve incomplete evidence and start
  a distinct fresh-baseline episode if the budget permits.

Graph checkpoints should reference the operation store, not substitute for it.
Use a stable per-case thread ID and version the state schema before graph changes.
External deployment approvals and customer risk decisions are separate from
routine authorized fixture actions.

## Prompt and model adapter

[PROMPTS-V5](PROMPTS-V5.md) supplies current shared instructions and complete
operational role contracts; PROMPTS-V4 and PROMPTS-V2 are historical. Supply supervisor
metadata separately from untrusted workload/log content. Validate structured
output against the handoff schema and assignment before accepting it. A schema
repair can correct malformed syntax only within budget; it cannot invent facts
or change the contract. Preserve the original rejected output.

The trial uses GPT-6.1 Sol for workers. Model provider errors return structured
task failures. No automatic alternate-model or prompt routing to bypass a safety
refusal. Work that remains independently authorized and narrower may continue
with an explicit separate task record; unavailable generation remains unavailable.

Limit context to source, case, current attempt, dependencies and relevant findings.
Cache compatible source analysis by content hash. Never cache physical results
as if they were a fresh environment or append all campaign history to every prompt.

## Build order and service acceptance

1. Port the tested handoff and measurement functions unchanged in semantics.
2. Implement authenticated tool adapters, artifact storage and durable leases.
3. Connect the case graph to a model's structured-output interface and prompts.
4. Reproduce the local pilot, including wrong-contract, outage, held dispatch,
   source drift, duplicate requests and interrupted-operation controls.
5. Implement a persistent-twin adapter and verify real pre-cleanup re-attack.
6. Add actual detector/controller/console paths and a second workload archetype.
7. Exercise the new-actuator branch and affected-workload availability gates.
8. Benchmark larger batches against a curated scripted baseline before increasing
   agent count or enabling automatic customer-specific discovery.

Learning records may store reviewed, source-scoped triples and measured metrics.
They do not automatically tune or structurally change the live brain. Calibration
and production promotion require their own validated release process.
