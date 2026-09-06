# The Phorvex fix loop

**Status:** normative workflow, version 1
**Scope:** issue intake through independent verification, deployment,
register/anatomy synchronization, and closure

The loop exists to change a live defensive system without silently weakening
another contract. Its product is not merely a patch: it is a closed issue
whose claim can be reproduced by a third party.

## 1. Non-negotiable laws

1. **Independent verification, never trust.** The implementation's author
   cannot approve its design attack, diff review, or final verdict.
2. **Blind derivation creates independence.** Role alternation distributes
   work; it does not create independent information.
3. **Evidence is reproducible.** Commands, pins, raw outputs and hashes are
   retained. A paraphrase is not evidence.
4. **Version and environment are part of every claim.** Static claims name
   the source SHA. Live claims also name image, embedded `gitSHA`, window and
   ambient conditions.
5. **A null is a claim.** It requires a positive control proving the rig
   could observe the expected effect.
6. **RED must be red for the right reason.** Compile failure or an absent
   symbol does not prove a behavioral regression test.
7. **Pre-registered predictions are immutable.** A missed band reopens or
   invalidates the model. Only the human owner may accept a separately
   recorded amendment.
8. **Generated files have one source.** Never hand-edit the rendered master
   register or anatomy.
9. **The bus is a notification channel, not memory.** Current state and next
   action live in `STATUS.yaml`.
10. **No implicit shared-cluster mutation.** Deployment, fault injection,
    attacks and destructive tests require explicit human approval.

## 2. Roles and capability assignment

Every fix names these roles in `STATUS.yaml`:

| Role | Owns |
|---|---|
| Human owner | triage, scope, priority, deadlock, PR merge, deployment, destructive tests, waivers, prediction amendments |
| Proposer | root-cause model, proposal, behavioral prediction |
| Implementer | code, tests, RED/GREEN and implementation evidence |
| Skeptic | blind derivation, proposal attack, independent diff review, final verdict |
| Live verifier | post-deploy L3; requires cluster access |
| Coordinator | state transitions, issue/register and release synchronization |

The proposer normally implements; the skeptic normally live-verifies.
Capabilities override alternation. An agent without Go may propose or review
statically but cannot claim to have run Go tests. An agent without cluster
access cannot sign L3.

`coordination/AGENTS.yaml` records current capabilities. Agent/model names may
appear in workflow provenance, but never in production commit messages or PR
text.

## 3. Fix profiles

Every intake chooses one profile:

- **standard:** full protocol below.
- **light:** human-approved local/mechanical change. Blind derivation, RED,
  independent diff review, version pins and final verdict remain mandatory;
  an omitted artifact is explicitly `not_required` with rationale.
- **batch:** several minor issues with disjoint touched files and a distinct
  invariant/test per issue. One failed item drops out rather than hiding in a
  batch verdict.
- **design:** decision memo; no code or deployment claim.
- **measurement:** experiment and evidence; no patch implied.

Severity alone does not select a profile. Anything touching objective,
belief, cover credit, cost, exposure clocks, routing, RBAC, deployment or
effect confirmation defaults to `standard`.

## 4. State machine

```text
TRIAGED
  -> DESIGNING                 (01 proposal || sealed 02A blind derivation)
  -> CRITIQUED                 (02B comparison and attacks)
  -> AGREED                    (03 decision)
  -> IMPLEMENTED               (branch + 04 diff)
  -> OFFLINE_VERIFIED          (L0-L2 + 05 evidence)
  -> DIFF_REVIEW_PASSED        (independent P3)
  -> PR_READY
  -> IN_PR
  -> MERGED
  -> DEPLOYED
  -> LIVE_VERIFIED             (L3/L4 where required)
  -> SYNCHRONIZED              (release, anatomy, issues, permanent tests)
  -> CLOSED
```

Side states:

- `HELD`: owner paused it; next condition is explicit.
- `BLOCKED`: an external dependency prevents the next transition.
- `DEFERRED`: triaged but not scheduled, with owner and review date.
- `ACCEPTED_RISK`: no patch; rationale and owner approval required.
- `REOPENED`: implementation or live evidence failed an agreed criterion.
- `INVALIDATED`: evidence contradicted the root-cause/prediction model.

Critique failure returns to `DESIGNING`; P3 failure returns to
`IMPLEMENTED`; L3 failure returns to `REOPENED` or `INVALIDATED`.

No state may contain two competing “next” actions. Transitions update
`STATUS.yaml` atomically, then regenerate the index with
`tools/workflow.py sync-index`.

Use `tools/workflow.py transition` for new cycles. It validates the edge,
checks state-specific pins/evidence, requires approval references at human
gates, appends transition history, and refreshes the index. Populate the
required PR, merge, deployment, verification, and synchronization fields
before requesting the corresponding transition. `--force` always requires a
human approval reference and records that it was forced.

## 5. Per-fix record

```text
fixes/<fix-id>/
  STATUS.yaml
  00-intake.md
  01-proposal.md
  02A-blind-derivation.md
  02A-blind-derivation.sha256
  02B-critique.md
  03-decision.md
  04-diff.patch
  05-evidence.md
  06-verdict.md
  PR_BODY.draft.md
  verify.sh
  evidence/
    manifest.yaml
    pre-fix/
    post-fix/
    p3/
    l3/
```

Legacy cycles retain their historical filenames. `STATUS.yaml` maps them to
the current schema; migration never rewrites evidence to pretend a historical
step occurred.

### 5.1 `STATUS.yaml`

Required fields:

- schema version, fix ID, issue IDs, title, profile and state;
- roles and capability requirements;
- base branch/SHA and deployed build at intake;
- implementation branch/head and `stacked_on`;
- PR URL, merge SHA and checks;
- deployed image, digest, embedded `gitSHA`, rollout time;
- required verification levels and verdicts;
- register/anatomy synchronization;
- blockers, residuals and exactly one `next_action`;
- update time and provenance.

### 5.2 `00-intake.md`

The coordinator records:

1. verbatim ticket or authoritative request;
2. issue entry and anatomy pin/locus;
3. current source and deployed pins;
4. dependencies, overlap and stack order;
5. role/capability assignment;
6. profile and change class;
7. mandatory human gates;
8. definition of done and expected register transition.

### 5.3 `01-proposal.md`

The proposer must provide:

1. root cause with source citations and why it is not a symptom;
2. minimal fix and touched files;
3. blast radius: all readers/writers/callers and related issues;
4. declared behavioral delta;
5. offline test plan and permanent regression test;
6. live plan or pre-declared L3-not-required argument;
7. version anchor, rollout and rollback;
8. known residual risk and explicit non-goals.

#### Change classes

- **Class A — local/mechanical:** exact delta and “nothing else changes.”
- **Class B — objective/belief/cover/cost/clock/control-loop:** falsifiable
  direction and magnitude bands over action mix, selections, cadence, lambda,
  churn, latency or other relevant distributional metrics.

The skeptic independently derives the class and prediction before reading
the proposal.

### 5.4 `02A` and `02B`

During `DESIGNING`, proposer and skeptic work in parallel:

- proposer writes `01-proposal.md`;
- skeptic reads intake, target issue, anatomy, pinned baseline and source,
  then writes and seals `02A-blind-derivation.md`.

The seal records SHA-256 and UTC. It proves immutability after the declared
blind phase; it does not replace professional honesty about access.

After sealing, the skeptic reads the proposal and writes `02B-critique.md`:

- agreements and material differences from 02A;
- undeclared deltas;
- counterexamples and failure modes;
- test-vacuity attacks;
- blast-radius omissions;
- requested changes classified blocking/non-blocking;
- at least one attempted attack or explicit coverage admission.

Three unresolved critique rounds trigger a human decision memo.

### 5.5 `03-decision.md`

The converged, immutable specification records:

- chosen design and rejected alternatives;
- resolved critique items;
- human rulings and ticket deviations;
- exact touched scope and non-goals;
- pre-registered RED/GREEN and L0-L4 matrix;
- exact L3 criteria, positive control, abort and cleanup;
- predicted Class A delta or Class B bands;
- rollback;
- follow-ups deliberately excluded.

Later amendments append a numbered human-approved record. They never rewrite
the original prediction.

### 5.6 Implementation and `04-diff.patch`

- Use an isolated worktree and a one-fix branch.
- Refuse to proceed through an unrelated dirty tree.
- Record base and head SHA.
- For stacked work, record the dependency fix and generate the diff against
  that declared base.
- After the dependency merges, rebase and either prove patch equivalence or
  rerun all affected verification.
- `04-diff.patch` is regenerated from the reviewed base/head; it is not a
  hand-edited patch.

### 5.7 `05-evidence.md` and manifest

The summary maps every decision criterion to evidence. Raw artifacts live in
`evidence/` and are indexed by `evidence/manifest.yaml` with:

- path or artifact URI;
- SHA-256 and size;
- producer and UTC;
- source/base/head or deployed build;
- exact command;
- evidence class;
- expected/actual result;
- positive-control relation;
- retention and sensitivity.

Large corpora do not belong in normal Git history. Keep them in
`artifacts/` or approved object storage and commit the manifest.

### 5.8 P3 — independent diff review

P3 is a protocol checkpoint, not L3.

The skeptic independently verifies:

1. base/head identity and complete diff;
2. touched files match the agreed scope;
3. every decision item maps to code/tests;
4. RED fails at the intended assertion on the old behavior;
5. GREEN, build, formatting, lint and tests on the new behavior;
6. pre-existing failures are pinned and no new failure is hidden;
7. fakes exercise the live request attributes they claim to model;
8. no undeclared delta or generated-file drift;
9. stacked/rebased patch identity;
10. at least one adversarial attempt.

The verdict lives at `evidence/p3/verdict.md`. `06-verdict.md` is not created
at P3. A pass transitions to `PR_READY`.

### 5.9 PR, merge and deployment

The PR body is production-facing: problem, behavior, tests, risks, rollout
and rollback; no agent attribution.

Record:

- PR URL and check results;
- reviewed head and final merge SHA;
- release tag and image digest;
- actual running image and embedded `gitSHA`;
- deployment/rollout time.

Merge and deployment remain human gates unless expressly delegated.

### 5.10 L3 and final verdict

L3 is required when:

- the issue was live-observed;
- code changes deployment, CRD, admission, RBAC, routing or actuation;
- behavior depends on another controller, external service, cache/informer,
  concurrency or timing;
- acceptance depends on records, metrics, conditions or cluster state.

L3 may be marked not required only for a deterministic in-process change
whose proposal makes that case before implementation and whose skeptic and
human owner approve it.

Each L3 plan includes:

- exact deployed image/digest/embedded SHA;
- pre-fix baseline and post-deploy window;
- success and failure thresholds;
- positive control;
- sample unit and minimum sample/window;
- ambient load, churn, co-tenancy and configuration;
- mutation and cleanup ledger;
- safe abort conditions;
- retained raw evidence.

Several fixes may share one deployment window, but each receives separate
criteria, evidence and verdict.

`06-verdict.md` is final and states `CLOSED`, `REOPENED`, or `INVALIDATED`.
Closure additionally requires issue/register synchronization, anatomy/release
synchronization, permanent tests, and version re-stamping.

## 6. Verification levels

`verification/LEVELS.md` is normative for detailed commands.

- **L0:** build, unit tests, formatting and static checks.
- **L1:** full invariant/property suite.
- **L2:** golden multi-tick behavioral comparison.
- **L3:** deployed scoped verification.
- **L4:** soak for belief, dual/lambda, learned cost, long-lived clocks or
  other time-evolved state.

Until a promised layer exists, status must say `unavailable` plus the waiver
or blocker. It may not be silently reported as passed. In particular, the
known CI Go-test and L2-battery gaps remain explicit program issues.

## 7. Register and anatomy lifecycle

### 7.1 Issue lifecycle

Issue entries, not the generated master document, are edited. Allowed states:

`OPEN`, `IN_PROGRESS`, `MAIN_PENDING_DEPLOY`, `DEPLOYED_PENDING_L3`,
`CLOSED`, `REOPENED`, `DEFERRED`, `ACCEPTED_RISK`, `SUPERSEDED`.

At PR merge, set `MAIN_PENDING_DEPLOY`. At deployment, set
`DEPLOYED_PENDING_L3`. After L3, close or reopen and link the verdict.

The generated master derives all counts, tiers, status tables and anatomy
joins. No hard-coded issue counts or closed-ID lists are allowed.

### 7.2 Anatomy lifecycle

The canonical anatomy follows the **deployed source SHA**, not an unshipped
branch or tag.

For every deployed version:

1. verify the actual running image and embedded SHA;
2. analyze that exact SHA in a clean worktree;
3. regenerate into a temporary tree;
4. run anchor, completeness, reachability, surface, operation, curation and
   mutation checks;
5. review changes to negative evidence rather than auto-accepting them;
6. atomically publish outputs and update `anatomy/PIN.yaml`;
7. record semantic drift or explicit no-drift in the release record.

Multiple fixes in one release require one anatomy refresh, not one per fix.
If L3 fails, anatomy still follows the deployed code; the register records
the regression.

### 7.3 Release synchronization

`releases/<tag>/RELEASE_SYNC.md` records:

1. source, merge, tag, image, digest and deployed SHA;
2. anatomy generation/audit result;
3. included fixes and dependencies;
4. L3/L4 verdicts;
5. issue transitions and new findings;
6. permanent verifier results;
7. baseline refresh after verdicts;
8. residual risk and rollback state.

A fix reaches `CLOSED` only after its release synchronization is complete.

## 8. Permanent regression defense

- Every closed fix deposits a permanent test and `verify.sh`.
- `verify.sh` runs offline by default. `--live` remains read-only/dry-run
  unless its help text names a human approval requirement.
- Run all cheap offline verifiers each release.
- Use changed-file reachability to prioritize review, never to skip the full
  invariant suite.
- Refresh a golden baseline only after the corresponding verdict passes.
  Re-baselining before review absorbs regressions into normal.
- Frozen invariant definitions require human sign-off and never change in the
  same PR as the fix they judge.

## 9. Full-system live campaigns

Campaigns are not an automatic fix-loop step. Only an explicit human request
creates one.

A campaign has its own dated directory, release/fix set, hypotheses,
preconditions, treatment arms, evidence manifest, analysis, review, cleanup
and issue reclassification. It may run after any number of fixes.

Campaign results can reopen closed issues or create findings. They do not
retroactively replace missing per-fix L3 evidence.

If a fix explicitly requires L4 soak and the human schedules that soak inside
a future campaign, the fix remains `DEPLOYED` or `BLOCKED` with
`reason: awaiting-scheduled-soak`; it
does not close early.

## 10. Coordination

Messages contain:

- immutable message ID and UTC;
- sender/recipient;
- fix ID and role;
- current and requested transition;
- `needs_reply`;
- references to authoritative artifacts.

Write a complete temporary file and atomically rename it into the inbox.
Archive only after successful read/ack. Allocate sequence IDs under a lock.

Bus history is archaeology. Context recovery reads `STATUS.yaml`, not the
archive.

## 11. Safe concurrency

- `fixes/INDEX.yaml` records dependencies, overlap and merge order.
- Parallel fixes that touch the same file require an explicit order or human
  override.
- Stacked branches name `stacked_on`; the child cannot close before the
  parent is merged/rebased.
- One release may carry several independently reviewed fixes.
- One shared L3 window may evaluate them, but evidence and verdicts remain
  separable.

## 12. Definition of done

A code fix is done only when:

1. agreed behavior is implemented;
2. RED/GREEN and required L0-L4 evidence pass;
3. an independent P3 attack passes;
4. PR, merge and deployment identities are recorded;
5. required L3/L4 passes on the exact deployed build;
6. permanent tests and `verify.sh` exist;
7. issue entry and generated master are synchronized;
8. anatomy and release pin match the deployed source;
9. residual findings are filed, not buried;
10. the skeptic signs `06-verdict.md`.

“Code complete,” “P3 pass,” “PR ready,” “merged,” and “deployed” are useful
states. None means `CLOSED`.
