# PHORVEXSEC-81 — Sub-ticket 5: General PR Review Agent — delivery report

Date: 2026-08-07
Deliverable: `tools/pr-review/` — a Claude Code **workflow** that reviews a PR for regressions,
semantic conflicts and cross-module impact.
Validation subject: **PR #8** of this repo (a real, human-reviewed PR whose contents were known in
advance, so the output could be judged rather than trusted).

---

## 1. What was built

```bash
python3 tools/pr-review/build-run.py 8 --repo PhorvexSecurity/operator --workdir "$PWD" -o /tmp/run8.js
# then: Workflow({scriptPath: "/tmp/run8.js"})
```

Runs **locally, on demand** (the agreed scope). It does not comment on the PR or block merges by
itself — a human reads the verdict.

```
Scope   →  extract changed CONTRACTS from the diff
   ↓        (signatures, sentinel errors, struct fields, config keys, label constants)
Find    →  5 reviewers in parallel, one failure mode each
   ↓
Verify  →  per finding, an independent agent whose job is to REFUTE it
   ↓
Report  →  {status, findings[], refuted[], summary}
```

Matches the epic's shared requirements: structured output
(`{status, findings:[{severity, component, description, evidence, suggested_fix}]}`), configurable
model/prompt, evidence-or-drop false-positive control, and every finding carrying a citation.

### The five lenses

| lens | looks for |
|---|---|
| `semantic-conflict` | merges cleanly, breaks an assumption elsewhere — sibling functions meant to agree that no longer do |
| `cross-module-impact` | every call site of a changed interface, and whether the PR updated it |
| `correctness` | bugs in the changed lines; partial mutation followed by an error return |
| `test-adequacy` | **would a test actually fail if this change were reverted?** |
| `contract-stability` | observable output: metrics, audit-record fields, JSON shapes, ordering something hashes |

---

## 2. Did it work? — validation on PR #8

**24 raised → 16 confirmed → 8 refuted (one third rejected by the verify pass).**
`0 fail · 6 warn · 10 info`

Three findings mattered. **None had been caught by the manual review that produced the PR.**

### 2.1 A cross-PR regression (the important one)

The workflow traced, and the author then confirmed by hand:

```
PR #8  → a client timeout now reaches the errStackUnreachable branch
         (before this PR it fell through to a hard error)
           ↓
adapter-rotate's unreachable branch does NOT return early — it stamps
phorvex.ai/adapter-epoch and returns Emitted:true   (handlers_ai_p4set.go:180-182 → :205 → :218)
           ↓
console/attack_results.go:262 reads ANY bump of that annotation as proof:
   Outcome, Action, Actuated = "DEFENDED", "adapter-rotate", true
           ↓
a poison attack is reported DEFENDED while the poisoned LoRA is still loaded
```

Before PR #8 the same timeout produced a hard error, so no epoch was written and the attack was
honestly scored **LANDED**. **PR #8 alone therefore makes the forensic record worse** — and it fires
exactly under the load the PR targets ("a saturated stack times out where an absent one refuses").

PR #7 is the fix (`Emitted:false`, no epoch). So **merge order matters**: #7 first, or both
together. Recorded as a comment on PR #8.

This is precisely the class the epic names — *"changes that merge cleanly but break assumptions
elsewhere"* — and it was invisible to a reviewer looking only at the diff, because the damage is in
a different package.

### 2.2 A 62x CI slowdown, measured

The three hung-server tests added by PR #8 each slept 2 s, and `httptest.Close()` waits for
outstanding handlers, so each paid the full sleep despite a 150 ms client timeout. The agent
exported both trees and timed them: `0.099s → 6.184s` on the actuator package — which holds the
completeness teeth and runs constantly.

Fixed (`7b12ec8`): a release channel via `t.Cleanup`. **6.184s → 0.58s**, same coverage.

### 2.3 A dead code path, proved with a compiled probe

The substring arm of `isUnreachable` is unreachable in production: every error `http.Client.Do`
returns is a `*url.Error`, which implements `net.Error`, so `errors.As` always matches first. Its
only coverage was hand-written `errors.New` strings — *the exact shortcut that file's own header
criticises*.

Fixed (`7b12ec8`): the test now drives a **real** refused connection and a **real** DNS failure and
asserts the error genuinely is a `net.Error`.

---

## 3. Two failure modes found the hard way — now hard-coded guards

Both wasted a full run before being understood, so both fail loudly now.

| failure | what happened | guard |
|---|---|---|
| **wrong repository** | Workflow subagents inherit the calling session's cwd. A bare `gh pr diff` reviewed an unrelated app's dirty working tree and produced confident, well-evidenced findings **about the wrong project**. | the diff is resolved by `build-run.py` and baked in; the script throws `WRONG REPOSITORY` if the scope agent reports files not in the PR |
| **empty target reading as clean** | `args` is **not** delivered to a workflow started via `scriptPath`; every value silently fell back to its default. | fail fast on missing PR / empty diff / relative workdir / empty file list, **before** spawning any agent |

The second guard's payoff is concrete: the failing run cost **0 tokens and 61 ms** instead of
**351k tokens and 13 agents**.

Worth recording: in the run where the target was empty, the reviewers **detected it themselves** and
refused, writing *"an empty result must not be interpreted as the PR is clean."* For a verification
tool that is the single most important behaviour — the dangerous output is not a wrong finding, it
is a confident "nothing to report" caused by the tool's own breakage.

---

## 4. False-positive control (epic requirement)

Two mechanisms, both load-bearing:

1. **Evidence or drop.** Every finding must cite `file:line` plus the actual code or value. The
   verify pass defaults to `stands=false` when it cannot confirm the claim by reading code.
   Measured effect: **8 of 24 findings refuted**, with specific reasons (one reviewer claimed `tsc`
   would error on a missing reference; the verifier reproduced it and showed it does not).
2. **`fail` only for the provable** — a caller that will misbehave, a contract used elsewhere and
   not updated, a test that would fail. Suspicion and taste cap at `warn`. On PR #8 the workflow
   returned **0 fail**, which is correct: nothing in it is provably broken *in isolation*, and the
   cross-PR regression is a merge-order constraint rather than a defect in the diff.

---

## 5. Cost

~31 agents · ~1.6M tokens · ~25 min for a 166-line diff. **Not free.** For small PRs, trim the lens
list. Running it on every PR automatically (the epic's stated goal) needs a cost decision first.

---

## 6. Status against the sub-ticket 5 acceptance criteria

| criterion | status |
|---|---|
| Detect merge conflicts and **semantic** conflicts | ✅ demonstrated (§2.1) |
| Cross-module impact: find all affected call sites, flag those not updated | ✅ demonstrated |
| Standard review dimensions incl. missing/outdated tests | ✅ `test-adequacy` lens (§2.2, §2.3) |
| Structured, machine-readable output | ✅ `{status, findings[], refuted[], summary}` |
| Runnable locally (CLI) | ✅ |
| **Triggered automatically on every PR; `fail` blocks merge** | ❌ **not built** — local-only was the agreed scope; needs a CI decision (§7) |
| Posts results as a PR comment | ❌ not built (same reason) |

## 7. Outstanding, and the decision it needs

Automatic per-PR execution and merge-blocking need three things settled first:

1. **Where it runs.** GitHub Actions needs an API key in the team's repo and a token budget; at ~1.6M
   tokens per PR this is a real cost decision, not a config change.
2. **Whether `fail` should block.** The current `fail` bar is deliberately strict. Before it gates
   merges it should run advisory on ~10 PRs to measure the false-positive rate.
3. **Sub-tickets 1–4.** They plug in as extra `LENSES` entries, or as a phase before `Find` feeding
   deterministic check output to the reviewers. Keep the epic's rule: **the numeric checks run in
   code and the LLM reasons about their results** — it must not do the arithmetic.

## 8. Artifacts

- `tools/pr-review/build-run.py` — resolves a PR and builds a runnable script
- `tools/pr-review/pr-regression-review.template.js` — the workflow
- `tools/pr-review/README.md` — usage, design, and the two guards
- `reports/pr-review-81-20260807/pr8-review-raw.json` — the full PR #8 run (24 findings + refutations)
- Applied fixes: `7b12ec8` on `fix/postjson-timeout-classification`; merge-order note on PR #8
