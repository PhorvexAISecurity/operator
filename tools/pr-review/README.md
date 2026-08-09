# PR regression review workflow (PHORVEXSEC-81, sub-ticket 5)

A Claude Code **workflow** that reviews a PR for regressions, semantic conflicts and cross-module
impact, and refuses to report "clean" unless it actually looked at something.

```bash
# 1. build a runnable script for one PR (resolves the diff and bakes it in)
python3 tools/pr-review/build-run.py 8 \
    --repo PhorvexSecurity/operator \
    --workdir "$PWD" \
    -o /tmp/run8.js

# 2. run it
#    Workflow({scriptPath: "/tmp/run8.js"})
```

Runs **locally**, on demand. It does not comment on the PR or block merges by itself — a human
reads the verdict and decides.

## Shape

```
Scope   →  extract the changed CONTRACTS from the diff
           (signatures, sentinel errors, struct fields, config keys, label constants)
   ↓
Find    →  5 reviewers in parallel, one failure mode each
   ↓
Verify  →  for every finding, an independent agent whose job is to REFUTE it
   ↓
Report  →  {status, findings[], refuted[], summary}
```

### The five lenses

| lens | looks for |
|---|---|
| `semantic-conflict` | merges cleanly, breaks an assumption elsewhere — sibling functions that were meant to agree and no longer do |
| `cross-module-impact` | every call site of a changed interface, and whether the PR updated it |
| `correctness` | bugs in the changed lines; partial mutation followed by an error return |
| `test-adequacy` | **would a test actually fail if this change were reverted?**; tests that assert only "no error" |
| `contract-stability` | observable output: metrics, audit-record fields, JSON shapes, ordering something hashes |

## Two guards against confident nonsense

1. **Evidence or drop.** Every finding must cite `file:line` plus the actual code or value. The
   verify pass defaults to `stands=false` when it cannot confirm the claim by reading code.
2. **`fail` only for the provable.** A caller that will misbehave, a contract used elsewhere and not
   updated, a test that would fail. Suspicion and taste are capped at `warn` — a false `fail` that
   blocks a merge is worse than a missed `warn`.

## Two mistakes this design exists to prevent

Both cost a full run before being caught, so they are encoded as hard failures:

- **Wrong repository.** Workflow subagents inherit the calling session's cwd. A bare `gh pr diff` or
  `git diff` silently reviews whatever repo that happens to be — the first run reviewed an unrelated
  app's dirty working tree and produced confident findings about it. The diff is therefore resolved
  by `build-run.py` and baked into the script, and the script throws `WRONG REPOSITORY` if the scope
  agent reports files that are not in the PR.
- **Empty target reading as clean.** `args` is **not** delivered to a workflow started via
  `scriptPath`; every value silently falls back to its default. A reviewer handed nothing finds
  nothing, which is indistinguishable from a clean PR. The script now fails fast — no PR number, no
  diff, no file list, or a relative workdir — **before** spawning any agent. (The failing run cost
  0 tokens and 61 ms instead of 351k tokens.)

## What it caught on its first real run (PR #8)

24 raised → 16 confirmed → 8 refuted. Three that mattered, none of which the author had spotted:

- **A cross-PR regression.** PR #8 made a timeout reach `adapter-rotate`'s unreachable branch, which
  stamps `phorvex.ai/adapter-epoch`; `console/attack_results.go:262` reads any bump of that
  annotation as proof of defence — so a poison attack would be scored **DEFENDED** while the
  poisoned adapter was still loaded. Fixed by PR #7, which means **merge order matters**.
- **A 62x CI slowdown** in the PR's own new tests (`0.099s → 6.184s`), measured by exporting both
  trees and timing them.
- **A dead code path**: the substring arm of `isUnreachable` is unreachable in production because
  every `http.Client.Do` error is a `*url.Error` (which implements `net.Error`), and its only test
  coverage was hand-written strings — the exact shortcut that file's own header criticises.

## Cost

~31 agents / ~1.6M tokens / ~25 min for a 166-line diff. Not free. Trim the lens list for small PRs.

## Extending to sub-tickets 1–4

Sub-tickets 1–4 (physics inputs, context inputs, brain+optimizer, outputs+actuators) plug in as
additional entries in `LENSES`, or as a separate phase before `Find` that feeds deterministic
check output into the reviewers. Keep the epic's rule: **the deterministic numeric checks run in
code, and the LLM reasons about their results** — it should not do the arithmetic.
