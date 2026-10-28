# Benchmark bot

The Telegram-driven layer on top of the benchmark lab. A team member sends a
plain-language change to the brain; the bot produces a candidate brain, runs the
PHORVEXSEC-281 benchmark against it in a throwaway lab, and returns the results
as tables / HTML / CSV. The brain under test is only ever benchmarked
shadow-only; promotion to production stays a separate, human decision.

This is layered **on top of** the ticket (`A-TICKET-benchmark-self-service.md`),
not part of it. The ticket treats the New brain as a pre-built input; this bot
adds an optional step that *produces* that input from a prompt with an LLM. The
safety model is unchanged: an isolated candidate branch, no auto-merge, no
production deploy, tag-scoped teardown, and shadow-only decisions.

## Pipeline

```
prompt ─▶ planner.py ─▶ candidate.py ─▶ lab/build-image.sh ─▶ run.sh ─▶ reports ─▶ Telegram
         (LLM → diff)   (apply + guard)  (tag → image)        (benchmark) (HTML/CSV/PDF)
```

Built so far: `planner.py` and `candidate.py`. `build-image.sh` is in
`../lab/`. `run.sh`, the fixtures, the report generator and the Telegram
front-end are still to come.

### `planner.py` — prompt to diff (non-deterministic)

Gathers brain source from the base commit (read-only, `git show`), asks an
OpenAI chat model for a unified diff, and refuses to emit anything that touches
a file outside the candidate scope. Prose or an out-of-scope diff is sent back
with a correction, up to `--max-attempts`.

```sh
OPENAI_API_KEY=... OPENAI_MODEL=<your model> \
benchmark/bot/planner.py --src-repo <repo> --base-commit <sha> \
  --prompt-file PROMPT.txt --out-diff D/brain.diff --out D/PLAN.json \
  [--context phorvex/internal/decision/decision.go ...]
```

- Provider is OpenAI; endpoint defaults to `https://api.openai.com/v1`
  (`OPENAI_BASE_URL` overrides, e.g. a compatible gateway).
- The model id is **not** hard-coded: set `OPENAI_MODEL` or `--model`.
  `OPENAI_REASONING_EFFORT` and `OPENAI_TEMPERATURE` are passed through only when
  set, so reasoning-only models that reject `temperature` work by default.
- The API key is read from the environment and never written to `PLAN.json`,
  the diff, logs or a command line.
- Context files: pass them with `--context`, or let the planner rank in-scope
  `.go` files by how often the prompt's identifiers appear in them.
- The HTTP call is injected, so the tests run with no network.

Exit codes: 2 bad arguments or environment; 8 no in-scope diff after retries;
9 transport or API error.

### `candidate.py` — diff to a throwaway branch and tag (deterministic)

Applies a diff on a disposable branch in a clone and tags it, with the
security-critical guardrails. See the module header for the full contract.

- **Scope:** only `phorvex/**/*.go`, never `phorvex/tools/` and never
  `_test.go`. So a candidate cannot change the Dockerfiles, charts, `go.mod` or
  release tooling, and cannot weaken the tests. `build-image.sh` enforces the
  same boundary again (Dockerfile drift check, `-mod=readonly`).
- **Isolation:** works only in a clone under the run dir; the working repo is
  cloned read-only and never written, `main` is untouched, and there is no
  merge or push. A refused candidate is cleaned up.
- **Provenance:** built from `--base-commit` detached; the base tag must resolve
  to exactly that commit; the candidate tag is never in the release namespace.

```sh
benchmark/bot/candidate.py --src-repo <repo> --run-dir D --run-id <hex> \
  --base-tag manager-v0.11.0 --base-commit <sha> --diff D/brain.diff \
  --out D/CANDIDATE.json
```

It writes `CANDIDATE.json`, which `build-image.sh` consumes:

```sh
benchmark/lab/build-image.sh --src-repo <CANDIDATE.repo> \
  --tag <CANDIDATE.candidateTag> --commit <CANDIDATE.candidateCommit> ...
```

Exit codes: 2 bad arguments; 3 base ref; 4 diff does not apply; 5 out of scope;
6 empty diff; 7 git failure.

## Decisions I made (no decision register was available)

- **OpenAI over stdlib HTTP, no SDK dependency.** `planner.py` uses `urllib`
  behind an injected transport, so there is no third-party dependency and the
  tests need no network. Swap the transport to use the `openai` SDK if preferred.
- **Chat Completions, not the Responses API.** Simpler and widely compatible;
  change the path via `OPENAI_BASE_URL` plus the endpoint if you move to it.
- **Edit scope = `phorvex/**/*.go` minus `tools/` and `_test.go`.** Brain
  parameters that are flags, not code, should go through the lab's
  `--brain-extra-args` path instead of a source edit — it is safer and needs no
  build. Source edits are for logic changes.
- **Deletions and renames are refused by default** (`--allow-delete` opts in),
  because a prompt-driven edit rarely needs them and they are the easiest way to
  do unintended damage.

## Tests

```sh
python3 -m unittest discover -s benchmark/bot -p 'test_*.py'
```

Offline and deterministic: the OpenAI transport and git are the only externals,
and the transport is faked. `benchmark-dashboard.yml` runs them in CI.

## Still to build

- `run.sh` + `teardown-by-tag.sh` and the four fixtures (ticket Parts 1 and 2).
- The report generator (HTML / CSV / PDF).
- The Telegram front-end: receive a prompt, **authenticate the sender** (an
  allowlist of chat ids), orchestrate the pipeline, stream progress, return the
  artifacts, and read every secret (bot token, AWS, OpenAI) from a mode-600
  env file on the jump-host — never from the repo.
