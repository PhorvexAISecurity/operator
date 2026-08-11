# PHORVEXSEC-123 (PHVX-29) — TestScenariosExport permanently red — fix report

Date: 2026-08-11 · Branch `fix/phvx-29-scenarios-export-red` · Commit `b314c16` · PR #21

## Verdict: fixed, and the ticket's framing was slightly off — it is not a test

## 1. Why it was red

`go test` runs a package binary with **cwd set to the package directory**, not the module root. So
the default path

```go
path = "bin/scenarios-instances.jsonl"
```

resolved to `internal/decision/bin/`, which does not exist and never has. The `bin/` that does exist
is `phorvex/bin/`, two levels up.

It could therefore never have passed on a fresh checkout. Worse, the invocation in the file's own
header comment carried the same relative path, so **following the documentation reproduced the
failure**.

## 2. It asserts nothing

Counted across the whole file: **zero** assertions about behaviour. Its only two `t.Fatal` calls are
I/O errors. It is a **generator** — it writes the scale-sweep instance grid (disjoint / non-disjoint ×
9 sizes × 3 budgets × 12 seeds) as JSONL so an external MILP solver can compute exact optima beyond
the brute-force cap.

Running a generator on every `go test` was the actual mistake. It has side effects and no verdict.

## 3. The change

- **Skip** unless `SCEN_OUT` is set — matching the file's own stated intent that it be run
  deliberately.
- **Create the output directory** when it is set, so an absolute path just works.
- **Correct the header comment** to an absolute path, with the reason, so the next reader does not
  repeat it.

## 4. Verification, both directions

```
SCEN_OUT=/tmp/scen-check.jsonl go test -count=1 -run TestScenariosExport
  -> ok, 648 instances written, first line is a well-formed disjoint n=6 b=1 record

go test -count=1 -run TestScenariosExport -v
  -> --- SKIP: TestScenariosExport   (not FAIL)

go test -count=1 ./internal/...
  -> fully green for the first time
```

The second check matters as much as the first: silencing a failure by deleting the capability would
have been the easy wrong fix. The generator still produces the full grid.

## 5. Why this was worth a ticket

A suite carrying one permanent failure teaches everyone to read `FAIL: 1` as normal.

Concretely, during today's review of thirteen open PRs I wrote *"only ScenariosExport, pre-existing"*
**more than ten times**. Every one of those was correct — and that is the danger: a real failure
arriving alongside it would have been dismissed by the same reflex. Twice today I did dismiss a green
result that turned out to be meaningless (a cached `go test`, and a regex that silently failed to
apply an edit), which is the same failure mode from the other side.

The suite is now green, so the next red means something.

## 6. Not done

- **No CI change.** This repository's workflow (`.github/workflows/ci.yml`) only builds and pushes to
  ECR; it never runs `go test`. So the suite being green protects nobody automatically today — it
  only helps a human running it locally. Adding a test gate changes what blocks other people's PRs
  and is a team decision, not this ticket's.
- The generated `bin/scenarios-instances.jsonl` is still not committed, and nothing consumes it
  automatically. That is unchanged and out of scope here.
