# 05 — Evidence · T1-A (offline half; live half is K3's `evidence/live-baseline/` and the post-deploy L3)

**Rule (FIX_LOOP §0.2):** commands and raw outputs, committed — never paraphrased. Every file below is the verbatim tool output; this index only says what each proves and how it was produced.
**Code base for all runs:** `016361c` (v0.4.72) == deployed `phorvex:0.4.72`. HEAD may be later (fixes/ + harness docs only; `phorvex/` tree verified identical).
**Toolchain:** user-local Go (`~/go-toolchain/go/bin`), `GOTOOLCHAIN=local GOFLAGS=-mod=mod`. K3 cannot run Go (02-critique B.7); the proposer owns L0/L1.

> **History note (2026-09-02, after AGREED):** by the repo owner's instruction the branch was rewritten to a single fix commit, **`57790cb`**; the fix-loop record (this folder, the register/anatomy docs, live-baseline evidence) is NOT committed and lives untracked on the shared filesystem. The seven-commit history these files cite (`5ae7b6b`, `1367cfa`, `9c5f224`, `edea448`, `5b9952c`, `cd514bd`, `8eadd5f`) is preserved at local ref `backup/t1a-fixloop-record` and resolves there. Nothing in the fix changed between `5b9952c` and `57790cb`: same 6 files, same content, only the commit message.

## Pre-fix (red before green — §4)

| file | produced by | proves |
|---|---|---|
| `pre-fix/00-anchor.txt` | `git rev-parse`, `git status` on `hazard.go` | tree state at capture: fix NOT applied |
| `pre-fix/01-build.txt` | `go build ./...` | pre-fix tree builds (exit 0) |
| `pre-fix/02-red-run.txt` | `go test ./internal/killchain/ -run TestLeakageGate -v` | fixtures **(a)** and **(d)** RED **at the named assertions**; (b) and (c) green (controls) |
| `pre-fix/03-l1-baseline.txt` | `go test` over 6 packages | baseline: only the new lock tests red; every other package ok |
| `pre-fix/05-fixture-e-red.txt` | 3 fix files restored via `git checkout HEAD`, `leakage_record_test.go` set aside, `go test -run TestLeakageGate_LivePersist -v` | fixture **(e)** RED at *"residency + a live event still reads model-theft"*, package compiled; fix restored byte-exact after (sha-checked) |
| `pre-fix-fb52e6c-SUPERSEDED-base-moved/` | same, at the stale base | **not evidence** — retained to show the base moved and the capture was redone |

`pre-fix/02-red-run.txt` — key lines:
```
    leakage_gate_test.go:49: T1-A regression: a loaded-idle GPU (VRAM=0.9931, SM=0) reads model-theft — residency alone satisfied the leakage gate; got stage=model-theft
--- FAIL: TestLeakageGate_LoadedIdleIsNotTheft (0.00s)
--- PASS: TestLeakageGate_ExtractionLoadIsTheft_PositiveControl (0.00s)
--- PASS: TestLeakageGate_ThresholdIsStrict (0.00s)
    leakage_gate_test.go:88: T1-A regression: VRAM allocation tipped an under-threshold SM reading into model-theft (stage=model-theft)
--- FAIL: TestLeakageGate_AllocationCarriesNoWeight (0.00s)
```

`pre-fix/05-fixture-e-red.txt` — key lines:
```
    leakage_gate_test.go:114: T1-A regression: residency + a live event still reads model-theft (stage=model-theft)
--- FAIL: TestLeakageGate_LivePersistEventOnTwoModelFleet_DeclaredDowngrade (0.00s)
```

Two earlier attempts at the fixture-(e) capture were VOID and deleted: a doubled pathspec made the stash a no-op (green filed as red), then the post-fix-only record test broke the package build (red-by-compile). Recorded here so the method is auditable, not just the result.

## Post-fix (green, and nothing else changed)

| file | produced by | proves |
|---|---|---|
| `post-fix/00-anchor.txt` | as above | fix applied, uncommitted |
| `post-fix/01-build.txt`, `01b-vet.txt` | `go build ./...`, `go vet` on killchain/model/decision | builds, vets clean |
| `post-fix/02-green-run.txt` | lock + record + trace tests `-v` | (a)(b)(c)(d) green; record tests green; all 8 DecisionTrace tests green incl. the new one |
| `post-fix/05-fixture-e-green.txt` | `-run TestLeakageGate\|TestLeakageRecord\|TestAIStageClassification -v` | fixture (e) green at the declared stage; pre-existing AI-stage test unchanged |
| `post-fix/03-l1-postfix.txt` | `go test` over 7 packages | whole offline suite ok — L1 never scoped (§4) |
| `post-fix/04-files-changed.txt` | `git status --porcelain phorvex/` | exactly 3 modified + 3 new test files — the declared blast radius |

`post-fix/03-l1-postfix.txt`:
```
ok  	github.com/phorvex/phorvex/internal/killchain	0.007s
ok  	github.com/phorvex/phorvex/internal/decision	(cached)
ok  	github.com/phorvex/phorvex/internal/actionset	(cached)
ok  	github.com/phorvex/phorvex/internal/feasibility	(cached)
ok  	github.com/phorvex/phorvex/internal/platform	(cached)
ok  	github.com/phorvex/phorvex/internal/audit	(cached)
ok  	github.com/phorvex/phorvex/internal/model	(cached)
```

## Diff and verifier

- `04-diff.patch` — 6 files (3 code + 3 tests; tests intent-to-added so `git diff` sees them). Scope: `killchain/hazard.go`, `model/decision_trace.go`, `decision/coverage.go`. `audit/log.go`, `model.Decision`, `rarity()`, `CoResidency`, threshold, weights: untouched.
- `verify.sh` — one command re-runs L0 + the fix's tests + L1 (§9). Last run: exit 0.

## Live half (K3) — `evidence/live-baseline/`

- `live-baseline/01-deployed-tag.txt` — 746 bytes
- `live-baseline/02-dcgm-inventory.txt` — 2,654 bytes
- `live-baseline/03-fleet-shape.txt` — 1,624 bytes
- `live-baseline/04-stage-distribution-and-N.txt` — 1,900 bytes
- `live-baseline/05-vllm-decision-record-0.4.72.json` — 72,188 bytes
- `live-baseline/06-vram-present-flag-investigation.txt` — 3,084 bytes

Established there (K3, bus 258): deployed 0.4.72 == base; **N = 0** model-theft in 6,139 records; `PROF_SM_ACTIVE` 0 series (DCP not enabled, human-gated DaemonSet patch to try); 1 ModelID ⇒ rarity 1.0, 6 namespaces ⇒ CoResidency 2.0; **M-152** — `stampGPU` drops `VRAMPresent`, so live `vramFraction` is `{present:false}`; L3 criteria must key on the gate outcome + `leakage`, not that flag.

## CI on PR #98 — red for a reason outside this fix (2026-09-02)

The "Vendored subchart matches its source" step failed with `Only in /tmp/vendored/phorvex/templates: admission-webhook.yaml`. Verified: our merge ref (`666e9fb`) has no such file in the tgz or the source chart; the chart tree is byte-identical to main; the file has never existed in git history except on PR #97 (`be0434c`, adds it to both source and tgz). The job runs on `runs-on: self-hosted` and extracts with `mkdir -p /tmp/vendored && tar xzf` — no cleanup — so #97's extracted file persisted on the runner and `diff -r` saw it during our run. Owner: CI/DevOps. Fix: `rm -rf /tmp/vendored` before extraction. Not part of this fix; #98 passes on re-run once the runner is cleared or #97 merges.

## Produced post-deploy (2026-09-03, `0.4.74`) — see `evidence/live/01-02` and `06-verdict.md`

- **L3**: zero AI-GPU-stage records across 4,978 post-deploy decision records (no-change assertion, vacuous as discrimination evidence per M-149); `leakage` honest-absent in all 263 vllm traces; DCP still not enabled → coverage admission on M-149. ✔
- **Golden structural diff** (one vllm record, 0.4.72 vs 0.4.74): only added key is `decisionTrace.inputs.leakage`; no presence-flag flips; stage/reason/selection identical. ✔ (Full battery-wide byte diff not run — the on-cluster battery harness is not deployed on this cluster; structural diff + 263-record uniformity stand in, noted in 06-verdict.)
- **06-verdict.md** (Skeptic): part 1 offline (above + 02/03), part 2 live → **CLOSED — LIVE-VERIFIED** with the M-149 coverage admission. ✔
