# PHORVEXSEC-104 (PHVX-14b) — EPSS feed: refresh, aggregation rule, cache builder — report

Date: 2026-08-19 · Branch `feat/phvx-14b-epss-cache-refresh` · PR #59
Commits `d5075cc`, `d22439f`, `b1e255c`

Follows `reports/phvx-14b-20260810/`, which measured the impact of wiring EPSS. This covers the
three pieces the feed still needed.

## Headline

**The task was in `Test` but its central deliverable did not exist.** What is wired is the
file-loading path (`--epss-cache`, `cmd/main.go:140`) plus a hand-maintained ConfigMap with four
digests, one of which points at a workload retired from the cluster. There is no scanning CronJob in
the repo or the cluster, and coverage is **2 of 71 live pods (2.8%)** — worse than the 9.2% the
ticket records. PHORVEXSEC-59 (`SeedEPSS` unwired) was genuinely fixed; 104 appears to have been
marked alongside it. Moved back to `In Progress`.

Three pieces landed here. The fourth — the CronJob itself — is deliberately deferred; see §4.

## 1. The cache is now re-read while running

The cache was read **once at startup**; the code says so directly (*"One package-level cache, seeded
once at startup"*). That is correct for a hand-curated ConfigMap that never changes, and wrong the
moment a scanner pipeline owns it: kubelet updates a mounted ConfigMap within about a minute, but
nothing re-reads the file, so the CronJob would write into a void until the pod happened to restart.
**A feed whose output is only observed by accident is not a wired feed**, so this had to land before
the pipeline was worth building.

`EPSSRefresher` is a controller-runtime `Runnable`. It does **not** require leader election: the
cache is per-process package state, so gating refresh on leadership would leave standby replicas
serving stale scores and then promote one of them.

**A failed read never clears a good cache.** `LoadEPSSFromFile` only seeds after a successful parse,
so a truncated, malformed or deleted file leaves the previous entries in force and reports the
error. The alternative is every pod in the fleet silently dropping to `EPSS = 1.0` because one read
caught the file mid-edit — a fleet-wide loss of signal caused by the mechanism meant to supply it.

`--epss-cache-refresh` defaults to `0`, i.e. exactly today's behaviour. Nothing changes at runtime
until a deployment sets it.

## 2. The aggregation rule, settled by measurement

EPSS is scored per CVE; the multiplier is per image, and an image routinely carries hundreds of
CVEs. That collapse is a modelling choice, and the wrong one produces a term that looks wired and
ranks nothing — the exact failure PHVX-24 is about. It was measured against the real FIRST.org
corpus (**360,781 CVEs, 2026-08-18**), simulating fleets of 40 images scored through the *shipped*
multiplier `1 + clamp01(0.5·EPSS + 0.5·CVSS/10)`.

**Two candidates die outright.**

*Noisy-OR* (`1-∏(1-p)`) is the probabilistically correct aggregation and is unusable: it reaches
**0.9995 at 200 CVEs and exactly 1.0000 at 500**, so every real image scores the maximum. It would
replace a dead input with a dead input.

*Mean* sits at ~0.027 regardless of CVE count or severity, because 60% of all CVEs score below 0.01.

**Between the survivors the answer flips once images share base layers**, which is what a real fleet
looks like. Under 70% base-layer sharing:

| rule | multiplier spread | correlation with image size |
|---|---|---|
| max | 0.407 | **0.29** — ranks by image *size* |
| **P99** | **0.399** | **0.01** |
| P97 | 0.270 | −0.05 |
| P95 | 0.131 | −0.03 — collapses under sharing |

P99 keeps max's discrimination and drops the size artefact; at 90% sharing it beats max outright
(0.367 vs 0.353). Note that **P95 — the convention used for the scales in PHVX-74 — would have been
the wrong borrowing here.**

Why P99 behaves: with nearest rank `ceil(0.99·n) == n` for n ≤ 99, so on a short CVE list **P99 is
the maximum**. It steps off only at n ≥ 100 — exactly where max stops measuring exploitability and
starts measuring image size.

**The CVSS pairing question dissolves rather than being answered.** Nearest rank returns an
*element*, so the pair always belongs to one real CVE. Taking the top EPSS from one CVE and the top
CVSS from another would put a vulnerability that does not exist into a score weighting the two
halves equally.

⚠️ **Caveat.** CVE sets were simulated from the real EPSS distribution, not scanned from our own
images — no scanner in this environment, and pulling the fleet's images was not justified. The
eliminations of noisy-OR and mean are structural and hold regardless. The max-vs-P99 margin would
shift with real scan data, but the deciding property is the size-correlation gap (0.29 vs 0.01),
which is driven by set size and holds for real images.

## 3. The cache builder

`internal/epssfeed` has no I/O: scanning, the HTTP fetch and the ConfigMap write stay in the caller,
so the part that decides what an image's score *is* can be tested offline. Verified end-to-end
against the actual FIRST.org file on images of 8, 120 and 380 CVEs, producing multipliers
**1.27 / 1.35 / 1.56** — real spread with no saturation, against a flat 1.0 on 69 of 71 pods today.

Two rules the multiplier depends on, both easy to get wrong in the direction that looks harmless:

**An unscored CVE is dropped, not zeroed.** EPSS covers published CVEs; a missing entry means
*unscored*. Reading that as "probability zero" would drag an image's percentile down in proportion
to how many of its CVEs are new — penalising precisely the images carrying the freshest
vulnerabilities.

**A clean image is omitted, not written as zero.** Zero scores `1 + clamp01(0) = 1.0` — numerically
identical to honest-absent but semantically a *claim*: "we looked and found nothing exploitable"
rather than "we have no data".

Smaller decisions of the same shape: images with no digest are skipped rather than keyed by tag (a
tag moves, and the scores would follow it to the wrong image); a CVE appearing in several package
layers collapses to its highest severity so a duplicate cannot shift the percentile by being
duplicated; an empty corpus is an **error**, since proceeding would rebuild the cache with every
image unscored and wipe the feed on the next refresh. Output is key-sorted and byte-stable so an
unchanged fleet does not rewrite the ConfigMap and churn the mount every run.

## 4. The CronJob, and why it is not here

Three reasons to land it separately rather than blind:

**CI cannot validate it.** GitHub Actions is failing at job-start org-wide on a billing error, so a
chart change would go in unverified — and a chart change also requires re-packing the vendored
subchart, which the `chart-sync` job is the only thing that checks.

**It needs an ownership switch, not just a new object.** The live ConfigMap is ArgoCD-managed. The
chart already anticipated this — `epss-configmap.yaml` says *"If you later point this at a real EPSS
pipeline, set `create: false` and let that pipeline own the ConfigMap instead"* — so the pipeline
landing must flip that flag in the same change, or ArgoCD and the CronJob will fight over the
object.

**It adds cluster write privilege** (update on a ConfigMap) and a new scheduled workload, worth
reviewing on its own rather than buried under logic changes.

No new container image is needed when it lands: the operator binary already uses a one-shot-flag
pattern (`--scan`, `--ablation`), so the sync can run as another mode with Trivy as an init
container.

## 5. Related, fixed here

The investor demo script claimed the scan derives EPSS with *"no hardcoded inputs; it's all
discovered"* (`dashboard-web/components/demo/overlay.tsx:18`). That is false and visible in any
demo; PHVX-14b asked for the fix and it had not been made. Corrected under PHVX-24 / PR #57.

## Verification

`go build ./...`, `go vet ./...`, full `go test ./...` green; `go test ./internal/platform -race`
clean. 24 new tests across the three pieces.
