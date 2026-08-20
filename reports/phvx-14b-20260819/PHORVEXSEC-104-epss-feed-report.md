# PHORVEXSEC-104 (PHVX-14b) — complete EPSS feed wiring — report

Updated: 2026-08-20 · Branch `feat/phvx-14b-epss-cache-refresh` · PR #59

Follows `reports/phvx-14b-20260810/`, which measured the impact of wiring EPSS. This covers the
complete feed path: runtime refresh, aggregation, cluster inventory, Trivy scanning, FIRST
lookup, controlled ConfigMap update, and deployment resources.

## Headline

The previously missing central deliverable now exists. A dedicated CronJob inventories running
image digests, scans them with pinned Trivy, resolves CVEs through FIRST, applies the measured P99
aggregation rule, and updates the mounted cache through narrowly-scoped RBAC. Every operator replica
then observes projected-file updates without a restart. The EKS overlay enables the complete job in
dry-run mode; applying generated data remains an explicit reviewed switch.

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

**A failed read never clears a good cache.** A truncated, malformed or deleted configured file
leaves the previous entries in force and invokes the error path. A missing file remains a nil no-op
only during optional startup. Runtime change detection compares cache contents, not entry count, so
a same-count score update is observable.

`--epss-cache-refresh` defaults to `0`, preserving standalone behaviour. The chart sets 30 seconds
when EPSS is enabled.

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

`internal/epssfeed/feed.go` keeps scoring independent of I/O, while `sync.go` supplies the explicitly
one-shot Kubernetes/Trivy/FIRST adapter. This keeps the scoring rule offline-testable without
pretending the deployment pipeline does not exist. Verified end-to-end
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
duplicated; an empty corpus or a zero-score FIRST response for a non-empty CVE set is an **error**,
since proceeding would rebuild the cache with every image unscored and wipe the feed on the next
refresh. Output is key-sorted and byte-stable. The ConfigMap is still updated after a successful
unchanged run so its `epss-last-success` evidence remains truthful.

## 4. CronJob, RBAC, and ownership

`epss-feed.yaml` adds a dedicated ServiceAccount, cluster-wide `pods/list` for inventory, and
namespace-local `get/update` restricted by `resourceNames` to the EPSS ConfigMap. It cannot read
Secrets or mutate workloads. The operator image runs a one-shot `--epss-feed`; a pinned Trivy init
container supplies the scanner binary through an `emptyDir`.

The chart bootstraps the ConfigMap so the Deployment always has a mountable object. When the feed is
enabled, the CronJob owns its runtime data and annotations; the ArgoCD Application uses
`RespectIgnoreDifferences` and ignores exactly those fields. This prevents self-heal from restoring
the four seed entries after every generated refresh while keeping the object itself in GitOps.

The EKS overlay schedules the real job daily with `apply=false`, `allowPartial=false`. Before
activation, a read-only ECR IRSA role must be attached for private images and the dry-run
before/after distribution reviewed. This is an explicit activation gate, not missing wiring.

## 5. Regression corrections

- Trivy JSON arrays and newline-delimited objects both parse as documented.
- A deleted configured feed invokes `OnError`, never `OnReload`.
- Same-count score changes report `changed=true`.
- Failed and partial scans retain the last-known-good cache; partial application is rejected by
  default.
- A successful-but-empty FIRST response cannot erase a good cache, and pod coverage still counts
  correctly when the first declared container is stopped but a later container is running.

## 6. Related

The investor demo script claimed the scan derives EPSS with *"no hardcoded inputs; it's all
discovered"* (`dashboard-web/components/demo/overlay.tsx:18`). That is false and visible in any
demo; PHVX-14b asked for the fix and it had not been made. Corrected under PHVX-24 / PR #57.

## Verification

Completed on the final combined PR #52–#59 integration:

- `go build ./...`, `go vet ./...`, `go test ./...`, and `go test -race ./...`;
- targeted EPSS feed/cache/platform tests, including last-known-good retention, partial-scan
  rejection, same-count reload detection, empty-FIRST-response rejection, and coverage when the
  first declared container is stopped;
- the dashboard production build;
- Helm 3.17.3 lint/template checks for the source chart and parent stack, including
  `deploy/helm/phorvex-stack/values-eks.yaml`;
- byte-identical generated/source-chart CRDs and matching vendored chart content (apart from Helm's
  normal `Chart.yaml` formatting normalization); and
- `git diff --check` plus confirmation that this PR does not modify `.github/workflows/`.

The GitHub Actions jobs triggered on 2026-08-20 did not start because GitHub reported an
organization billing/spending-limit problem. The local/combined checks above passed; the CI
infrastructure failure is not represented as a code failure.
