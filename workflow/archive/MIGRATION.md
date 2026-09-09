# Additive migration record

**Date:** 2026-09-07
**Initial inventory base:** `4cad00f` (`v0.4.87`)
**Final PR base:** `origin/main` at `0bc6890` (`v0.4.88`)
**Mode:** copy and normalize; never move or delete the original local trees

## Original local sources

- `/home/mehrdad/operator/build/test-harness/PHORVEX_FIX_LOOP.md`
- `/home/mehrdad/operator/build/test-harness/PHORVEX_MASTER_ISSUES.md`
- `/home/mehrdad/operator/build/test-harness/PHORVEX_MASTER_ISSUES_V2.md`
- `/home/mehrdad/operator/build/test-harness/PHORVEX_ANATOMY.md`
- `/home/mehrdad/operator/build/test-harness/PHORVEX_ANATOMY_V2.md`
- `/home/mehrdad/operator/build/test-harness/campaign/anatomy-v2/`
- `/home/mehrdad/operator/build/test-harness/PHORVEX_LIVE_CAMPAIGN.md`
- `/home/mehrdad/operator/build/test-harness/campaign/round-*`
- `/home/mehrdad/operator/build/test-harness/campaign/bus/`
- `/home/mehrdad/operator/fixes/`

The originals remain untracked/local as requested. This branch adds only
`workflow/`.

## Promotions

- Anatomy V2 becomes generated `anatomy/ANATOMY.md`.
- Master Issues V2 becomes generated `issues/MASTER_ISSUES.md` after
  reconciliation with the newer base-register bodies.
- The old fix loop is superseded by root `WORKFLOW.md`.
- The old live campaign becomes the dated historical campaign
  `campaigns/2026-08-25-live-validation/`.

## Historical copies

- old workflow: `archive/workflow-v1/`
- anatomy v1/design/module graph: `archive/anatomy-v1/`
- original base register and stale V2 snapshot: `archive/register-v1/`
- old two-agent bus protocol/tool: `archive/coordination-v1/`

Historical files are read-only and excluded from normal agent startup.
The one-time import scripts are retained under `archive/migration-tools/`;
their replacement modes are not operational workflow commands.

## Large evidence omitted from Git

Large legacy artifacts remain at their original local paths. Their byte sizes
and SHA-256 values are recorded in `artifacts/legacy-manifest.yaml`.

## Known migration corrections

The copied V2 register was not current:

- M-160's latest status existed in the base register but not V2;
- V2 banner counts were stale;
- the projector's manually maintained closed-ID set lagged recent closures.

The new issue renderer therefore treats the newer base issue bodies as source,
imports joins separately, and derives counts/status from entry metadata.

Three legacy root files named `06-verdict.md` (M-020, M-023 and M-160) were
actually P3 “ready for PR” verdicts. In the workflow copy they are relocated
byte-for-byte to `evidence/p3/verdict.md`; no final verdict is present before
L3 and synchronization. The original local files are unchanged.

## Explicit non-actions

- No original file or directory is removed, renamed, moved or overwritten.
- No production source, chart, deployment value or active fix branch is
  modified.
- No legacy raw evidence is silently rewritten.
- No historical missing artifact is fabricated.

## Migration validation

- 159 issue entries parsed; the initial entry/layout rendering was
  byte-identical to the newer base register
  (`sha256:c8f0a94f7cec9163da4315c56935b83235557e0d14b755c8ee4df4bdfe117cb2`).
  Immutable per-entry migration hashes retain that proof while current issue
  bodies advance through reviewed `rehash-issue` updates.
- 159 Anatomy V2 joins imported without rewriting issue bodies.
- The promoted `anatomy/ANATOMY.md` baseline is byte-identical to the accepted
  Anatomy V2 source; only its portable generator pipeline was refactored.
- 11 legacy fix directories received additive structured status.
- 171 copied legacy fix files are byte-identical to their originals; the
  three relocated P3 files are also byte-identical at their normalized paths.
- 82 retained fix evidence artifacts were size/SHA-256 indexed, including the
  three normalized P3 verdicts.
- 30 round-1 campaign artifacts are indexed (8 Git-retained, 22
  local-original).
- The historical campaign narrative is byte-identical to its original
  `PHORVEX_LIVE_CAMPAIGN.md`.
- 25 omitted artifacts (386,027,815 bytes, including the 21-file campaign raw
  corpus) remain at their original local paths and matched their recorded
  size/SHA-256 during migration.
- The portable anatomy pipeline passed 11/11 audits and 65/65 mutation tests
  from a clean detached worktree at its frozen `fb52e6c976df` source pin.
  The outer freshness check remains intentionally red because portable-path
  normalization changes generated outputs and the canonical anatomy must next
  be published against the observed deployed SHA, not republished at the old
  pin.
