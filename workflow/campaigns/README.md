# Full-system live campaigns

A campaign is a broad, hypothesis-driven study of the deployed system. It is
not an automatic step in the fix loop and may begin only after an explicit
request from the human owner.

Start with `operations/CAMPAIGN.md`. Use `workflow.py new-campaign` to copy the
forward-looking `_template/`, `new-campaign-round` for additional rounds, and
`campaign-transition` for every lifecycle edge. `INDEX.yaml` is a generated
projection of campaign status.

Campaigns and rounds listed in `../ARCHIVE.yaml` were imported with their
evidence left in `PhorvexSecurity/operator@65af1c99`; they are immutable here.
Continue that work in a new campaign (see `../README.md`, “Archived records”).

Use fix-level L3 for the narrow live verification that closes one fix. Use a
campaign to study cross-fix interactions, long soaks, workload effects,
open-world controller behavior, or attack-to-effect coverage across a
release.

## Start conditions

The owner supplies:

- campaign question and included fixes/releases;
- permission level: read-only, dry-run, controlled mutation, or attack;
- environment and safety boundary;
- duration/cost ceiling;
- named approver for every destructive phase.

No agent may infer a campaign from “run L3” or from several fixes sharing a
release.

## Directory schema

```text
campaigns/<YYYY-MM-DD-name>/
  STATUS.yaml
  CAMPAIGN.md
  hypotheses.yaml
  rounds/
    <round>/
      spec.md
      evidence/manifest.yaml
      observations.md
      analysis.md
      review.md
      cleanup.md
  verdict.md
```

Each round’s evidence manifest uses paths relative to that round directory.

## Scientific and safety rules

- Pin source SHA, image digest and embedded `gitSHA`.
- Pre-register hypotheses, falsifiers and sample requirements.
- A null needs a positive control.
- Record ambient load, node churn, co-tenancy and configuration.
- Keep `Selected`, `Emitted`, `Executed`, `Confirmed` and
  `Attack-mitigated` separate.
- One arm or one time series supports an observation, not a population claim.
- Retain raw evidence or label the claim `UNRETAINED`; an unretained claim
  cannot ground another finding.
- Maintain a complete cluster mutation and cleanup ledger.
- Stop on an unapproved mutation, scope escape, safety threshold, or
  unidentifiable build.

## Relationship to issue closure

A campaign may:

- confirm, sharpen, reopen or supersede issue claims;
- discover and file new issues;
- supply an explicitly scheduled L4 soak.

It does not repair missing per-fix L3 retroactively. A fix waiting for a
campaign-owned L4 remains open until that campaign verdict lands.

## Historical campaign

`2026-08-25-live-validation/` is the migrated historical campaign originally
stored in `build/test-harness/PHORVEX_LIVE_CAMPAIGN.md`. Its header and
version pins are historical; it is not current deployment state. Structured
status records rounds 1–2 complete and round 3 deferred. Its retained and
local-original evidence is indexed in `round-1/evidence/manifest.yaml`.
It remains on its historical layout and cannot be transitioned with the v2
campaign commands.
