# Anatomy

`ANATOMY.md` is the definitive generated reader view of Phorvex structure,
responsibilities, relations, seams and actuation operations.

Do not edit it directly. Its source inventories and generator/audit suite are
under `pipeline/`; diagrams are under `generated/`.

## Current status

The migrated baseline is the accepted Anatomy V2 frozen at
`fb52e6c976df` (`v0.4.64`). It is intentionally labelled stale relative to
newer releases until the first release-sync run refreshes it.

`PIN.yaml` distinguishes:

- the source commit represented by the anatomy;
- the currently deployed build recorded by the workflow;
- whether a release refresh has passed.

## Refreshing for a deployed release

Use:

```bash
python3 workflow/tools/workflow.py anatomy-refresh \
  --source-ref <embedded-gitSHA> --check
```

The refresh must operate on a clean worktree at the exact SHA, generate into
a temporary directory, run the full audit and mutation suite, and publish
atomically. A check that fails because code closed a previously recorded gap
requires curation and review; it must not be auto-weakened.

`--check` also fails when the generated outputs differ from the committed
outputs. A green audit suite with generated drift is therefore still a
failing freshness check until an approved `--publish` at the observed
deployed SHA.

Required checks are documented in `pipeline/STATE.md`:

- repository census;
- schema and anchor validation;
- completeness and entrypoint/delivery boundaries;
- surface and reachability validation;
- operation and curation accuracy;
- mutation tests.

## Release cadence

Refresh once per **deployed source SHA**. If several fixes ship in one image,
one refresh covers them. If structure is unchanged, record a validated
no-drift result and advance the pin. Do not advance the canonical pin for an
unshipped branch or tag.

## V1 retirement

The old hand-maintained anatomy and module graph are retained under
`archive/anatomy-v1/` for archaeology. They are not part of agent startup and
must not receive new issue joins.
