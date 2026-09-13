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

## Staging a candidate for an unshipped source

`--check` and `--publish` both speak about the DEPLOYED source. Neither can
produce a reviewable anatomy for a source the canonical pin must not move to,
which is what an assessment needs. `--stage` does:

```bash
python3 workflow/tools/workflow.py anatomy-refresh \
  --source-ref <sha> --stage <dir> \
  --stage-doc ANATOMY_V3.md --stage-stem anatomy_v3 --stage-edition V3
```

It generates a whole candidate edition — pipeline, inventories, reader,
diagram — into `<dir>` from a clean temporary worktree at `--source-ref`, and
never writes inside `workflow/anatomy/`. Flags:

- `--stage-doc` / `--stage-stem` name the reader and the diagram/SVG stem;
  each must be a single path component.
- `--stage-edition` sets `edition_label` in the staged `SOURCE_PIN.json`, which
  is what the reader titles itself with. Omit it and the candidate is titled as
  a candidate without an edition; the canonical edition remains `v2`.
- `--stage-regen-anchors` re-pins the anchor fingerprints at the staged source.
  Opt-in, because re-pinning is a reviewed act: it makes every drifted citation
  pass by definition.

Staging refuses to write outside `<dir>`, and that refusal is enforced at both
layers. Every destination is resolved and required to land under the staging
directory and outside the canonical one, and the whole staged tree is scanned
for symlinks pointing out of it — before seeding, and again after, because
`pipeline/` and `generated/` do not exist on the first pass. Containment is
tested in BOTH directions: `<dir>` may be neither inside `workflow/anatomy/` nor
an ancestor of it, because the promise cannot hold for a stage tree that
encloses the thing it promises not to touch.

At the generator layer, `paths.py` repeats the descendant scan on import, and
the pipeline scripts that write without importing it —
`build_effect_matrix.py`, `build_operation_matrix.py` and `mutation_test.py` —
import `guard.py`, which runs the same scan over both directories a relative
write can land in: the script's own directory and the process CWD. So a direct
invocation is refused too. Both are preconditions, not sandboxes: a script
importing neither module is outside what they can promise, and a test asserts
that no such writer exists in the pipeline.

Staging never advances `PIN.yaml`. A staged candidate becomes canonical only
through a reviewed `--publish` at the observed deployed SHA.

## Release cadence

Refresh once per **deployed source SHA**. If several fixes ship in one image,
one refresh covers them. If structure is unchanged, record a validated
no-drift result and advance the pin. Do not advance the canonical pin for an
unshipped branch or tag.

## V1 retirement

The old hand-maintained anatomy and module graph are retained under
`archive/anatomy-v1/` for archaeology. They are not part of agent startup and
must not receive new issue joins.
