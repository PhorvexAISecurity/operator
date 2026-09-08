# Synchronize main, releases, issues, and Anatomy

Source-main truth and live truth are deliberately separate:

- fixes are implemented against reviewed `origin/main`;
- live claims and canonical Anatomy stay pinned to the observed deployment.

## Main reconciliation

1. Fetch the code remote outside this tool and ensure the source ref is
   available locally.
2. Run `sync-main --check --source-ref origin/main`.
3. Review the emitted commit range, issue/fix references, changed Anatomy
   surfaces, source release, and unattributed changes.
4. Record decisions in the reconciliation record. Do not infer closure from a
   commit subject or tag.
5. Run `sync-main --publish` with an approval reference. This updates only
   code-main/source-release facts and reviewed issue transitions such as
   `MAIN_PENDING_DEPLOY`, then regenerates Master Issues.

## Deployment reconciliation

1. Observe the running image, digest, embedded `gitSHA`, rollout timestamp,
   environment, and population.
2. Run `release-sync --check`, then `release-sync --publish` with deployment
   approval. Publishing creates the `DEPLOY-*` record and establishes the
   observed-deployment pin required by Anatomy.
3. Publish Anatomy at that exact embedded SHA after its full suite passes.
4. Run required scoped L3/L4. A rollout alone permits at most
   `DEPLOYED_PENDING_L3`.
5. Run `release-sync --finalize` to apply evidence-backed issue/fix verdicts,
   regenerate Master Issues, run
   permanent verifiers, and publish the release transaction atomically.

Every main advance is reconciled, including changes made by colleagues with no
M-number. Such commits remain `unattributed_changes` until an agent reviews
their effect; they are never silently ignored.
