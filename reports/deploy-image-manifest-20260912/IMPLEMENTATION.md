# Implementation: digest-bound deploy retagging

Implemented by `deploy_digest_worker` on 2026-09-12 for independent review by
`root`.

## Result

- `build-operator` and `build-console` now export the immutable digest returned
  by their `docker/build-push-action` step.
- A normal deploy retags `repository@sha256:...`; it never reconstructs a source
  tag from Git's adaptive short SHA.
- Operator, console, and Phoenix convenience SHA tags now use the full commit
  SHA through `docker/metadata-action`'s `format=long` setting.
- Forced recovery is a separate tag-source mode and requires an explicit,
  validated `release_from` value.
- `deploy/ci/retag-images.sh` validates the registry, destination tag, source
  mode, every marker, and every selected digest/source tag before invoking
  Docker. Validation of a later component cannot leave an earlier component
  half-tagged.
- `tools/test_deploy_image_manifest.py` covers exact digest sources, a
  single-component release, explicit forced recovery, fail-closed input cases,
  and the static workflow wiring.

No product code, chart values, GitHub state, registry, GitOps branch, or cluster
state was changed.

## Verification

- `bash -n deploy/ci/retag-images.sh`: PASS.
- `/private/tmp/phorvex-pr171-venv/bin/python -m unittest -v tools.test_deploy_image_manifest`:
  5 tests PASS.
- `/private/tmp/phorvex-pr171-venv/bin/python -m unittest discover -s tools -p 'test_*.py' -v`:
  43 tests PASS.
- `TMPDIR=/private/tmp PATH=/private/tmp/phorvex-pr171-venv/bin:/opt/homebrew/bin:/usr/bin:/bin KUBECONFIG=/dev/null USE_EXISTING_CLUSTER=false bash workflow/tools/check.sh`:
  113 tests PASS, 5 SKIP; fix index PASS; issues render PASS.
- `git diff --check`: PASS.

An initial workflow check using macOS's default symlinked temporary directory
reported nine path-canonicalization failures (`/var/...` versus
`/private/var/...`) in existing attack/bus tests. Re-running with the repository's
portable `TMPDIR=/private/tmp` test environment produced the clean result above.

## Recovery boundary

The existing failed release is not recovered by this commit. After independent
review, merge, and separate production approval, the bounded recovery input is
documented in `RECOVERY_PLAN.md`.
