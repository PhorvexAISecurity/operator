# Independent review: deploy image provenance

Reviewed and signed by `root` on 2026-09-12 against implementation commit
`74d1643a2fe9391761058f534b504eb3786b0808`.

## Verdict

PASS. The incident is a producer/consumer reference mismatch, not an ECR or
ArgoCD failure. Run `34707032598` proves both build jobs pushed
`sha-6624065`, while the deploy job independently selected
`sha-6624065d`; the latter manifest did not exist, so the workflow correctly
stopped before changing GitOps values.

The implementation removes that inference from normal releases. Each build job
exports the digest returned by its own `docker/build-push-action` invocation,
and deploy retags the selected `repository@sha256:...` reference. The extracted
boundary validates every selected source and destination before its first Docker
call. A missing second digest therefore cannot produce a partially tagged
release. Forced recovery remains a distinct, explicit tag-source mode and does
not silently fall back to an inferred commit abbreviation.

Full-SHA convenience tags remove the original adaptive-abbreviation collision
from future recovery references. Historical short tags remain addressable when
explicitly supplied, including the two artifacts from this incident.

## Independent validation

- `bash -n deploy/ci/retag-images.sh`: PASS.
- All tool regressions: 43 tests PASS, including exact producer digests,
  single-component releases, explicit forced recovery, and 11 fail-closed input
  cases with zero Docker calls.
- Workflow contract suite: 113 tests PASS, 5 declared skips.
- Fix index and issue projections: PASS.
- Workflow doctor: 0 errors; 17 unrelated historical/release warnings.
- YAML parsing, configured-author/trailer check, clean base diff and
  `git diff --check`: PASS.

No registry write, workflow dispatch, GitOps change, release tag, rollout, or
cluster mutation was performed during implementation or review. Production
recovery remains pending the explicit approval described in `RECOVERY_PLAN.md`.
