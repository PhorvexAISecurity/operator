# Signed lead plan: deploy image provenance

Signed by `root` on 2026-09-12.

## Incident

Main run `34707032598` at
`6624065dba0b4ee0ef325360baebb294b643742f` built and pushed both images as
`sha-6624065`. The deploy job independently ran `git rev-parse --short HEAD`,
which selected the now-necessary eight-character abbreviation
`sha-6624065d`. ECR correctly returned `not found`; no GitOps values commit or
rollout was attempted.

## Decision

Normal releases must consume the immutable digest emitted by each successful
`docker/build-push-action` job. The deploy job must not reconstruct or discover
the image reference. Export the operator and console build digests as job
outputs, validate each selected digest, and retag `repository@sha256:...` to the
release version.

Keep forced recovery explicit and separately bounded: it may consume the
operator-supplied `release_from` tag. Future SHA convenience tags should use the
full commit SHA (`format=long`) so Git's adaptive abbreviation and registry tag
generation cannot diverge or collide. Historical short tags remain valid when
named explicitly; in particular, recovery of this failed run must use
`release_from=sha-6624065` after the fix reaches `main`.

Extract the retag boundary into a shell script that can be exercised without
AWS. It must reject missing/malformed digests, unknown markers and invalid tag
inputs before invoking Docker. Add positive and negative tests with a fake
Docker transport, plus static workflow assertions binding build outputs to the
deploy inputs.

## Scope and handoff

Implementer: `deploy_digest_worker`; independent reviewer: `root`. Product code,
chart values and cluster state are out of scope. Deliver an independently
reviewed PR from `fix/deploy-image-manifest`; do not merge it, dispatch a release,
push a GitOps version commit, or mutate the cluster in this task. The current
failed release remains safely unapplied until the reviewed workflow fix is on
`main` and an authorized forced recovery names the already-built seven-character
tag.
