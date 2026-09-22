# M104 authoritative EPSS canary handoff

Status: **public review package; not deployable yet**.

This package enables one bounded `voice` canary for the authoritative EPSS consumer. It contains no credentials, no live object identities, and no authorization to deploy. The retained authenticated dry-run scan of the exact voice image digest passed, but the short-lived registry Secret used for that scan was deleted. Before any rollout, the root operator must complete the exact policy barrier, revalidate all runtime identities, and provide a fresh registry Secret name and UID.

Place this directory at `deploy/helm/phorvex-stack/examples/m104-voice-canary` in a clean checkout of the approved operator revision. Commands below are relative to that checkout and require Helm 3.

## Fixed bounds

- Namespace scope: `voice` only.
- Digest scope: `753556437180.dkr.ecr.us-east-2.amazonaws.com/pipecat-voice@sha256:c9c598c406ed517eebf17f92a36863b39a15d9a7875cfcb2710f7b084dd539b8` only.
- Dedicated canary ConfigMap: `phorvex-epss-m104-canary`.
- CronJob remains suspended in the rendered rollout.
- At most one applied Job is created from its exact captured template.
- At most two policy patches: active to dry-run, then exact restoration.
- No SecurityEvent, workload mutation, target restart, action dispatch, or kill-switch change.
- Observation window: 60 minutes. Detached cleanup: 15 minutes.

Any identity, policy generation, digest, source, template, ConfigMap, or Secret drift makes the trial incomplete. Never select a substitute object.

## Inputs that must exist before rendering

1. A root-approved current GitOps revision and manager image/source containing the authoritative EPSS consumer.
2. A fresh, short-lived Docker config Secret in `phorvex-system`, restricted to the selected ECR registry. Root records its exact name, UID, expiry, key `config.json`, and data hash without publishing its bytes.
3. A fresh root capture of the manager Deployment and Pod, `phorvex-system` and `voice` namespace UIDs, the complete `voice` policy inventory, `voice/voice-defense` UID/generation/full spec/status, all matching Ready target Pod/container identities, and the original shared `phorvex-epss` UID/resourceVersion/data hash.
4. The exact-policy zero-actuation barrier described below, including a fresh raw dry-run audit row.

Replace `RUNTIME_FILL_FRESH_SECRET_NAME` in `values-m104-voice-canary.yaml` only with the root-approved Secret name. This template must remain undeployable while that placeholder remains or while the policy barrier is incomplete.

## Render and inspect

Merge this overlay into the actual current GitOps values; do not use stale `helm get values` output as a deployment baseline. Append the entry in `argocd-ignore-differences-m104.yaml` to the Application's existing `spec.ignoreDifferences` list without removing existing entries.

From the repository root:

```sh
helm dependency build deploy/helm/phorvex-stack
helm template phorvex deploy/helm/phorvex-stack \
  --namespace phorvex-system \
  -f deploy/helm/phorvex-stack/values-eks.yaml \
  -f deploy/helm/phorvex-stack/examples/m104-voice-canary/values-m104-voice-canary.yaml \
  > m104-rendered.yaml
```

Review the complete diff against the current GitOps render. The only intended M104 behavior is a dedicated authoritative ConfigMap, suspended scoped feed CronJob and its narrow RBAC, registry Secret reference, and authoritative manager arguments. Preserve all unrelated manager arguments, environment, volumes, service account, probes, annotations, scheduling, and other resources exactly.

## DevOps shared-rollout tasks

DevOps performs only the reviewed GitOps changes:

1. Verify the approved repository revision and current baseline render.
2. Insert the root-provided fresh registry Secret name into the overlay.
3. Add the Argo ignore-difference entry for only the dedicated canary ConfigMap data and feed annotations.
4. Apply the reviewed current-values merge after root confirms the zero-actuation barrier.
5. Prove the new manager image/source and exact authoritative arguments, dedicated ConfigMap UID, suspended CronJob UID/template, scoped RBAC, and unchanged original shared feed.
6. After root completes the canary, restore the reviewed legacy/shared configuration and remove the temporary ignore-difference entry only after the original feed and healthy manager are reverified.

DevOps does not create the applied Job, patch the policy, emit events, modify voice workloads, or interpret the resulting economics.

## Root/Codex controlled verification

Before DevOps rollout, root revalidates every identity and proves no other active policy selects the scoped digest. Root then patches only `voice/voice-defense` using JSON Patch tests for its exact UID, generation, and complete captured spec before replacing `/spec/mode` with `dryRun`. Root waits for the same UID, generation increment, exact expected spec, matching `status.observedGeneration`, Ready, and DryRun=True. A fresh raw row for the same policy generation and a current target UID must show `dryRun=true`, `actuated=false`, the exact running digest, and the pre-rollout legacy/provenance-unavailable state.

After the shared rollout, root first retains an authoritative-unavailable dry-run row. Root creates exactly one Job from the captured suspended CronJob template, requires successful completion with zero failed images and the exact namespace/digest scope, and binds the resulting ConfigMap UID/resourceVersion, cache and metadata hashes, source, timestamps, counts, EPSS, and CVSS to the producer receipt.

The adoption row must use the same policy generation and target UID and report authoritative/available with the exact digest and evidence identities. Its multiplier must equal `1 + EPSS*(CVSS/10)`. It must remain `dryRun=true` and `actuated=false`.

For expiry, root performs no second feed write. With the CronJob still suspended, the ConfigMap UID/resourceVersion and bytes must remain unchanged. After metadata expiry plus one bounded decision interval, the same policy generation and target UID must report authoritative/expired, no EPSS/CVSS/multiplier, and no stale non-neutral multiplier, while still dry-run and non-actuated.

Root then coordinates the shared configuration restoration, deletes only exact recorded canary resource and Secret UIDs, and restores the same policy using tests for its exact UID, current generation, and complete dry-run spec before replacing the full spec with the captured original. Final evidence must show the original shared feed unchanged, a healthy restored manager, exact original policy spec, unchanged targets, zero dispatch, and no surviving canary resources.

## Accepted prerequisite and claim boundary

The authenticated dry-run scan for the exact voice digest passed in the independent M104 voice review. Its temporary auth Secret and runner objects were deleted. Treat that as producer feasibility for one digest only; revalidate target identities and create a fresh pinned Secret for the applied Job.

This canary can establish scoped feed production, authoritative consumption, arithmetic recomputation, expiry, and zero actuation under dry-run. It cannot establish ranking, selected action, defense efficacy, compromise probability, fleet coverage, or savings. No deployment or live M104 consumer claim has been made by this package.
