# Deliver reviewed fixed catalogue profiles

The fixed harness YAML files in `build/test-harness/` are templates, not installation authority. Use a new private input directory for each deployment review. Replace every installation placeholder from a fresh, independently reviewed cluster/source projection. Keep exact profile bytes, the source/build review records, and a narrow stack values fragment together. Do not commit or apply a filled bundle until the deployment owner reviews current identities, scope, and cleanup prerequisites.

`tools/package_fixed_catalogue_profiles.py` is offline. Run it with the project Python environment, which includes PyYAML from `workflow/requirements.txt` (`PyYAML>=6,<7`). It checks the selected profile bytes, binds them to `evidence/JOIN.json` and `evidence/SOURCE-BUILD.json`, and writes create-once immutable ConfigMaps, a matching umbrella-chart values fragment, copied proof files under `evidence/`, and a receipt. It never reads a cluster, constructs a grant, creates a TokenRequest, or deploys. The script packages reviewed facts; it cannot certify that those facts are still current. The source-controlled subchart switches remain off by default.

Use the exact supported profile filenames in the input directory:

| `--profile` | ConfigMap key | Values block under `phorvex.phorvex.console` |
| --- | --- | --- |
| `mongo` | `config.mongo-exposure-baseline.yaml` | `mongoExposure` |
| `guardrail-static` | `config.guardrail-confidentiality-static.yaml` | `guardrailStatic` |
| `nats-baseline` | `config.nats-exposure-baseline.yaml` | `natsExposure` |
| `nats-response` | `config.nats-client-response.yaml` | `natsExposure.clientResponse` |
| `pod-token` | `config.pod-bound-api-auth-response.yaml` and `manifest.json` | `podBoundToken` |

The input `values-overlay.reviewed.yaml` uses the umbrella path `phorvex.phorvex.console`. For each selected suite it declares `enabled: false` while preparing the package, plus any other suite-specific fixed values required by the chart. Both `phorvex.phorvex.image.tag` and `phorvex.phorvex.console.image.tag` must explicitly match the reviewed release in `evidence/SOURCE-BUILD.json`; the package also checks both immutable image IDs and Ready Pod identities in `evidence/JOIN.json`. The packager inserts the digest-suffixed `configMapName` and exact `profileSHA256`; it rejects conflicting nonempty values and an enabled suite whose profile was omitted. It refuses all enabled profiles unless `--allow-enabled` is explicitly passed after review. NATS response cannot be enabled without the baseline. Output values are rebuilt from selected profile blocks and these explicit image tags; unrelated input stack settings are rejected.

All `__SET_` YAML scalar keys and values must be filled. The original NATS response template has a comment mentioning `__SET_*__`; that comment may remain after the actual values are filled because comments are not executable profile fields. The copied profile bytes, including comments, are still hashed exactly.

For Pod-token, copy the reviewed build record, the bounded rollout Pod projection (`evidence/PODS.json`), and the independent source-review JSON into input `evidence/`. Set `manifest.json` `buildEvidenceRef` and `reviewRecordRef` to the exact relative paths `evidence/SOURCE-BUILD.json` and `evidence/source-review.json`, with their exact SHA-256 values. The packager checks the source commit, build digests, reviewed manager/console images, the source review's Pod-read hash, and the Pod UID, deployment incarnation, image and cluster joins against `evidence/JOIN.json`. The profile may contain exactly one `__SET_EXACT_REVIEWED_MANIFEST_SHA256__` marker, which the packager replaces with the hash of the exact manifest bytes. The manifest and final profile bytes are then hashed into the output. All four proof files are copied byte-for-byte into output `evidence/`; `receipt.json` lists their hashes. An absolute workstation path or an output-file collision in a manifest reference is rejected. `sourceManifestPath` in the profile remains the fixed in-Pod path `/etc/phorvex-catalogue-pod-bound-token/manifest.json`.

Example offline preparation (paths are local; no cluster call):

```sh
python3 tools/package_fixed_catalogue_profiles.py \
  --input /private/reviewed-catalogue-input \
  --profile nats-baseline \
  --profile pod-token \
  --overlay values-overlay.reviewed.yaml \
  --output /private/new-catalogue-package
```

The output `configmaps.yaml` and `values-overlay.yaml` are a GitOps **proposal**. Render them against the exact deployment chart and values in the target branch, check the projected read-only keys and namespace-local RBAC, then review the final diff before normal deployment. For an enabled proposal, pass `--allow-enabled` and retain the resulting receipt with the review. The umbrella chart can alternatively own the same immutable, single-key Mongo ConfigMap when `catalogueProfiles.mongoExposure` supplies the exact package's `configMapName` and canonical `profileBase64`; it checks the decoded bytes against the enabled console name and SHA. Supplying source bytes alone does not enable Mongo. A new manager/console rollout can change image IDs and Pod incarnation; new source/target ConfigMaps, route, node eligibility, journals, and protected ledger state can also change. Refresh those facts, rebuild manifest/profile/ConfigMap hashes and rerender before applying a later release. The exact mounted bytes, grant admission, prior-run barrier, outcome, and cleanup are checked separately after deployment.

Current campaign limits: the reviewed Mongo parser repair accepts a pinned EKS DNS-subdomain node; an enabled Mongo package still needs fresh authenticated build, rollout, target and untainted-node originals. The historical `.166` proof path remains accepted only with its five `--expect-mongo166-*-sha256` pins. For a later reviewed release, use the five `--expect-mongo-current-*-sha256` pins with `evidence/source-current/{SOURCE-BUILD.json,SOURCE-REVIEW.json}`, `evidence/rollout-current/RECEIPT.json` and its original projected response files, plus `evidence/mongo/{RECEIPT.json,ELIGIBLE-NODES.json}` and the raw Mongo/node GET bodies. The current path derives the release tag, source commit and installed image digests from the signed original evidence; it checks the retained projected rollout responses as projections, not raw Kubernetes GET bodies. A changed parser needs a new reviewed source rule. The static guardrail profile needs a current exact eligible variant and fresh journal/route identities. NATS response and network containment remain deferred while CNI policy enforcement is unresolved; a NATS baseline is a configuration control only. A Pod-token package needs current scrape approval and a disjoint Voice policy graph, and its old protected capacity record must be preserved. No packaged file by itself establishes defense efficacy or a live passing case.
