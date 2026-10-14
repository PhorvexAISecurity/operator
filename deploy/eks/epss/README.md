# EPSS ECR auth: prepare, publish, activate, verify

E2 adds disabled chart support and a standalone init helper. Existing Secret mode,
EPSS dry-run (`apply: false`), strict partial rejection (`allowPartial: false`),
active image/source pins and `values-eks.yaml` stay as they were. No live action is
performed by preparing these files. E1 owns IAM; the publication/activation owner
performs the later steps only after review, exact-head green CI, P0 preservation
and a serialized stack release window.

## Auth modes

`phorvex.epss.feed.registryAuth.mode` defaults to `secret` with auth disabled.
The previous `enabled`, `secretName`, `secretKey`, `registries` settings keep their
meaning. Secret mode projects the caller's file as `config.json`, mode `0440`,
read-only; no Kubernetes Secret API read is granted to the feed.

For E3, set `registryAuth.enabled: true`, `mode: irsaInit`,
`irsaInit.enabled: true`, `irsaInit.image` to the receipt's verified full
`753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:...`,
`irsaInit.roleARN` to `arn:aws:iam::753556437180:role/phorvex-dev-epss-feed`, and
`irsaInit.region: us-east-2`. Add that exact role ARN to the **feed** ServiceAccount
annotation `eks.amazonaws.com/role-arn`, through the reviewed E3 values change.
IRSA mode also requires the exact namespace/ServiceAccount trust subject above.
Set `registries` to exactly the two approved hosts:

- `753556437180.dkr.ecr.us-east-2.amazonaws.com`
- `602401143452.dkr.ecr.us-east-2.amazonaws.com`

`secretName` must remain empty and `secretKey` must remain its inert default
`config.json`. Both modes cannot be enabled together. No guessed digest or
unapplied role is added to active values. Keep `activeDeadlineSeconds: 3600` and
`scanTimeout: 10m`; opt-in validation rejects deadlines above 3600 or another
scan timeout. The helper's expiry exceeds the combined 4200-second horizon.
The chart mounts a dedicated projected STS-audience token and a `1Mi` memory
credential volume; the feed's existing loader, permission mask and scrubbed
scanner environment are unchanged.

## Stage 2 commands and gates (not executed by E2)

1. E1 applies its reviewed role/policy-only saved Terraform plan. Recheck the exact
   trust subject `system:serviceaccount:phorvex-system:phorvex-phorvex-epss-feed`,
   OIDC audience and two-registry repository authority. No extra IAM, node role,
   EKS root apply, new repository or capacity belongs to this change.
2. After E2 review/merge, publish with the command in the
   [helper README](../../../build/integrations/epss-ecr-auth-runtime/README.md).
   Record merged source SHA, workflow run URL, digest and receipt checksums.
   The publisher checks existing lifecycle retention and source-tag absence.
3. Prepare E3 on fresh main using the receipt digest and applied role. Render the
   entire stack off the gateway and review all intended differences:

   ```sh
   helm template phorvex deploy/helm/phorvex-stack -n phorvex-system \
     -f deploy/helm/phorvex-stack/values.yaml \
     -f deploy/helm/phorvex-stack/values-eks.yaml \
     --api-versions monitoring.coreos.com/v1/PodMonitor --include-crds > "$E3_EVIDENCE/rendered.yaml"
   python3 tools/test_epss_irsa_chart.py
   bash tools/check-vendored-chart.sh
   ```

   Do not update Phoenix or blanket-sync unrelated Argo drift. Compare the active
   CronJob/ServiceAccount, operator/Console pins and concurrent owner release before
   the lead merges E3. Merging active GitOps inputs is an apply action; automated
   Argo sync may start immediately. If targeted synchronization is needed after
   that separately authorized merge, limit it to these resource names:

   ```sh
   argocd app sync phorvex-stack \
     --resource :ServiceAccount:phorvex-phorvex-epss-feed \
     --resource batch:CronJob:phorvex-phorvex-epss-feed
   ```

4. After E3 sync, capture an unmodified **full-inventory** witness and the cache
   baseline. Run approved kubectl commands off the gateway and save only nonsecret
   evidence on the VPS/approved isolated host. Never read credential files, Secret
   payloads or authenticated scanner stderr. Record gateway disk through the owner
   preflight without placing any sources, repositories or evidence there. The
   following commands are later-stage instructions:

   ```sh
   set -euo pipefail
   umask 077
   mkdir -p "$E3_EVIDENCE"
   kubectl get cronjob phorvex-phorvex-epss-feed -n phorvex-system -o json > "$E3_EVIDENCE/cronjob.json"
   kubectl get configmap phorvex-epss -n phorvex-system -o json > "$E3_EVIDENCE/cache-before.json"
   E3_JOB="epss-auth-witness-$(date -u +%Y%m%d%H%M%S)-$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
   kubectl create job "$E3_JOB" -n phorvex-system --from=cronjob/phorvex-phorvex-epss-feed
   kubectl get job "$E3_JOB" -n phorvex-system -o json > "$E3_EVIDENCE/job.json"
   kubectl wait --for=condition=complete --timeout=3700s -n phorvex-system "job/$E3_JOB"
   kubectl logs -n phorvex-system "job/$E3_JOB" -c feed --limit-bytes=16777216 > "$E3_EVIDENCE/feed.log"
   kubectl get configmap phorvex-epss -n phorvex-system -o json > "$E3_EVIDENCE/cache-after.json"
   ```

   The bounded wait is an operator command, not an agent blocking wait. If the Job
   fails or times out, retain safe evidence, report failure, and clean up that exact
   witness after confirming its recorded UID; do not retry until a concrete cause
   is resolved. Do not narrow namespaces, repositories, digests or pod inventory.
   Record the full current image inventory, role ARN, helper digest, Job name/UID
   and UTC separately; `uniqueImages` alone cannot prove repository membership.
   Extract the feed's single final JSON `Result` from `feed.log` into `result.json`
   without treating progress logs or the Job's complete condition as scan success.
   The output includes `mode`, `uniqueImages`, `scannedImages`, `failedImages` and
   coverage; do not accept a partial/failed scan or publish that dry-run cache.

   ```sh
   python3 deploy/eks/epss/verify_dry_run.py \
     --cronjob "$E3_EVIDENCE/cronjob.json" --job "$E3_EVIDENCE/job.json" \
     --before "$E3_EVIDENCE/cache-before.json" --after "$E3_EVIDENCE/cache-after.json" \
     --result "$E3_EVIDENCE/result.json"
   ```

   This offline helper bounds each input to 16MiB, verifies the full Job template
   (ignoring only Kubernetes' automatic selector/Job labels), rejects scope flags,
   requires `mode=dry-run`, zero failures and scanned count equal to full unique
   count, and compares cache UID/resourceVersion/data/annotations. The metadata
   key must remain absent. It makes no API call and performs no cleanup implicitly.
   Keep detailed failure evidence for missing digests or cross-account denial;
   those do not pass the witness and do not justify widening authority.
5. After evidence capture, compare the live witness UID with the saved UID and
   delete **only** that witness:

   ```sh
   E3_EXPECTED_UID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["metadata"]["uid"])' "$E3_EVIDENCE/job.json")"
   test "$(kubectl get job "$E3_JOB" -n phorvex-system -o jsonpath='{.metadata.uid}')" = "$E3_EXPECTED_UID"
   kubectl delete job "$E3_JOB" -n phorvex-system --wait=true --timeout=60s
   ```

   Confirm the next scheduled run with the same full-template/result/cache checks;
   no separate witness replaces that acceptance. In already-approved isolated AWS,
   use the actual role for an allowed exact digest and an existing denied
   out-of-scope repository in an approved host. Capture only success/denial
   metadata; never print tokens. No capacity is created for this control.

## Rollback

Before E3 merge, record the immediately preceding chart auth/ServiceAccount values
and Git revision. If E3 fails, the lead prepares/reviews a Git revert of the E3
activation commit (rebase it to preserve later unrelated changes), and merges it
in the same serialized release process:

```sh
git revert "$E3_ACTIVATION_COMMIT"
# Lead reviews/publishes this revert; Argo applies the recorded prior auth mode.
argocd app sync phorvex-stack \
  --resource :ServiceAccount:phorvex-phorvex-epss-feed \
  --resource batch:CronJob:phorvex-phorvex-epss-feed
```

Allow safe active Jobs to finish; verify subsequent Jobs use the prior auth mode.
Retain the deployed/rollback helper tag and evidence. Do not delete images,
EPSS cache, snapshots, PVCs, Secret credentials or shared chart objects. E1 can
remove only its newly isolated IAM resources through a separately reviewed
Terraform destroy plan once no Job/ServiceAccount uses the role. There is no live
E2 rollback while its support remains disabled; revert E2 source/package only
through the lead's review/publication process if necessary.
