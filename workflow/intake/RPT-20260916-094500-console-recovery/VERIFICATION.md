# Console recovery verification

Observed 2026-09-16 through the authorized EKS VPS.

Baseline: console and operator 0.4.118; sync failure explicitly rejected non-null rollingUpdate with Recreate. PVC WaitForFirstConsumer had no consumer. Console scanner subprocess exited 1 because phorvex-phorvex-console cannot list networking.k8s.io/networkpolicies. The handler discards that exit status and returns HTTP 200 with zero fields. The prd ingress uses an independently verified second ALB while verifier accepts only the first ARN and trusts only the dev origin.

Falsifiers: desired Deployment validates and syncs without migration; scanner returns populated output with old permissions; prd signer passes the existing exact signer comparison. None held.

Positive control: atomic strategy replacement passed server dry-run and applied; terminating the obsolete stuck operation and syncing current main produced successful ArgoCD sync, both images 0.4.119 and Bound console PVC. Grants remained one approved subject. Scanner positive control and signed-token tests remain pending until implementation.

Safety: read-only scan, no attack execution, no credential bypass, no additional user grants. Production migration explicitly requested by user. No signed-in browser claim is made.
