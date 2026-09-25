# Root-cause deduplication

## Search terms and source locus

`allowedNodeName`, `allowedNodeNames`, `nsRe`, `IsDNS1123Subdomain`, and `Pod-bound token profile has incomplete fixed destination or authority` were traced in current console and harness source. The installed immutable CPU ConfigMap uses the valid Kubernetes node name `ip-172-27-11-9.us-east-2.compute.internal`. `pod_bound_token.go:122` at baseline `f63f2f63` applied the single-label namespace regex to that node and rejected catalogue admission before POST. The producer-side harness `config.go:738` already accepts DNS subdomains.

## Candidate comparison

- `CAT-MONGO-ADMISSION` repaired the same validator category (`allowedNodeNames` on actual EKS FQDNs), but in the Mongo named-profile parser at `console/runs.go:967`. It did not change `pod_bound_token.go`, whose separate CPU and Voice profile field remained broken. The new patch is a follow-up to the shared validation lesson, not a duplicate implementation of the Mongo correction.
- `CAT-CPU-TOKEN-RESPONSE` owns the existing CPU response mechanism. This report is a distinct console-admission blocker for that existing case: a valid installed profile could not get to its first run POST. The fix changes no signal, brain, actuator, response oracle, or case ID.

## Determination

**NEW, bounded consumer follow-up** to `CAT-CPU-TOKEN-RESPONSE`, with `CAT-MONGO-ADMISSION` as the analogous prior correction. No new catalogue case is requested. This descriptive comparison is not an intake transition, issue promotion, or investigator signature; `codex-lead` owns those workflow decisions.
