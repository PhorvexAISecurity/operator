# Reviewed vLLM caller-lease console profile

This offline renderer creates the immutable console profile from the owner activation package's non-secret `ADOPTION.json`. It does not create credentials, modify the cluster, or fire a test. The owner installs the immutable five-file `guardrail-proxy` source, the tenant A/B/seed Secret, the separate console A/B copy, the rev0 policy ConfigMap, and the protected empty journal through the reviewed activation. The policy must be the existing `vllm-defense` with ordinary action alternatives, including `endpoint-lease-revoke`.

After reading the current policy UID/generation and exact authenticated audit-source identity, render:

```sh
python3 render_profile.py /private/ADOPTION.json \
  --policy-uid <current-vllm-defense-uid> \
  --policy-generation <current-generation> \
  --audit-source-identity <reviewed-audit-source-id> \
  --out /private/endpoint-lease-console-profile
```

The output contains canonical `profile.json`, an immutable `profile-configmap.json`, and `helm-values.json`. The latter enables only the console option; the native action has its own default-off `phorvex.endpointLease.enabled` gate. Review the rendered names, UIDs and source/image hashes before normal owner rollout. The mounted profile carries only opaque hashes and Kubernetes identities. The mounted console Secret carries the two owned callers and is never copied into the profile or result.

Fire calls the real public vLLM Service with A and B, requires exact real model answers from both, then labels its SecurityEvent `TEST_INJECTED`. The first accepted A request remains a loss. A defended result requires a normal selected decision, the protected terminal journal joined by event/tick/decision and prior proxy container incarnations, every current proxy readback, a fresh A 401, and a fresh B 200 with the expected model answer. An existing revocation, source mismatch, incomplete model answer, brain NOOP, unknown dispatch, 503, or failed evidence persistence earns no new defended result. This trial covers only the two owner-provisioned callers; it does not establish natural detection, SSRF prevention, extraction prevention, or other credential protection.
