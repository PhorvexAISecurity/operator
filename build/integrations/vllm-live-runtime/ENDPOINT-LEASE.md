# Opt-in vLLM caller lease boundary

`endpoint_lease.py` adds a default-off caller credential gate to the public
listener in `dual_server.py`. It changes no installed workload by itself. The
normal workload owner must provision migrated callers, an immutable named
Secret, a durable policy ConfigMap, a dependency-preinstalled proxy image, and
an exact five-file source mount before setting
`PHORVEX_ENDPOINT_LEASE_REQUIRED=true`. Today's anonymous public inference
callers remain served by the unchanged default-off mode.

When enabled, each public model request reads the exact
`vllm/phorvex-endpoint-lease-policy` ConfigMap from the Kubernetes API and
checks its sole canonical `state.json` (maximum 16 KiB). It also reads the
exact immutable `vllm/phorvex-endpoint-lease-keys` Secret, verifies its UID,
seed digest, two HMAC roster IDs, and equality to one atomic projection of the
mounted `client-a`, `client-b`, and `seed` bytes. The source, Pod, Service,
ConfigMap and Secret UIDs must equal reviewed environment pins. No prior
successful read or Pod-local file grants admission after an API failure. An
allowed caller reaches the existing guardrail/vLLM handler with only the
internal `VLLM_API_KEY`; a revoked or malformed bearer receives 401 before
forwarding, while uncertain source, policy, API or Secret returns 503. Public
`/health` is 503 until the same authority joins. The raw engine stays on
loopback as required by the separate runtime rollout.

The authenticated private TLS listener has one read-only endpoint:
`GET /v1/endpoint-lease/state?revokedClientHMAC=<64hex>&retainedClientHMAC=<64hex>`.
It requires the existing distinct admin bearer and reports the exact
`WIRE.json.privateStatus.response` fields, including current canonical state
SHA, identities, allow booleans and prior-revision requests still in flight.
It never returns a bearer or HMAC seed. A response already admitted before a
policy CAS may finish; the count remains nonzero until its final body or
disconnect. The native actuator must also account for an old Pod replaced
during an active stream before claiming quiescence.

The reviewed source digest is SHA-256 of exact bytes in this order, separated
by single NUL bytes: `guardrail_proxy.py`, `dual_server.py`,
`endpoint_lease.py`, `drain_v11.py`, `drain_v11_init.py`. The opt-in source
ConfigMap must be immutable with exactly these five keys, mounted read-only at
`/src/<filename>`. The guardrail command is direct
`python3 -B /src/dual_server.py` with no startup shell, pip or PYTHONPATH
override; a separate reviewed dependency-preinstalled image is required.
The guardrail loader pins its existing pgv1 and pgv2 classifier IDs to the
reviewed Hub commits `373b6af0f8d16739cff5de28be326652246bfaa3` and
`90c9989b1a342275dd0d1a95aad283c04e075671`, respectively, and refuses
readiness if the loaded model reports a different commit. This preserves the
two existing variants while avoiding mutable `main` cache refs.
The manager must not GET Secret data. The proxy alone gets the two exact
named API resources using its projected service-account token and CA.

The canonical shared synthetic wire is retained privately under
`N/endpoint-security-design-20260927/WIRE.json` and `WIRE-API.md`. Its UIDs,
HMAC IDs and source digest are test values, not rollout pins. Focused source
checks use the pinned Python 3.11 environment:

```sh
/home/mehrdad/.local/share/phorvex-tools/m116-py311/bin/python \
  -m unittest -v test_endpoint_lease.py test_real_app.py
# In build/test-harness/guardrail:
/home/mehrdad/.local/share/phorvex-tools/m116-py311/bin/python \
  -m unittest -v test_guardrail_proxy.GuardrailHTTPTest.test_load_all_pins_and_verifies_both_classifier_revisions
```

These tests exercise the ASGI boundary and actual guardrail FastAPI handler
against a bounded fake upstream, fake named Kubernetes reads, a real local
HTTP API read, restart, stale Secret, API outage, duplicate Authorization,
all public model routes, and streaming completion/cancellation. They do not
prove a live caller migration, model behavior or selected native action.
