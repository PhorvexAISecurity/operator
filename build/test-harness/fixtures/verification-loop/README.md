# Endpoint lease runtime fixture

This helper verifies **credential admission with a synthetic downstream**, not
GPU inference. It imports the repository's unchanged `EndpointLease` and
`ServingBoundary`, computes the same five-file source digest used by the runtime,
and reads the actual named policy ConfigMap and immutable caller Secret from an
isolated envtest API over verified TLS with an envtest client certificate.
Production policy parsing, identity checks, Secret comparison, Kubernetes
`..data` projection-generation checks, anti-replay state, and admission remain
inside the real `EndpointLease`. The harness creates the real projected bytes.

The local adaptations are the API transport (envtest mTLS instead of an in-pod
service account token) and ASGI listener scope (ephemeral sockets mapped to the
boundary's fixed logical public/private ports). The synthetic downstream is a
separate HTTP listener accepting only the configured upstream credential. A
successful completion echoes an owned marker and request nonce and increments
its counter. It provides no model output or GPU claim.

Run `runtime_fixture.py --config /absolute/config.json` with Python, `httpx`, and
`uvicorn`. The config file must be private and contain these fields:

```json
{
  "repo_root": "/absolute/operator",
  "api_url": "https://127.0.0.1:ENVTEST_PORT",
  "api_ca_file": "/private/envtest-ca.crt",
  "api_client_cert_file": "/private/envtest-client.crt",
  "api_client_key_file": "/private/envtest-client.key",
  "host": "127.0.0.1",
  "pod_uid": "POD_UUID",
  "service_uid": "SERVICE_UUID",
  "policy_configmap_uid": "POLICY_UUID",
  "secret_uid": "SECRET_UUID",
  "source_sha256": "FIVE_FILE_SOURCE_SHA256",
  "secret_dir": "/private/projected-secret",
  "admin_token": "PRIVATE_ADMIN_TOKEN",
  "upstream_key": "PRIVATE_UPSTREAM_TOKEN",
  "tls_cert_file": "/private/admin.crt",
  "tls_key_file": "/private/admin.key",
  "ready_file": "/private/ready.json"
}
```

`public_port` and `admin_port` default to zero for ephemeral allocation;
`repo_root` defaults to the checkout containing this helper. All listeners bind
only IPv4 loopback. Startup writes an atomic private readiness JSON file and one
JSON stdout line containing `public_url`, `admin_url`, `observer_url`, the actual
ports, source digest, marker, and scope. `listeners_ready` asserts sockets only;
admission is proved by the caller's actual HTTP requests. No credential is emitted.

Public `POST /v1/completions` takes a JSON `nonce` of 1–128 printable non-space
ASCII characters and a caller bearer. Successful admission returns `marker`,
`nonce`, `call_count`, and `scope`. The boundary supplies the upstream bearer.
Private HTTPS `GET /v1/endpoint-lease/state` is the unchanged production status
route and requires the admin bearer and the two production HMAC query arguments.
Plain HTTP cannot serve that TLS listener. The fixture-only observer's
`GET /stats` requires the admin bearer and returns the downstream `call_count`;
it has no policy mutation route. SIGTERM/SIGINT shuts down all sockets.

Focused checks (they deliberately have no successful API authority and cannot
serve as the full successful verification-loop proof):

```sh
python -m unittest discover -s build/test-harness/fixtures/verification-loop -p 'test_*.py' -v
```

The Go harness owns envtest provisioning and the full real-API before/revoke/after
flow. Its evidence must demonstrate both A and B reaching the downstream before
mutation, A receiving the production denial without a downstream increment after
mutation, B continuing to reach the downstream, and private TLS status agreeing
with the actual policy identities and state. API unavailability returns 503 and
cannot establish a successful revocation proof.
