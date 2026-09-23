# Limited v1 console authentication fixtures

The authentication profiles are fixed, read-only checks against the console's own loopback HTTP listener. They do not accept a URL, token, tenant, or target from a launch request.

Required trusted runtime configuration:

- `FixedLoopback`: a literal loopback HTTP origin with an explicit port, normally `http://127.0.0.1:8090`. Paths, credentials, queries, fragments, redirects, hostnames, and non-loopback addresses are refused.
- `ScopedTokenFile`: a clean absolute path to an operator-provisioned, short-lived bearer token. The console never mints this token. The file must be regular, 32–16384 bytes, contain no whitespace or NUL, have no execute or group-write bit, and have no permissions for other users. Kubernetes Secret projection as owner-readable or owner/group-readable is supported.
- `ExpectedSubject`: the exact subject that `/api/session` must return for the mounted token.
- `GrantFile`: the exact mounted console grant file. Only its SHA-256 is retained; its contents and path are not returned.
- `AllowedTenant`: a tenant granted to the token. The scoped profile reads `/api/owner/events?tenant=<allowed>` before and after its denials.
- `DeniedTenant`: a different, ungranted tenant expected to return HTTP 403.
- `DeniedTarget`: an ungranted cluster target expected to return HTTP 403 from `/api/workloads`.

The deployment must create the token outside the console and mount it directly into the console process. Do not place token bytes in Helm values, a ConfigMap, a job, a browser request, Git, or console state. The example JSON records only nonsecret configuration shape and is not executable input.

`limited-v1-console-unauthenticated` performs four GETs: missing credential (401), unsigned ALB identity headers (401), scoped bearer session (200), and the same scoped bearer session again (200). The exact session subject and response fingerprint must remain stable.

`limited-v1-console-scoped-authorization` performs five GETs with the mounted bearer: exact-subject session (200), allowed tenant (200), denied tenant (403), denied target (403), and allowed tenant again (200). Both allowed response fingerprints are retained but are not required to match because the underlying read-only event stream may advance during the control. Every request is preceded by a durable nonmutation intent and followed by a sanitized event containing only the path, status, response schema, and response SHA-256.

Both profiles also hash the running executable and grant file before and after the HTTP sequence. A changed source, grant, or authenticated subject makes the result inconclusive. Missing or expired credentials and 429/5xx responses make the fixture unavailable/inconclusive. A refused positive control cannot establish a boundary result. Only an authenticated-shaped HTTP 200 on a request that the fixed control required to return 401 or 403 establishes a functional boundary failure. Stale endpoints, malformed responses and unbounded responses are test failures. Reconciliation never replays a request because every operation is a GET and has no cleanup effect.
