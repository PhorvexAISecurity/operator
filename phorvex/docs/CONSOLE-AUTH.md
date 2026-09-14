# Console authentication and authorization (M-136)

The Phorvex console serves cluster **controls**, not just dashboards: `/api/policy/edit` patches a
PhorvexPolicy, `/api/vllm/attack` and `/api/workload/attack` exec into pods and apply
SecurityEvents, `/api/live/clear` truncates the decision audit. It runs as a sidecar in the
operator pod and inherits that pod's ServiceAccount. Everything below exists because that surface
must never be reachable by an unauthenticated or unauthorized caller.

## What changed

Before this fix the console had no trust boundary of its own:

- `PHORVEX_OIDC_ISSUER` unset meant "demo-trust dev mode"; identity was whatever the request
  asserted. A configured IdP that **failed to load** logged `staying demo-trust` and continued.
- The role gate read a self-declared `X-Phorvex-Lens` header or `?lens=` query parameter, so any
  HTTP client could name itself `operator`.
- Tenant scoping came from `?tenant=` / `?user=`, supplied by the caller.
- CORS was `Access-Control-Allow-Origin: *`.

Now: every data, stream and control request is authenticated once at the outer boundary, and
authorized against an explicit server-side grant. The console **refuses to start** without a
configured credential path. There is no demo-trust mode in the shipped binary.

## The two credential paths

At least one must be configured. If both are, a request must present **exactly one** — a request
carrying both is rejected rather than resolved, and an invalid bearer token never falls back to
the proxy headers.

### 1. ALB Cognito (the browser path)

`console.phorvex.ai` is an ALB ingress with `alb.ingress.kubernetes.io/auth-type: cognito`, so an
authenticated request reaches the pod carrying `x-amzn-oidc-data` — a JWT the load balancer signs
with ES256. The console verifies, in order: `alg` is exactly ES256; `signer` equals the configured
load-balancer ARN; `iss` and `client` equal the configured user pool and app client; the signed
header's `exp` is present and unexpired; the `kid` is charset-validated and its key fetched from
the fixed regional AWS endpoint (`https://public-keys.auth.elb.<region>.amazonaws.com/<kid>`); and
only then the ES256 signature over the literal `header.payload` bytes. `sub` is read from the
verified payload afterwards.

`x-amzn-oidc-identity` and `x-amzn-oidc-accesstoken` are **not** identity and are rejected
explicitly when presented without the signed header.

| Setting | Env | Chart value |
|---|---|---|
| Load-balancer ARN | `PHORVEX_CONSOLE_ALB_SIGNER_ARN` | `phorvex.console.auth.alb.signerArn` |
| User-pool issuer | `PHORVEX_CONSOLE_ALB_ISSUER` | `phorvex.console.auth.alb.issuer` |
| App-client id | `PHORVEX_CONSOLE_ALB_CLIENT_ID` | `phorvex.console.auth.alb.clientId` |
| Region (optional) | `PHORVEX_CONSOLE_ALB_REGION` | `phorvex.console.auth.alb.region` |

These are configuration identifiers, not secrets — but they are **per-environment**. Copying one
cluster's signer ARN into another makes that cluster's load balancer a trusted issuer here.

### 2. Bearer OIDC (CLI and automation)

`Authorization: Bearer <jwt>`, verified against a configured issuer, audience and JWKS URL.
Requirements are all mandatory: an exact algorithm allowlist (default `RS256`; `none` and the HMAC
family are not supported), a matching key type for the algorithm family, exact `iss`, an `aud`
containing the configured audience, a non-empty `sub`, a **mandatory** unexpired `exp`, `nbf` when
present, and a bounded clock-skew leeway.

| Setting | Env | Chart value |
|---|---|---|
| Issuer | `PHORVEX_CONSOLE_OIDC_ISSUER` | `phorvex.console.auth.oidc.issuer` |
| Audience | `PHORVEX_CONSOLE_OIDC_AUDIENCE` | `phorvex.console.auth.oidc.audience` |
| JWKS URL (https) | `PHORVEX_CONSOLE_OIDC_JWKS_URL` | `phorvex.console.auth.oidc.jwksUrl` |
| Algorithms | `PHORVEX_CONSOLE_OIDC_ALGS` | `phorvex.console.auth.oidc.algorithms` |

Keys come only from the configured JWKS URL. Nothing in a token influences the endpoint, so a
token claiming a different issuer cannot redirect the key fetch. Fetches are bounded (deadline,
response size, no redirects), cached and shared, and cache **misses** are rate-limited so a flood
of forged arbitrary-`kid` tokens cannot turn the console into a fetch amplifier. A key-endpoint
failure fails the request closed; it never downgrades authentication.

## Authorization: the subject grant table

Authentication says *who* is calling. Authorization is a separate, explicit table binding a
verified `issuer` + `subject` to roles and scope. **The console never infers a grant** — not from
an email address, not from a group claim, not from the fact that the IdP allowed the login.

```json
{
  "version": 1,
  "subjects": [
    {
      "issuer": "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_JfwlBPRbB",
      "subject": "b3f2c1a0-1111-2222-3333-444455556666",
      "roles": ["operator"],
      "tenants": ["vllm", "litellm"],
      "targets": ["default"],
      "note": "platform on-call"
    }
  ]
}
```

Supply it with `-auth-grants <path>` or `PHORVEX_CONSOLE_GRANTS`; the chart can render it into a
ConfigMap via `phorvex.console.auth.grants`.

### Roles

| Role | May do |
|---|---|
| `owner` | Read the owner-safe projection (`ToOwnerEvent`) for its granted tenants only. |
| `investor` | Read the evidence and aggregate group. **Read-only** — never a control. |
| `operator` | Everything `investor` reads, plus controls and cluster writes, confined to its granted tenant and target scope. |

A request may send `X-Phorvex-Lens` or `?lens=`. That is a **presentation hint**: it can narrow a
caller's projection below its grant and can never widen it. It is not a credential.

### Scope

- `tenants` — tenant / namespace identifiers. `["*"]` is cross-tenant admin and has to be written
  out; an omitted or empty list grants nothing.
- `targets` — cluster target identifiers. `"default"` names the cluster this console runs on;
  `["*"]` is every target. An omitted list grants no target, so an omitted parameter cannot escape
  the configured scope.

  Three spellings mean that one cluster and are treated as a single resource everywhere — in a
  grant, in an effective destination, and in the credential resolver: an **omitted**
  `?target=`/`?context=`, the id `in-cluster` (what the target selector sends in a deployed pod),
  and the `default` sentinel. Writing the documented `["default"]` therefore covers what the
  dashboard actually sends. A kubeconfig that deliberately defines a context named `default` or
  `in-cluster` is still honoured as that context; the sentinel only applies when no such context
  exists.

  Any OTHER named cluster must resolve. A request that names a cluster the console cannot reach is
  an error — it is never served from the pod's own cluster instead, because that would silently
  substitute a different resource for the one the grant was checked against.

Unknown subject, role, tenant or target fails closed. The audit actor on `/api/policy/edit` and
the requester/approver on the apply-fix two-key flow are the **verified subject**
(`<issuer>#<subject>`), never a body field.

### Scope is checked against the EFFECTIVE destination

A route's declared scope has to match what its handler actually does, not what the request names:

- **Effective destination.** `POST /api/runs/start` reads the named suite's own config for the
  cluster context and namespace it will drive; `POST /api/runs/scenario` substitutes its own
  context when the target is unknown and forces the disposable sandbox namespace regardless of
  what was asked for. Both are authorized against those resolved values, plus the `default`
  target — launching a harness subprocess is itself a privileged act on the host this console
  runs on. An omitted target cannot slip through as "unscoped".
- **Indivisible effects need the wildcard.** `POST /api/live/clear` truncates one audit file
  holding every tenant's decisions. There is no way to clear only one tenant's records, so it
  requires `"tenants": ["*"]` — the operator role alone is not enough. The same applies to the
  global red-team controls (`/api/redteam/decision`, `/run`, `/continuous`), whose state belongs
  to no tenant.
- **A tenant grant is not a cluster grant.** Every control that drives this console's own cluster
  (`/api/policy/edit`, the attack and fire-scenario triggers, the three-arm runner, the apply-fix
  write path) declares that cluster explicitly, so an identity granted a namespace but no target
  cannot reach it. The same applies to the cluster-reading endpoints.
- **Omitting a scope parameter is a widening.** `GET /api/scan` and `GET /api/ablation` become
  cluster-wide when `ns` is omitted, so the unscoped form requires the cross-tenant grant while
  `?ns=<granted>` stays available to a limited one.
- **Cluster-wide listings are filtered, not returned whole.** `/api/cluster`, `/api/workloads`,
  `/api/targets`, `/api/attack-results`, `/api/attack-monitoring`, `/api/uptime`,
  `/api/availability-arms`, `/api/metrics`, `/api/live`, `/api/live/history` and the owner
  surfaces all confine their rows to the granted tenants. A read role does not bypass the
  grant's tenant limits.
- **Aggregates over the decision audit are tenant data too.** `/api/cost-timeseries` and the
  actuation-rate half of `/api/cost` are summed only over the granted tenants, so a
  tenant-limited operator's totals and decision counts are its own.
- **A run id is authorized by what the run drives, under the grant held now.** Each run records
  the cluster target and the namespace resolved from its producer. `list`, `status`, `stream`,
  `evidence` and `stop` all require both to be in scope. There is deliberately **no creator
  bypass**: "I started it" is not authorization, so narrowing or revoking a grant takes the run
  with it. A run whose namespace could not be recorded fails closed short of a cross-tenant grant.
- **An endpoint authorizes the destination it will actually read.** `/api/cost` falls back to the
  first runnable cluster when no `context`/`target` is named; the boundary resolves and authorizes
  that same cluster rather than the `default` sentinel.
- **An identifier is resolved once, for both authorization and execution.** `/api/runs/stop`
  accepts a run id in the query or the body. The boundary resolves exactly one, refuses a request
  whose query and body name *different* runs, and hands the resolved id to the handler — which
  never re-reads it. Previously the boundary preferred the query id and the handler preferred the
  body id, so a caller could be authorized for one run and stop another.
- **Query aliases for one target resolve once.** Where a route accepts both `?context=` and
  `?target=`, they are aliases for a single cluster, not two independent scopes. Checking each
  separately made the alias a caller *did not* use mean "default", so an identity granted only a
  remote cluster was refused for naming that cluster explicitly.
- **A composite endpoint authorizes each source separately.** `/api/cost` mixes three: the
  selected cluster's pricing and operator footprint, this console's own decision audit (the
  actuation rate), and this console's local benchmark corpus (the scenario comparison). A grant
  for a remote cluster authorizes the first and nothing else; the figures it does not cover are
  **omitted and named** in a `withheld` list rather than emitted as zeros that would read as a
  measurement.
- **Every local reader names the source it reads.** The owner surfaces, the audit aggregates, the
  attack ledger and the whole private evidence corpus read this console's own audit file, ledger
  and harness corpus. They declare that source's cluster, so an identity with a tenant grant but
  no cluster target cannot read them. A tenant grant is not a source grant.

### The three data classes

| Class | Rule | Routes |
|---|---|---|
| Shared product metadata | Any read grant | `/api/catalog`, `/api/suites`, `/api/threat-matrix`, `/api/handlers`, `/api/version`, `/api/session` |
| Tenant-attributable data | Filtered to the granted tenants | `/api/cost`, `/api/cost-timeseries`, `/api/uptime`, `/api/live`, `/api/live/history`, `/api/owner/*`, `/api/attack-results`, `/api/attack-monitoring`, `/api/availability-arms`, `/api/workloads`, `/api/cluster`, `/api/metrics`, `/api/targets`, the run routes |
| Private evidence corpus | Requires an explicit cross-tenant grant | `/api/effectiveness`, `/api/frontier`, `/api/benchmarks`, `/api/posture`, `/api/matrix`, `/api/ai-surface`, `/api/reports`, `/api/rawlog`, `/api/benchmark-sim`, `/api/redteam/*`, `/redteam` |

The third class is the vendor-side moat: benchmark corpora, retained evidence reports and their
raw logs, and red-team artifacts. None of it is attributable to a tenant, so it cannot be filtered
down to one — an identity limited to some tenants gets none of it, and a vendor-side identity is
granted `"tenants": ["*"]` and gets all of it. **Consequence for grants:** a customer-facing
operator scoped to specific tenants will not see the benchmark/evidence tabs. That is intended; if
an identity needs them, grant it the wildcard deliberately rather than by accident.

## Rollout prerequisite

**With no bindings, the console authenticates every logged-in user and authorizes none of them.**

That is deliberate and visible, not a regression:

- the startup log prints `grants : NONE CONFIGURED — every authenticated caller is denied`;
- authenticated requests return `403` with `no authorization grant for this identity`;
- `GET /api/session` reports `"grantsConfigured": false`, and the dashboard says so.

Before rollout, DevOps must decide who the operators are and bind them explicitly. For the Cognito
pool, subjects are the `sub` UUID, not the username:

```sh
aws cognito-idp list-users --user-pool-id <pool-id> \
  --query 'Users[].{sub:Attributes[?Name==`sub`].Value|[0],user:Username}'
```

Grant the narrowest role and tenant scope that works. An `operator` role with `"tenants": ["*"]`
is effectively cluster-wide control through the operator pod's ServiceAccount.

## Browser boundary

- **CORS**: no wildcard. Only the exact origins in `PHORVEX_CONSOLE_TRUSTED_ORIGINS` /
  `phorvex.console.auth.trustedOrigins` are reflected, with `Vary: Origin`. An unlisted origin
  receives no CORS grant and its preflight is refused.
- **CSRF**: a non-GET request authenticated by the ALB session cookie must carry an `Origin` (or
  `Referer`) matching a trusted origin. With no trusted origin configured, browser-driven state
  changes are refused entirely. Bearer callers are unaffected — `Origin` is a CSRF defence, never
  an authentication factor.
- **SSE**: `/api/live` and `/api/runs/stream` authenticate through the signed ALB header the
  browser already carries (`withCredentials`), or a bearer header for CLI callers. A token is
  never accepted from a query string.
- **`GET /api/session`** reports the effective grant so the SPA renders only the lenses and
  controls the grant supports. It is a convenience; server enforcement remains authoritative.

## Public surface

Exactly two things are public:

- `GET /api/health` — liveness only, `{"ok": true}`. It no longer discloses the root path or the
  harness/binary layout; those moved to `GET /api/diagnostics`, behind the boundary.
- `/` and the static SPA assets.

Every other `/api/` path requires a verified identity, and an unknown `/api/` path returns a JSON
`404` rather than falling through to `index.html`.

## Method contract

`/api/runs/start`, `/api/runs/scenario` and `/api/runs/stop` launch and stop real harness runs
against a cluster. They are **POST-only** now; they used to be reachable by GET. The dashboard
client already posts to all three.

## The End-to-End pipeline as a caller

`End-to-End/pipeline/transport.py` used to reach the console through the API-server proxy to
the in-cluster Service (`mode: kubectl-proxy`) and "authorize" itself with `?lens=operator`.
That is exactly the self-asserted identity this fix removed, so after the rollout the
pipeline reached `/api/health` (public) and got `401` on everything else — PR179's E2E run
aborted at preflight (2026-09-13 14:24 UTC). PR179 itself has since merged (15:35 UTC,
v0.4.113); the deployment observed at 15:52 UTC still ran v0.4.112 without it, and merging
changes nothing about the caller's need for a provisioned identity. The proxy path was never a credential: `kubectl get --raw` authenticates the
kubectl user to the **API server**, and nothing about arriving through that proxy says who is
calling the console. No "in-cluster callers are trusted" exception was added; it would restore
the defect in a narrower shape.

The pipeline now has an explicitly configured authenticated mode (`console.mode: http`,
`console.auth: bearer`; see `End-to-End/README.md`):

- it sends `Authorization: Bearer <token>` on every GET, POST and SSE request, delivered to
  curl as a `-K -` configuration on stdin — never argv, a URL, a query string, a child's
  environment, a log or a retained error;
- the token comes from exactly one *configured* source — `PHORVEX_CONSOLE_TOKEN` (CI secret)
  or a private `0600` file — and configuring both is refused whether or not the file exists;
  empty, multi-line, oversized, malformed or world-readable inputs are refused, and the client
  never decodes the token — the verifier here is the authority;
- curl runs with its default configuration disabled (`-q`), so a `.curlrc` on the transport
  host cannot add a recipient, disable verification or trace the request;
- the endpoint must be HTTPS with normal certificate verification (a private CA can be named,
  verification cannot be disabled) or plain HTTP to a *literal* loopback address (127.0.0.0/8
  or `[::1]`, never a name) **on the transport host**, connected to directly so an inherited
  `http_proxy` cannot divert it; URL userinfo and non-loopback HTTP are refused, redirects are
  never followed and a credential is never re-sent to a `Location`;
- in `ssh` mode the jump host that receives the password and the bearer configuration is
  verified against a provisioned `known_hosts` file on the client with strict checking; an
  unknown or changed key fails non-interactively, with no accept-new fallback, for every
  command the transport (and `publish-report.sh`) runs;
- a `401` or `403` stops preflight at once, keeps the endpoint's (redacted, bounded) message as
  provenance and names the possible causes — an intermediary can answer either, and a `403`
  alone is not proof the console verified an identity; a failed POST is never retried, and an
  unsuccessful stream response never fires the attack stimulus;
- the old proxy mode remains available only by explicit choice, and its `401` now says that
  the proxy carries no console credential rather than "the console did not become ready".

None of that makes the pipeline authorized. Authorization is the grant table, and the
pipeline's identity does not exist until DevOps provisions it.

### DevOps handoff: what the pipeline needs provisioned

The source change is complete without any of the following; the live Tier 1 acceptance run
cannot pass until all of them exist. They are deployment decisions, recorded with the
deployment, not defaults in this repository.

1. **A bearer issuer the console verifies.** Enable the bearer path on the deployment
   (`phorvex.console.auth.oidc.issuer` / `audience` / `jwksUrl`, optionally `algorithms`)
   against an IdP that can issue a **headless** client-credentials or machine token for CI.
   The existing Cognito ALB authenticates browsers with a login redirect and must **not** be
   assumed to accept a bearer from a headless caller; the `x-amzn-oidc-*` headers are not a
   path the pipeline can or should use.
2. **A token provisioning and refresh method** for that identity — how the value lands in the
   `PHORVEX_CONSOLE_TOKEN` repository secret (or a `0600` file on the runner), its lifetime,
   and who rotates it. The pipeline never mints, extracts or caches a token, and it fails
   closed on an expired one rather than retrying.
3. **An explicit grant for the token's `sub`** in `phorvex.console.auth.grants` (or the
   `PHORVEX_CONSOLE_GRANTS` file), keyed by the issuer above. Two callers want two different
   grants:
   - observe-only runs: `investor` on the tenants they capture (e.g. `["voice"]`) with
     `"targets": ["default"]` — read-only, cannot fire anything;
   - attack runs: `operator` scoped to exactly the target namespaces the run fires at
     (`voice`, `nats`, `vllm` as configured in `End-to-End/config.json`) and
     `"targets": ["default"]`. Not `"tenants": ["*"]`.
4. **An endpoint that reaches the verifier**, set as the `PHORVEX_CONSOLE_BASE` repository
   variable: an HTTPS URL served by the console (or an in-front proxy that passes the
   `Authorization` header through unchanged and does not itself redirect to a login), or a
   literal-loopback `http://127.0.0.1:<port>` tunnel/port-forward terminated **on the SSH jump
   host** the pipeline's `ssh` transport uses. Whoever can bind that port on that host receives
   the credential: DevOps must control the listener, and on a shared host the port must not be
   one another account can squat. A private CA is named with `PHORVEX_CONSOLE_CA_FILE` (a path
   on that host — where curl runs). An HTTPS endpoint elsewhere is not by itself new public
   exposure; the choice and any change of endpoint stay with DevOps. The pipeline does not
   start a port-forward, expose a Service, create a ServiceAccount or change RBAC.
5. **The jump host's SSH host key**, as the `PHORVEX_SSH_KNOWN_HOSTS` repository variable:
   the `ssh-keyscan -p PORT HOST` line(s), compared out of band against the fingerprint the
   host itself reports (`ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub` on the host). CI writes it
   to a runner-local `0600` file before any ssh; the pipeline and `publish-report.sh` verify
   the host against that file only. This is read on the SSH **client** (the runner), unlike
   the CA file, which curl reads on the SSH **host**. Rotating the host key means updating
   this variable first; until then every ssh fails closed rather than trusting a new key.
6. **A controlled acceptance run** after 1–5: `observe` first, then `attack` on the
   authorized target only. Until the real authenticated preflight, session and stream
   succeed against the deployed console, the Tier 1 caller repair is not verified live.

## Local development

There is no bypass. To run the console locally, configure a bearer IdP (any OIDC provider that
publishes a JWKS over https) and a grant file naming your own subject. The console will refuse to
start otherwise, and will tell you which settings are missing.

## Out of scope

Approval-lifecycle concurrency/persistence and experiment-recovery defects, and the writable
audit-mount question, are separate open issues. This fix neither widens nor closes them: the
apply-fix applier remains nil (record-only) by default, and the operator's decision audit is still
mounted read-only.
