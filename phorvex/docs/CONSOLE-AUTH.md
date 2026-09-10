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
- `targets` — cluster target identifiers. `"default"` names the cluster this console runs on (the
  target a request selects by omitting `?target=` / `?context=`); `["*"]` is every target. An
  omitted list grants no target, so an omitted parameter cannot escape the configured scope.

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

## Known caller impact: the End-to-End pipeline

`End-to-End/pipeline/transport.py` reaches the console through the API-server proxy to the
in-cluster Service, deliberately bypassing the ALB, and authorizes itself with `?lens=operator`.
That is exactly the self-asserted identity this fix removes, so it stops working: `/api/health`
still answers (it is public), and every other call returns `401`.

This was left as a **configuration** change rather than a code exception on purpose. An
"in-cluster callers are trusted" bypass would restore the defect in a narrower shape — reaching
the pod through the API-server proxy is not evidence of who is calling, and the console holds the
operator ServiceAccount either way.

To restore the pipeline, DevOps configures a machine identity:

1. enable the bearer path on the deployment (`phorvex.console.auth.oidc.*`) against an IdP that
   can issue a client-credentials token for CI;
2. add one grant entry for that token's `sub`, scoped to what the pipeline actually reads —
   `investor` is sufficient for the read-only checks, and it cannot mutate;
3. have `transport.py` send `Authorization: Bearer <token>` instead of `?lens=`.

Step 3 is a one-line change in `_curl`/`get_json`, but it is only meaningful once steps 1–2 exist,
and the token and grant are decisions for whoever runs the pipeline. This is tracked as a
follow-up, not as part of this fix's scope.

## Local development

There is no bypass. To run the console locally, configure a bearer IdP (any OIDC provider that
publishes a JWKS over https) and a grant file naming your own subject. The console will refuse to
start otherwise, and will tell you which settings are missing.

## Out of scope

Approval-lifecycle concurrency/persistence and experiment-recovery defects, and the writable
audit-mount question, are separate open issues. This fix neither widens nor closes them: the
apply-fix applier remains nil (record-only) by default, and the operator's decision audit is still
mounted read-only.
