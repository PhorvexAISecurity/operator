# Disposable staging console loops

The staging console exposes three fixed cases in Protect → Live launcher and
`GET /api/newstack/catalog`: `newstack:voice-rotate`,
`newstack:litellm-rotate`, and `newstack:crm-refund-revoke`. The implementation
is disabled unless both `PHORVEX_NEWSTACK_LOOPS_ENABLED=true` and
`POD_NAMESPACE=phorvex-staging` are set. No caller can supply a namespace, Pod,
policy, image or external destination.

Their fixture profiles are the immutable `newstackCases` definitions in
`phorvex/internal/console/newstack.go` and the fixed provisioning/policy builders
in `newstack_runtime.go`. The HTTP fixture is embedded in `newstack_fixture.go`;
its reviewable source is `build/test-harness/newstack/fixture.py`. Each run
records its source hash, image, generated object intents and admitted identities.
The Voice/LiteLLM names distinguish profiles; both use a small generic stateless
process, not those installed applications. No external inference call is made.

`POST /api/newstack/fire` accepts only `{"caseId":"<catalogued-id>"}` and waits
up to 300 seconds for the result. The attacks service persists a run before any
effect, acquires a shared lane, creates two fixture replicas with minAvailable=1,
establishes a real baseline, creates a trusted test-generated event, observes
the normal brain, then tears down and checks for residuals. An authenticated
remote audit source supplies decisions. Selected-only, unrelated, stale,
dry-run and killed decisions cannot establish defense.

Rotate requires the exact marked Pod to disappear, a fresh replacement with an
empty process marker, an untouched peer, full recovery, matching brain actuation
and sampled availability >=1. The reported class is proactive hygiene: replacing
a Pod clears resident state. It does not prove natural detection, exploit
blocking or protection from reinfection. The fixture installs no exploit session.

CRM first issues a refund of another synthetic account's order. Its event binds
the policy generation, target/peer UID, guard UID and Service UID. Defense requires
the existing refund-revoke actuator, all-replica guard readback, denied exact
replay and a successful legitimate refund. The first refund remains a loss.
Staging refund authority requires the explicit namespace setting and fixture
markers; the default contract remains `crm`.

`GET /api/newstack/check?caseId=...` checks the fixed deployment boundary without
creating fixtures. `GET /api/newstack/result?runId=...` retrieves one exact record.
`POST /api/newstack/cleanup` with the same case body reconciles a retained run;
unknown ownership, UID drift or an executing lane causes refusal. Run/audit
records are retained; disposable resources are deleted with UID preconditions.

`tools/phvx-newstack.py` provides `list`, `targets`, `check`, `fire <case>` and
`cleanup [case]`. Every cluster request goes through `ssh -o BatchMode=yes
phorvex-gw kubectl` with the exact dev-EKS context and staging namespace. Explicit
fire/cleanup can request a ten-minute console token, held only in memory, and
use a managed foreground port-forward. `check` never mints a token. Exit 0 for
fire requires the server's exact DEFENDED result and successful cleanup/postflight.

Before live use: merge the source PR, merge its source-containing `release/next`
PR, wait for published digest pins, apply the staging services ApplicationSet
(which adds attacks), and require all five Argo Applications and six Deployments
healthy. Reuse the existing audit TLS secrets and external creator guard.
No live proof accompanies the source change. After interrupted-run cleanup,
rollback by reverting the feature commit and syncing Argo; prune only its newly
added staging resources/grants explicitly because the Applications use prune=false.
