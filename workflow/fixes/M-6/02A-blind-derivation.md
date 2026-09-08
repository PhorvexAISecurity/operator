# M6 independent baseline derivation

Reviewer: codex-m006. Baseline: 79c0370dd460a1d6400bc62346638655f64ae709. Written before receiving or opening any Claude M6 proposal, diff, implementation or messages. Inputs: user ticket, baseline source, read-only cluster evidence. This is an initial model and test demand, not an approved SEC contract or final security verdict.

## Root cause and request path
The committed phorvex/config/admission/codeexec-denylist.yaml matches PhorvexPolicy CREATE/UPDATE. It restricts action enablement by policy namespace; it does not match Pod/ephemeralcontainers UPDATE or validate the emitted execution payload. Merely installing that object cannot establish the new ticket's direct-API execution boundary.

Native debugger/custom-inject call injectEphemeral in internal/actuator/handlers_k8s.go. It appends an EphemeralContainer then SubResource("ephemeralcontainers").Update. Native debugger uses phorvex-debugger / busybox:1.36, no explicit command; custom-inject uses phorvex-custom / busybox:1.36 and sh -c "echo phorvex-custom-action; sleep 1". Both omit explicit privilege/capability/env/mount profiles and target container and set Stdin/TTY false. Absence/defaulting must be assessed rather than equated with safety. Idempotency is name-only. Do not alter these behaviors silently.

RuleTypeFor maps only rotate/quarantine, so hybrid routes these two code-exec actions to native handlers. Phoenix separately has ephemeral-container handlers; inventory alternate principals/paths without automatically expanding this ticket's promised boundary. The existing code-exec feasibility guard is a system-namespace veto. Native SupportsAction only inspects MIG transport; no admission contract witness is present there. Trace actual generator and dispatch checks before designing the freshness mechanism.

## Expected correction and decisions
A reviewed contract must bind permitted identity, actual mutation/subresource, target scope and payload, with an applicable deny binding and protected scope controls. Existing policy-namespace validation is a separate layer. SEC-1/SEC-2/PO-1 must specify image/commands/privileges/targets, customer exceptions, version/install models and degraded behavior. No cluster-wide operator-only policy or arbitrary label exemption is pre-approved.

Observe policy/binding/parameters and relevant selectors with explicit unknown/stale semantics. Capability must fail closed for affected actions when enforcement is known missing/invalid/unverified, including at dispatch after earlier eligibility. Keep unrelated defenses available under the agreed contract. Installer and runtime authorities remain separate. Names alone do not prove content, binding applicability, or CEL enforcement.

## Required incident and adversarial verification
1. Actual baseline request -> API operation -> matched policy/binding -> rule result; approved control and one isolated violation per field. RBAC or PSA rejection must not substitute for VAP denial.
2. Assert the fixture actually reaches ephemeral-container admission and reproduces the original gap; no mocked final availability boolean as incident proof. Real API-server tests must accompany fake-client tests.
3. Missing policy/binding, Warn-only binding, altered CEL, changed selector/parameters, unreadable/stale state, invalid CEL diagnostics, startup/post-start enablement, queued work after observed loss and recovery. Each relevant predicate arm needs a case.
4. Pre-existing ephemeral containers, namespace/label changes by constrained identities, runtime self-modification of protection and effective indirect RBAC paths; document exclusions instead of claiming universal safety.
5. Install/upgrade/rollback/uninstall and multiple-release ownership; no automatic permission/action enablement. Measure detection/in-flight limits; never promise instantaneous credential revocation.

## Coverage limits
No enforcement changes, API deny probes, persisted injections or new capability tests have been run for this kickoff. Baseline manifest/request inspection is source evidence. Effective RBAC analysis and full request inventory remain to be completed. No admission or action-effectiveness claim is approved by this document.
