# PHORVEXSEC-76 — Guardrail rotation fail-closed report

Date: 2026-08-17  
Branch: `fix/phvx-76-guardrail-fail-closed`  
Base: `origin/main` at `7d2be46` (`v0.4.30`)

## Problem

`guardrail-rotate` persisted the alternate variant, rollback snapshot, and epoch in Kubernetes before asking the live guardrail service to apply that variant. If the service was unreachable, the handler still returned `Emitted: true` even though the live filter had not changed.

That produced three inconsistent claims:

- the runner counted a completed actuation;
- Kubernetes said the alternate variant was current;
- the serving guardrail continued using the old variant.

The existing unreachable-path test explicitly accepted this partial defence as success.

## Fix

The handler now treats the transition as a confirmed two-stage operation:

1. Apply the distinct variant to the live guardrail service.
2. Only after the live apply succeeds, persist the variant, rollback snapshot, and epoch in Kubernetes.

Outcomes are now fail-closed:

| Outcome | Emitted | Kubernetes record | Result |
|---|---:|---|---|
| Live apply succeeds; record succeeds | `true` | New variant, snapshot, epoch | Confirmed success |
| Service unreachable | `false` | Unchanged | Honest unconfirmed result; no credit |
| Service returns a hard failure | no result | Unchanged | Error |
| Live apply succeeds; record fails | no result | Unchanged | Restore old live variant and return error |

If the Kubernetes write fails after a successful live apply, the handler makes a best-effort call to restore the old live variant. If both persistence and restore fail, both errors are retained with `errors.Join`.

## Regression coverage

The tests now prove that:

- a reachable service applies a distinct variant and records it;
- an unreachable service returns `Emitted: false` and `MutationKind: none`;
- unreachable and hard-failure paths preserve the old stored variant;
- neither failure path writes a snapshot or false epoch;
- a Kubernetes record failure causes the live apply sequence `v2 -> v1`.

## Validation

```text
go test ./internal/actuator -run 'TestGuardrailRotate' -count=1
PASS

go test -race ./internal/actuator -run 'TestGuardrailRotate' -count=1
PASS

go test ./...
PASS

go test -race ./internal/actuator
PASS

go vet ./...
PASS

git diff --check
PASS
```

## Operational note

No production guardrail was deliberately made unreachable. The failure mode is validated with the existing mockable guardrail connector and a failing Kubernetes client. Post-merge CI and deployment validation remain the release gates.
