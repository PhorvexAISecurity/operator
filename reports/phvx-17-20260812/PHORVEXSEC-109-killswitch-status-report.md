# PHORVEXSEC-109 (PHVX-17) — Kill-switch status contradiction — report

Date: 2026-08-12 · Branch `fix/phvx-17-killswitch-status`

## The ticket's premise is false — and there is still a real defect underneath

> *"`status.killSwitchEngaged` is an independent field fed from a different source than the engine,
> so the CRD can say halted while the engine runs."*

**Not independent.** `manager.go:218` computes `killEngaged` once per tick, and that same variable
gates actuation (`:224`, `:543`), sets the Prometheus gauge, and is passed to the status writer
(`status.go:47`). There is exactly one writer of the field repo-wide.

The ticket's supporting inference is also wrong: advancing decision counters do **not** mean the
engine is un-halted. By design, "when engaged, the engine still DECIDES + LOGS + emits metrics, but
NO actuation occurs" (`killswitch.go:16-18`), and `DecisionsTotal` increments regardless.

## What I checked on the live cluster instead

Two hypotheses were testable, so they were tested rather than argued.

**Hypothesis A — silent fail-closed via an unset namespace.** `killswitch.go:40-45` returns `true`
(engaged) when `Namespace == ""`, so a non-Helm deploy would disable actuation silently.

```
POD_NAMESPACE=            <- empty on the running pod
```

Alarming, but **refuted**: the deployment passes `--operator-namespace=phorvex-system` explicitly,
and `cmd/main.go:113` uses the env var only as the flag's *default*. The flag wins, so the namespace
is set and the sentinel is read normally.

**Hypothesis B — the readout cannot express "safe".** Confirmed:

```
sentinel ConfigMap    {"engaged":"false"}
status on litellm     killSwitchEngaged ABSENT
status on nats        killSwitchEngaged ABSENT
status on vllm        killSwitchEngaged ABSENT
status on voice       killSwitchEngaged ABSENT
```

With `json:"killSwitchEngaged,omitempty"` a `false` **vanishes from the CR**. So "the defence is
running normally" and "this status has never been reconciled" produce byte-identical output. For a
safety control, that is the one distinction that has to survive.

## The five fixes

**1. `omitempty` removed.** A safety-control readout must state the safe value explicitly. Omitting
it is not the same as reporting it. The generated CRD manifests (chart + config/crd) were updated in
the same change so the schema description does not contradict the code — the "correct in one file,
stale in the other" pattern found twice today under PHVX-9e and PHVX-76.

**2. The `KillSwitch` condition is now written.** The CRD has documented one all along —
*"Conditions includes Ready, DryRun, ValidationError, KillSwitch"* — and nothing ever wrote it.
A condition carries a reason and a transition timestamp, which a bare bool cannot: an operator can
see **when** actuation stopped, not only that it is stopped.

**3. Status-update errors are no longer swallowed.** `_ = m.Client.Status().Update(...)` meant a
dropped write left the CR showing a stale kill-switch with no signal anywhere — precisely the failure
mode this ticket describes, reached by a different route. It is now logged with the tenant, the
policy and the value that failed to land.

**4. Runtime/status disagreement is now measurable and alertable.**
`phorvex_kill_switch_status_disagreement{namespace,policy}` is asserted when the policy status cannot
be read or when a runtime transition cannot be persisted. It is cleared only after a successful
status write and its series is removed when the policy leaves the registry. The Helm chart includes
`PhorvexKillSwitchStatusDisagreement` plus the shared
`PhorvexOperatorRestartStorm` warning based on kube-state-metrics restart counters. The rules are
feature-gated (`phorvex.alerts.enabled`) because clusters without the Prometheus Operator CRD would
otherwise reject the release; enabling them renders a valid `PrometheusRule`.

**5. The chart is actually deployable.** The subchart is bumped to `0.1.4`, the stack dependency and
lock are updated, and `phorvex-0.1.4.tgz` is regenerated from the source chart. Extracted source and
vendored contents are identical, closing the previous `chart-sync` CI failure.

## Tests

| test | what it proves |
|---|---|
| `TestKillSwitchFalseIsSerialised` | a disengaged switch remains explicit in JSON; against the old definition the field vanishes |
| `TestKillSwitchEngageDisengageSuppressesAndResumesActuation` | reads a real sentinel ConfigMap, runs `processTenant`, and checks the actuator call count, decision and actuation Prometheus counters, bool, and `KillSwitch` condition in both directions: engaged keeps deciding but emits zero; changing the sentinel to false resumes one real emit |
| `TestKillSwitchStatusDisagreementSurvivesFailedTransition` | an injected status-subresource failure during `false→true` leaves the disagreement gauge at `1` so the alert can fire |

The chart was rendered both with alerts disabled (safe default) and enabled. The enabled render
contains both rules with the configured thresholds.

## Not claimed

- **Not verified live.** This revision is not deployed; the ABSENT readings above are the *defect*
  measured on the running fleet, not the fix.
- The `omitempty` removal makes the field appear on every policy status from the next reconcile. That
  is the intent, but it is a visible CR change and worth mentioning at rollout.
- The existing dashboard policy panel already renders `status.killSwitchEngaged`; this change does
  not add a write/toggle control.
- Alert rules are installed only when `phorvex.phorvex.alerts.enabled=true` and require Prometheus
  Operator plus kube-state-metrics. The production EKS values currently point at plain Prometheus,
  so this PR does not silently assume that CRD exists or claim the alerts are live there.
