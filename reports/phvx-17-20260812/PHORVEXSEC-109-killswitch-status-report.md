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

## The three fixes

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

## Tests

`TestKillSwitchFalseIsSerialised` — a disengaged kill-switch must appear in the serialised status.
Against the previous definition it fails with `{"lastTickTime":null,"lastDecisionTime":null}`, the
field simply gone.

## Not claimed

- **Not verified live.** This revision is not deployed; the ABSENT readings above are the *defect*
  measured on the running fleet, not the fix.
- The `omitempty` removal makes the field appear on every policy status from the next reconcile. That
  is the intent, but it is a visible CR change and worth mentioning at rollout.
- Not addressed: the ticket also asks for a dashboard surface and a disagreement alert. There is no
  kill-switch surface in `internal/console/` at all today (only the Prometheus gauge and a Grafana
  panel), and the alert is shared with PHVX-16. Both are separate work.
