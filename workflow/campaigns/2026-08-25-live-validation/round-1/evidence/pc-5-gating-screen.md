# PC-5 supporting detail — gating-entry spot screen at v0.4.50

Repo fetched 2026-08-25; `v0.4.50` = `b163c69`. All quotes from `git show v0.4.50:...`.

## Window shape

```
$ git log --oneline v0.4.43..v0.4.50 | head -30
b163c69 release: v0.4.50 [skip ci]
99e2559 Merge PR #70 fix/phvx-115-reactive-optimality
6288579 Merge PR #73 feat/attack-launcher-verdicts
ae3ed80 feat(console): actuator verdicts in the per-app attack launcher
ea7045a Merge PR #72 feat/per-app-attack-launcher
761645e fix: align reactive-only optimality substrate
3c11b01 Merge PR #67 feat/phorvexsec-125-cover-taxonomy
36d0037 feat(recon): implement scoped cover taxonomy
2ba155a Merge PR #69 fix/inventory_repair
3d275fe Merge PR #66 fix/phorvexsec-130-ready-delay-metric
203f69a Merge PR #64 feat/phorvexsec-91-cost-model
11dbd30 Merge PR #63 feat/phorvexsec-83-pending-gate
... (23 commits, releases v0.4.44–v0.4.50)
```

38 non-test Go files changed; headline areas: decision core, cost model, killchain hazard, NEW `internal/pendinggate`, recon cover taxonomy, console attack-launcher, CRD yaml + types + defaults.

## M-22 — the "green-but-wrong" fix, quoted

`phorvex/api/v1alpha1/defaults.go` at v0.4.50:

```go
// EffectiveMaxMovesPerTick is the per-tick move budget B (default 3).
func (s *PhorvexPolicySpec) EffectiveMaxMovesPerTick() int {
	if s.Budget.MaxMovesPerTick <= 0 {
		// 0 is a legitimate "decide+log only" budget; preserve an explicit 0 only when
		// the field was deliberately set. A negative/unset value falls back to default.
		if s.Budget.MaxMovesPerTick == 0 {
			return defaultMaxMovesPerTick
		}
	}
	return s.Budget.MaxMovesPerTick
}
```

The comment claims explicit 0 is preserved. The code returns 3 for 0. The field is `int` (not `*int`) with `+kubebuilder:default=3`, so an explicit 0 is representable and reaches this function — where it becomes 3. The selection loop consumes it via `manager.go:1126: MaxMovesPerTick: s.EffectiveMaxMovesPerTick()` → `coverage.go:337: B := pol.MaxMovesPerTick`.

Live confirmation status: V7 on 0.4.39 proved 11 selections with budget 0; the code path at 0.4.50 is stricter-looking but equivalent for the user (0 → 3). A V7 re-run on 0.4.50 is cheap and worth folding into a later round; the static path is unambiguous.

## M-2 marker at v0.4.50

```
// +kubebuilder:validation:Enum=rotate;quarantine;noop;debugger;custom-inject;identity-rotate;route-rotate;warm-swap;mig-rebind;kv-reset;endpoint-rotate;model-shard-replace
type ActionType string
```

12 values. `adapter-rotate`, `request-drain`, `guardrail-rotate`, `kv-migrate-invalidate`, `disable` absent — matches the installed CRD (PC-2 live dry-run rejection).

## M-140 at v0.4.50

```go
func (m *Manager) Remove(key types.NamespacedName) {
	m.mu.Lock()
	e := m.policies[key.String()]
	delete(m.policies, key.String())
	m.mu.Unlock()
	if e != nil {
		metrics.ResetTenant(e.tenant)
		metrics.ResetKillSwitchStatus(e.key.Namespace, e.key.Name)
	}
}
```

No pruning of `costByTenant`, killchain memory, pending rotations, or exposure clocks. Byte-equivalent to 0.4.39/0.4.43. Rule 4 (fresh tenant names) stays mandatory — this campaign's `cv1-*` names were chosen fresh for exactly this reason.
