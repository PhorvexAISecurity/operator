package mathlab

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type memorySink struct{ items []Pending }

func (m *memorySink) Enqueue(p Pending) bool { m.items = append(m.items, p); return true }

func allClocks(d time.Duration) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, v := range model.LiveExposureVariables {
		out[v] = d
	}
	return out
}

// fleet builds a tick with: a measured-load stateless pod with a trusted event (selectable),
// a pod with no load telemetry (rotate is G9-only excluded: uncertain-regime CHi >= 1.6),
// and a pod whose kv-reset the capability gate refuses before any cost gate runs.
func fleet() []*model.WorkloadView {
	mk := func(name string, exposure time.Duration) *model.WorkloadView {
		return &model.WorkloadView{
			Pod:                model.Pod{Namespace: "vllm", Name: name, UID: "uid-" + name, DesiredReplicas: 3, ReadyReplicas: 3, Ready: true, MountedSecrets: []string{"creds"}},
			Phase:              model.PhaseWarm,
			BlastRadius:        0.5,
			Neighbors:          []model.NeighborRef{{Key: "vllm/crown", Value: 4}},
			ExposureByVariable: allClocks(exposure),
			Telemetry:          model.Telemetry{ReqRate: model.PresentSignal(20, "fixture")},
		}
	}
	hot := mk("hot", 3*time.Hour)
	hot.Events = []model.SecurityEventInfo{{Name: "ev", UID: "ev-1", Type: "Anomaly", ThreatLevel: "high", TargetsPod: true, Trust: "trusted", Age: 15 * time.Second}}
	unmeasured := mk("unmeasured", 3*time.Hour)
	unmeasured.Telemetry = model.Telemetry{}
	gated := mk("gated", 3*time.Hour)
	return []*model.WorkloadView{hot, unmeasured, gated}
}

func fixturePolicy() (model.Policy, v1alpha1.PhorvexPolicySpec) {
	spec := v1alpha1.PhorvexPolicySpec{}
	pol := model.Policy{Tenant: "vllm", Namespace: "vllm", PolicyName: "vllm-defense", PolicyUID: "pol-uid", PolicyGeneration: 7,
		Lambda: 0.5, NormSparsity: 0.4, FlowDisruption: 0.6, CostCeiling: 1.2, WeightSecrets: 0.8, BlastRadiusFromGraph: true,
		MaxMovesPerTick: 1, ProactiveFloor: 15 * time.Minute, AntiOverRotationWindow: 90 * time.Second, MinAvailableReplicas: 1,
		P99Ms: 500, TraceEnabled: true, BrainImage: "img:test", GitSHA: "deadbeef", TickID: "tick-1",
		EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true, model.ActionKVReset: true}}
	return pol, spec
}

func capabilityGate(v *model.WorkloadView, a model.Action, _ []string) *actionset.Eligibility {
	if v.Pod.Name == "gated" && a == model.ActionKVReset {
		return &actionset.Eligibility{Excluded: true, Kind: "capability-unsupported", Detail: "fixture: no serving stack"}
	}
	return nil
}

// recordTick runs one production-shaped tick through the recorder and returns the stored
// snapshot bytes.
func recordTick(t *testing.T, dir string) []byte {
	t.Helper()
	return recordTickWith(t, dir, 3, false)
}

// recordTickWith records the tick after warmup earlier ticks. With advancingClock every clock
// read returns a later instant, as a real wall clock does within one tick.
func recordTickWith(t *testing.T, dir string, warmup int, advancingClock bool) []byte {
	t.Helper()
	recon.Registry.SetDefault("ucw-recon")
	prod := decision.NewCoverageEngine()
	prod.Capability, prod.ShadowCapability = capabilityGate, capabilityGate
	prod.FailureExclusion = func(*model.WorkloadView, model.Action) (string, bool) { return "", false }
	pol, spec := fixturePolicy()
	base := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	for i := 0; i < warmup; i++ {
		now := base.Add(time.Duration(i) * 10 * time.Second)
		prod.Now = func() time.Time { return now }
		if _, err := prod.DecideChecked(fleet(), pol); err != nil {
			t.Fatal(err)
		}
		prod.ObserveRotation(pol.Owner(), fleet()[0], 0.35+0.02*float64(i))
	}
	decidedAt := base.Add(40 * time.Second)
	prod.Now = func() time.Time { return decidedAt }
	if advancingClock {
		next := decidedAt
		prod.Now = func() time.Time { n := next; next = next.Add(time.Microsecond); return n }
	}

	sink := &memorySink{}
	r, err := NewRecorder(Config{Policies: []string{"vllm/vllm-defense"}, GPUEnvelopeMax: cost.GPUEnvelopeMax(),
		ProcessConfig: map[string]string{"gpu-envelope-max": "1"}}, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	views := fleet()
	capture := r.Begin(prod, spec, views, pol, base.Add(39*time.Second))
	decisions, err := prod.DecideChecked(views, pol)
	capture.Decided(decisions, err)
	// The runner stamps decisions after selection; the inputs recorded above must not see it.
	views[0].Pod.Name = "mutated-after-capture"
	final := append([]model.Decision(nil), decisions...)
	for i := range final {
		final[i].DryRun = true
	}
	capture.Finalize(final)
	capture.Close()
	if len(sink.items) != 1 {
		t.Fatalf("expected one queued snapshot, got %d", len(sink.items))
	}
	store, err := OpenStore(dir, 64<<20, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.write(sink.items[0])
	list := store.List(ListFilter{PolicyUID: "pol-uid"})
	if len(list) != 1 {
		t.Fatalf("store listed %d snapshots", len(list))
	}
	raw, err := store.Read(list[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func f(v float64) *float64 { return &v }

func replayArms(t *testing.T, raw []byte, arms ...Arm) []ArmResult {
	t.Helper()
	snap, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Header.Finalized || snap.Final == nil {
		t.Fatal("snapshot was not finalized")
	}
	res, err := Replay(snap, ReplayOptions{Arms: append([]Arm{{ID: "baseline"}}, arms...)})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func byArm(rs []ArmResult) map[string]ArmResult {
	out := map[string]ArmResult{}
	for _, r := range rs {
		out[r.ArmID] = r
	}
	return out
}

func gate(r ArmResult, asset, action, gateID, law string) *GateRow {
	for i := range r.Gates {
		g := &r.Gates[i]
		if g.Asset == asset && g.Action == action && g.GateID == gateID && g.Law == law {
			return g
		}
	}
	return nil
}

func candidate(r ArmResult, asset, action string) *CandidateRow {
	for i := range r.Candidates {
		if r.Candidates[i].Asset == asset && r.Candidates[i].Action == action {
			return &r.Candidates[i]
		}
	}
	return nil
}

// R-01, R-03: the recorded production tick reproduces exactly and deterministically.
func TestBaselineReplayReproducesProductionExactlyAndDeterministically(t *testing.T) {
	raw := recordTick(t, t.TempDir())
	first := byArm(replayArms(t, raw))["baseline"]
	if first.Status != StatusOK || first.Baseline == nil || !first.Baseline.Reproduced {
		t.Fatalf("baseline not reproduced: status=%s reasons=%v check=%+v", first.Status, first.Reasons, first.Baseline)
	}
	if first.Funnel.Selected == 0 {
		t.Fatal("fixture selected nothing")
	}
	if len(first.Dispatch) != 3 || !first.Dispatch[0].DryRun {
		t.Fatalf("final dispatch evidence missing: %+v", first.Dispatch)
	}
	second := byArm(replayArms(t, raw))["baseline"]
	first.ReplaySeconds, second.ReplaySeconds = 0, 0
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("identical snapshot replayed to different output")
	}
}

// The tick that creates the owner's cost bucket (the first one after an operator start)
// reproduces exactly: the bucket is stamped with the decision's own time, not with a
// second, later clock read that a replay pinned to the decision time cannot see.
func TestBucketCreationTickReproduces(t *testing.T) {
	raw := recordTickWith(t, t.TempDir(), 0, true)
	snap, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Inputs.Engine.HasBucket || snap.Inputs.Engine.HasMeta {
		t.Fatal("fixture should record the tick that creates the bucket")
	}
	base := byArm(replayArms(t, raw))["baseline"]
	if base.Status != StatusOK || base.Baseline == nil || !base.Baseline.Reproduced {
		t.Fatalf("bucket-creation tick not reproduced: status=%s reasons=%v check=%+v", base.Status, base.Reasons, base.Baseline)
	}
}

// The proactive floor arm moves both roles buildPolicy derives from spec.budget.proactiveFloor
// and changes the cadence gate only for moves without event evidence.
func TestProactiveFloorArmMovesCadenceAndExposureHorizon(t *testing.T) {
	raw := recordTick(t, t.TempDir())
	// The fixture pods were last reset 3h ago: a 4h floor caps hygiene, a 1m floor does not.
	rs := byArm(replayArms(t, raw,
		Arm{ID: "floor-4h", Overrides: []Override{{ParamID: ParamProactiveFloor, Value: f(4 * 3600)}}},
		Arm{ID: "floor-1m", Overrides: []Override{{ParamID: ParamProactiveFloor, Value: f(60)}}}))
	base, high, low := rs["baseline"], rs["floor-4h"], rs["floor-1m"]
	for id, r := range rs {
		if r.Status != StatusOK {
			t.Fatalf("%s: %s %v", id, r.Status, r.Reasons)
		}
	}
	if len(high.PolicyDiff) != 1 || high.PolicyDiff[0].After != "proactiveFloor=4h0m0s exposurePressureScale=4h0m0s" {
		t.Fatalf("arm must move both coupled roles: %+v", high.PolicyDiff)
	}
	cadence := func(r ArmResult, asset, action string) *GateRow {
		return gate(r, asset, action, actionset.GateFeasibility, "proactive-cadence")
	}
	if g := cadence(base, "vllm/unmeasured", "rotate"); g == nil || g.ActualStatus != GatePass {
		t.Fatalf("baseline cadence should pass at 15m: %+v", g)
	}
	if g := cadence(high, "vllm/unmeasured", "rotate"); g == nil || g.ActualStatus != GateFail {
		t.Fatalf("a 4h floor should cap a hygiene move 3h after the last reset: %+v", g)
	}
	if g := cadence(high, "vllm/hot", "rotate"); g == nil || g.ActualStatus != GatePass {
		t.Fatalf("event-backed moves bypass the cadence law: %+v", g)
	}
	if g := cadence(low, "vllm/unmeasured", "rotate"); g == nil || g.ActualStatus != GatePass {
		t.Fatalf("a 1m floor should not cap: %+v", g)
	}
	if c := candidate(high, "vllm/unmeasured", "rotate"); c == nil || c.FirstVetoGate != actionset.GateFeasibility {
		t.Fatalf("under a 4h floor the cadence law should veto before the ceiling: %+v", c)
	}
	if high.Funnel.Admitted > base.Funnel.Admitted {
		t.Fatalf("raising the floor admitted more: %d -> %d", base.Funnel.Admitted, high.Funnel.Admitted)
	}
	if high.ArmPolicyOverrides == base.ArmPolicyOverrides {
		t.Fatal("the floor must change the arm overrides hash")
	}

	snap, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	snap.Inputs.Policy.ExposurePressureScale = 2 * time.Hour
	decoupled, err := Replay(snap, ReplayOptions{Arms: []Arm{{ID: "baseline"},
		{ID: "floor", Overrides: []Override{{ParamID: ParamProactiveFloor, Value: f(600)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if decoupled[1].Status != StatusInvalidArm {
		t.Fatalf("a recorded horizon set apart from the floor must refuse the coupled override, got %s", decoupled[1].Status)
	}
}

// G-01, R-05: a G9-only veto is verified from the actual short-circuit trace and a higher
// hypothetical ceiling admits exactly that candidate, with no dispatch.
func TestCostCeilingArmAdmitsOnlyVerifiedSoleG9Vetoes(t *testing.T) {
	raw := recordTick(t, t.TempDir())
	rs := byArm(replayArms(t, raw, Arm{ID: "ceiling-2", Overrides: []Override{{ParamID: ParamCostCeiling, Value: f(2.0)}}}))
	base, arm := rs["baseline"], rs["ceiling-2"]
	row := candidate(base, "vllm/unmeasured", "rotate")
	if row == nil || row.G9Category != G9SoleVetoVerified || row.FirstVetoGate != actionset.GateCHiCeiling {
		t.Fatalf("unmeasured rotate is not a verified sole G9 veto: %+v", row)
	}
	g := gate(base, "vllm/unmeasured", "rotate", actionset.GateCHiCeiling, "")
	if g.ActualStatus != GateFail || !g.FirstVeto || g.WouldPassAllOther != "YES" || g.CounterfactualOnly {
		t.Fatalf("G9 row wrong: %+v", g)
	}
	for _, earlier := range []string{actionset.GatePolicyBinding, actionset.GateCapability, actionset.GateFeasibility, actionset.GateCostNaN} {
		if r := gate(base, "vllm/unmeasured", "rotate", earlier, ""); r.ActualStatus != GatePass {
			t.Fatalf("%s should have actually passed: %+v", earlier, r)
		}
	}
	if c := candidate(arm, "vllm/unmeasured", "rotate"); c == nil || !c.Admitted {
		t.Fatalf("higher ceiling did not admit the sole-G9 candidate: %+v", c)
	}
	for _, d := range arm.Decisions {
		if d.DispatchStatus != DispatchCounterfactualOnly {
			t.Fatalf("counterfactual arm claims dispatch: %+v", d)
		}
	}
	if arm.Funnel.Admitted <= base.Funnel.Admitted {
		t.Fatalf("admitted %d -> %d", base.Funnel.Admitted, arm.Funnel.Admitted)
	}
	if arm.ArmPolicyOverrides == base.ArmPolicyOverrides || arm.Snapshot.PolicyOverridesHash != base.Snapshot.PolicyOverridesHash {
		t.Fatal("R-07: the tested parameter must change the arm overrides hash while the recorded identity stays the same")
	}
}

// G-02/G-03: an earlier capability veto leaves G9 NOT_EVALUATED; only a labeled
// counterfactual diagnostic speaks about it.
func TestEarlierVetoNeverCountsAsG9(t *testing.T) {
	raw := recordTick(t, t.TempDir())
	base := byArm(replayArms(t, raw))["baseline"]
	cap := gate(base, "vllm/gated", "kv-reset", actionset.GateCapability, "")
	if cap.ActualStatus != GateFail || !cap.FirstVeto {
		t.Fatalf("capability should be the first veto: %+v", cap)
	}
	g9 := gate(base, "vllm/gated", "kv-reset", actionset.GateCHiCeiling, "")
	if g9.ActualStatus != GateNotEvaluated || !g9.CounterfactualOnly || g9.FirstVeto {
		t.Fatalf("G9 must be not-evaluated counterfactual: %+v", g9)
	}
	if g9.DiagnosticStatus != DiagPass && g9.DiagnosticStatus != DiagFail {
		t.Fatalf("pure CHi diagnostic missing: %+v", g9)
	}
	if c := candidate(base, "vllm/gated", "kv-reset"); c.G9Category == G9SoleVetoVerified {
		t.Fatal("capability-vetoed candidate counted as sole G9")
	}
}

// G-04: an unusable p99 under a configured ceiling is SKIPPED_UNUSABLE, not a pass.
func TestUnusableTelemetryIsNotAPass(t *testing.T) {
	raw := recordTick(t, t.TempDir())
	base := byArm(replayArms(t, raw))["baseline"]
	r := gate(base, "vllm/hot", "rotate", actionset.GateFeasibility, "slo-headroom")
	if r == nil || r.ActualStatus != GateUnavailable || r.ReasonCode != "SKIPPED_UNUSABLE" || r.TelemetryStatus != "absent" {
		t.Fatalf("slo-headroom row: %+v", r)
	}
	tf := gate(base, "vllm/hot", "rotate", actionset.GateFeasibility, "tokens-floor")
	if tf == nil || tf.ActualStatus != GateNotApplicable {
		t.Fatalf("unconfigured tokens floor should be not-applicable: %+v", tf)
	}
}

// R-04: beta changes pricing only; gate admission is unchanged.
func TestBetaArmChangesOnlyObjectivePricing(t *testing.T) {
	raw := recordTick(t, t.TempDir())
	rs := byArm(replayArms(t, raw,
		Arm{ID: "beta-0", Overrides: []Override{{ParamID: ParamDisruptionAversion, Value: f(0)}}},
		Arm{ID: "beta-10", Overrides: []Override{{ParamID: ParamDisruptionAversion, Value: f(10)}}},
		Arm{ID: "beta-unset", Overrides: []Override{{ParamID: ParamDisruptionAversion, Unset: true}}}))
	base := rs["baseline"]
	for _, id := range []string{"beta-0", "beta-10", "beta-unset"} {
		arm := rs[id]
		if arm.Status != StatusOK {
			t.Fatalf("%s: %s %v", id, arm.Status, arm.Reasons)
		}
		if arm.Funnel.Admitted != base.Funnel.Admitted || len(arm.Funnel.FirstVetoByGate) != len(base.Funnel.FirstVetoByGate) {
			t.Fatalf("%s changed admission: %+v vs %+v", id, arm.Funnel, base.Funnel)
		}
		if arm.FactWeightsMatch == nil || !*arm.FactWeightsMatch {
			t.Fatalf("%s changed fact weights", id)
		}
	}
	if rs["beta-10"].EconomicsMode != model.EconomicsFixedDisruptionAversionV1 || rs["beta-unset"].EconomicsMode == model.EconomicsFixedDisruptionAversionV1 {
		t.Fatalf("economics modes: beta-10=%s unset=%s", rs["beta-10"].EconomicsMode, rs["beta-unset"].EconomicsMode)
	}
	if rs["beta-10"].Funnel.Selected > rs["beta-0"].Funnel.Selected {
		t.Fatal("a much higher disruption price selected more moves on this fixture")
	}
}

// V-04: invalid trial values are refused before any replay.
func TestInvalidArmsAreRefused(t *testing.T) {
	bad := []Arm{
		{ID: "nan", Overrides: []Override{{ParamID: ParamDisruptionAversion, Value: f(nan())}}},
		{ID: "neg", Overrides: []Override{{ParamID: ParamDisruptionAversion, Value: f(-1)}}},
		{ID: "ceil0", Overrides: []Override{{ParamID: ParamCostCeiling, Value: f(0)}}},
		{ID: "floor0", Overrides: []Override{{ParamID: ParamProactiveFloor, Value: f(0)}}},
		{ID: "floor-frac", Overrides: []Override{{ParamID: ParamProactiveFloor, Value: f(1.5)}}},
		{ID: "floor-huge", Overrides: []Override{{ParamID: ParamProactiveFloor, Value: f(MaxReplayProactiveFloorSeconds + 1)}}},
		{ID: "floor-unset", Overrides: []Override{{ParamID: ParamProactiveFloor, Unset: true}}},
		{ID: "unknown", Overrides: []Override{{ParamID: "P-FEA-001", Value: f(0)}}},
		{ID: "dup", Overrides: []Override{{ParamID: ParamCostCeiling, Value: f(1)}, {ParamID: ParamCostCeiling, Value: f(2)}}},
	}
	for _, a := range bad {
		if err := ValidateArm(a); err == nil {
			t.Errorf("%s accepted", a.ID)
		}
	}
}

// The advertised list (brain-replay -version) is exactly what ValidateArm accepts.
func TestOverridableParametersMatchValidation(t *testing.T) {
	valid := map[string]float64{ParamDisruptionAversion: 1, ParamCostCeiling: 1.5, ParamProactiveFloor: 600}
	if len(OverridableParameters) != len(valid) {
		t.Fatalf("advertised %v", OverridableParameters)
	}
	for _, id := range OverridableParameters {
		v, ok := valid[id]
		if !ok {
			t.Fatalf("%s advertised without a validation case", id)
		}
		if err := ValidateArm(Arm{ID: "a", Overrides: []Override{{ParamID: id, Value: f(v)}}}); err != nil {
			t.Fatalf("%s advertised but refused: %v", id, err)
		}
	}
}

// R-02: a snapshot missing replay-critical state is UNREPLAYABLE, never approximated.
func TestIncompleteSnapshotIsUnreplayable(t *testing.T) {
	raw := recordTick(t, t.TempDir())
	snap, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	snap.Inputs.Engine.Owner = ""
	rs, err := Replay(snap, ReplayOptions{Arms: []Arm{{ID: "baseline"}, {ID: "c", Overrides: []Override{{ParamID: ParamCostCeiling, Value: f(2)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Status != StatusUnreplayable || len(r.Decisions) != 0 {
			t.Fatalf("%s: %s with %d decisions", r.ArmID, r.Status, len(r.Decisions))
		}
	}
	snap2, _ := Decode(raw)
	snap2.Outcome.Capability = nil // production verdicts lost
	rs2, _ := Replay(snap2, ReplayOptions{Arms: []Arm{{ID: "baseline"}}})
	if rs2[0].Status != StatusUnreplayable {
		t.Fatalf("missing capability verdicts replayed as %s", rs2[0].Status)
	}
}

func TestStoreEvictsOldestAndVerifiesContent(t *testing.T) {
	dir := t.TempDir()
	raw := recordTick(t, dir)
	digest := Digest(raw)
	store, err := OpenStore(dir, int64(len(raw))*2, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.List(ListFilter{}); len(got) != 1 || got[0].Digest != digest {
		t.Fatalf("reopened store lost its index: %+v", got)
	}
	snap, _ := Decode(raw)
	for i := 1; i <= 2; i++ {
		h := snap.Header
		h.CapturedAt = h.CapturedAt.Add(time.Duration(i) * time.Minute)
		h.TickID = "later"
		store.write(Pending{Header: h, Stream: payloadOf(t, raw)})
	}
	list := store.List(ListFilter{})
	if len(list) != 2 || list[0].Header.CapturedAt.Equal(snap.Header.CapturedAt) {
		t.Fatalf("oldest snapshot not evicted: %d entries", len(list))
	}
	if err := os.WriteFile(filepath.Join(dir, list[0].Digest+snapshotExt), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(list[0].Digest); err == nil {
		t.Fatal("tampered snapshot passed the content check")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store.Run(ctx)
}

func nan() float64 { var z float64; return z / z }

// payloadOf extracts the gob stream from a snapshot file image.
func payloadOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	size := int(binaryLen(raw))
	zr, err := gzip.NewReader(bytes.NewReader(raw[len(fileMagic)+4+size:]))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func binaryLen(raw []byte) uint32 {
	return binary.BigEndian.Uint32(raw[len(fileMagic) : len(fileMagic)+4])
}

// Positive control for R-01: the comparison must detect a single changed number.
func TestBaselineComparisonDetectsATamperedProductionRecord(t *testing.T) {
	raw := recordTick(t, t.TempDir())
	snap, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	snap.Outcome.Production[0].Net += 1e-9
	rs, err := Replay(snap, ReplayOptions{Arms: []Arm{{ID: "baseline"}}})
	if err != nil {
		t.Fatal(err)
	}
	if rs[0].Baseline == nil || rs[0].Baseline.Reproduced || rs[0].Status != StatusUnreplayable {
		t.Fatalf("tampered record reproduced: %+v", rs[0].Baseline)
	}
	if len(rs[0].Baseline.Mismatches) == 0 || !strings.Contains(rs[0].Baseline.Mismatches[0], "$.Net") {
		t.Fatalf("mismatch does not name the field: %v", rs[0].Baseline.Mismatches)
	}
}
