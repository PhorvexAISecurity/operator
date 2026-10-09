package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/mathlab"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type sink struct{ items []mathlab.Pending }

func (s *sink) Enqueue(p mathlab.Pending) bool { s.items = append(s.items, p); return true }

func writeSnapshot(t *testing.T, dir, gitSHA string) {
	t.Helper()
	recon.Registry.SetDefault("ucw-recon")
	e := decision.NewCoverageEngine()
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	e.Now = func() time.Time { return now }
	pol := model.Policy{Tenant: "t", Namespace: "ns", PolicyName: "p", PolicyUID: "uid", PolicyGeneration: 1, Lambda: 0.5,
		NormSparsity: 0.4, FlowDisruption: 0.6, CostCeiling: 1.2, WeightSecrets: 0.8, MaxMovesPerTick: 1,
		ProactiveFloor: time.Minute, AntiOverRotationWindow: time.Minute, MinAvailableReplicas: 1, TraceEnabled: true,
		BrainImage: "img", GitSHA: gitSHA, TickID: "tick", EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true}}
	views := []*model.WorkloadView{{Pod: model.Pod{Namespace: "ns", Name: "a", UID: "ua", DesiredReplicas: 3, ReadyReplicas: 3, Ready: true, MountedSecrets: []string{"s"}},
		Phase: model.PhaseWarm, Telemetry: model.Telemetry{ReqRate: model.PresentSignal(5, "f")},
		ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: time.Hour, model.VarNetworkIdentity: time.Hour}}}
	s := &sink{}
	rec, err := mathlab.NewRecorder(mathlab.Config{Policies: []string{"ns/p"}, GPUEnvelopeMax: cost.GPUEnvelopeMax()}, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := rec.Begin(e, v1alpha1.PhorvexPolicySpec{}, views, pol, now)
	ds, derr := e.DecideChecked(views, pol)
	c.Decided(ds, derr)
	c.Finalize(ds)
	c.Close()
	store, err := mathlab.OpenStore(dir, 1<<30, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.Enqueue(s.items[0])
	ctx, cancel := context.WithCancel(context.Background())
	go store.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for len(store.List(mathlab.ListFilter{})) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
}

func readLines(t *testing.T, path string) []output {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []output
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var o output
		if err := json.Unmarshal(sc.Bytes(), &o); err != nil {
			t.Fatal(err)
		}
		out = append(out, o)
	}
	return out
}

func TestReplayCommandReproducesAndRefusesForeignRevisions(t *testing.T) {
	dir := t.TempDir()
	writeSnapshot(t, dir, "rev-a")
	arms := filepath.Join(t.TempDir(), "arms.json")
	if err := os.WriteFile(arms, []byte(`[{"arm_id":"baseline","overrides":[]},{"arm_id":"ceiling-2","overrides":[{"param_id":"P-FEA-006","value":2}]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, sumPath := filepath.Join(t.TempDir(), "out.jsonl"), filepath.Join(t.TempDir(), "summary.json")
	if err := run(dir, arms, out, sumPath, false, buildinfo.Identity{GitSHA: "rev-a"}); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, out)
	if len(lines) != 2 || lines[0].Baseline == nil || !lines[0].Baseline.Reproduced || lines[0].CrossVersion {
		t.Fatalf("baseline not reproduced: %+v", lines)
	}
	var sum summary
	raw, _ := os.ReadFile(sumPath)
	if err := json.Unmarshal(raw, &sum); err != nil || sum.BaselineExact != 1 || sum.Snapshots != 1 {
		t.Fatalf("summary: %+v %v", sum, err)
	}
	if err := run(dir, arms, out, "", false, buildinfo.Identity{GitSHA: "rev-b"}); err != nil {
		t.Fatal(err)
	}
	for _, l := range readLines(t, out) {
		if l.Status != mathlab.StatusUnreplayable || len(l.Reasons) == 0 || l.Reasons[0][:16] != "VERSION_MISMATCH" {
			t.Fatalf("foreign revision replayed: %+v", l.ArmResult.Reasons)
		}
	}
	if err := run(dir, arms, out, "", true, buildinfo.Identity{GitSHA: "rev-b"}); err != nil {
		t.Fatal(err)
	}
	if l := readLines(t, out); !l[0].CrossVersion {
		t.Fatal("cross-version replay not flagged")
	}
	inspectOut := filepath.Join(t.TempDir(), "inspect.jsonl")
	if err := runInspect(dir, inspectOut); err != nil {
		t.Fatal(err)
	}
	rawInspect, _ := os.ReadFile(inspectOut)
	var ins struct {
		Effective map[string]any `json:"effective"`
		Learned   map[string]any `json:"learned"`
	}
	if err := json.Unmarshal(rawInspect, &ins); err != nil || ins.Effective["spec.slo.costCeiling"] != 1.2 || ins.Effective["spec.objective.disruptionAversion"] != nil {
		t.Fatalf("inspection: %v %+v", err, ins.Effective)
	}
	if ins.Learned["bucketExists"] != false || ins.Learned["lambdaSeedPendingConsumption"] != 0.5 {
		t.Fatalf("learned state missing: %+v", ins.Learned)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte(`[{"arm_id":"x","overrides":[{"param_id":"P-FEA-006","value":2}]}]`), 0o600)
	if err := run(dir, bad, out, "", false, buildinfo.Identity{GitSHA: "rev-a"}); err == nil {
		t.Fatal("arms without a leading baseline accepted")
	}
}
