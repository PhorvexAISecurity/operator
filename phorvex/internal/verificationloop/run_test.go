package verificationloop

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func TestRuntimeEarlyExitPreservesCompletionForCleanup(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 7")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var rt ready
	if err := waitReady(ctx, done, filepath.Join(t.TempDir(), "never-ready"), &rt); err == nil {
		t.Fatal("early subprocess exit accepted")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("lost process exit error")
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup completion consumed by readiness waiter")
	}
}

func TestExactShadowReplayAndTraceTampering(t *testing.T) {
	clock := time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC)
	pol := model.Policy{Tenant: "unit-replay", Namespace: "vllm", PolicyName: "defense", PolicyUID: "unit-policy", PolicyGeneration: 1, TickID: "unit-tick", BrainImage: "unit-brain", GitSHA: "unit-source", TraceEnabled: true, Lambda: cost.DefaultLambdaSeed, NormSparsity: 0.4, FlowDisruption: 0.6, MaxMovesPerTick: 1, ReactiveOnly: true, EnabledActions: map[model.Action]bool{model.ActionEndpointLeaseRevoke: true}}
	views := []*model.WorkloadView{{Pod: model.Pod{Namespace: "vllm", Name: "unit", UID: "unit-pod", Ready: true, ReadyReplicas: 1, DesiredReplicas: 1}, Phase: model.PhaseWarm}}
	e := decision.NewCoverageEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("UCW missing")
	}
	e.Recon = profile
	e.Now = func() time.Time { return clock }
	input := replayInput{ReconProfile: profile.Name(), Clock: clock, Policy: pol, Views: views, State: e.ExportOwnerState(pol.Owner()), Capabilities: map[string]capabilityObservation{}}
	e.ShadowCapability = func(v *model.WorkloadView, a model.Action, keys []string) *actionset.Eligibility {
		input.Capabilities[capabilityKey(v, a, keys)] = capabilityObservation{Nil: true}
		return nil
	}
	ds, err := e.DecideShadowChecked(views, pol)
	if err != nil {
		t.Fatal(err)
	}
	same, err := replay(input, ds)
	if err != nil || !same {
		t.Fatalf("exact replay: same=%v err=%v", same, err)
	}
	ds[0].Trace.GitSHA = "tampered-valid-source"
	same, err = replay(input, ds)
	if err == nil && same {
		t.Fatal("valid-schema trace identity tampering accepted")
	}
}

// Set VERIFICATION_LOOP_INTEGRATION=1, KUBEBUILDER_ASSETS and
// VERIFICATION_LOOP_PYTHON to exercise the real API/runtime in the test suite.
func TestPrivateAPIAndRuntimeIntegration(t *testing.T) {
	if os.Getenv("VERIFICATION_LOOP_INTEGRATION") != "1" {
		t.Skip("requires explicitly enabled isolated API/runtime integration")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	o := Options{RepoRoot: root, OutputDir: filepath.Join(t.TempDir(), "evidence"), Python: os.Getenv("VERIFICATION_LOOP_PYTHON"), Assets: os.Getenv("KUBEBUILDER_ASSETS"), GitSHA: "integration-source-label", Timeout: 2 * time.Minute, HoldDuration: 300 * time.Millisecond, HoldInterval: 100 * time.Millisecond, MaxLegitimateLatency: 2 * time.Second}
	r, err := Run(t.Context(), o)
	if err != nil {
		t.Fatalf("local run: %v", err)
	}
	if r.Verdict != "LOCAL_RUNTIME_DEFENDED" || !r.ReplayExact || !r.ShadowStateUnchanged || r.LegitimateDispatchOverlaps < 1 {
		t.Fatalf("incomplete real effect: %+v", r)
	}
	same, err := ReplayFile(filepath.Join(o.OutputDir, "replay-input.gob"), r.Decisions)
	if err != nil || !same {
		t.Fatalf("persisted snapshot replay: %v %v", same, err)
	}
}

func TestStudyArmsAreCheckedBeforeAnyEnvironmentStarts(t *testing.T) {
	base := Options{GitSHA: "label", Timeout: time.Second, HoldDuration: time.Second, HoldInterval: time.Second, MaxLegitimateLatency: time.Second}
	for name, o := range map[string]Options{
		"unknown arm":                 {Arm: "cf-quarantine"},
		"baseline with skip-dispatch": {Arm: ArmBaseline, SkipDispatch: true},
		"counterfactual with outage":  {Arm: ArmCFRotate, UnavailableAuthority: true},
		"unknown scenario":            {Arm: ArmBaseline, Scenario: "kv"},
		"token defended path":         {Scenario: ScenarioToken},
		"combined intervention":       {Arm: ArmIntervention, Scenario: ScenarioCombined},
	} {
		o.GitSHA, o.Timeout, o.HoldDuration, o.HoldInterval, o.MaxLegitimateLatency = base.GitSHA, base.Timeout, base.HoldDuration, base.HoldInterval, base.MaxLegitimateLatency
		o.OutputDir = filepath.Join(t.TempDir(), "evidence")
		if _, err := Run(t.Context(), o); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if _, err := os.Stat(o.OutputDir); !os.IsNotExist(err) {
			t.Fatalf("%s: evidence directory created before validation", name)
		}
	}
}

// A rotate counterfactual evicts the pod, but credential A lives in the lease Secret and policy,
// not the pod: it stays usable, while the brain's view of the replacement no longer mints the
// lease-reuse fact. Gated like the integration test above.
func TestStudyArmsRecordOutcomesWithoutAsserting(t *testing.T) {
	if os.Getenv("VERIFICATION_LOOP_INTEGRATION") != "1" {
		t.Skip("requires explicitly enabled isolated API/runtime integration")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, arm := range []string{ArmBaseline, ArmCFRotate} {
		o := Options{RepoRoot: root, OutputDir: filepath.Join(t.TempDir(), arm), Python: os.Getenv("VERIFICATION_LOOP_PYTHON"), Assets: os.Getenv("KUBEBUILDER_ASSETS"), GitSHA: "integration-source-label", Timeout: 2 * time.Minute, HoldDuration: 300 * time.Millisecond, HoldInterval: 100 * time.Millisecond, MaxLegitimateLatency: 2 * time.Second, Arm: arm}
		r, err := Run(t.Context(), o)
		if err != nil || r.Verdict != "STUDY_ARM_RECORDED" || r.Arm != arm || len(r.PostDecisions) == 0 {
			t.Fatalf("%s: verdict=%s err=%v post=%d %s", arm, r.Verdict, err, len(r.PostDecisions), r.PostObservationError)
		}
		attacks := 0
		for _, p := range r.Probes {
			if p.Name == "A-study-hold" || p.Name == "A-after-replacement" {
				attacks++
				if err := ValidateProbe(p, true, o.MaxLegitimateLatency); err != nil {
					t.Fatalf("%s: credential A should stay usable: %v", arm, err)
				}
			}
		}
		if attacks == 0 {
			t.Fatalf("%s: no attack probes recorded", arm)
		}
		var lease bool
		for _, d := range r.PostDecisions {
			if d.Trace == nil {
				continue
			}
			for _, f := range d.Trace.Facts {
				lease = lease || strings.HasSuffix(f.FactKey, "|endpointLeaseReuse")
			}
		}
		switch arm {
		case ArmBaseline:
			if r.Dispatch != nil || !lease {
				t.Fatalf("baseline: dispatch=%+v leaseFact=%v", r.Dispatch, lease)
			}
		case ArmCFRotate:
			if r.Dispatch == nil || !r.Dispatch.Emitted || r.Dispatch.Handler != string(model.ActionRotate) || !strings.HasPrefix(r.PostTarget, "harness-simulated ReplicaSet replacement") || lease {
				t.Fatalf("cf-rotate: dispatch=%+v target=%q leaseFact=%v", r.Dispatch, r.PostTarget, lease)
			}
		}
	}
}

// The stolen Pod-bound bearer authenticates until rotate retires its Pod, then the private
// API server rejects it (after its authentication cache expires) while the replica serves.
func TestTokenScenarioRotateRetiresTheStolenBearer(t *testing.T) {
	if os.Getenv("VERIFICATION_LOOP_INTEGRATION") != "1" {
		t.Skip("requires explicitly enabled isolated API/runtime integration")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	o := Options{RepoRoot: root, OutputDir: filepath.Join(t.TempDir(), "token"), Python: os.Getenv("VERIFICATION_LOOP_PYTHON"), Assets: os.Getenv("KUBEBUILDER_ASSETS"), GitSHA: "integration-source-label", Timeout: 3 * time.Minute, HoldDuration: 14 * time.Second, HoldInterval: 500 * time.Millisecond, MaxLegitimateLatency: 2 * time.Second, Arm: ArmCFRotate, Scenario: ScenarioToken}
	r, err := Run(t.Context(), o)
	if err != nil || r.Verdict != "STUDY_ARM_RECORDED" || r.Scenario != ScenarioToken || r.Dispatch == nil || !r.Dispatch.Emitted {
		t.Fatalf("verdict=%s err=%v dispatch=%+v", r.Verdict, err, r.Dispatch)
	}
	var baseline, last *Probe
	legit := 0
	for i := range r.Probes {
		p := &r.Probes[i]
		switch {
		case p.Name == "attack-baseline-T":
			baseline = p
		case p.Capability == CapabilityPodBoundToken:
			last = p
		case strings.HasPrefix(p.Name, "B-") && p.Replica == "b":
			if err := ValidateProbe(*p, true, o.MaxLegitimateLatency); err != nil {
				t.Fatalf("surviving replica refused a legitimate caller: %v", err)
			}
			legit++
		}
	}
	if baseline == nil || baseline.Status != 201 || last == nil || last.Status != 401 || legit == 0 {
		t.Fatalf("baseline=%+v last=%+v legit=%d", baseline, last, legit)
	}
	for _, d := range r.PostDecisions {
		for _, f := range d.Trace.Facts {
			if strings.HasSuffix(f.FactKey, "|podBoundKubeAPIAuthPotential") && f.SteeredBy != nil {
				t.Fatalf("replacement still carries the attributed token fact: %s", f.FactKey)
			}
		}
	}
}
