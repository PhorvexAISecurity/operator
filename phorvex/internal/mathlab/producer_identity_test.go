package mathlab

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/recon"
)

func TestRecorderProcessIdentityDoesNotRelabelDecisionPolicy(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		recon.Registry.SetDefault("ucw-recon")
		engine := decision.NewCoverageEngine()
		now := time.Unix(100000, 0)
		engine.Now = func() time.Time { return now }
		pol, spec := fixturePolicy()
		pol.GitSHA, pol.BrainImage = strings.Repeat("a", 40), "manager:stage@sha256:"+strings.Repeat("1", 64)
		sink := &memorySink{}
		cfg := Config{Policies: []string{"vllm/vllm-defense"}, GPUEnvelopeMax: cost.GPUEnvelopeMax()}
		identity := &CaptureIdentity{GitSHA: strings.Repeat("b", 40), BrainImage: "brain:stage@sha256:" + strings.Repeat("2", 64)}
		if explicit {
			cfg.ProducerIdentity = identity
		}
		recorder, err := NewRecorder(cfg, sink, nil)
		if err != nil {
			t.Fatal(err)
		}
		identity.GitSHA = "changed-after-construction"
		views := fleet()
		capture := recorder.Begin(engine, spec, views, pol, now)
		decisions, err := engine.DecideChecked(views, pol)
		capture.Decided(decisions, err)
		capture.Finalize(decisions)
		capture.Close()
		if err != nil || len(sink.items) != 1 {
			t.Fatal("capture failed", err)
		}
		raw, err := assemble(sink.items[0].Header, sink.items[0].Stream)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(snapshot.Inputs.Policy, pol) || !reflect.DeepEqual(snapshot.Outcome.Production, decisions) {
			t.Fatal("recorder identity changed decision inputs/output")
		}
		if explicit {
			if snapshot.Header.GitSHA != strings.Repeat("b", 40) || snapshot.Header.BrainImage != "brain:stage@sha256:"+strings.Repeat("2", 64) || snapshot.Header.CaptureIdentitySource != "recorder-process" {
				t.Fatal(snapshot.Header)
			}
		} else if snapshot.Header.GitSHA != pol.GitSHA || snapshot.Header.BrainImage != pol.BrainImage || snapshot.Header.CaptureIdentitySource != "" {
			t.Fatal("legacy local identity changed")
		}
		result, err := Replay(snapshot, ReplayOptions{Arms: []Arm{{ID: "baseline"}}})
		if err != nil || len(result) != 1 || result[0].Baseline == nil || !result[0].Baseline.Reproduced {
			t.Fatalf("producer-labelled capture not exactly replayable: %+v %v", result, err)
		}
	}
}

func TestRecorderRejectsUnprovenExplicitProducerIdentity(t *testing.T) {
	for _, identity := range []*CaptureIdentity{{}, {GitSHA: strings.Repeat("a", 40), BrainImage: "notAvailable"}, {GitSHA: "wrong", BrainImage: "image"}} {
		if _, err := NewRecorder(Config{Policies: []string{"stage/policy"}, ProducerIdentity: identity}, &memorySink{}, nil); err == nil {
			t.Fatal("invalid producer identity accepted", identity)
		}
	}
}
