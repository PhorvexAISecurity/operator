package decisionconfig

import (
	"testing"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/recon"
)

func TestApplyInstallsTheDescribedConfiguration(t *testing.T) {
	optimizer, err := Apply("p1", cost.DefaultGPUEnvelopeMax, "vllm, voice")
	if err != nil {
		t.Fatal(err)
	}
	if name := recon.Registry.DefaultName(); name != ReconProfile {
		t.Fatalf("recon default %q, want %q", name, ReconProfile)
	}
	got, err := Describe(optimizer, cost.DefaultGPUEnvelopeMax, "vllm, voice")
	if err != nil {
		t.Fatal(err)
	}
	if got.Engine != optimizer.Name() || got.ReconProfile != ReconProfile || got.ParameterManifestSHA256 == "" {
		t.Fatalf("description incomplete: %+v", got)
	}
	same, err := Describe(optimizer, cost.DefaultGPUEnvelopeMax, "voice,vllm,")
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256() != same.SHA256() {
		t.Fatal("the same flow-residual classes in another order must describe the same configuration")
	}
	other, err := Describe(optimizer, 0.5, "vllm, voice")
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256() == other.SHA256() {
		t.Fatal("a different GPU envelope must describe a different configuration")
	}
}

func TestApplyRefusesAnUnknownEngine(t *testing.T) {
	if _, err := Apply("p0", cost.DefaultGPUEnvelopeMax, ""); err == nil {
		t.Fatal("removed engine accepted")
	}
	if _, err := Apply("p1", 2, ""); err == nil {
		t.Fatal("out-of-range GPU envelope accepted")
	}
	if _, err := Apply("p1", cost.DefaultGPUEnvelopeMax, ""); err != nil {
		t.Fatal(err)
	}
}
