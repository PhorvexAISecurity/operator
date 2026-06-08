package config

import (
	"errors"
	"testing"
)

func TestRefuseMissingAck(t *testing.T) {
	yaml := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
ownedAck: false
`)
	_, err := Parse(yaml)
	if !errors.Is(err, ErrAckMissing) {
		t.Fatalf("expected ErrAckMissing for ownedAck=false, got %v", err)
	}
}

func TestRefuseAbsentAck(t *testing.T) {
	// ownedAck not present at all => defaults to false => refused.
	yaml := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
`)
	_, err := Parse(yaml)
	if !errors.Is(err, ErrAckMissing) {
		t.Fatalf("expected ErrAckMissing for absent ownedAck, got %v", err)
	}
}

func TestRefuseEmptyContext(t *testing.T) {
	yaml := []byte(`
namespace: phorvex-harness
ownedAck: true
`)
	_, err := Parse(yaml)
	if err == nil || errors.Is(err, ErrAckMissing) {
		t.Fatalf("expected non-ack error for empty context, got %v", err)
	}
}

func TestRefuseEmptyNamespace(t *testing.T) {
	yaml := []byte(`
context: kind-amtd-test
ownedAck: true
`)
	_, err := Parse(yaml)
	if err == nil {
		t.Fatalf("expected error for empty namespace")
	}
}

func TestValidConfigDefaults(t *testing.T) {
	yaml := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
ownedAck: true
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.TrialsPerArm != 2 {
		t.Fatalf("smoke default trials want 2 got %d", cfg.TrialsPerArm)
	}
	if cfg.OutDir != "out" {
		t.Fatalf("default outDir want out got %q", cfg.OutDir)
	}
}

func TestTrialsKnobHonored(t *testing.T) {
	yaml := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
ownedAck: true
trialsPerArm: 20
masterSeed: 42
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.TrialsPerArm != 20 {
		t.Fatalf("trials knob not honored: %d", cfg.TrialsPerArm)
	}
	if cfg.MasterSeed != 42 {
		t.Fatalf("masterSeed not honored: %d", cfg.MasterSeed)
	}
}
