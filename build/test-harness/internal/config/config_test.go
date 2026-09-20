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

func TestCredentialObservationWindowDefault(t *testing.T) {
	yaml := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
ownedAck: true
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.CredentialObservationWindowSeconds != DefaultCredentialObservationWindowSeconds {
		t.Fatalf("omitted observation window want default %d got %d",
			DefaultCredentialObservationWindowSeconds, cfg.CredentialObservationWindowSeconds)
	}
}

func TestCredentialObservationWindowHonored(t *testing.T) {
	yaml := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
ownedAck: true
credentialObservationWindowSeconds: 120
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.CredentialObservationWindowSeconds != 120 {
		t.Fatalf("observation window knob not honored: %d", cfg.CredentialObservationWindowSeconds)
	}
}

func TestCredentialObservationWindowRejectsOverMax(t *testing.T) {
	yaml := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
ownedAck: true
credentialObservationWindowSeconds: 1801
`)
	if _, err := Parse(yaml); err == nil {
		t.Fatalf("expected rejection of observation window > %d", MaxCredentialObservationWindowSeconds)
	}
}

func TestCredentialObservationWindowRejectsNegative(t *testing.T) {
	yaml := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
ownedAck: true
credentialObservationWindowSeconds: -5
`)
	if _, err := Parse(yaml); err == nil {
		t.Fatalf("expected rejection of negative observation window")
	}
}

func TestCredentialObservationWindowAtMaxAccepted(t *testing.T) {
	yaml := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
ownedAck: true
credentialObservationWindowSeconds: 1800
`)
	cfg, err := Parse(yaml)
	if err != nil {
		t.Fatalf("observation window at the max should be accepted: %v", err)
	}
	if cfg.CredentialObservationWindowSeconds != MaxCredentialObservationWindowSeconds {
		t.Fatalf("max observation window not honored: %d", cfg.CredentialObservationWindowSeconds)
	}
}

func TestBenignSessionNodeSelectorValidation(t *testing.T) {
	valid := []byte(`
context: kind-amtd-test
namespace: phorvex-harness
ownedAck: true
benignSessionNodeSelector:
  kubernetes.io/hostname: ip-172-27-12-233.us-east-2.compute.internal
`)
	cfg, err := Parse(valid)
	if err != nil {
		t.Fatalf("valid benign session selector rejected: %v", err)
	}
	if got := cfg.BenignSessionNodeSelector["kubernetes.io/hostname"]; got != "ip-172-27-12-233.us-east-2.compute.internal" {
		t.Fatalf("selector not retained: %q", got)
	}

	for _, tc := range []struct {
		name     string
		selector map[string]string
	}{
		{name: "invalid key", selector: map[string]string{"bad key": "node"}},
		{name: "invalid value", selector: map[string]string{"kubernetes.io/hostname": "bad value"}},
		{name: "too many entries", selector: map[string]string{
			"a": "1", "b": "2", "c": "3", "d": "4", "e": "5",
			"f": "6", "g": "7", "h": "8", "i": "9",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := TargetConfig{Context: "kind-amtd-test", Namespace: "phorvex-harness", OwnedAck: true, TrialsPerArm: 1, CredentialObservationWindowSeconds: 90, BenignSessionNodeSelector: tc.selector}
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid selector accepted: %v", tc.selector)
			}
		})
	}
}
