package config

import (
	"errors"
	"strings"
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

func TestBenignCheckpointStorageClassValidation(t *testing.T) {
	valid := TargetConfig{Context: "kind-amtd-test", Namespace: "phorvex-harness", OwnedAck: true, TrialsPerArm: 1, CredentialObservationWindowSeconds: 90, BenignCheckpointStorageClass: "gp3.reviewed"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid storage class rejected: %v", err)
	}
	valid.BenignCheckpointStorageClass = "Bad Storage Class"
	if err := valid.Validate(); err == nil {
		t.Fatal("invalid storage class accepted")
	}
}

func TestBenignCheckpointLocalFixtureValidation(t *testing.T) {
	base := TargetConfig{
		Context: "kind-amtd-test", Namespace: "phorvex-harness", OwnedAck: true,
		TrialsPerArm: 3, CredentialObservationWindowSeconds: 90,
		BenignCheckpointNodeSelector:   map[string]string{"kubernetes.io/hostname": "reviewed-node"},
		BenignCheckpointStorageClass:   "checkpoint-local",
		BenignCheckpointLocalFixture:   true,
		BenignCheckpointLocalHolderUID: "11111111-2222-4333-8444-555555555555",
		BenignCheckpointLocalNodeUID:   "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		BenignCheckpointLocalNonce:     "checkpoint-local-r1",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid local checkpoint fixture rejected: %v", err)
	}
	for name, mutate := range map[string]func(*TargetConfig){
		"missing storage class": func(c *TargetConfig) { c.BenignCheckpointStorageClass = "" },
		"wrong trials":          func(c *TargetConfig) { c.TrialsPerArm = 2 },
		"missing node selector": func(c *TargetConfig) { c.BenignCheckpointNodeSelector = nil },
		"extra node selector":   func(c *TargetConfig) { c.BenignCheckpointNodeSelector["node-type"] = "database" },
		"bad holder uid":        func(c *TargetConfig) { c.BenignCheckpointLocalHolderUID = "holder" },
		"bad node uid":          func(c *TargetConfig) { c.BenignCheckpointLocalNodeUID = "node" },
		"bad nonce":             func(c *TargetConfig) { c.BenignCheckpointLocalNonce = "bad nonce" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.BenignCheckpointNodeSelector = map[string]string{"kubernetes.io/hostname": "reviewed-node"}
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid local checkpoint fixture accepted")
			}
		})
	}
}

func TestBenignCheckpointLocalFieldsRefusedWhenDisabled(t *testing.T) {
	base := TargetConfig{Context: "kind-amtd-test", Namespace: "phorvex-harness", OwnedAck: true, TrialsPerArm: 1, CredentialObservationWindowSeconds: 90, BenignCheckpointStorageClass: "ordinary-provisioner"}
	if err := base.Validate(); err != nil {
		t.Fatalf("default provisioned checkpoint config changed: %v", err)
	}
	for name, mutate := range map[string]func(*TargetConfig){
		"node selector": func(c *TargetConfig) {
			c.BenignCheckpointNodeSelector = map[string]string{"kubernetes.io/hostname": "reviewed-node"}
		},
		"holder uid": func(c *TargetConfig) { c.BenignCheckpointLocalHolderUID = "11111111-2222-4333-8444-555555555555" },
		"node uid":   func(c *TargetConfig) { c.BenignCheckpointLocalNodeUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" },
		"nonce":      func(c *TargetConfig) { c.BenignCheckpointLocalNonce = "checkpoint-local-r1" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("disabled local checkpoint accepted partial local identity")
			}
		})
	}
}

func TestNATSJetStreamFixtureRequiresExactIsolatedAuthority(t *testing.T) {
	valid := TargetConfig{Context: "kind-amtd-test", Namespace: "sandbox", OwnedAck: true, TrialsPerArm: 1, CredentialObservationWindowSeconds: 90, ScenarioFilter: []string{"c2-nats-jetstream-durability"}, DefenderFilter: []string{"d-nomtd"}, NATSJetStreamFixture: &NATSJetStreamFixtureConfig{Mode: "member-restart", StorageClass: "nats-local", StorageClassUID: "99999999-9999-4999-8999-999999999999", NodeName: "reviewed-node", NodeUID: "11111111-2222-4333-8444-555555555555", HolderName: "nats-local-holder", HolderUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Nonce: "post25-nats-local-r1", PVs: []NATSJetStreamLocalPV{{Name: "nats-pv-0", UID: "00000000-0000-4000-8000-000000000001", Slot: 0, PathSHA256: strings.Repeat("a", 64)}, {Name: "nats-pv-1", UID: "00000000-0000-4000-8000-000000000002", Slot: 1, PathSHA256: strings.Repeat("b", 64)}, {Name: "nats-pv-2", UID: "00000000-0000-4000-8000-000000000003", Slot: 2, PathSHA256: strings.Repeat("c", 64)}}}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TargetConfig){
		"multiple trials": func(c *TargetConfig) { c.TrialsPerArm = 2 },
		"installed mode":  func(c *TargetConfig) { c.NATSJetStreamFixture.Mode = "installed-dispatch" },
		"wrong scenario":  func(c *TargetConfig) { c.ScenarioFilter[0] = "c2-stateful-training" },
		"wrong defender":  func(c *TargetConfig) { c.DefenderFilter[0] = "d-phorvex" },
		"bad sc uid":      func(c *TargetConfig) { c.NATSJetStreamFixture.StorageClassUID = "storage-class" },
		"bad node uid":    func(c *TargetConfig) { c.NATSJetStreamFixture.NodeUID = "node" },
		"duplicate slot":  func(c *TargetConfig) { c.NATSJetStreamFixture.PVs[2].Slot = 1 },
		"bad path hash":   func(c *TargetConfig) { c.NATSJetStreamFixture.PVs[0].PathSHA256 = "abc" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			fixture := *valid.NATSJetStreamFixture
			fixture.PVs = append([]NATSJetStreamLocalPV(nil), valid.NATSJetStreamFixture.PVs...)
			candidate.NATSJetStreamFixture = &fixture
			candidate.ScenarioFilter = append([]string(nil), valid.ScenarioFilter...)
			candidate.DefenderFilter = append([]string(nil), valid.DefenderFilter...)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid NATS fixture authority accepted")
			}
		})
	}
}
