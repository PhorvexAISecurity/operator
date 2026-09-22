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

func TestGPUFunctionalFixtureRequiresExactSingleFunctionalArm(t *testing.T) {
	fixture := &GPUFunctionalFixtureConfig{
		Operation: "request-drain", Mode: "direct",
		NamespaceUID: "00000000-0000-4000-8000-000000000001", RunLabel: "gpu-functional-r1",
		NodeName: "gpu-node", NodeUID: "00000000-0000-4000-8000-000000000002",
		PodName: "vllm-0", PodUID: "00000000-0000-4000-8000-000000000003",
		OwnerKind: "StatefulSet", OwnerName: "vllm", OwnerUID: "00000000-0000-4000-8000-000000000004",
		ServiceName: "vllm", ServiceUID: "00000000-0000-4000-8000-000000000005",
		ContainerName: "vllm", Image: "registry.example/vllm@sha256:" + strings.Repeat("a", 64),
		ImageID: "containerd://sha256:" + strings.Repeat("b", 64), StartedAt: "2026-09-22T01:02:03.123456789Z",
		Port: 8000, Model: "facebook/opt-125m", ModelDigest: "sha256:" + strings.Repeat("c", 64),
		EngineSourceSHA256: strings.Repeat("d", 64), ProxySourceGitSHA: strings.Repeat("e", 40), BearerTokenFile: "/private/gpu-token",
	}
	valid := TargetConfig{Context: "eks", Namespace: "gpu-owned", ExpectedNamespaceUID: fixture.NamespaceUID, OwnedAck: true, TrialsPerArm: 1, ScenarioFilter: []string{"c2-vllm-request-drain"}, DefenderFilter: []string{"d-nomtd"}, GPUFunctionalFixture: fixture}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	actualPlainImageID := valid
	actualPlainFixture := *fixture
	actualPlainFixture.ImageID = "docker.io/vllm/vllm-openai@sha256:" + strings.Repeat("b", 64)
	actualPlainImageID.GPUFunctionalFixture = &actualPlainFixture
	if err := actualPlainImageID.Validate(); err != nil {
		t.Fatalf("actual canonical plain repo imageID rejected: %v", err)
	}
	for name, mutate := range map[string]func(*TargetConfig){
		"wrong scenario":          func(c *TargetConfig) { c.ScenarioFilter[0] = "c2-vllm-prefix-cache-reset" },
		"wrong defender":          func(c *TargetConfig) { c.DefenderFilter[0] = "d-phorvex-installed" },
		"multiple trials":         func(c *TargetConfig) { c.TrialsPerArm = 2 },
		"installed mode":          func(c *TargetConfig) { c.GPUFunctionalFixture.Mode = "installed" },
		"mutable image":           func(c *TargetConfig) { c.GPUFunctionalFixture.Image = "registry.example/vllm:latest" },
		"partial image id":        func(c *TargetConfig) { c.GPUFunctionalFixture.ImageID = "sha256:" + strings.Repeat("b", 64) },
		"partial model digest":    func(c *TargetConfig) { c.GPUFunctionalFixture.ModelDigest = strings.Repeat("c", 64) },
		"relative token":          func(c *TargetConfig) { c.GPUFunctionalFixture.BearerTokenFile = "gpu-token" },
		"wrong port":              func(c *TargetConfig) { c.GPUFunctionalFixture.Port = 8001 },
		"missing namespace pin":   func(c *TargetConfig) { c.ExpectedNamespaceUID = "" },
		"different namespace pin": func(c *TargetConfig) { c.ExpectedNamespaceUID = "99999999-9999-4999-8999-999999999999" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			copyFixture := *fixture
			candidate.GPUFunctionalFixture = &copyFixture
			candidate.ScenarioFilter = append([]string(nil), valid.ScenarioFilter...)
			candidate.DefenderFilter = append([]string(nil), valid.DefenderFilter...)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid GPU functional fixture accepted")
			}
		})
	}
}

func TestInstalledManagerFixtureAcceptsActualTaggedRuntimeAndImmutableImageID(t *testing.T) {
	fixture := &InstalledManagerFixtureConfig{
		ManagerNamespace: "phorvex-system", ManagerServiceAccount: "phorvex-phorvex-manager", FixtureNonce: "installed-r1", AuthorizationDenyNamespace: "installed-r1-unowned", DeploymentName: "phorvex-phorvex", DeploymentUID: "11111111-2222-4333-8444-555555555555",
		ReplicaSetName: "phorvex-phorvex-7699c6dd69", ReplicaSetUID: "22222222-3333-4444-8555-666666666666",
		PodName: "phorvex-phorvex-7699c6dd69-k4j2n", PodUID: "33333333-4444-4555-8666-777777777777", ContainerName: "manager",
		Image:     "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:0.4.144",
		ImageID:   "docker-pullable://753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:" + strings.Repeat("4", 64),
		StartedAt: "2026-09-21T22:35:00Z", RestartCount: 0, OCIRevision: "60aabe2a", ExpectedBrainImage: "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:0.4.144",
		TraceSchema: "phorvex.decision-trace.v6", PolicyCRDUID: "44444444-5555-4666-8777-888888888888", PolicyCRDResourceVersion: "150500",
		ObserverBinary: "/private/installed-audit-observer", ObserverBinarySHA256: strings.Repeat("a", 64), AuditURL: "https://127.0.0.1:18445",
		AuditServerName: "phorvex-stack-phorvex-audit-source.phorvex-system.svc", AuditCAFile: "/private/ca.crt", AuditClientCertFile: "/private/tls.crt", AuditClientKeyFile: "/private/tls.key",
		ParameterManifestID: "phorvex-production-decision-parameters", ParameterManifestHash: "sha256:" + strings.Repeat("b", 64), ObservationTimeoutSeconds: 15, ObservationMaxBytes: 16 << 20, ObservationMaxRows: 512,
	}
	valid := TargetConfig{Context: "eks", Namespace: "owned-fixture", OwnedAck: true, TrialsPerArm: 1, ScenarioFilter: []string{"c2-installed-manager-session"}, DefenderFilter: []string{"d-phorvex-installed"}, InstalledManagerFixture: fixture}
	if err := valid.Validate(); err != nil {
		t.Fatalf("actual tagged manager/imageID shape rejected: %v", err)
	}
	for name, mutate := range map[string]func(*InstalledManagerFixtureConfig){
		"mutable image id": func(f *InstalledManagerFixtureConfig) { f.ImageID = "docker://sha256:latest" },
		"invented digest brain": func(f *InstalledManagerFixtureConfig) {
			f.ExpectedBrainImage = f.Image + "@sha256:" + strings.Repeat("4", 64)
		},
		"wrong trace":                  func(f *InstalledManagerFixtureConfig) { f.TraceSchema = "phorvex.decision-trace.v5" },
		"unbounded observer":           func(f *InstalledManagerFixtureConfig) { f.ObservationTimeoutSeconds = 31 },
		"too-small source budget":      func(f *InstalledManagerFixtureConfig) { f.ObservationMaxBytes = 7_169_228 },
		"unbounded source budget":      func(f *InstalledManagerFixtureConfig) { f.ObservationMaxBytes = 64<<20 + 1 },
		"unbounded source rows":        func(f *InstalledManagerFixtureConfig) { f.ObservationMaxRows = 1025 },
		"same authorization namespace": func(f *InstalledManagerFixtureConfig) { f.AuthorizationDenyNamespace = "owned-fixture" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			copyFixture := *fixture
			candidate.InstalledManagerFixture = &copyFixture
			mutate(&copyFixture)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid installed manager fixture accepted")
			}
		})
	}
}

func TestExpectedNamespaceUIDValidation(t *testing.T) {
	valid := TargetConfig{Context: "kind", Namespace: "sandbox", OwnedAck: true, TrialsPerArm: 1, ExpectedNamespaceUID: "11111111-2222-4333-8444-555555555555"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid expected namespace UID rejected: %v", err)
	}
	valid.ExpectedNamespaceUID = ""
	if err := valid.Validate(); err != nil {
		t.Fatalf("unset expected namespace UID broke compatibility: %v", err)
	}
	for _, bad := range []string{"namespace-uid", "11111111-2222-4333-8444-55555555555A", " 11111111-2222-4333-8444-555555555555"} {
		valid.ExpectedNamespaceUID = bad
		if err := valid.Validate(); err == nil {
			t.Fatalf("invalid expected namespace UID %q accepted", bad)
		}
	}
}
