package actuatorconfig

import (
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/cmd/internal/trustconfig"
	"github.com/phorvex/phorvex/internal/actuator"
)

func parse(t *testing.T, args ...string) Flags {
	t.Helper()
	var f Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Register(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestFlagsKeepTheManagersNamesAndDefaults pins the flags the manager defined
// before they moved here; deployments set them by these names.
func TestFlagsKeepTheManagersNamesAndDefaults(t *testing.T) {
	t.Setenv("PHORVEX_VOICE_MCP_APPROVED_IMAGE", "")
	var f Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Register(fs)
	want := map[string]string{
		"lora-clean-sources-file":                "",
		"mig-profiles-file":                      "",
		"serving-security-file":                  "",
		"serving-security-mode":                  string(actuator.ServingSecuritySecureRequired),
		"voice-mcp-approved-image":               "",
		"max-retained-quarantines-per-namespace": "1",
		"mig-node-exec":                          "false",
		"mig-agent-namespace":                    "",
		"mig-agent-service-accounts":             "",
		"mig-agent-daemonset":                    "",
		"mig-agent-gpu-container":                "",
		"mig-agent-helper-container":             "",
		"mig-allocation-helper":                  "/phorvex-mig-allocation-helper",
		"mig-allocation-socket":                  "/var/lib/kubelet/pod-resources/kubelet.sock",
		"mig-agent-exec-timeout":                 "5s",
		"mig-allocation-read-timeout":            "3s",
		"mig-allocation-release-timeout":         "45s",
		"mig-exclusive-maintenance":              "false",
	}
	got := map[string]string{}
	fs.VisitAll(func(fl *flag.Flag) { got[fl.Name] = fl.DefValue })
	if len(got) != len(want) {
		t.Fatalf("flags = %v, want %v", got, want)
	}
	for name, def := range want {
		if got[name] != def {
			t.Fatalf("--%s default = %q, want %q", name, got[name], def)
		}
	}
}

func TestValidation(t *testing.T) {
	if err := parse(t, "--voice-mcp-approved-image=mcp:latest").ValidateImage(); err == nil {
		t.Fatal("a mutable MCP image reference was accepted")
	}
	if err := parse(t, "--voice-mcp-approved-image=registry.example/mcp@sha256:"+strings.Repeat("a", 64)).ValidateImage(); err != nil {
		t.Fatalf("a digest-pinned MCP image was refused: %v", err)
	}
	for _, bound := range []string{"-1", "129"} {
		if err := parse(t, "--max-retained-quarantines-per-namespace="+bound).ValidateBound(); err == nil {
			t.Fatalf("bound %s accepted", bound)
		}
	}
	for _, bound := range []string{"0", "128"} {
		if err := parse(t, "--max-retained-quarantines-per-namespace="+bound).ValidateBound(); err != nil {
			t.Fatalf("bound %s refused: %v", bound, err)
		}
	}
	if _, err := parse(t, "--serving-security-mode=plaintext-please").Load("phorvex-system"); err == nil || !strings.Contains(err.Error(), "serving security mode") {
		t.Fatalf("an unknown serving security mode was accepted: %v", err)
	}
	if _, err := parse(t, "--mig-profiles-file=/nonexistent/profiles.json").Load("phorvex-system"); err == nil || !strings.Contains(err.Error(), "MIG profile") {
		t.Fatalf("an unreadable MIG profile file was accepted: %v", err)
	}
	settings, err := parse(t).Load("phorvex-system")
	if err != nil || settings.SecurityMode != actuator.ServingSecuritySecureRequired {
		t.Fatalf("defaults = %+v, %v", settings, err)
	}
}

func TestVoiceAdmissionFeatureFlag(t *testing.T) {
	for value, want := range map[string]bool{"": false, "false": false, "true": true} {
		t.Setenv("PHORVEX_VOICE_ADMISSION_ENABLED", value)
		if got, err := VoiceAdmissionEnabled(); err != nil || got != want {
			t.Fatalf("%q = %v, %v", value, got, err)
		}
	}
	t.Setenv("PHORVEX_VOICE_ADMISSION_ENABLED", "yes")
	if _, err := VoiceAdmissionEnabled(); err == nil {
		t.Fatal("an invalid Voice admission flag was accepted")
	}
}

func TestConfigureAppliesTheSettingsToTheNativeBackend(t *testing.T) {
	image := "registry.example/mcp@sha256:" + strings.Repeat("b", 64)
	settings, err := parse(t, "--voice-mcp-approved-image="+image).Load("phorvex-system")
	if err != nil {
		t.Fatal(err)
	}
	native := actuator.NewNativeActuator(nil)
	settings.Configure(native, nil, "phorvex-system", true, trustconfig.Trust{})
	if native.JournalNamespace != "phorvex-system" || native.VoiceMCPApprovedImage != image || !native.VoiceAdmissionEnabled {
		t.Fatalf("native backend not configured: journal=%q image=%q admission=%v", native.JournalNamespace, native.VoiceMCPApprovedImage, native.VoiceAdmissionEnabled)
	}
	settings.Configure(actuator.NewPhoenixActuator(nil), nil, "phorvex-system", true, trustconfig.Trust{}) // has none of these controls
}

func TestPreflightNamesTheMIGAgentOnlyWhenEnabled(t *testing.T) {
	f := parse(t, "--mig-agent-namespace=gpu", "--mig-agent-daemonset=agent")
	if cfg := f.Preflight(Settings{}, actuator.BackendNative, "phorvex-system", nil); cfg.MIGAgent != nil || cfg.OperatorNamespace != "phorvex-system" {
		t.Fatalf("disabled node exec still checked: %+v", cfg)
	}
	f.MIG.Enabled = true
	if cfg := f.Preflight(Settings{}, actuator.BackendNative, "phorvex-system", nil); cfg.MIGAgent == nil || cfg.MIGAgent.Namespace != "gpu" || cfg.MIGAgent.DaemonSet != "agent" {
		t.Fatalf("enabled node exec not checked: %+v", cfg)
	}
	if err := (MIGNodeExec{}).Wire(nil, nil); err != nil {
		t.Fatalf("disabled node exec wired: %v", err)
	}
	if f.MIG.ExecTimeout != 5*time.Second {
		t.Fatalf("exec timeout = %s", f.MIG.ExecTimeout)
	}
}

func TestSharedConfigurationIsOneDerivation(t *testing.T) {
	a := Shared("phorvex-system", trustconfig.Trust{TrustedDetectors: "vllm/b, vllm/a,,vllm/a", EndpointLeaseApprovedSource: "src"}, nil)
	b := Shared("phorvex-system", trustconfig.Trust{TrustedDetectors: "vllm/a,vllm/b", EndpointLeaseApprovedSource: "src"}, nil)
	if a.SHA256() != b.SHA256() {
		t.Fatalf("the same trust describes differently: %+v vs %+v", a, b)
	}
	if Shared("other", trustconfig.Trust{TrustedDetectors: "vllm/a,vllm/b", EndpointLeaseApprovedSource: "src"}, nil).SHA256() == a.SHA256() {
		t.Fatal("another operator namespace must change the configuration")
	}
}

// The policy scope is part of the handshake: a manager and an actuator scoped
// differently refuse each other, an unscoped one keeps its earlier identity, and
// the namespaces compare as a set.
func TestSharedComparesThePolicyScope(t *testing.T) {
	trust := trustconfig.Trust{TrustedDetectors: "vllm/a"}
	unscoped := Shared("staging", trust, nil)
	if Shared("staging", trust, []string{}).SHA256() != unscoped.SHA256() {
		t.Fatal("an empty scope changed the unscoped identity")
	}
	scoped := Shared("staging", trust, []string{"b", "a"})
	if scoped.SHA256() == unscoped.SHA256() {
		t.Fatal("a scoped actuator matches an unscoped manager")
	}
	if Shared("staging", trust, []string{"a", "b"}).SHA256() != scoped.SHA256() {
		t.Fatal("the scope compares in order")
	}
}

// The injector is part of the handshake once configured; the default keeps the
// identity the actuator had before it was configurable.
func TestSharedComparesTheInjector(t *testing.T) {
	trust := trustconfig.Trust{TrustedDetectors: "vllm/a"}
	defaulted := Shared("staging", trust, nil)
	trust.InjectorIdentity = "phorvex-staging/staging-attacks"
	configured := Shared("staging", trust, nil)
	if configured.InjectorIdentity != "system:serviceaccount:phorvex-staging:staging-attacks" || configured.SHA256() == defaulted.SHA256() {
		t.Fatalf("configured injector = %q, same identity as the default: %v", configured.InjectorIdentity, configured.SHA256() == defaulted.SHA256())
	}
	if defaulted.InjectorIdentity != "" {
		t.Fatalf("default injector described as %q", defaulted.InjectorIdentity)
	}
}
