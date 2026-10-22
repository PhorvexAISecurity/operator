// Package actuatorconfig holds the command-line configuration of the actuator's
// backends: serving control security, adapter reload sources, MIG profiles and
// the trusted MIG node agent, the Voice controls, and the retained-quarantine
// bound. The manager, when it acts in process, and the actuator service register
// the same flags and apply them the same way (ADR-0001).
package actuatorconfig

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/cmd/internal/trustconfig"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/startupauthz"
	"github.com/phorvex/phorvex/internal/voicemcppolicy"
)

// Flags is the backends' configuration.
type Flags struct {
	LoRACleanSourcesFile   string
	MIGProfilesFile        string
	ServingSecurityFile    string
	ServingSecurityMode    string
	VoiceMCPApprovedImage  string
	MaxRetainedQuarantines int
	MIG                    MIGNodeExec
}

// MIGNodeExec configures the trusted MIG node-agent transport.
type MIGNodeExec struct {
	Enabled               bool
	Namespace             string
	ServiceAccounts       string
	DaemonSet             string
	GPUContainer          string
	HelperContainer       string
	AllocationHelper      string
	AllocationSocket      string
	ExecTimeout           time.Duration
	AllocationReadTimeout time.Duration
	ReleaseTimeout        time.Duration
	ExclusiveMaintenance  bool
}

// Register defines the flags on fs.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.LoRACleanSourcesFile, "lora-clean-sources-file", "", "Operator-owned JSON mapping exact namespace and adapter identities to serving-local reload paths. Empty disables reload.")
	fs.StringVar(&f.MIGProfilesFile, "mig-profiles-file", "", "Operator-owned JSON mapping exact namespace and MIG resource classes to approved profiles. Empty disables mig-rebind.")
	fs.StringVar(&f.ServingSecurityFile, "serving-security-file", "", "Operator-owned versioned exact policy/workload binding configuration for serving TLS credentials.")
	fs.StringVar(&f.ServingSecurityMode, "serving-security-mode", string(actuator.ServingSecuritySecureRequired), "Serving control mode: secure-required (default) or explicit legacy-plaintext migration compatibility.")
	fs.StringVar(&f.VoiceMCPApprovedImage, "voice-mcp-approved-image", os.Getenv("PHORVEX_VOICE_MCP_APPROVED_IMAGE"), "Reviewed immutable MCP repo@sha256 required for Voice MCP pinning; empty disables that action.")
	fs.IntVar(&f.MaxRetainedQuarantines, "max-retained-quarantines-per-namespace", 1, fmt.Sprintf("Hard namespace-wide bound on retained or pending Phorvex quarantines (0 disables new quarantine, maximum %d).", actuator.MaxRetainedQuarantinesUpperBound))
	m := &f.MIG
	fs.BoolVar(&m.Enabled, "mig-node-exec", false, "Enable the explicitly configured trusted MIG node-agent transport.")
	fs.StringVar(&m.Namespace, "mig-agent-namespace", "", "Exact namespace of the trusted MIG node-agent DaemonSet.")
	fs.StringVar(&m.ServiceAccounts, "mig-agent-service-accounts", "", "Comma-separated exact ServiceAccount allowlist for the trusted MIG node agent.")
	fs.StringVar(&m.DaemonSet, "mig-agent-daemonset", "", "Exact trusted MIG node-agent DaemonSet name.")
	fs.StringVar(&m.GPUContainer, "mig-agent-gpu-container", "", "Exact GPU tooling container name in the trusted agent.")
	fs.StringVar(&m.HelperContainer, "mig-agent-helper-container", "", "Exact PodResources helper container name in the trusted agent.")
	fs.StringVar(&m.AllocationHelper, "mig-allocation-helper", "/phorvex-mig-allocation-helper", "Fixed absolute helper path inside the trusted helper container.")
	fs.StringVar(&m.AllocationSocket, "mig-allocation-socket", "/var/lib/kubelet/pod-resources/kubelet.sock", "Fixed kubelet PodResources Unix socket path inside the trusted helper container.")
	fs.DurationVar(&m.ExecTimeout, "mig-agent-exec-timeout", 5*time.Second, "Deadline for each trusted-agent read or GPU command.")
	fs.DurationVar(&m.AllocationReadTimeout, "mig-allocation-read-timeout", 3*time.Second, "Deadline for each kubelet PodResources helper request (maximum 30s).")
	fs.DurationVar(&m.ReleaseTimeout, "mig-allocation-release-timeout", 45*time.Second, "Deadline to observe target PodResources allocation release after UID-bound deletion.")
	fs.BoolVar(&m.ExclusiveMaintenance, "mig-exclusive-maintenance", false, "Declare that MIG repartition runs only under an externally controlled exclusive-maintenance scheduling contract.")
}

// ValidateImage checks the reviewed Voice MCP image reference, which the
// manager refuses before anything else.
func (f Flags) ValidateImage() error {
	if f.VoiceMCPApprovedImage != "" && !voicemcppolicy.ValidApprovedImage(f.VoiceMCPApprovedImage) {
		return fmt.Errorf("invalid reviewed MCP image reference")
	}
	return nil
}

// ValidateBound checks the retained-quarantine bound.
func (f Flags) ValidateBound() error {
	if f.MaxRetainedQuarantines < 0 || f.MaxRetainedQuarantines > actuator.MaxRetainedQuarantinesUpperBound {
		return fmt.Errorf("max-retained-quarantines-per-namespace must be in [0,%d], got %d", actuator.MaxRetainedQuarantinesUpperBound, f.MaxRetainedQuarantines)
	}
	return nil
}

// Settings is the validated configuration, its operator-owned files read.
type Settings struct {
	AdapterSources  actuator.AdapterSources
	MIGProfiles     *actuator.MIGProfiles
	SecurityMode    actuator.ServingSecurityMode
	ServingSecurity *actuator.ServingSecurityConfig
	VoiceMCPImage   string
}

// Load reads the operator-owned files. The serving security bindings are bound
// to operatorNamespace.
func (f Flags) Load(operatorNamespace string) (Settings, error) {
	var s Settings
	var err error
	if s.AdapterSources, err = actuator.LoadAdapterSourcesFile(f.LoRACleanSourcesFile); err != nil {
		return s, fmt.Errorf("invalid adapter reload source configuration: %w", err)
	}
	if s.MIGProfiles, err = actuator.LoadMIGProfilesFile(f.MIGProfilesFile); err != nil {
		return s, fmt.Errorf("invalid MIG profile authority configuration: %w", err)
	}
	if s.SecurityMode, err = actuator.ParseServingSecurityMode(f.ServingSecurityMode); err != nil {
		return s, fmt.Errorf("invalid serving security mode: %w", err)
	}
	if s.ServingSecurity, err = actuator.LoadServingSecurityFile(f.ServingSecurityFile, s.SecurityMode, operatorNamespace); err != nil {
		return s, fmt.Errorf("invalid serving security configuration: %w", err)
	}
	s.VoiceMCPImage = f.VoiceMCPApprovedImage
	return s, nil
}

// VoiceAdmissionEnabled reads the PHORVEX_VOICE_ADMISSION_ENABLED feature flag:
// unset or "false" disables Voice admission enforcement, "true" enables it.
func VoiceAdmissionEnabled() (bool, error) {
	switch mode := os.Getenv("PHORVEX_VOICE_ADMISSION_ENABLED"); mode {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, fmt.Errorf("invalid PHORVEX_VOICE_ADMISSION_ENABLED")
}

// Configure applies s, the Voice admission flag and the endpoint lease authority
// to a backend built by actuator.New. boundary is the uncached reader the native
// journals read through, in operatorNamespace. A Phoenix backend has none of
// these controls.
func (s Settings) Configure(act actuator.Actuator, boundary client.Reader, operatorNamespace string, voiceAdmission bool, trust trustconfig.Trust) {
	if native, ok := act.(*actuator.NativeActuator); ok {
		native.SetBoundaryReader(boundary)
		native.JournalNamespace = operatorNamespace
		native.SetAdapterSources(s.AdapterSources)
		native.SetMIGProfiles(s.MIGProfiles)
		native.SetServingSecurity(s.ServingSecurity)
		native.VoiceMCPApprovedImage = s.VoiceMCPImage
		native.VoiceAdmissionEnabled = voiceAdmission
		native.SetEndpointLeaseApprovedSourceSHA256(trust.EndpointLeaseApprovedSource)
		native.SetEndpointLeaseApprovedProxyImage(trust.EndpointLeaseApprovedProxyImage)
		native.SetEndpointLeaseApprovedEngineImage(trust.EndpointLeaseApprovedEngineImage)
	}
	if hybrid, ok := act.(*actuator.HybridActuator); ok {
		hybrid.ConfigureNativeJournal(boundary, operatorNamespace)
		hybrid.SetAdapterSources(s.AdapterSources)
		hybrid.SetMIGProfiles(s.MIGProfiles)
		hybrid.SetServingSecurity(s.ServingSecurity)
		hybrid.SetVoiceMCPApprovedImage(s.VoiceMCPImage)
		hybrid.SetVoiceAdmissionEnabled(voiceAdmission)
		hybrid.SetEndpointLeaseApprovedSourceSHA256(trust.EndpointLeaseApprovedSource)
		hybrid.SetEndpointLeaseApprovedProxyImage(trust.EndpointLeaseApprovedProxyImage)
		hybrid.SetEndpointLeaseApprovedEngineImage(trust.EndpointLeaseApprovedEngineImage)
	}
}

// Shared is the configuration the manager and a separate actuator must share,
// which the actuator's handshake compares. Both binaries derive it here.
func Shared(operatorNamespace string, trust trustconfig.Trust, policyNamespaces []string) actuatorapi.Config {
	return actuatorapi.Config{
		OperatorNamespace:                operatorNamespace,
		PolicyNamespaces:                 policyNamespaces,
		TrustedDetectors:                 trust.Detectors().List(),
		EndpointLeaseApprovedSource:      trust.EndpointLeaseApprovedSource,
		EndpointLeaseApprovedProxyImage:  trust.EndpointLeaseApprovedProxyImage,
		EndpointLeaseApprovedEngineImage: trust.EndpointLeaseApprovedEngineImage,
		InjectorIdentity:                 trust.Injector(),
	}
}

// Preflight is the startup authorization the backend's identity must hold, for the
// policies in scope (every namespace when policyNamespaces is empty).
func (f Flags) Preflight(s Settings, backend actuator.Backend, operatorNamespace string, policyNamespaces []string) startupauthz.Config {
	cfg := startupauthz.Config{Backend: backend, OperatorNamespace: operatorNamespace, ServingSecurity: s.ServingSecurity, PolicyNamespaces: policyNamespaces}
	if f.MIG.Enabled {
		cfg.MIGAgent = &startupauthz.MIGAgentAccess{Namespace: f.MIG.Namespace, DaemonSet: f.MIG.DaemonSet}
	}
	return cfg
}

// Wire wires the trusted MIG node-agent transport when it is enabled.
func (m MIGNodeExec) Wire(restConfig *rest.Config, cs kubernetes.Interface) error {
	if !m.Enabled {
		return nil
	}
	return actuator.WireRemoteNodeExec(actuator.RemoteExecConfig{Config: restConfig, Clientset: cs, Agent: actuator.MIGAgentPolicy{
		Namespace: m.Namespace, ServiceAccounts: strings.Split(m.ServiceAccounts, ","), DaemonSet: m.DaemonSet,
		Container: m.GPUContainer, AllocationContainer: m.HelperContainer,
		AllocationHelper: m.AllocationHelper, AllocationSocket: m.AllocationSocket,
		ExecTimeout: m.ExecTimeout, AllocationReadTimeout: m.AllocationReadTimeout, AllocationReleaseTimeout: m.ReleaseTimeout, ExclusiveMaintenance: m.ExclusiveMaintenance,
	}})
}
