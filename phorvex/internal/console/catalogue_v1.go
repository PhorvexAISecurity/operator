package console

import (
	"os"
	"strings"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

const (
	limitedV1GuardrailID            = "limited-v1-vllm-guardrail-effect"
	limitedV1GPUName                = "limited-v1-vllm-request-drain"
	limitedV1GuardrailCalibrationID = "limited-v1-vllm-guardrail-calibration"
)

func boolPtr(value bool) *bool { return &value }

func (c Config) limitedV1Catalogue() []CatalogItem {
	functional := func(id cataloguev1.ProfileID, name, product, category, limits string, prereqs []string, available bool, reason string) CatalogItem {
		return CatalogItem{EntryID: string(id), Name: name, Product: product, Category: category,
			R6Tag: "not-applicable", Techniques: []string{}, ExercisedTechniques: []string{}, Caps: []string{},
			Realism: "executable-mechanism", BenignControl: boolPtr(true), ExpectedActuators: []string{},
			ResponseGuidanceBasis: "none", ResponseGuidance: "Benign functional control; no actuator response or security outcome is asserted.",
			MeaningfulWhen: limits, RunnableNote: reason, Prereqs: prereqs,
			LaunchKind: "fixed-suite", ClaimClass: "functional", Profile: string(id),
			Available: available, UnavailableReason: reason, RuntimeContext: c.catalogueV1RuntimeContext(id)}
	}
	enabledReason := "limited-v1 fixed suites are disabled by deployment configuration"
	voiceReady := c.CatalogueV1.Enabled && c.CatalogueV1.VoiceEnabled && c.CatalogueV1.VoiceNamespace != "" &&
		c.CatalogueV1.VoiceDeployment != "" && c.CatalogueV1.VoiceService != "" && c.CatalogueV1.VoiceContainer != "" &&
		c.CatalogueV1.VoiceServicePort > 0 && c.CatalogueV1.VoicePDB != "" && c.CatalogueV1.TranscriptSelector != "" &&
		c.CatalogueV1.TranscriptContainer != ""
	voiceReason := enabledReason
	if c.CatalogueV1.Enabled && !voiceReady {
		voiceReason = "installed Voice profile names and port are not configured"
	}
	if voiceReady {
		voiceReason = "installed Voice runtime is configured; launch performs fresh identity and readiness checks"
	}
	authReady := c.CatalogueV1.Enabled && validPrivateRegular(c.CatalogueV1.ScopedTokenFile) && strings.HasPrefix(c.CatalogueV1.LoopbackURL, "http://127.0.0.1:") &&
		c.CatalogueV1.AllowedTenant != "" && c.CatalogueV1.DeniedTenant != "" && c.CatalogueV1.DeniedTarget != "" &&
		c.CatalogueV1.ExpectedSubject != "" && validPrivateRegular(c.CatalogueV1.GrantFile)
	authReason := enabledReason
	if c.CatalogueV1.Enabled && !authReady {
		authReason = "fixed loopback URL or private projected scoped bearer token is unavailable"
	}
	if authReady {
		authReason = "fixed loopback and projected scoped identity are configured"
	}
	gpuReady := c.CatalogueV1.Enabled && c.CatalogueV1.GPUEnabled && c.CatalogueV1.GPUFixtureNamespace != "" &&
		validPrivateRegular(c.CatalogueV1.GPUFixtureConfig) && validPrivateRegular(c.CatalogueV1.GPUKubeconfigPath) &&
		c.CatalogueV1.GPUKubeContext != "" && validExecutableRegular(c.HarnessBin)
	gpuReason := enabledReason
	if c.CatalogueV1.Enabled && !gpuReady {
		gpuReason = "dedicated reviewed GPU fixture authority is not configured"
	}
	if gpuReady {
		gpuReason = "dedicated GPU fixture authority is configured; launch revalidates every identity"
	}
	guardrailRuntime := cataloguev1.GuardrailCalibrationRuntime{Enabled: c.CatalogueV1.GuardrailCalibrationEnabled,
		Namespace: c.CatalogueV1.GuardrailNamespace, Service: c.CatalogueV1.GuardrailService,
		Port: c.CatalogueV1.GuardrailPort, Container: c.CatalogueV1.GuardrailContainer,
		SourceConfigMap: c.CatalogueV1.GuardrailSourceConfigMap, SourceKey: c.CatalogueV1.GuardrailSourceKey,
		ExpectedSourceSHA256: c.CatalogueV1.GuardrailSourceSHA256}
	guardrailReady := c.CatalogueV1.Enabled && cataloguev1.ValidateGuardrailCalibrationRuntime(guardrailRuntime) == nil
	guardrailReason := "installed guardrail calibration route and source are not configured"
	if guardrailReady {
		guardrailReason = "configured only; launch rechecks route, permissions, source and runtime before two fixed classifier reads"
	}
	mcpRuntime := cataloguev1.MCPSessionRuntime{Enabled: c.CatalogueV1.MCPEnabled,
		Namespace: c.CatalogueV1.MCPNamespace, Deployment: c.CatalogueV1.MCPDeployment,
		Service: c.CatalogueV1.MCPService, Container: c.CatalogueV1.MCPContainer,
		Port: c.CatalogueV1.MCPPort, SourceConfigMap: c.CatalogueV1.MCPSourceConfigMap,
		SourceKey: c.CatalogueV1.MCPSourceKey, ExpectedImageID: c.CatalogueV1.MCPImageID,
		ExpectedSourceSHA256: c.CatalogueV1.MCPSourceSHA256}
	mcpReady := c.CatalogueV1.Enabled && cataloguev1.ValidateMCPSessionRuntime(mcpRuntime) == nil
	mcpReason := "installed MCP profile source, image and fixed route are not configured"
	if mcpReady {
		mcpReason = "configured only; launch checks current installed Pod, mounted source and protocol"
	}
	return []CatalogItem{
		functional(cataloguev1.MCPSessionBaseline, "catalogue-mcp-session-baseline", "application", "Functional", "One synthetic MCP tool read and exact in-memory session invalidation with mounted-file/package hash pins; already-loaded Python bytes, business mutation, provider, authorization, brain, actuator and security efficacy are not attested.", []string{"reviewed installed MCP source and image", "fixed Pod proxy authority", "exact session cleanup"}, mcpReady, mcpReason),
		functional(cataloguev1.VoiceMedia, "limited-v1-voice-media", "application", "Functional", "Ordinary installed Pipecat media only; no phone-call, semantic, brain or security claim.", []string{"installed Voice service", "three Ready endpoints", "exact transcript cleanup"}, voiceReady, voiceReason),
		functional(cataloguev1.VoiceRecovery, "limited-v1-voice-recovery", "application", "Functional", "One PDB-honoring exact-UID eviction and fresh-session recovery; no seamless-session or security claim.", []string{"installed Voice service", "PDB minAvailable=2", "one eviction permission"}, voiceReady, voiceReason),
		functional(cataloguev1.GPUDrain, limitedV1GPUName, "ai", "Functional", "Owned ordinary-GPU drain/reopen/recovery fixture only; no installed-brain or security claim.", []string{"dedicated reviewed GPU fixture", "private operation bearer", "ordinary GPU"}, gpuReady, gpuReason),
		functional(cataloguev1.AuthUnauth, "limited-v1-console-unauthenticated", "platform", "Boundary", "Installed API authentication boundary only; no application attack, brain or actuator claim.", []string{"fixed loopback origin", "projected scoped test identity"}, authReady, authReason),
		functional(cataloguev1.AuthScope, "limited-v1-console-scoped-authorization", "platform", "Boundary", "Installed API tenant/target authorization boundary only; no application attack, brain or actuator claim.", []string{"fixed loopback origin", "projected scoped test identity", "fixed allowed and denied scopes"}, authReady, authReason),
		{EntryID: limitedV1GuardrailCalibrationID, Name: limitedV1GuardrailCalibrationID, Product: "ai", Category: "Benign calibration", R6Tag: "not-applicable",
			Techniques: []string{}, ExercisedTechniques: []string{}, Caps: []string{}, Realism: "executable-mechanism", BenignControl: boolPtr(true),
			ExpectedActuators: []string{}, ResponseGuidanceBasis: "none",
			ResponseGuidance: "Two fixed benign texts are sent to the reviewed non-forwarding classifier endpoint/source contract. The loaded process, forwarding behavior, guarded serving, injected response and security efficacy are not attested.",
			MeaningfulWhen:   "Shows per-variant benign false positives at the installed threshold, with source and runtime pins; no guarded serving or mitigation claim.",
			RunnableNote:     guardrailReason, Prereqs: []string{"explicit installed guardrail route and source configuration", "read-only Pod, Service, EndpointSlice and ConfigMap access", "fixed Pod proxy state and classify access"},
			LaunchKind: "fixed-suite", ClaimClass: "calibration", Profile: string(cataloguev1.GuardrailCalibration),
			Available: guardrailReady, UnavailableReason: guardrailReason, RuntimeContext: c.catalogueV1RuntimeContext(cataloguev1.GuardrailCalibration)},
		{EntryID: limitedV1GuardrailID, Name: limitedV1GuardrailID, Product: "ai", Category: "Effect observation", R6Tag: "not-applicable",
			Techniques: []string{}, ExercisedTechniques: []string{}, Caps: []string{}, Realism: "executable-mechanism", BenignControl: boolPtr(true),
			ExpectedActuators: []string{"guardrail-rotate"}, ResponseGuidanceBasis: "explicit-effect",
			ResponseGuidance: "guardrail-rotate names the operation observed for an exact-target runtime variant effect. A variant change does not establish behavioral bypass or mitigation.",
			MeaningfulWhen:   "Observes an exact-target runtime variant transition; behavioral bypass and mitigation are not measured.",
			RunnableNote:     "Uses the existing installed vLLM guardrail-effect handler and exact-ID result polling.", Prereqs: []string{"installed vLLM guardrail sidecar", "eligible guardrail-rotate policy"},
			LaunchKind: "live-vllm-effect", ClaimClass: "effect", Profile: "guardrail-rotate", Available: true, RuntimeContext: "in-cluster"},
	}
}

func (c Config) catalogueV1RuntimeContext(profile cataloguev1.ProfileID) string {
	if profile == cataloguev1.GPUDrain {
		if value := strings.TrimSpace(c.CatalogueV1.GPUKubeContext); value != "" {
			return value
		}
	}
	if profile == cataloguev1.VoiceMedia || profile == cataloguev1.VoiceRecovery || profile == cataloguev1.GuardrailCalibration || profile == cataloguev1.MCPSessionBaseline {
		if value := strings.TrimSpace(c.CatalogueV1.KubeContext); value != "" {
			return value
		}
	}
	if profile == cataloguev1.AuthUnauth || profile == cataloguev1.AuthScope {
		return "in-cluster"
	}
	if value := strings.TrimSpace(c.CatalogueV1.KubeContext); value != "" {
		return value
	}
	return "in-cluster"
}

func validPrivateRegular(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o007 == 0
}

func validExecutableRegular(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}
