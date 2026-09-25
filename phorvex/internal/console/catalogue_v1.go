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
	crmRuntime := cataloguev1.CRMCapabilityRuntime{Enabled: c.CatalogueV1.CRMEnabled, ServiceAccountName: c.CatalogueV1.CRMServiceAccountName,
		Namespace: c.CatalogueV1.CRMNamespace, NamespaceUID: c.CatalogueV1.CRMNamespaceUID,
		ManifestFile: c.CatalogueV1.CRMManifestFile, ManifestSHA256: c.CatalogueV1.CRMManifestSHA256,
		HarnessBinary: c.HarnessBin, HarnessSHA256: c.CatalogueV1.CRMHarnessSHA256, HarnessDir: c.HarnessDir,
		KubeconfigPath: c.CatalogueV1.CRMKubeconfigPath, KubeconfigSHA256: c.CatalogueV1.CRMKubeconfigSHA256, KubeContext: c.CatalogueV1.CRMKubeContext}
	crmReady := c.CatalogueV1.Enabled && cataloguev1.ValidateCRMLocalAuthority(crmRuntime) == nil
	crmReason := "approved immutable CRM fixture manifest and scoped runtime are not configured"
	if crmReady {
		crmReason = "configured; current namespace identity and launch admission are checked on open"
	}
	mcpReason := "installed MCP profile source, image and fixed route are not configured"
	if mcpReady {
		mcpReason = "configured only; launch checks current installed Pod, mounted source and protocol"
	}
	chromaRuntime := cataloguev1.ChromaRuntime{Enabled: c.CatalogueV1.ChromaEnabled,
		Namespace: c.CatalogueV1.ChromaNamespace, Deployment: c.CatalogueV1.ChromaDeployment,
		Service: c.CatalogueV1.ChromaService, Container: c.CatalogueV1.ChromaContainer,
		Port: c.CatalogueV1.ChromaPort, ExpectedImageID: c.CatalogueV1.ChromaImageID,
		ExpectedVersionSourceSHA256: c.CatalogueV1.ChromaVersionSourceSHA256,
		ExpectedServerSourceSHA256:  c.CatalogueV1.ChromaServerSourceSHA256,
		ExpectedSchemaSourceSHA256:  c.CatalogueV1.ChromaSchemaSourceSHA256}
	chromaReady := c.CatalogueV1.Enabled && cataloguev1.ValidateChromaRuntime(chromaRuntime) == nil
	chromaReason := "installed Chroma image, source and route are not configured"
	if chromaReady {
		chromaReason = "configured only; launch checks exact ownership, route, source and synthetic state"
	}
	liteLLMRuntime := cataloguev1.LiteLLMRuntime{Enabled: c.CatalogueV1.LiteLLMEnabled,
		Namespace: c.CatalogueV1.LiteLLMNamespace, Deployment: c.CatalogueV1.LiteLLMDeployment,
		Service: c.CatalogueV1.LiteLLMService, Container: c.CatalogueV1.LiteLLMContainer,
		Port: c.CatalogueV1.LiteLLMPort, ConfigMap: c.CatalogueV1.LiteLLMConfigMap,
		ConfigKey: c.CatalogueV1.LiteLLMConfigKey, ExpectedConfigSHA256: c.CatalogueV1.LiteLLMConfigSHA256,
		InferenceEnabled: c.CatalogueV1.LiteLLMInferenceEnabled, ModelAlias: c.CatalogueV1.LiteLLMModelAlias}
	liteLLMReady := c.CatalogueV1.Enabled && cataloguev1.ValidateLiteLLMRuntime(liteLLMRuntime) == nil
	liteLLMReason := "installed LiteLLM config and fixed route are not configured"
	if liteLLMReady {
		liteLLMReason = "configured only; launch checks each exact serving Pod and per-request outcome"
	}
	chromaItem := functional(cataloguev1.ChromaOwnedVector, string(cataloguev1.ChromaOwnedVector), "application", "Functional", "One fresh nonce-owned Chroma collection and synthetic vector; direct service control only. No SecurityEvent or defense efficacy. Brain and actuator evidence: NOT_EVALUATED.", []string{"reviewed installed Chroma 0.5.23 image and source", "fixed Pod route", "exact owned collection cleanup"}, chromaReady, chromaReason)
	chromaItem.EventMode = "none; direct protocol control"
	chromaItem.ResponseGuidance = "Direct Chroma state control; no SecurityEvent or actuator is expected. Brain and actuator evidence: NOT_EVALUATED."
	liteHealthItem := functional(cataloguev1.LiteLLMHealth, string(cataloguev1.LiteLLMHealth), "ai", "Functional", "GET /health/liveliness on every exact serving Pod. A 200 response establishes listener health only; authenticated model serving, brain and actuator evidence: NOT_EVALUATED.", []string{"reviewed installed LiteLLM config", "fixed Pod routes", "per-Pod identity and response"}, liteLLMReady, liteLLMReason)
	liteHealthItem.EventMode = "none; direct protocol control"
	liteHealthItem.ResponseGuidance = "Direct health read; no SecurityEvent or actuator is expected. Brain and actuator evidence: NOT_EVALUATED."
	liteCredentialItem := functional(cataloguev1.LiteLLMCredential, string(cataloguev1.LiteLLMCredential), "ai", "Boundary", "Missing and generated invalid bearer on reviewed GET /v1/models authentication route for every exact Pod. NO_CONNECTED_DB is UNKNOWN authorization, not bypass or verified denial. Brain and actuator evidence: NOT_EVALUATED.", []string{"reviewed installed LiteLLM config", "fixed /v1/models path", "per-Pod identity and response"}, liteLLMReady, liteLLMReason)
	liteCredentialItem.EventMode = "none; direct protocol control"
	liteCredentialItem.ResponseGuidance = "Direct credential configuration boundary; no SecurityEvent or actuator is expected. Brain and actuator evidence: NOT_EVALUATED."
	liteRoutingReady := liteLLMReady && cataloguev1.ValidateLiteLLMInferenceRuntime(liteLLMRuntime) == nil
	liteRoutingReason := "authenticated LiteLLM inference is disabled or its reviewed model alias is unavailable"
	if liteRoutingReady {
		liteRoutingReason = "configured only; launch checks the SHA-pinned alias, master-key env reference and each exact Pod before bounded completion requests"
	}
	liteRoutingItem := functional(cataloguev1.LiteLLMRouting, string(cataloguev1.LiteLLMRouting), "ai", "Functional", "One fixed harmless authenticated completion and one nonexistent-model request per exact serving Pod. A valid assistant completion proves serving; only an explicit typed model-not-found error proves rejection. Provider internals and absence of upstream requests are not attested. SecurityEvent, brain, actuator and security efficacy: NOT_EVALUATED.", []string{"separate inference opt-in and reviewed configured alias", "SHA-pinned mounted LiteLLM config and master-key env reference", "each exact serving Pod and bounded sanitized response"}, liteRoutingReady, liteRoutingReason)
	liteRoutingItem.EventMode = "none; direct protocol control"
	liteRoutingItem.ResponseGuidance = "Direct authenticated inference-routing control; no SecurityEvent or actuator is expected. Brain and actuator evidence: NOT_EVALUATED."
	return []CatalogItem{
		chromaItem,
		liteHealthItem,
		liteCredentialItem,
		liteRoutingItem,
		functional(cataloguev1.MCPSessionBaseline, "catalogue-mcp-session-baseline", "application", "Functional", "One synthetic MCP tool read and exact in-memory session invalidation with mounted-file/package hash pins; already-loaded Python bytes, business mutation, provider, authorization, brain, actuator and security efficacy are not attested.", []string{"reviewed installed MCP source and image", "fixed Pod proxy authority", "exact session cleanup"}, mcpReady, mcpReason),
		functional(cataloguev1.CRMRefund, "c2-crm-refund-capability", "application", "Functional", "DIRECT functional capability: synthetic A refund and cross-record B refund in one disposable Mongo; A/B are record labels, not principals; no phone/provider, customer write, auth-bypass, brain or security efficacy claim.", []string{"approved digest-pinned CRM/Mongo images and dependency closure", "dedicated UID-pinned fixture namespace", "exact Pod and ConfigMap cleanup"}, crmReady, crmReason),
		functional(cataloguev1.CRMReset, "c2-crm-reset-capability", "application", "Functional", "DIRECT functional capability: synthetic A reset and cross-record B reset in one disposable Mongo; A/B are record labels, not principals; no phone/provider, customer write, auth-bypass, brain or security efficacy claim.", []string{"approved digest-pinned CRM/Mongo images and dependency closure", "dedicated UID-pinned fixture namespace", "exact Pod and ConfigMap cleanup"}, crmReady, crmReason),
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
	if profile == cataloguev1.VoiceMedia || profile == cataloguev1.VoiceRecovery || profile == cataloguev1.GuardrailCalibration || profile == cataloguev1.MCPSessionBaseline || profile == cataloguev1.ChromaOwnedVector || profile == cataloguev1.LiteLLMHealth || profile == cataloguev1.LiteLLMCredential || profile == cataloguev1.LiteLLMRouting {
		if value := strings.TrimSpace(c.CatalogueV1.KubeContext); value != "" {
			return value
		}
	}
	if profile == cataloguev1.CRMRefund || profile == cataloguev1.CRMReset {
		if value := strings.TrimSpace(c.CatalogueV1.CRMKubeContext); value != "" {
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
