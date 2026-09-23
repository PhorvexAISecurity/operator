package console

import (
	"os"
	"strings"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

const (
	limitedV1GuardrailID = "limited-v1-vllm-guardrail-effect"
	limitedV1GPUName     = "limited-v1-vllm-request-drain"
)

func boolPtr(value bool) *bool { return &value }

func (c Config) limitedV1Catalogue() []CatalogItem {
	functional := func(id cataloguev1.ProfileID, name, product, category, limits string, prereqs []string, available bool, reason string) CatalogItem {
		return CatalogItem{EntryID: string(id), Name: name, Product: product, Category: category,
			R6Tag: "not-applicable", Techniques: []string{}, ExercisedTechniques: []string{}, Caps: []string{},
			Realism: "executable-mechanism", BenignControl: boolPtr(true), ExpectedActuators: []string{},
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
	return []CatalogItem{
		functional(cataloguev1.VoiceMedia, "limited-v1-voice-media", "application", "Functional", "Ordinary installed Pipecat media only; no phone-call, semantic, brain or security claim.", []string{"installed Voice service", "three Ready endpoints", "exact transcript cleanup"}, voiceReady, voiceReason),
		functional(cataloguev1.VoiceRecovery, "limited-v1-voice-recovery", "application", "Functional", "One PDB-honoring exact-UID eviction and fresh-session recovery; no seamless-session or security claim.", []string{"installed Voice service", "PDB minAvailable=2", "one eviction permission"}, voiceReady, voiceReason),
		functional(cataloguev1.GPUDrain, limitedV1GPUName, "ai", "Functional", "Owned ordinary-GPU drain/reopen/recovery fixture only; no installed-brain or security claim.", []string{"dedicated reviewed GPU fixture", "private operation bearer", "ordinary GPU"}, gpuReady, gpuReason),
		functional(cataloguev1.AuthUnauth, "limited-v1-console-unauthenticated", "platform", "Boundary", "Installed API authentication boundary only; no application attack, brain or actuator claim.", []string{"fixed loopback origin", "projected scoped test identity"}, authReady, authReason),
		functional(cataloguev1.AuthScope, "limited-v1-console-scoped-authorization", "platform", "Boundary", "Installed API tenant/target authorization boundary only; no application attack, brain or actuator claim.", []string{"fixed loopback origin", "projected scoped test identity", "fixed allowed and denied scopes"}, authReady, authReason),
		{EntryID: limitedV1GuardrailID, Name: limitedV1GuardrailID, Product: "ai", Category: "Effect observation", R6Tag: "not-applicable",
			Techniques: []string{}, ExercisedTechniques: []string{}, Caps: []string{}, Realism: "executable-mechanism", BenignControl: boolPtr(true),
			ExpectedActuators: []string{"guardrail-rotate"}, MeaningfulWhen: "Observes an exact-target runtime variant transition; behavioral bypass and mitigation are not measured.",
			RunnableNote: "Uses the existing installed vLLM guardrail-effect handler and exact-ID result polling.", Prereqs: []string{"installed vLLM guardrail sidecar", "eligible guardrail-rotate policy"},
			LaunchKind: "live-vllm-effect", ClaimClass: "effect", Profile: "guardrail-rotate", Available: true, RuntimeContext: "in-cluster"},
	}
}

func (c Config) catalogueV1RuntimeContext(profile cataloguev1.ProfileID) string {
	if profile == cataloguev1.GPUDrain {
		if value := strings.TrimSpace(c.CatalogueV1.GPUKubeContext); value != "" {
			return value
		}
	}
	if profile == cataloguev1.VoiceMedia || profile == cataloguev1.VoiceRecovery {
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
