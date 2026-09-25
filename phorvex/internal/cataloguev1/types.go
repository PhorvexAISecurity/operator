package cataloguev1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/phorvex/metricvalidity"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ProfileID is a closed identifier selected by the console's server-side
// catalogue. It is never a command name supplied by the browser.
type ProfileID string

const (
	VoiceMedia           ProfileID = "limited-v1-voice-media"
	VoiceRecovery        ProfileID = "limited-v1-voice-recovery"
	GPUDrain             ProfileID = "limited-v1-vllm-request-drain"
	AuthUnauth           ProfileID = "limited-v1-console-unauthenticated"
	AuthScope            ProfileID = "limited-v1-console-scoped-authorization"
	GuardrailCalibration ProfileID = "limited-v1-vllm-guardrail-calibration"
	MCPSessionBaseline   ProfileID = "catalogue-mcp-session-baseline"
	ChromaOwnedVector    ProfileID = "catalogue-chroma-owned-vector"
	LiteLLMHealth        ProfileID = "catalogue-litellm-route-health"
	LiteLLMCredential    ProfileID = "catalogue-litellm-credential-boundary"
	LiteLLMRouting       ProfileID = "catalogue-litellm-inference-routing"
	CRMRefund            ProfileID = "c2-crm-refund-capability"
	CRMReset             ProfileID = "c2-crm-reset-capability"
)

// Definition is immutable product metadata for a fixed profile.
type Definition struct {
	ID           ProfileID     `json:"id"`
	Title        string        `json:"title"`
	Product      string        `json:"product"`
	Category     string        `json:"category"`
	ClaimLimits  string        `json:"claimLimits"`
	FixedTarget  string        `json:"fixedTarget"`
	FixedTenant  string        `json:"fixedTenant"`
	MaxDuration  time.Duration `json:"maxDuration"`
	MaxMutations int           `json:"maxMutations"`
}

func DefinitionFor(id ProfileID) (Definition, error) {
	definitions := map[ProfileID]Definition{
		VoiceMedia:           {ID: VoiceMedia, Title: "Installed Voice media", Product: "application", Category: "Functional", ClaimLimits: "ordinary installed Pipecat media only; no phone-call, semantic, brain or security claim", FixedTarget: "default", FixedTenant: "voice", MaxDuration: 4 * time.Minute, MaxMutations: 0},
		VoiceRecovery:        {ID: VoiceRecovery, Title: "Installed Voice replacement recovery", Product: "application", Category: "Functional", ClaimLimits: "one PDB-honoring exact-UID eviction and fresh-session recovery; no seamless-session or security claim", FixedTarget: "default", FixedTenant: "voice", MaxDuration: 10 * time.Minute, MaxMutations: 1},
		GPUDrain:             {ID: GPUDrain, Title: "Owned GPU request drain", Product: "ai", Category: "Functional", ClaimLimits: "owned ordinary-GPU drain/reopen/recovery fixture only; no installed-brain or security claim", FixedTarget: "default", FixedTenant: "vllm-functional", MaxDuration: 12 * time.Minute, MaxMutations: 1},
		AuthUnauth:           {ID: AuthUnauth, Title: "Console unauthenticated boundary", Product: "platform", Category: "Boundary", ClaimLimits: "installed API authentication boundary only; no application attack, brain or actuator claim", FixedTarget: "default", FixedTenant: "vllm", MaxDuration: time.Minute, MaxMutations: 0},
		AuthScope:            {ID: AuthScope, Title: "Console scoped authorization boundary", Product: "platform", Category: "Boundary", ClaimLimits: "installed API tenant/target authorization boundary only; no application attack, brain or actuator claim", FixedTarget: "default", FixedTenant: "vllm", MaxDuration: time.Minute, MaxMutations: 0},
		GuardrailCalibration: {ID: GuardrailCalibration, Title: "Installed guardrail benign calibration", Product: "ai", Category: "Calibration", ClaimLimits: "two fixed benign requests to the reviewed non-forwarding classifier endpoint/source contract; loaded process, forwarding behavior, guarded serving, injected response, detector, actuator and security efficacy are not attested", FixedTarget: "default", FixedTenant: "vllm", MaxDuration: 2 * time.Minute, MaxMutations: 0},
		MCPSessionBaseline:   {ID: MCPSessionBaseline, Title: "Installed MCP owned session", Product: "application", Category: "Functional", ClaimLimits: "one synthetic MCP tool read and exact in-memory session invalidation with mounted-file/package hash pins; already-loaded Python bytes, business mutation, provider, authorization, brain, actuator and security efficacy are not attested", FixedTarget: "default", FixedTenant: "mcp", MaxDuration: 2 * time.Minute, MaxMutations: 2},
		ChromaOwnedVector:    {ID: ChromaOwnedVector, Title: "Chroma owned vector state", Product: "application", Category: "Functional", ClaimLimits: "one fresh synthetic collection and document on the exact installed Chroma route; no customer data, authorization bypass, SecurityEvent, brain, actuator or security efficacy claim", FixedTarget: "default", FixedTenant: "document-store", MaxDuration: 3 * time.Minute, MaxMutations: 3},
		LiteLLMHealth:        {ID: LiteLLMHealth, Title: "LiteLLM route availability", Product: "ai", Category: "Functional", ClaimLimits: "fixed listener liveliness on each exact serving Pod; no authenticated model serving, SecurityEvent, brain, actuator or security efficacy claim", FixedTarget: "default", FixedTenant: "litellm", MaxDuration: 2 * time.Minute, MaxMutations: 0},
		LiteLLMCredential:    {ID: LiteLLMCredential, Title: "LiteLLM credential configuration boundary", Product: "ai", Category: "Boundary", ClaimLimits: "missing and generated invalid bearer on reviewed GET /v1/models authentication route for each exact serving Pod; NO_CONNECTED_DB is configuration-limited, not a verified denial or bypass; no SecurityEvent, brain, actuator or security efficacy claim", FixedTarget: "default", FixedTenant: "litellm", MaxDuration: 2 * time.Minute, MaxMutations: 0},
		LiteLLMRouting:       {ID: LiteLLMRouting, Title: "LiteLLM authenticated inference routing", Product: "ai", Category: "Functional", ClaimLimits: "at most one harmless nonstreaming completion and one unknown-model request per exact serving Pod; completion and explicit typed model rejection are separate observations; returned model metadata does not prove loaded provider model or weights; provider internals, absence of upstream work, SecurityEvent, brain, actuator and security efficacy are not attested", FixedTarget: "default", FixedTenant: "litellm", MaxDuration: 3 * time.Minute, MaxMutations: 0},
		CRMRefund:            {ID: CRMRefund, Title: "Disposable CRM refund capability", Product: "application", Category: "Functional", ClaimLimits: "synthetic A/B record capability in isolated Mongo only; A/B are not authenticated principals; no installed customer write, phone/provider, authentication bypass, brain or security efficacy claim", FixedTarget: "default", FixedTenant: "crm-functional", MaxDuration: 14 * time.Minute, MaxMutations: 2},
		CRMReset:             {ID: CRMReset, Title: "Disposable CRM reset capability", Product: "application", Category: "Functional", ClaimLimits: "synthetic A/B record capability in isolated Mongo only; A/B are not authenticated principals; no installed customer write, phone/provider, authentication bypass, brain or security efficacy claim", FixedTarget: "default", FixedTenant: "crm-functional", MaxDuration: 14 * time.Minute, MaxMutations: 2},
	}
	definition, ok := definitions[id]
	if !ok {
		return Definition{}, fmt.Errorf("unknown catalogue v1 profile %q", id)
	}
	return definition, nil
}

// Job is the only child-process input. Runtime destinations and credentials
// are deliberately absent and come from validated deployment configuration.
type Job struct {
	Version             int       `json:"version"`
	RunID               string    `json:"runID"`
	Profile             ProfileID `json:"profile"`
	OutputDir           string    `json:"outputDir"`
	DefinitionSHA256    string    `json:"definitionSHA256"`
	OwnerDigest         string    `json:"ownerDigest"`
	ResolvedTarget      string    `json:"resolvedTarget"`
	ResolvedTenant      string    `json:"resolvedTenant"`
	RuntimeConfigSHA256 string    `json:"runtimeConfigSHA256"`
	CreatedAt           time.Time `json:"createdAt"`
	Deadline            time.Time `json:"deadline"`
}

type VoiceRuntime struct {
	Enabled               bool   `json:"enabled"`
	Namespace             string `json:"namespace"`
	Deployment            string `json:"deployment"`
	Service               string `json:"service"`
	Container             string `json:"container"`
	ServicePort           int32  `json:"servicePort"`
	PDB                   string `json:"pdb"`
	TranscriptPodSelector string `json:"transcriptPodSelector"`
	TranscriptContainer   string `json:"transcriptContainer"`
}

type GPUFixtureRuntime struct {
	Enabled           bool   `json:"enabled"`
	Namespace         string `json:"namespace"`
	FixtureConfigFile string `json:"fixtureConfigFile"`
	HarnessBinary     string `json:"harnessBinary"`
	HarnessDir        string `json:"harnessDir"`
	KubeconfigPath    string `json:"kubeconfigPath"`
	KubeContext       string `json:"kubeContext"`
}

// GuardrailCalibrationRuntime is a server-owned, disabled-by-default route and
// source authority. The browser cannot provide any of these fields.
type GuardrailCalibrationRuntime struct {
	Enabled              bool   `json:"enabled"`
	Namespace            string `json:"namespace"`
	Service              string `json:"service"`
	Port                 int32  `json:"port"`
	Container            string `json:"container"`
	SourceConfigMap      string `json:"sourceConfigMap"`
	SourceKey            string `json:"sourceKey"`
	ExpectedSourceSHA256 string `json:"expectedSourceSHA256"`
}

// MCPSessionRuntime is fixed by the deployment, never by a launch request.
type MCPSessionRuntime struct {
	Enabled              bool   `json:"enabled"`
	Namespace            string `json:"namespace"`
	Deployment           string `json:"deployment"`
	Service              string `json:"service"`
	Container            string `json:"container"`
	Port                 int32  `json:"port"`
	SourceConfigMap      string `json:"sourceConfigMap"`
	SourceKey            string `json:"sourceKey"`
	ExpectedImageID      string `json:"expectedImageID"`
	ExpectedSourceSHA256 string `json:"expectedSourceSHA256"`
}

type CRMCapabilityRuntime struct {
	Enabled            bool   `json:"enabled"`
	Namespace          string `json:"namespace"`
	ServiceAccountName string `json:"serviceAccountName"`
	NamespaceUID       string `json:"namespaceUID"`
	ManifestFile       string `json:"manifestFile"`
	ManifestSHA256     string `json:"manifestSHA256"`
	HarnessBinary      string `json:"harnessBinary"`
	HarnessSHA256      string `json:"harnessSHA256"`
	HarnessDir         string `json:"harnessDir"`
	KubeconfigPath     string `json:"kubeconfigPath"`
	KubeconfigSHA256   string `json:"kubeconfigSHA256"`
	KubeContext        string `json:"kubeContext"`
}

// Runtime contains trusted process configuration. It is assembled by the
// console from chart/startup settings, never decoded from the launch request or
// the private Job file.
type Runtime struct {
	StateDir        string
	ConfigSHA256    string
	KubeconfigPath  string
	KubeContext     string
	RESTConfig      *rest.Config
	Kube            kubernetes.Interface
	HTTPClient      *http.Client
	FixedLoopback   *url.URL
	ScopedTokenFile string
	AllowedTenant   string
	DeniedTenant    string
	DeniedTarget    string
	ExpectedSubject string
	GrantFile       string
	Voice           VoiceRuntime
	GPU             GPUFixtureRuntime
	Guardrail       GuardrailCalibrationRuntime
	MCP             MCPSessionRuntime
	Chroma          ChromaRuntime
	LiteLLM         LiteLLMRuntime
	CRM             CRMCapabilityRuntime
}

type Outcome string

const (
	OutcomeFunctionalPass Outcome = "functional-pass"
	OutcomeFunctionalFail Outcome = "functional-fail"
	OutcomeInconclusive   Outcome = "inconclusive"
	OutcomeTestFailed     Outcome = "test-failed"
)

type Cleanup struct {
	Attempted     bool              `json:"attempted"`
	Verified      bool              `json:"verified"`
	Status        string            `json:"status"`
	Details       map[string]string `json:"details,omitempty"`
	UnsafeToRetry bool              `json:"unsafeToRetry,omitempty"`
}

type Result struct {
	Version             int               `json:"version"`
	RunID               string            `json:"runID"`
	Profile             ProfileID         `json:"profile"`
	DefinitionSHA256    string            `json:"definitionSHA256"`
	OwnerDigest         string            `json:"ownerDigest"`
	ResolvedTarget      string            `json:"resolvedTarget"`
	ResolvedTenant      string            `json:"resolvedTenant"`
	RuntimeConfigSHA256 string            `json:"runtimeConfigSHA256"`
	Outcome             Outcome           `json:"outcome"`
	Summary             string            `json:"summary"`
	Evidence            map[string]string `json:"evidence,omitempty"`
	Limits              []string          `json:"limits"`
	Cleanup             Cleanup           `json:"cleanup"`
	UnsafeToRetry       bool              `json:"unsafeToRetry,omitempty"`
	StartedAt           time.Time         `json:"startedAt"`
	FinishedAt          time.Time         `json:"finishedAt"`
}

type Intent struct {
	Step     string            `json:"step"`
	Mutation bool              `json:"mutation"`
	Identity map[string]string `json:"identity,omitempty"`
	At       time.Time         `json:"at"`
}

type Event struct {
	Step     string            `json:"step"`
	Status   string            `json:"status"`
	Identity map[string]string `json:"identity,omitempty"`
	At       time.Time         `json:"at"`
}

type JournalRecord struct {
	Kind   string  `json:"kind"`
	Intent *Intent `json:"intent,omitempty"`
	Event  *Event  `json:"event,omitempty"`
}

type Journal struct {
	Records []JournalRecord `json:"records"`
}

// Metric is the fixed benign-functional projection consumed by the console's
// shared PR317 outcome classifier.
type Metric struct {
	Scenario              string                   `json:"scenario"`
	Defender              string                   `json:"defender"`
	Trial                 int                      `json:"trial"`
	OracleAchieved        bool                     `json:"oracleAchieved"`
	DisruptionVsOracle    float64                  `json:"disruptionVsOracle"`
	Skipped               bool                     `json:"skipped"`
	SkipReason            string                   `json:"skipReason,omitempty"`
	ScenarioRealism       string                   `json:"scenarioRealism"`
	ScenarioBenignControl bool                     `json:"scenarioBenignControl"`
	ScenarioClaimLimits   string                   `json:"scenarioClaimLimits"`
	BenchmarkEvidence     map[string]string        `json:"benchmarkEvidence"`
	Validity              *metricvalidity.Validity `json:"validity"`
}

type Recorder interface {
	Intent(Intent) error
	Event(Event) error
	Metric(Metric) error
	// MetricRaw persists one already validated harness metric without projecting
	// away its evidence fields. It is used only by the fixed GPU harness profile.
	MetricRaw(json.RawMessage) error
	Result(Result) error
}

type JobContext struct {
	Job      Job
	Runtime  Runtime
	Recorder Recorder
}

type Handler interface {
	Definition() Definition
	Validate(Runtime) error
	Run(context.Context, JobContext) Result
	Reconcile(context.Context, JobContext, Journal) Cleanup
}
