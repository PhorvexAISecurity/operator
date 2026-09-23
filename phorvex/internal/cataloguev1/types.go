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
	VoiceMedia    ProfileID = "limited-v1-voice-media"
	VoiceRecovery ProfileID = "limited-v1-voice-recovery"
	GPUDrain      ProfileID = "limited-v1-vllm-request-drain"
	AuthUnauth    ProfileID = "limited-v1-console-unauthenticated"
	AuthScope     ProfileID = "limited-v1-console-scoped-authorization"
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
		VoiceMedia:    {ID: VoiceMedia, Title: "Installed Voice media", Product: "application", Category: "Functional", ClaimLimits: "ordinary installed Pipecat media only; no phone-call, semantic, brain or security claim", FixedTarget: "default", FixedTenant: "voice", MaxDuration: 4 * time.Minute, MaxMutations: 0},
		VoiceRecovery: {ID: VoiceRecovery, Title: "Installed Voice replacement recovery", Product: "application", Category: "Functional", ClaimLimits: "one PDB-honoring exact-UID eviction and fresh-session recovery; no seamless-session or security claim", FixedTarget: "default", FixedTenant: "voice", MaxDuration: 10 * time.Minute, MaxMutations: 1},
		GPUDrain:      {ID: GPUDrain, Title: "Owned GPU request drain", Product: "ai", Category: "Functional", ClaimLimits: "owned ordinary-GPU drain/reopen/recovery fixture only; no installed-brain or security claim", FixedTarget: "default", FixedTenant: "vllm-functional", MaxDuration: 12 * time.Minute, MaxMutations: 1},
		AuthUnauth:    {ID: AuthUnauth, Title: "Console unauthenticated boundary", Product: "platform", Category: "Boundary", ClaimLimits: "installed API authentication boundary only; no application attack, brain or actuator claim", FixedTarget: "default", FixedTenant: "vllm", MaxDuration: time.Minute, MaxMutations: 0},
		AuthScope:     {ID: AuthScope, Title: "Console scoped authorization boundary", Product: "platform", Category: "Boundary", ClaimLimits: "installed API tenant/target authorization boundary only; no application attack, brain or actuator claim", FixedTarget: "default", FixedTenant: "vllm", MaxDuration: time.Minute, MaxMutations: 0},
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
