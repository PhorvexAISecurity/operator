/*
 * Phorvex — producer-driven recon cover map (M-123).
 *
 * This command EXECUTES the registered ReconProfiles (standard-recon, ucw-recon) on a
 * fixed set of named, deterministic fixtures and reports, per fixture and profile, every
 * emitted fact and every declared action's cover set. It never parses Go comments and it
 * keeps no hand-maintained fact→action mapping: the only mapping it prints is the one
 * recon.AssetFacts returned for that fixture.
 *
 * The union of fixtures is a branch inventory of the producers, not a statement of
 * runtime eligibility: candidate generation, the capability gate, feasibility, cost and
 * selection all sit after fact emission and are documented separately in
 * build/test-harness/ACTUATOR_COVERAGE.md.
 *
 *	go run ./tools/covermap --check    # exit 1 when docs/recon-cover-map.generated.md drifted
 *	go run ./tools/covermap --write    # regenerate it
 */

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/outputpolicy"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
)

// SchemaVersion is bumped whenever the JSON block's shape changes.
const SchemaVersion = 1

// DefaultOutput is the checked-in report, relative to the phorvex module root.
const DefaultOutput = "docs/recon-cover-map.generated.md"

// inputPackages are the module-relative directories whose non-test Go files determine the
// report. recon and registry are the producers; model declares the Action vocabulary,
// the Pod/WorkloadView inputs and the attack-vector constants; this tool's own source
// defines the fixtures and the rendering.
var inputPackages = []string{"internal/recon", "internal/registry", "internal/model", "internal/outputpolicy", "tools/covermap"}

// profileNames are executed in this order. Both are looked up in recon.Registry so the
// report exercises the registered producers, not a private copy.
var profileNames = []string{"standard-recon", "ucw-recon"}

// declaredOnlyActions are Action constants that model.MutatingActions deliberately
// excludes (never generatable). They are still listed so a reader sees they carry no
// cover. TestDeclaredActionsAreAllListed cross-checks this list against the AST of
// internal/model/types.go, so a new constant cannot be silently omitted.
var declaredOnlyActions = []model.Action{model.ActionNoop, model.ActionDisable}

// PodSpec is the subset of model.Pod a fixture sets. Every field is copied verbatim
// onto model.Pod in buildView; unset fields keep the zero value.
type PodSpec struct {
	Namespace                 string                               `json:"namespace"`
	Name                      string                               `json:"name"`
	UID                       string                               `json:"uid,omitempty"`
	PodResourceVersion        string                               `json:"podResourceVersion,omitempty"`
	ServiceAccount            string                               `json:"serviceAccount,omitempty"`
	PodBoundKubeAPIAuth       *model.PodBoundKubeAPIAuthProjection `json:"podBoundKubeAPIAuth,omitempty"`
	OutputPolicyConfigMap     string                               `json:"outputPolicyConfigMap,omitempty"`
	OutputPolicyRuleSHA256    string                               `json:"outputPolicyRuleSHA256,omitempty"`
	OutputProxySourceSHA256   string                               `json:"outputProxySourceSHA256,omitempty"`
	OutputSupportSourceSHA256 string                               `json:"outputSupportSourceSHA256,omitempty"`
	OutputEventCreator        string                               `json:"outputEventCreator,omitempty"`
	OutputPolicyObservation   *model.SensitiveOutputObservation    `json:"outputPolicyObservation,omitempty"`
	Node                      string                               `json:"node,omitempty"`
	HasGPU                    bool                                 `json:"hasGPU,omitempty"`
	MIGDevice                 string                               `json:"migDevice,omitempty"`
	ModelID                   string                               `json:"modelID,omitempty"`
	SuspectAdapter            string                               `json:"suspectAdapter,omitempty"`
	SuspectConfigObject       string                               `json:"suspectConfigObject,omitempty"`
	SuspectImageDigest        string                               `json:"suspectImageDigest,omitempty"`
	ControllerUID             string                               `json:"controllerUID,omitempty"`
	RouteService              string                               `json:"routeService,omitempty"`
	Stateful                  bool                                 `json:"stateful,omitempty"`
	ServingEndpointReady      bool                                 `json:"servingEndpointReady,omitempty"`
	WarmPoolConfigured        bool                                 `json:"warmPoolConfigured,omitempty"`
	WarmPoolOwnerUID          string                               `json:"warmPoolOwnerUID,omitempty"`
	SwapGroup                 string                               `json:"swapGroup,omitempty"`
	ModelShard                string                               `json:"modelShard,omitempty"`
	ParallelGroup             string                               `json:"parallelGroup,omitempty"`
	Role                      string                               `json:"role,omitempty"`
	Bound                     *BoundSpec                           `json:"bound,omitempty"`
}

// BoundSpec carries the ingestion-bound, admission-stamped observations of the
// application-scoped actuators, plus the Pod-side source pins each one is checked
// against. Each pointer is copied verbatim onto model.Pod; nil leaves it unbound.
type BoundSpec struct {
	VoiceMemoryConfigMap        string                           `json:"voiceMemoryConfigMap,omitempty"`
	VoiceMemorySourceSHA256     string                           `json:"voiceMemorySourceSHA256,omitempty"`
	VoiceMemoryDeploymentUID    string                           `json:"voiceMemoryDeploymentUID,omitempty"`
	VoiceMemoryEventCreator     string                           `json:"voiceMemoryEventCreator,omitempty"`
	VoiceMemoryObservation      *model.VoiceMemoryObservation    `json:"voiceMemoryObservation,omitempty"`
	VoiceRefundConfigMap        string                           `json:"voiceRefundConfigMap,omitempty"`
	VoiceRefundSourceSHA256     string                           `json:"voiceRefundSourceSHA256,omitempty"`
	VoiceRefundDeploymentUID    string                           `json:"voiceRefundDeploymentUID,omitempty"`
	VoiceRefundEventCreator     string                           `json:"voiceRefundEventCreator,omitempty"`
	VoiceRefundObservation      *model.VoiceRefundObservation    `json:"voiceRefundObservation,omitempty"`
	VoiceMCPConfigMap           string                           `json:"voiceMcpConfigMap,omitempty"`
	VoiceMCPSourceSHA256        string                           `json:"voiceMcpSourceSHA256,omitempty"`
	VoiceMCPDeploymentUID       string                           `json:"voiceMcpDeploymentUID,omitempty"`
	VoiceMCPEventCreator        string                           `json:"voiceMcpEventCreator,omitempty"`
	VoiceMCPObservation         *model.VoiceMCPObservation       `json:"voiceMcpObservation,omitempty"`
	VoiceOutputConfigMap        string                           `json:"voiceOutputConfigMap,omitempty"`
	VoiceOutputSourceSHA256     string                           `json:"voiceOutputSourceSHA256,omitempty"`
	VoiceOutputDeploymentUID    string                           `json:"voiceOutputDeploymentUID,omitempty"`
	VoiceOutputEventCreator     string                           `json:"voiceOutputEventCreator,omitempty"`
	VoiceOutputObservation      *model.VoiceOutputObservation    `json:"voiceOutputObservation,omitempty"`
	VoiceAdmissionConfigMap     string                           `json:"voiceAdmissionConfigMap,omitempty"`
	VoiceAdmissionSourceSHA256  string                           `json:"voiceAdmissionSourceSHA256,omitempty"`
	VoiceAdmissionDeploymentUID string                           `json:"voiceAdmissionDeploymentUID,omitempty"`
	VoiceAdmissionEventCreator  string                           `json:"voiceAdmissionEventCreator,omitempty"`
	VoiceAdmissionObservation   *model.VoiceAdmissionObservation `json:"voiceAdmissionObservation,omitempty"`
	LiteLLMClientObservation    *model.LiteLLMClientObservation  `json:"litellmClientObservation,omitempty"`
	EndpointLeaseObservation    *model.EndpointLeaseObservation  `json:"endpointLeaseObservation,omitempty"`
	CRMRefundObservation        *model.CRMRefundObservation      `json:"crmRefundObservation,omitempty"`
	// The seven combined-actuator witnesses, each the narrow authenticated authority behind one
	// native action. K8sObjectRevert/Image are paired with the Pod-side SuspectConfigObject/
	// SuspectImageDigest pins; the rest bind through the Pod UID/namespace/node the fixture sets.
	K8sObjectRevertObservation   *model.K8sObjectRevertObservation   `json:"k8sObjectRevertObservation,omitempty"`
	ImageObservation             *model.ImageObservation             `json:"imageObservation,omitempty"`
	DatastoreRestoreObservation  *model.DatastoreRestoreObservation  `json:"datastoreRestoreObservation,omitempty"`
	AgentActionDenyObservation   *model.AgentActionDenyObservation   `json:"agentActionDenyObservation,omitempty"`
	NodeEscapeObservation        *model.NodeEscapeObservation        `json:"nodeEscapeObservation,omitempty"`
	NetworkIsolateObservation    *model.NetworkIsolateObservation    `json:"networkIsolateObservation,omitempty"`
	CredentialRevokeObservation  *model.CredentialRevokeObservation  `json:"credentialRevokeObservation,omitempty"`
	ServingRateBudgetObservation *model.ServingRateBudgetObservation `json:"servingRateBudgetObservation,omitempty"`
}

// PhysicsSpec is the dispersion witness a fixture supplies. nil means model.NeutralPhysics().
type PhysicsSpec struct {
	ImageRarity    float64 `json:"imageRarity"`
	EPSSMultiplier float64 `json:"epssMultiplier"`
	CoResidency    float64 `json:"coResidency"`
	ModelRarity    float64 `json:"modelRarity"`
}

// EventSpec is a SecurityEventInfo as the recon layer sees it on view.Events. In
// production only TRUSTED, pod-targeting events reach view.Events with TargetsPod=true
// (ingest/events.go); neighbour-propagated copies carry TargetsPod=false.
type EventSpec struct {
	Type       string  `json:"type"`
	TargetsPod bool    `json:"targetsPod"`
	Trust      string  `json:"trust"`
	AgeSeconds float64 `json:"ageSeconds"`
}

// NeighborSpec is one blast-graph neighbour with its asset value.
type NeighborSpec struct {
	Key   string  `json:"key"`
	Value float64 `json:"value"`
}

// CtxSpec mirrors recon.FactContext. In production HasGPU/Stateful are copied from
// view.Pod.HasGPU / view.Pod.Stateful (decision/coverage.go factCtx); fixtures set them
// explicitly so the M-42 asymmetry (ucw keys AI facts on Pod.HasGPU||Pod.ModelID, the
// session/kv-reset arm keys on FactContext.HasGPU||Stateful) is visible, not hidden.
type CtxSpec struct {
	AssetValue     float64        `json:"assetValue"`
	PHold          float64        `json:"pHold"`
	StageUrgency   float64        `json:"stageUrgency"`
	LateralUrgency float64        `json:"lateralUrgency"`
	Neighbors      []NeighborSpec `json:"neighbors,omitempty"`
	HasGPU         bool           `json:"hasGPU,omitempty"`
	Stateful       bool           `json:"stateful,omitempty"`
}

// Fixture is one named, fully serialised producer input.
type Fixture struct {
	Name    string       `json:"name"`
	Why     string       `json:"why"`
	Pod     PodSpec      `json:"pod"`
	Physics *PhysicsSpec `json:"physics,omitempty"`
	Events  []EventSpec  `json:"events,omitempty"`
	Ctx     CtxSpec      `json:"ctx"`
}

// FactRow is one emitted fact with the actions whose cover set names its key.
type FactRow struct {
	Scope     string   `json:"scope"`
	Kind      string   `json:"kind"`
	Edge      string   `json:"edge,omitempty"`
	Weight    float64  `json:"weight"`
	CoveredBy []string `json:"coveredBy"`
}

// Result is one (fixture, profile) execution.
type Result struct {
	Fixture      string              `json:"fixture"`
	Profile      string              `json:"profile"`
	AbsentReason string              `json:"absentReason,omitempty"`
	Facts        []FactRow           `json:"facts"`
	Cover        map[string][]string `json:"cover"` // action -> covered fact labels (every declared action present)
}

// PackageHash pins one input package by the sha256 of its sorted non-test Go files.
type PackageHash struct {
	Path   string   `json:"path"`
	Files  []string `json:"files"`
	SHA256 string   `json:"sha256"`
}

// Declared is the AST-derived vocabulary used to make new/unknown names visible.
type Declared struct {
	Actions      []string `json:"actions"`      // every Action-typed constant in internal/model/types.go
	Mutating     []string `json:"mutating"`     // model.MutatingActions, in its load-bearing order
	DeclaredOnly []string `json:"declaredOnly"` // declared but never generatable
	FactKinds    []string `json:"factKinds"`    // every Fact* string constant in internal/recon/facts.go
	NeverEmitted []string `json:"neverEmitted"` // declared kinds no fixture emitted (should be empty)
}

// Report is the complete generated artifact.
type Report struct {
	Schema        int           `json:"schema"`
	Generator     string        `json:"generator"`
	Inputs        []PackageHash `json:"inputs"`
	InputsSHA256  string        `json:"inputsSHA256"`
	Profiles      []string      `json:"profiles"`
	RegistryOrder []string      `json:"registryOrder"`
	Declared      Declared      `json:"declared"`
	Fixtures      []Fixture     `json:"fixtures"`
	Results       []Result      `json:"results"`
}

// Fixtures returns the deterministic producer inputs, in report order.
func Fixtures() []Fixture {
	const ns = "covermap"
	unit := CtxSpec{AssetValue: 1, PHold: 1, StageUrgency: 1, LateralUrgency: 1}
	gpuCtx := unit
	gpuCtx.HasGPU = true
	gpuPod := PodSpec{Namespace: ns, Name: "gpu", Node: "node-a", HasGPU: true, ModelID: "model-x", RouteService: "svc", ServingEndpointReady: true}
	apiPod := PodSpec{Namespace: ns, Name: "pod-bound-api", UID: "bound-pod-uid", PodResourceVersion: "17", ServiceAccount: "workload", Node: "node-a",
		PodBoundKubeAPIAuth: &model.PodBoundKubeAPIAuthProjection{
			PodUID: "bound-pod-uid", PodResourceVersion: "17", ServiceAccountName: "workload", ServiceAccountUID: "sa-uid",
			VolumeName: "kube-api-access", MountedContainer: "app", AudienceSource: "kube-apiserver-default",
			EvidenceSource: "admitted-pod-and-serviceaccount",
		}}
	staleAPIPod := apiPod
	staleAPIPod.Name = "pod-bound-api-stale-uid"
	staleProjection := *apiPod.PodBoundKubeAPIAuth
	staleProjection.PodUID = "old-pod-uid"
	staleAPIPod.PodBoundKubeAPIAuth = &staleProjection
	const outputUID = "11111111-1111-4111-8111-111111111111"
	const outputCMUID = "22222222-2222-4222-8222-222222222222"
	const outputCreator = "system:serviceaccount:covermap:console"
	outputRuleSHA := outputpolicy.RuleSHA256(outputUID)
	outputPod := PodSpec{Namespace: ns, Name: "sensitive-output", UID: outputUID, Node: "node-a",
		OutputPolicyConfigMap: "phorvex-output-policy-sensitive-output", OutputPolicyRuleSHA256: outputRuleSHA,
		OutputProxySourceSHA256: strings.Repeat("a", 64), OutputSupportSourceSHA256: strings.Repeat("b", 64),
		OutputEventCreator: outputCreator,
		OutputPolicyObservation: &model.SensitiveOutputObservation{
			EventName: "observed", EventUID: "33333333-3333-4333-8333-333333333333",
			CreatorIdentity: outputCreator, TargetPodUID: outputUID, ConfigMapUID: outputCMUID,
			PolicyName: "guardrail-output-fixture", PolicyUID: "44444444-4444-4444-8444-444444444444", PolicyGeneration: 1,
			RuleSHA256: outputRuleSHA, ProxySourceSHA256: strings.Repeat("a", 64), SupportSourceSHA256: strings.Repeat("b", 64),
			ProxyImageID: "proxy@sha256:aaa", SupportImageID: "support@sha256:bbb", ObservedAt: time.Unix(1, 0).UTC(),
		}}
	unboundOutputPod := outputPod
	unboundOutputPod.Name = "sensitive-output-unbound"
	unboundOutputPod.OutputPolicyObservation = nil
	vector := func(name, why, typ string, targetsPod bool, age float64) Fixture {
		pod := gpuPod
		pod.Name = name
		return Fixture{Name: name, Why: why, Pod: pod, Ctx: gpuCtx,
			Events: []EventSpec{{Type: typ, TargetsPod: targetsPod, Trust: "trusted", AgeSeconds: age}}}
	}
	at := time.Unix(1, 0).UTC()
	const consoleCreator = eventtrust.DefaultInjector
	uid := func(n int) string { return fmt.Sprintf("%08d-0000-4000-8000-%012d", n, n) }
	sha := func(c string) string { return strings.Repeat(c, 64) }
	// The admitted typed observation alone mints each application-scoped fact (ingest binds it
	// from the trusted event); recon never reads the raw event for these, so none is attached.
	boundFixture := func(name, why, namespace, podUID string, b BoundSpec) Fixture {
		return Fixture{Name: name, Why: why, Ctx: unit,
			Pod: PodSpec{Namespace: namespace, Name: name, UID: podUID, Node: "node-a", Bound: &b}}
	}
	admissionPod, admissionDeploy, admissionCM := uid(61), uid(62), uid(63)
	admission := voiceadmissionpolicy.EventAssertion{Version: 1, ScenarioID: voiceadmissionpolicy.ScenarioID, CaseID: "case-1",
		RunSHA256: sha("1"), SessionID: uid(64), DeploymentUID: admissionDeploy, PodUID: admissionPod,
		AdmissionSourceSHA256: sha("2"), LegacyBundleSHA256: sha("3"), AuthProfileSHA256: sha("4"), PolicyCMUID: admissionCM,
		PolicyResourceVersion: "7", RuleSHA256: sha("5"), SecurityPolicyUID: uid(65), SecurityPolicyGeneration: 1,
		ObservedAtUnixMs: 1000, EvidenceSource: "TEST_INJECTED", Observed: true, SentAudioFrames: 10, SentAudioBytes: 640,
		ReceiptSHA256: sha("6"), ProviderEvidenceSHA256: sha("7")}
	appScoped := []Fixture{
		boundFixture("voice-memory", "Admitted Voice memory-note observation bound to the exact Pod, owner, source and rule: voiceMemoryContamination appears at 3x and only voice-memory-note-revoke covers it.",
			ns, uid(11), BoundSpec{VoiceMemoryConfigMap: "voice-memory-policy", VoiceMemorySourceSHA256: sha("a"),
				VoiceMemoryDeploymentUID: uid(12), VoiceMemoryEventCreator: consoleCreator,
				VoiceMemoryObservation: &model.VoiceMemoryObservation{EventName: "observed", EventUID: uid(13), CreatorIdentity: consoleCreator,
					ScenarioID: "ai2-agent-memory-contamination", CaseID: "case-1", TargetPodUID: uid(11), DeploymentUID: uid(12), ConfigMapUID: uid(14),
					SourceSHA256: sha("a"), CallerID: "+15550000001", NoteSHA256: sha("b"), PolicyName: "voice-defense", PolicyUID: uid(15), PolicyGeneration: 1, ObservedAt: at}}),
		boundFixture("voice-refund", "Admitted asserted-caller/order pair after an owned CRM refund side effect: voiceRefundPairExposure appears at 3x and only voice-refund-pair-deny covers it.",
			ns, uid(21), BoundSpec{VoiceRefundConfigMap: "voice-refund-policy", VoiceRefundSourceSHA256: sha("a"),
				VoiceRefundDeploymentUID: uid(22), VoiceRefundEventCreator: consoleCreator,
				VoiceRefundObservation: &model.VoiceRefundObservation{EventName: "observed", EventUID: uid(23), CreatorIdentity: consoleCreator,
					ScenarioID: "ai2-agent-excessive-agency", CaseID: "case-1", TargetPodUID: uid(21), DeploymentUID: uid(22), ConfigMapUID: uid(24),
					SourceSHA256: sha("a"), AssertedCallerSHA256: sha("c"), OrderSHA256: sha("d"), PolicyName: "voice-defense", PolicyUID: uid(25), PolicyGeneration: 1, ObservedAt: at}}),
		boundFixture("voice-mcp", "Admitted poisoned-descriptor observation for the installed MCP tool: voiceMcpDescriptorSteering appears at 3x and only voice-mcp-tool-pin covers it.",
			"voice", uid(31), BoundSpec{VoiceMCPConfigMap: "voice-mcp-tool-policy", VoiceMCPSourceSHA256: sha("a"),
				VoiceMCPDeploymentUID: uid(32), VoiceMCPEventCreator: consoleCreator,
				VoiceMCPObservation: &model.VoiceMCPObservation{EventName: "observed", EventUID: uid(33), CreatorIdentity: consoleCreator,
					ScenarioID: "ai2-mcp-tool-poisoning", RunSHA256: sha("e"), TargetPodUID: uid(31), DeploymentUID: uid(32), ConfigMapUID: uid(34),
					SourceConfigMapUID: uid(35), SourceSHA256: sha("a"), ToolName: "store_directory", GoodDescriptorSHA256: sha("f"), ObservedDescriptorSHA256: sha("9"),
					MCPServiceName: "mcp-server", MCPServiceUID: uid(36), MCPPodName: "mcp-server-0", MCPPodUID: uid(37), MCPDeploymentUID: uid(38),
					MCPConfigMapUID: uid(39), MCPSourceSHA256: sha("8"), PolicyName: "voice-defense", PolicyUID: uid(40), PolicyGeneration: 1, ObservedAt: at}}),
		boundFixture("voice-output", "Admitted raw-model and assistant-output marker observation: voiceOutputExposure appears at 3x and only voice-output-policy-activate covers it.",
			"voice", uid(41), BoundSpec{VoiceOutputConfigMap: "voice-output-policy", VoiceOutputSourceSHA256: sha("a"),
				VoiceOutputDeploymentUID: uid(42), VoiceOutputEventCreator: consoleCreator,
				VoiceOutputObservation: &model.VoiceOutputObservation{EventName: "observed", EventUID: uid(43), CreatorIdentity: consoleCreator,
					ScenarioID: "ai2-system-prompt-leakage", EvidenceSource: "TEST_INJECTED", TargetPodUID: uid(41), DeploymentUID: uid(42), ConfigMapUID: uid(44),
					SourceSHA256: sha("a"), MarkerSHA256: sha("b"), PolicyName: "voice-defense", PolicyUID: uid(45), PolicyGeneration: 1,
					RawModelMarkerObserved: true, AssistantOutputMarkerObserved: true, ObservedAt: at}}),
		boundFixture("voice-admission", "Admitted unsigned-media session assertion matching the exact admission rule: voiceAdmissionAccess appears at 3x and only voice-session-admission-enforce covers it.",
			"voice", admissionPod, BoundSpec{VoiceAdmissionConfigMap: voiceadmissionpolicy.ConfigMapName, VoiceAdmissionSourceSHA256: sha("2"),
				VoiceAdmissionDeploymentUID: admissionDeploy, VoiceAdmissionEventCreator: eventtrust.DefaultInjector,
				VoiceAdmissionObservation: &model.VoiceAdmissionObservation{EventName: "observed", EventUID: uid(66), CreatorIdentity: eventtrust.DefaultInjector,
					ScenarioID: voiceadmissionpolicy.ScenarioID, EvidenceSource: "TEST_INJECTED", TargetPodUID: admissionPod, DeploymentUID: admissionDeploy,
					ConfigMapUID: admissionCM, ConfigMapResourceVersion: "7", RuleSHA256: sha("5"), SourceSHA256: sha("2"), SessionID: uid(64),
					PolicyName: "voice-defense", PolicyUID: uid(65), PolicyGeneration: 1, Assertion: admission, ObservedAt: at}}),
		boundFixture("litellm-client", "Admitted owned synthetic client abuse at the installed gateway: litellmOwnedClientChannel appears at 3x and only litellm-client-revoke covers it.",
			"litellm", uid(71), BoundSpec{LiteLLMClientObservation: &model.LiteLLMClientObservation{
				EventName: "observed", EventUID: uid(72), CreatorIdentity: consoleCreator, TargetPodUID: uid(71), PeerPodUID: uid(73),
				ClientSHA256: sha("a"), ConfigMapUID: uid(74), ClientsConfigMapUID: uid(75), SeedSHA256: sha("b"), ServiceUID: uid(76),
				GatewaySourceSHA256: sha("c"), PolicyName: "litellm-defense", PolicyUID: uid(77), PolicyGeneration: 1, ObservedAt: at}}),
		boundFixture("endpoint-lease", "Admitted reuse of one revocable caller lease while the retained caller still works: endpointLeaseReuse appears at 3x and only endpoint-lease-revoke covers it.",
			"vllm", uid(81), BoundSpec{EndpointLeaseObservation: &model.EndpointLeaseObservation{
				EventName: "observed", EventUID: uid(82), CreatorIdentity: consoleCreator, ScenarioID: "ai2-endpoint-security", EvidenceSource: "TEST_INJECTED",
				PolicyName: "vllm-defense", PolicyUID: uid(83), PolicyGeneration: 1, TargetPodUID: uid(81), ServiceUID: uid(84), PolicyConfigMapUID: uid(85),
				ProxySourceSHA256: sha("a"), SecretUID: uid(86), SeedSHA256: sha("b"), RevokedClientHMAC: sha("c"), RetainedClientHMAC: sha("d"),
				AcceptedStatus: 200, AcceptedResponseSHA256: sha("e"), RetainedBaselineStatus: 200, RetainedBaselineResponseSHA256: sha("f"), ObservedAt: at}}),
		boundFixture("crm-refund", "Admitted cross-account refund of one exact order bound to the live deny-guard and serving Pods: crmRefundOrderAbuse appears at 3x and only crm-refund-revoke covers it.",
			"crm", uid(91), BoundSpec{CRMRefundObservation: &model.CRMRefundObservation{
				EventName: "observed", EventUID: uid(92), CreatorIdentity: consoleCreator, OrderID: "OR-5002", OrderAccountID: "AC-1002",
				CallerAccountID: "AC-1001", GuardConfigMapUID: uid(93), ServiceUID: uid(94), TargetPodUID: uid(91), PeerPodUID: uid(95),
				PolicyName: "crm-defense", PolicyUID: uid(96), PolicyGeneration: 1, ObservedAt: at}}),
	}
	// nativeScoped are the seven combined/native actuators plus throttle. Each carries the exact
	// admitted witness its HasBound* authority requires (model.Pod), so the matching fact is minted
	// at 3x (ucw) or 1x (throttle, standard-recon) and only its dedicated action covers it. The
	// config-object/image witnesses pair with the Pod-side SuspectConfigObject/SuspectImageDigest
	// pins; datastore/agent-action are namespace-parametric (observation namespace == pod namespace);
	// node-escape binds to the pod's own live node; throttle binds to the pod's controller UID.
	imgRunning, imgPin := "sha256:"+sha("d"), "sha256:"+sha("c")
	nativeScoped := []Fixture{
		{Name: "config-object", Why: "Admitted trusted observation that an operator-trusted ConfigMap drifted from its snapshot, bound to the exact Pod UID and object name: configObjectIntegrity appears at 3x and only k8s-object-revert covers it.",
			Pod: PodSpec{Namespace: ns, Name: "config-object", UID: uid(101), Node: "node-a", SuspectConfigObject: "agent-config",
				Bound: &BoundSpec{K8sObjectRevertObservation: &model.K8sObjectRevertObservation{
					EventName: "observed", EventUID: uid(102), CreatorIdentity: consoleCreator, TargetPodUID: uid(101),
					ConfigMapName: "agent-config", ObservedSHA256: sha("a"), TrustedSHA256: sha("b"), CreatedAt: at}}}, Ctx: unit},
		{Name: "image-integrity", Why: "Admitted trusted observation that the running image digest drifted from the owner-declared pin, bound to the exact Pod UID: imageIntegrity appears at 3x and only registry-rollback covers it.",
			Pod: PodSpec{Namespace: ns, Name: "image-integrity", UID: uid(111), Node: "node-a", SuspectImageDigest: imgRunning,
				Bound: &BoundSpec{ImageObservation: &model.ImageObservation{
					EventName: "observed", EventUID: uid(112), CreatorIdentity: consoleCreator, TargetPodUID: uid(111),
					RunningDigest: imgRunning, TrustedPin: imgPin, CreatedAt: at}}}, Ctx: unit},
		boundFixture("datastore-poisoned", "Admitted trusted datastore-poisoning observation in the pod's own namespace: datastorePoisoned appears at 3x and only datastore-restore covers it.",
			ns, uid(121), BoundSpec{DatastoreRestoreObservation: &model.DatastoreRestoreObservation{
				EventName: "observed", EventUID: uid(122), CreatorIdentity: consoleCreator, Namespace: ns, StoreName: "rag-index",
				StoreConfigMapUID: uid(123), TrustedSnapshotConfigMapUID: uid(124), ServiceUID: uid(125), TargetPodUID: uid(121),
				PoisonedSHA256: sha("a"), TrustedSHA256: sha("b"), PolicyName: "defense", PolicyUID: uid(126), PolicyGeneration: 1, ObservedAt: at}}),
		boundFixture("agent-action-abuse", "Admitted trusted unauthorized-agent-action observation in the pod's own namespace: agentActionAbuse appears at 3x and only agent-action-deny covers it.",
			ns, uid(131), BoundSpec{AgentActionDenyObservation: &model.AgentActionDenyObservation{
				EventName: "observed", EventUID: uid(132), CreatorIdentity: consoleCreator, Namespace: ns, AgentName: "agent",
				CallerID: "caller-1", ActionID: "refund", GuardConfigMapUID: uid(133), ServiceUID: uid(134), TargetPodUID: uid(131),
				PolicyName: "defense", PolicyUID: uid(135), PolicyGeneration: 1, ObservedAt: at}}),
		boundFixture("node-host-escape", "Admitted trusted container->host escape observation bound to the pod's own live node: nodeHostEscape appears at 3x and only node-cordon-drain-replace covers it.",
			ns, uid(141), BoundSpec{NodeEscapeObservation: &model.NodeEscapeObservation{
				EventName: "observed", EventUID: uid(142), CreatorIdentity: consoleCreator, TargetPodUID: uid(141), NodeName: "node-a",
				PolicyName: "defense", PolicyUID: uid(143), PolicyGeneration: 1, EscapeSHA256: sha("a"), CreatedAt: at}}),
		boundFixture("network-egress-channel", "Admitted trusted open-egress-channel observation with a forbidden edge to cut: networkEgressChannel appears at 3x and only network-isolate covers it.",
			ns, uid(151), BoundSpec{NetworkIsolateObservation: &model.NetworkIsolateObservation{
				EventName: "observed", EventUID: uid(152), CreatorIdentity: consoleCreator, TargetPodUID: uid(151),
				PolicyName: "defense", PolicyUID: uid(153), PolicyGeneration: 1, ForbiddenEdges: []string{"169.254.169.254/32"}, ChannelSHA256: sha("a"), CreatedAt: at}}),
		boundFixture("credential-reuse", "Admitted trusted stolen-ServiceAccount-token observation naming a token Secret to revoke: credentialReuse appears at 3x and only credential-revoke covers it.",
			ns, uid(161), BoundSpec{CredentialRevokeObservation: &model.CredentialRevokeObservation{
				EventName: "observed", EventUID: uid(162), CreatorIdentity: consoleCreator, TargetPodUID: uid(161),
				PolicyName: "defense", PolicyUID: uid(163), PolicyGeneration: 1, ServiceAccountName: "workload",
				CredentialSecrets: []string{"workload-token"}, CredentialSHA256: sha("a"), CreatedAt: at}}),
		{Name: "serving-rate-budget", Why: "Admitted trusted cost-load observation bound to the installed authoritative limiter, the pod's controller UID and a measured over-baseline rate: servingRateBudget appears and only throttle covers it (standard-recon).",
			Pod: PodSpec{Namespace: ns, Name: "serving-rate-budget", UID: uid(171), Node: "node-a", ControllerUID: "rs-171",
				Bound: &BoundSpec{ServingRateBudgetObservation: &model.ServingRateBudgetObservation{
					EventName: "observed", EventUID: uid(172), CreatorIdentity: consoleCreator, TargetPodUID: uid(171), ControllerUID: "rs-171",
					PolicyName: "defense", PolicyUID: uid(173), PolicyGeneration: 1, ServiceUID: uid(174), LimiterDeploymentUID: uid(175),
					LimiterConfigMapUID: uid(176), LimiterSourceSHA256: sha("a"), LimiterBootID: "boot", OffendingCallerScope: "caller|/",
					BaselineReqPerSec: 42, ReservedReqPerSec: 42, ObservedReqPerSec: 1821, WindowSeconds: 60, ObservedAt: at}}}, Ctx: unit},
	}
	appScoped = append(appScoped, nativeScoped...)
	return append([]Fixture{
		{Name: "plain", Why: "CPU pod, no model, no neighbours, no event: the six base facts, rotate process-state grants and the quarantine network grant; route selector changes are coverless.",
			Pod: PodSpec{Namespace: ns, Name: "plain", Node: "node-a"}, Ctx: unit},
		{Name: "pod-bound-api", Why: "Exact current Pod UID and resourceVersion, ServiceAccount UID, and admitted mounted default API-audience projection: the separate planned API-auth capability fact appears with rotate-only cover; copied credential knowledge stays audit-only.",
			Pod: apiPod, Ctx: unit},
		{Name: "pod-bound-api-stale-uid", Why: "Projection names an old Pod UID: no API-auth capability fact or related rotate grant, despite otherwise complete witness fields.",
			Pod: staleAPIPod, Ctx: unit},
		{Name: "sensitive-output-admitted", Why: "The typed output observation already carries the authenticated event identity; recon receives it from ingest even if the raw event slice is absent.",
			Pod: outputPod, Ctx: unit},
		{Name: "sensitive-output", Why: "Ingestion-bound exact policy/Pod/rule/source observation: sensitiveOutputExposure appears at 3x and only the dedicated output-policy action covers it.",
			Pod: outputPod, Ctx: unit, Events: []EventSpec{{Type: model.AttackVectorSensitiveOutput, TargetsPod: true, Trust: "trusted"}}},
		{Name: "sensitive-output-no-assertion", Why: "Matching Pod source bindings without an admitted typed output observation do not mint response-field cover.",
			Pod: unboundOutputPod, Ctx: unit},
		{Name: "sensitive-output-unbound", Why: "An otherwise identical raw event without a typed admitted output observation does not mint response-field cover.",
			Pod: unboundOutputPod, Ctx: unit, Events: []EventSpec{{Type: model.AttackVectorSensitiveOutput, TargetsPod: true, Trust: "trusted"}}},
		{Name: "stateful", Why: "Stateful CPU pod without a serving endpoint: the session fact reaches full weight but neither endpoint-dependent eraser earns cover.",
			Pod: PodSpec{Namespace: ns, Name: "stateful", Node: "node-a", Stateful: true}, Ctx: func() CtxSpec { c := unit; c.Stateful = true; return c }()},
		{Name: "neighbors", Why: "Two blast-graph neighbours: one lateralEdge fact per neighbour, quarantine-only cover, weight scales with neighbour value.",
			Pod: PodSpec{Namespace: ns, Name: "neighbors", Node: "node-a"},
			Ctx: func() CtxSpec {
				c := unit
				c.Neighbors = []NeighborSpec{{Key: ns + "/neighbor-a", Value: 1}, {Key: ns + "/neighbor-b", Value: 0.5}}
				return c
			}()},
		{Name: "gpu", Why: "GPU served model without a MIG device: the AI facts appear; mig-rebind gets nothing because the pod has no MIG device.",
			Pod: gpuPod, Ctx: gpuCtx},
		{Name: "gpu-warm-pool", Why: "Verified scalar warm-pool leader: warm-swap covers only the exact old process identity, memory and session facts; placement facts remain audit-only.",
			Pod: func() PodSpec {
				p := gpuPod
				p.Name = "gpu-warm-pool"
				p.WarmPoolConfigured = true
				p.WarmPoolOwnerUID = "rs-uid"
				p.SwapGroup = "g"
				p.Role = "leader"
				return p
			}(), Ctx: gpuCtx},
		{Name: "gpu-model-shard-pool", Why: "Verified scalar model-shard pool leader: model-shard-replace predicts only exact old-process identity, memory and session retirement; model identity, route and placement facts remain audit-only.",
			Pod: func() PodSpec {
				p := gpuPod
				p.Name = "gpu-model-shard-pool"
				p.WarmPoolConfigured = true
				p.WarmPoolOwnerUID = "rs-uid"
				p.ModelShard = "main"
				p.Role = "leader"
				return p
			}(), Ctx: gpuCtx},
		{Name: "gpu-mig", Why: "Same pod with a MIG device: mig-rebind covers gpuContentionChannel only; gpuColocation stays audit-only.",
			Pod: func() PodSpec { p := gpuPod; p.Name = "gpu-mig"; p.MIGDevice = "1g.10gb"; return p }(), Ctx: gpuCtx},
		{Name: "cpu-served-model", Why: "Ready CPU served model: both session erasers share the produced serving-endpoint prerequisite while the non-GPU session weight remains 0.6.",
			Pod: PodSpec{Namespace: ns, Name: "cpu-served-model", Node: "node-a", ModelID: "model-x", RouteService: "svc", ServingEndpointReady: true}, Ctx: unit},
		{Name: "gpu-adapter", Why: "UID-bound trusted detector observation: adapterIntegrity appears at 3x weight and only adapter-rotate covers it.",
			Pod: func() PodSpec { p := gpuPod; p.Name = "gpu-adapter"; p.SuspectAdapter = "evil"; return p }(), Ctx: gpuCtx},
		{Name: "gpu-phold-zero", Why: "PHold=0: every weight is 0 (base = 0.001*pHold), facts and cover sets are still emitted, nothing can carry gain.",
			Pod: func() PodSpec { p := gpuPod; p.Name = "gpu-phold-zero"; return p }(), Ctx: func() CtxSpec { c := gpuCtx; c.PHold = 0; return c }()},
		{Name: "gpu-dispersion", Why: "Non-neutral physics: the single scarcity scalar (capped at MaxDispersionMult=4) multiplies every fact uniformly; gpuColocation additionally carries CoResidency and modelFingerprint carries ModelRarity.",
			Pod: func() PodSpec { p := gpuPod; p.Name = "gpu-dispersion"; return p }(), Ctx: gpuCtx,
			Physics: &PhysicsSpec{ImageRarity: 2, EPSSMultiplier: 1.5, CoResidency: 2, ModelRarity: 2}},
		vector("gpu-vector-kv", "Trusted pod-targeting phorvex.attack.kv event: session weight x3; cover sets unchanged.", model.AttackVectorKV, true, 0),
		vector("gpu-vector-guardrail", "Trusted pod-targeting phorvex.attack.guardrail event: guardrailBypass weight x3; cover sets unchanged.", model.AttackVectorGuardrail, true, 0),
		vector("gpu-vector-inflight", "Trusted pod-targeting phorvex.attack.inflight event: inflightRequests weight x3; cover sets unchanged.", model.AttackVectorInflight, true, 0),
		vector("gpu-vector-adapter", "Adapter vector without event-owned adapter name and Pod UID: no adapter-integrity fact or boost.", model.AttackVectorAdapter, true, 0),
		vector("gpu-vector-kv-neighbor", "KV vector event propagated from a neighbour (TargetsPod=false): no boost.", model.AttackVectorKV, false, 0),
		vector("gpu-vector-kv-aged", "KV vector event 10h old: recon does not read Age, so the x3 persists while the event is still in the snapshot; only the kill-chain evidence weight ages.", model.AttackVectorKV, true, 36000),
		{Name: "plain-vector-kv", Why: "CPU pod with a KV vector event: the boost lives inside the AI branch, so a non-serving pod is not steered.",
			Pod: PodSpec{Namespace: ns, Name: "plain-vector-kv", Node: "node-a"}, Ctx: unit,
			Events: []EventSpec{{Type: model.AttackVectorKV, TargetsPod: true, Trust: "trusted"}}},
	}, appScoped...)
}

// buildView turns a fixture into the exact producer inputs.
func buildView(f Fixture) (*model.WorkloadView, recon.FactContext) {
	pod := model.Pod{
		Namespace: f.Pod.Namespace, Name: f.Pod.Name, UID: f.Pod.UID, PodResourceVersion: f.Pod.PodResourceVersion,
		ServiceAccount: f.Pod.ServiceAccount, PodBoundKubeAPIAuth: f.Pod.PodBoundKubeAPIAuth, Node: f.Pod.Node,
		OutputPolicyConfigMap: f.Pod.OutputPolicyConfigMap, OutputPolicyRuleSHA256: f.Pod.OutputPolicyRuleSHA256,
		OutputProxySourceSHA256: f.Pod.OutputProxySourceSHA256, OutputSupportSourceSHA256: f.Pod.OutputSupportSourceSHA256,
		OutputEventCreator: f.Pod.OutputEventCreator, OutputPolicyObservation: f.Pod.OutputPolicyObservation,
		HasGPU: f.Pod.HasGPU, MIGDevice: f.Pod.MIGDevice, ModelID: f.Pod.ModelID,
		SuspectAdapter: f.Pod.SuspectAdapter, SuspectConfigObject: f.Pod.SuspectConfigObject,
		SuspectImageDigest: f.Pod.SuspectImageDigest, ControllerUID: f.Pod.ControllerUID,
		RouteService: f.Pod.RouteService, Stateful: f.Pod.Stateful,
		ServingEndpointReady: f.Pod.ServingEndpointReady,
		WarmPoolConfigured:   f.Pod.WarmPoolConfigured, WarmPoolOwnerUID: f.Pod.WarmPoolOwnerUID,
	}
	if f.Pod.SwapGroup != "" || f.Pod.ModelShard != "" || f.Pod.ParallelGroup != "" || f.Pod.Role != "" {
		pod.Labels = map[string]string{
			"phorvex.ai/swap-group":     f.Pod.SwapGroup,
			"phorvex.ai/model-shard":    f.Pod.ModelShard,
			"phorvex.ai/parallel-group": f.Pod.ParallelGroup,
			"phorvex.ai/role":           f.Pod.Role,
		}
	}
	if b := f.Pod.Bound; b != nil {
		pod.VoiceMemoryConfigMap, pod.VoiceMemorySourceSHA256 = b.VoiceMemoryConfigMap, b.VoiceMemorySourceSHA256
		pod.VoiceMemoryDeploymentUID, pod.VoiceMemoryEventCreator = b.VoiceMemoryDeploymentUID, b.VoiceMemoryEventCreator
		pod.VoiceMemoryObservation = b.VoiceMemoryObservation
		pod.VoiceRefundConfigMap, pod.VoiceRefundSourceSHA256 = b.VoiceRefundConfigMap, b.VoiceRefundSourceSHA256
		pod.VoiceRefundDeploymentUID, pod.VoiceRefundEventCreator = b.VoiceRefundDeploymentUID, b.VoiceRefundEventCreator
		pod.VoiceRefundObservation = b.VoiceRefundObservation
		pod.VoiceMCPConfigMap, pod.VoiceMCPSourceSHA256 = b.VoiceMCPConfigMap, b.VoiceMCPSourceSHA256
		pod.VoiceMCPDeploymentUID, pod.VoiceMCPEventCreator = b.VoiceMCPDeploymentUID, b.VoiceMCPEventCreator
		pod.VoiceMCPObservation = b.VoiceMCPObservation
		pod.VoiceOutputConfigMap, pod.VoiceOutputSourceSHA256 = b.VoiceOutputConfigMap, b.VoiceOutputSourceSHA256
		pod.VoiceOutputDeploymentUID, pod.VoiceOutputEventCreator = b.VoiceOutputDeploymentUID, b.VoiceOutputEventCreator
		pod.VoiceOutputObservation = b.VoiceOutputObservation
		pod.VoiceAdmissionConfigMap, pod.VoiceAdmissionSourceSHA256 = b.VoiceAdmissionConfigMap, b.VoiceAdmissionSourceSHA256
		pod.VoiceAdmissionDeploymentUID, pod.VoiceAdmissionEventCreator = b.VoiceAdmissionDeploymentUID, b.VoiceAdmissionEventCreator
		pod.VoiceAdmissionObservation = b.VoiceAdmissionObservation
		pod.LiteLLMClientObservation = b.LiteLLMClientObservation
		pod.EndpointLeaseObservation = b.EndpointLeaseObservation
		pod.CRMRefundObservation = b.CRMRefundObservation
		pod.K8sObjectRevertObservation = b.K8sObjectRevertObservation
		pod.ImageObservation = b.ImageObservation
		pod.DatastoreRestoreObservation = b.DatastoreRestoreObservation
		pod.AgentActionDenyObservation = b.AgentActionDenyObservation
		pod.NodeEscapeObservation = b.NodeEscapeObservation
		pod.NetworkIsolateObservation = b.NetworkIsolateObservation
		pod.CredentialRevokeObservation = b.CredentialRevokeObservation
		pod.ServingRateBudgetObservation = b.ServingRateBudgetObservation
	}
	if pod.SuspectAdapter != "" {
		pod.UID = "fixture-pod-uid"
		pod.AdapterObservation = &model.AdapterObservation{EventName: "fixture-detector", EventUID: "fixture-event-uid",
			CreatorIdentity: "system:serviceaccount:fixture:detector", TargetPodUID: pod.UID, AdapterName: pod.SuspectAdapter}
	}
	ph := model.NeutralPhysics()
	if f.Physics != nil {
		ph.Scanned = true
		ph.ImageRarity, ph.EPSSMultiplier = f.Physics.ImageRarity, f.Physics.EPSSMultiplier
		ph.CoResidency, ph.ModelRarity = f.Physics.CoResidency, f.Physics.ModelRarity
	}
	var events []model.SecurityEventInfo
	for _, e := range f.Events {
		events = append(events, model.SecurityEventInfo{
			Type: e.Type, TargetsPod: e.TargetsPod, Trust: e.Trust,
			Age: time.Duration(e.AgeSeconds * float64(time.Second)), ThreatLevel: "critical",
		})
	}
	view := &model.WorkloadView{Pod: pod, Physics: ph, Events: events}
	ctx := recon.FactContext{
		AssetValue: f.Ctx.AssetValue, PHold: f.Ctx.PHold, StageUrgency: f.Ctx.StageUrgency,
		LateralUrgency: f.Ctx.LateralUrgency, HasGPU: f.Ctx.HasGPU, Stateful: f.Ctx.Stateful,
	}
	for _, nb := range f.Ctx.Neighbors {
		ctx.Neighbors = append(ctx.Neighbors, recon.NeighborRef{Key: nb.Key, Value: nb.Value})
	}
	return view, ctx
}

// factLabel is the human label used in cover lists: the kind, plus the edge for lateral edges.
func factLabel(f recon.Fact) string {
	if f.Edge != "" {
		return f.Kind + "[" + f.Edge + "]"
	}
	return f.Kind
}

// allActions is the full declared vocabulary in report order: MutatingActions first (its
// order is load-bearing for the engine's tie-break), then the declared-only constants.
func allActions() []model.Action {
	out := append([]model.Action(nil), model.MutatingActions...)
	return append(out, declaredOnlyActions...)
}

// Execute runs one fixture through one registered profile.
func Execute(f Fixture, profile recon.ReconProfile) Result {
	view, ctx := buildView(f)
	af := profile.AssetFacts(view, ctx)
	res := Result{Fixture: f.Name, Profile: profile.Name(), AbsentReason: af.AbsentReason, Cover: map[string][]string{}}
	byKey := map[string]recon.Fact{}
	for _, fact := range af.Facts {
		byKey[fact.Key()] = fact
	}
	coveredBy := map[string][]string{}
	for _, action := range allActions() {
		labels := []string{}
		for _, key := range af.CoverByAction[action] {
			fact, ok := byKey[key]
			if !ok {
				// A cover key that names no emitted fact is a producer defect; surface it verbatim.
				labels = append(labels, "UNEMITTED:"+key)
				continue
			}
			labels = append(labels, factLabel(fact))
			coveredBy[key] = append(coveredBy[key], string(action))
		}
		sort.Strings(labels)
		res.Cover[string(action)] = labels
	}
	for action := range af.CoverByAction {
		if _, listed := res.Cover[string(action)]; !listed {
			// An action outside the declared vocabulary would otherwise be invisible.
			labels := append([]string(nil), af.CoverByAction[action]...)
			sort.Strings(labels)
			res.Cover["UNDECLARED:"+string(action)] = labels
		}
	}
	// Facts keep producer emission order: it is deterministic and documents the append sequence.
	for _, fact := range af.Facts {
		actions := append([]string(nil), coveredBy[fact.Key()]...)
		sort.Strings(actions)
		if actions == nil {
			actions = []string{}
		}
		res.Facts = append(res.Facts, FactRow{Scope: string(fact.Scope), Kind: fact.Kind, Edge: fact.Edge, Weight: fact.Weight, CoveredBy: actions})
	}
	if res.Facts == nil {
		res.Facts = []FactRow{}
	}
	return res
}

// Build executes every fixture on every profile and pins the inputs.
func Build(moduleRoot string) (Report, error) {
	rep := Report{Schema: SchemaVersion, Generator: "go run ./tools/covermap", Profiles: profileNames}
	for _, pkg := range inputPackages {
		h, err := hashPackage(moduleRoot, pkg)
		if err != nil {
			return rep, err
		}
		rep.Inputs = append(rep.Inputs, h)
	}
	sum := sha256.New()
	for _, h := range rep.Inputs {
		fmt.Fprintf(sum, "%s %s\n", h.Path, h.SHA256)
	}
	rep.InputsSHA256 = hex.EncodeToString(sum.Sum(nil))
	rep.RegistryOrder = recon.Registry.Names()

	decl, err := declaredVocabulary(moduleRoot)
	if err != nil {
		return rep, err
	}
	rep.Declared = decl
	rep.Fixtures = Fixtures()
	emitted := map[string]bool{}
	for _, name := range profileNames {
		profile, ok := recon.Registry.Get(name)
		if !ok {
			return rep, fmt.Errorf("profile %q is not registered", name)
		}
		for _, f := range rep.Fixtures {
			r := Execute(f, profile)
			for _, fact := range r.Facts {
				emitted[fact.Kind] = true
			}
			rep.Results = append(rep.Results, r)
		}
	}
	rep.Declared.NeverEmitted = []string{}
	for _, kind := range rep.Declared.FactKinds {
		if !emitted[kind] {
			rep.Declared.NeverEmitted = append(rep.Declared.NeverEmitted, kind)
		}
	}
	return rep, nil
}

// hashPackage hashes the sorted non-test .go files of one module-relative directory.
func hashPackage(moduleRoot, rel string) (PackageHash, error) {
	dir := filepath.Join(moduleRoot, filepath.FromSlash(rel))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return PackageHash{}, err
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		files = append(files, n)
	}
	sort.Strings(files)
	sum := sha256.New()
	for _, n := range files {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return PackageHash{}, err
		}
		// Path-prefixed, length-framed so renames and concatenation ambiguities change the hash.
		fmt.Fprintf(sum, "%s\x00%d\x00", n, len(b))
		sum.Write(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
	}
	return PackageHash{Path: rel, Files: files, SHA256: hex.EncodeToString(sum.Sum(nil))}, nil
}

// declaredVocabulary reads the Action constants and Fact* kind constants from the AST of the
// declaring files. This is the declaration itself (not comment text), used only to make a
// constant that no fixture reaches visible; the cover mapping never comes from here.
func declaredVocabulary(moduleRoot string) (Declared, error) {
	var d Declared
	actions, err := stringConsts(filepath.Join(moduleRoot, "internal", "model", "types.go"), func(spec *ast.ValueSpec, ident *ast.Ident) bool {
		t, ok := spec.Type.(*ast.Ident)
		return ok && t.Name == "Action"
	})
	if err != nil {
		return d, err
	}
	d.Actions = actions
	for _, a := range model.MutatingActions {
		d.Mutating = append(d.Mutating, string(a))
	}
	for _, a := range declaredOnlyActions {
		d.DeclaredOnly = append(d.DeclaredOnly, string(a))
	}
	kinds, err := stringConsts(filepath.Join(moduleRoot, "internal", "recon", "facts.go"), func(spec *ast.ValueSpec, ident *ast.Ident) bool {
		return spec.Type == nil && strings.HasPrefix(ident.Name, "Fact") && ident.Name != "FactScope"
	})
	if err != nil {
		return d, err
	}
	d.FactKinds = kinds
	return d, nil
}

// stringConsts returns the string VALUES of the const declarations in file accepted by keep,
// in declaration order.
func stringConsts(file string, keep func(*ast.ValueSpec, *ast.Ident) bool) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !keep(vs, name) || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					return nil, fmt.Errorf("%s: %s: %w", file, name.Name, err)
				}
				out = append(out, v)
			}
		}
	}
	return out, nil
}

// ModuleRoot walks up from dir to the phorvex go.mod.
func ModuleRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for d := abs; ; d = filepath.Dir(d) {
		b, err := os.ReadFile(filepath.Join(d, "go.mod"))
		if err == nil && strings.HasPrefix(string(b), "module github.com/phorvex/phorvex\n") {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("phorvex go.mod not found above %s", abs)
		}
	}
}

// Check reports whether the checked-in report at path equals a fresh render. The returned
// message names which part drifted; nothing is written.
func Check(path string, fresh []byte) (ok bool, msg string, err error) {
	got, err := os.ReadFile(path)
	if err != nil {
		return false, "", err
	}
	if bytes.Equal(got, fresh) {
		return true, "up to date", nil
	}
	gotPin, freshPin := pinLine(got), pinLine(fresh)
	gotTables, freshTables := stripPin(got), stripPin(fresh)
	switch {
	case bytes.Equal(gotTables, freshTables):
		return false, fmt.Sprintf("only the source-input pin differs (checked-in %s, fresh %s): an input package changed without changing the tables; regenerate to re-pin", gotPin, freshPin), nil
	case gotPin == freshPin:
		return false, "the tables differ from a fresh producer run with the SAME source pin: the checked-in file was edited by hand or the fixtures changed; regenerate", nil
	default:
		return false, fmt.Sprintf("the tables AND the source pin differ (checked-in %s, fresh %s): producers or fixtures changed; regenerate", gotPin, freshPin), nil
	}
}

const pinPrefix = "inputs-sha256: "

func pinLine(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, pinPrefix) {
			return strings.TrimPrefix(line, pinPrefix)
		}
	}
	return "(absent)"
}

func stripPin(b []byte) []byte {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, pinPrefix) || strings.HasPrefix(line, `  "inputsSHA256"`) || strings.HasPrefix(line, `      "sha256"`) {
			continue
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}

// Render writes the Markdown report. Everything in it is derived from rep; there is no
// free-text status claim about deployments or live results.
func Render(rep Report) ([]byte, error) {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("# Recon cover map (generated)\n\n")
	w("GENERATED by `%s` — do not edit by hand. `go run ./tools/covermap --check` exits 1 when this file no longer matches a fresh producer run; `--write` regenerates it. `TestCoverMapDocumentIsCurrent` (tools/covermap) runs the same check under `go test ./...`.\n\n", rep.Generator)
	w("Every row below is the output of an actual `ReconProfile.AssetFacts` call on the named fixture. The fixtures are a branch inventory of the producers; their union is **not** runtime eligibility. Candidate generation (actionset), the capability gate, feasibility, cost and selection are downstream of everything here and are described in `build/test-harness/ACTUATOR_COVERAGE.md`. Weights use AssetValue=1, PHold=1, StageUrgency=1 unless the fixture says otherwise, so a weight reads as the producer's multiplier.\n\n")
	w("inputs-sha256: %s\n\n", rep.InputsSHA256)
	w("## Source inputs\n\n")
	w("Content hashes of the non-test Go files that determine this report (renames, comment edits and code edits all change the pin; a commit that touches nothing here does not).\n\n")
	w("| Package | Files | sha256 |\n|---|---|---|\n")
	for _, h := range rep.Inputs {
		w("| `%s` | %d | `%s` |\n", h.Path, len(h.Files), h.SHA256)
	}
	w("\nRegistered profiles, in registration order: %s. Registration alone makes `%s` the default; the runner explicitly selects `ucw-recon` (`internal/runner/manager.go`, `recon.Registry.SetDefault`). Profiles executed here: %s.\n\n",
		codeList(rep.RegistryOrder), first(rep.RegistryOrder), codeList(rep.Profiles))

	w("## Declared vocabulary\n\n")
	w("- Action constants in `internal/model/types.go` (%d): %s\n", len(rep.Declared.Actions), codeList(rep.Declared.Actions))
	w("- `model.MutatingActions` (generatable, in the engine's tie-break order): %s\n", codeList(rep.Declared.Mutating))
	w("- `identity-rotate` remains known stored vocabulary, but native/hybrid support and new dispatch declare it unimplemented for a security effect. A generatable spelling is not proof of runtime support or cover. Historical epoch-label rollback remains metadata cleanup.\n")
	w("- Declared but never generatable: %s\n", codeList(rep.Declared.DeclaredOnly))
	w("- Fact kind constants in `internal/recon/facts.go` (%d): %s\n", len(rep.Declared.FactKinds), codeList(rep.Declared.FactKinds))
	if len(rep.Declared.NeverEmitted) == 0 {
		w("- Declared fact kinds emitted by no fixture: none\n\n")
	} else {
		w("- **Declared fact kinds emitted by no fixture (fixture gap): %s**\n\n", codeList(rep.Declared.NeverEmitted))
	}

	w("## Fixtures\n\n| Fixture | Pod | Context | Events | Why |\n|---|---|---|---|---|\n")
	for _, f := range rep.Fixtures {
		w("| `%s` | %s | %s | %s | %s |\n", f.Name, podSummary(f), ctxSummary(f.Ctx), eventSummary(f.Events), f.Why)
	}
	w("\n")

	w("## Cover grants by action\n\n")
	w("For each declared action: the fact labels its cover set named, and the fixtures (per profile) in which that grant appeared. An action with no row content is coverless in every fixture and is excluded by the capability gate's `no-cover` step before scoring.\n\n")
	w("| Action | Generatable | Cover observed (fact labels) | Granted in |\n|---|---|---|---|\n")
	mutating := map[string]bool{}
	for _, a := range rep.Declared.Mutating {
		mutating[a] = true
	}
	for _, action := range actionOrder(rep) {
		labels := map[string]bool{}
		var granted []string
		for _, r := range rep.Results {
			c := r.Cover[action]
			if len(c) == 0 {
				continue
			}
			for _, l := range c {
				labels[l] = true
			}
			granted = append(granted, r.Profile+":"+r.Fixture)
		}
		gen := "no"
		if mutating[action] {
			gen = "yes"
		}
		if len(labels) == 0 {
			w("| `%s` | %s | — (coverless in every fixture) | — |\n", action, gen)
			continue
		}
		w("| `%s` | %s | %s | %s |\n", action, gen, codeList(sortedKeys(labels)), grantedSummary(granted, rep))
	}
	w("\n")

	w("## Event steering observed\n\n")
	w("For each fixture that carries a SecurityEvent: the fact weights that differ from the event-less fixture with identical pod, physics and context, and whether any cover set differs. A weight boost never adds or removes a cover key.\n\n")
	w("| Fixture | Profile | Event-less baseline | Weight changes | Cover sets changed |\n|---|---|---|---|---|\n")
	for _, row := range steeringRows(rep) {
		changes := "none"
		if len(row.Changes) > 0 {
			changes = codeList(row.Changes)
		}
		w("| `%s` | `%s` | `%s` | %s | %t |\n", row.Fixture, row.Profile, row.Baseline, changes, row.CoverChanged)
	}
	w("\n")

	w("## Facts by fixture and profile\n\n")
	for _, r := range rep.Results {
		w("### `%s` · `%s`\n\n", r.Fixture, r.Profile)
		if r.AbsentReason != "" {
			w("Facts absent: `%s`\n\n", r.AbsentReason)
			continue
		}
		w("| Scope | Fact | Weight | Covered by |\n|---|---|---|---|\n")
		for _, f := range r.Facts {
			cov := "— (audit-only: no action names this key)"
			if len(f.CoveredBy) > 0 {
				cov = codeList(f.CoveredBy)
			}
			label := f.Kind
			if f.Edge != "" {
				label += "[" + f.Edge + "]"
			}
			w("| %s | `%s` | %s | %s |\n", f.Scope, label, strconv.FormatFloat(f.Weight, 'g', -1, 64), cov)
		}
		var coverless []string
		for _, action := range actionOrder(rep) {
			if len(r.Cover[action]) == 0 {
				coverless = append(coverless, action)
			}
		}
		w("\nCoverless actions here: %s\n\n", codeList(coverless))
	}

	w("## Machine-readable report\n\n")
	w("The same content as JSON (fixture inputs are complete, so any reader can rebuild the `WorkloadView`/`FactContext` and re-run the registered profile to verify a row).\n\n")
	js, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, err
	}
	w("```json\n%s\n```\n", js)
	return []byte(b.String()), nil
}

func actionOrder(rep Report) []string {
	out := append([]string(nil), rep.Declared.Mutating...)
	out = append(out, rep.Declared.DeclaredOnly...)
	extra := map[string]bool{}
	for _, r := range rep.Results {
		for a := range r.Cover {
			if strings.HasPrefix(a, "UNDECLARED:") {
				extra[a] = true
			}
		}
	}
	return append(out, sortedKeys(extra)...)
}

// grantedSummary compresses a "profile:fixture" list per profile so a grant that appears
// in most fixtures reads as "all except ..." rather than a wall of names.
func grantedSummary(granted []string, rep Report) string {
	if len(granted) == len(rep.Results) {
		return "every fixture, both profiles"
	}
	byProfile := map[string]map[string]bool{}
	for _, g := range granted {
		profile, fixture, _ := strings.Cut(g, ":")
		if byProfile[profile] == nil {
			byProfile[profile] = map[string]bool{}
		}
		byProfile[profile][fixture] = true
	}
	var parts []string
	for _, profile := range rep.Profiles {
		have := byProfile[profile]
		if len(have) == 0 {
			continue
		}
		var in, out []string
		for _, f := range rep.Fixtures {
			if have[f.Name] {
				in = append(in, f.Name)
			} else {
				out = append(out, f.Name)
			}
		}
		switch {
		case len(out) == 0:
			parts = append(parts, "`"+profile+"`: every fixture")
		case len(in) > len(out):
			parts = append(parts, "`"+profile+"`: all except "+codeList(out))
		default:
			parts = append(parts, "`"+profile+"`: "+codeList(in))
		}
	}
	return strings.Join(parts, "; ")
}

// steeringRows derives, for every fixture that carries events, which fact weights differ
// from the event-less fixture with the same pod, physics and context, and whether any
// cover set changed. This is how the vector boost is reported: measured, not asserted.
type steeringRow struct {
	Fixture, Profile, Baseline string
	Changes                    []string
	CoverChanged               bool
}

func steeringRows(rep Report) []steeringRow {
	byName := map[string]Fixture{}
	for _, f := range rep.Fixtures {
		byName[f.Name] = f
	}
	sameInputs := func(a, b Fixture) bool {
		pa, pb := a.Pod, b.Pod
		pa.Name, pb.Name = "", ""
		if pa != pb || len(b.Events) != 0 {
			return false
		}
		if (a.Physics == nil) != (b.Physics == nil) || (a.Physics != nil && *a.Physics != *b.Physics) {
			return false
		}
		ca, cb := a.Ctx, b.Ctx
		return ca.AssetValue == cb.AssetValue && ca.PHold == cb.PHold && ca.StageUrgency == cb.StageUrgency &&
			ca.LateralUrgency == cb.LateralUrgency && ca.HasGPU == cb.HasGPU && ca.Stateful == cb.Stateful &&
			fmt.Sprint(ca.Neighbors) == fmt.Sprint(cb.Neighbors)
	}
	results := map[string]Result{}
	for _, r := range rep.Results {
		results[r.Profile+":"+r.Fixture] = r
	}
	var rows []steeringRow
	for _, r := range rep.Results {
		f := byName[r.Fixture]
		if len(f.Events) == 0 {
			continue
		}
		row := steeringRow{Fixture: r.Fixture, Profile: r.Profile}
		for _, cand := range rep.Fixtures {
			if sameInputs(f, cand) {
				row.Baseline = cand.Name
				break
			}
		}
		if row.Baseline == "" {
			row.Changes = []string{"(no event-less fixture with identical inputs)"}
			rows = append(rows, row)
			continue
		}
		base := results[r.Profile+":"+row.Baseline]
		baseW := map[string]float64{}
		for _, bf := range base.Facts {
			baseW[bf.Kind+"|"+bf.Edge] = bf.Weight
		}
		for _, ff := range r.Facts {
			bw, ok := baseW[ff.Kind+"|"+ff.Edge]
			switch {
			case !ok:
				row.Changes = append(row.Changes, ff.Kind+" (new fact)")
			case bw == 0 && ff.Weight == 0:
			case bw == 0:
				row.Changes = append(row.Changes, ff.Kind+" 0 -> "+strconv.FormatFloat(ff.Weight, 'g', -1, 64))
			case ff.Weight != bw:
				row.Changes = append(row.Changes, ff.Kind+" x"+strconv.FormatFloat(ff.Weight/bw, 'g', -1, 64))
			}
		}
		for action, cover := range r.Cover {
			if strings.Join(cover, ",") != strings.Join(base.Cover[action], ",") {
				row.CoverChanged = true
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func podSummary(f Fixture) string {
	var parts []string
	if f.Pod.UID != "" {
		parts = append(parts, "uid="+f.Pod.UID)
	}
	if f.Pod.PodResourceVersion != "" {
		parts = append(parts, "podRV="+f.Pod.PodResourceVersion)
	}
	if f.Pod.ServiceAccount != "" {
		parts = append(parts, "serviceAccount="+f.Pod.ServiceAccount)
	}
	if w := f.Pod.PodBoundKubeAPIAuth; w != nil {
		parts = append(parts, "projectionPodUID="+w.PodUID, "projectionSAUID="+w.ServiceAccountUID, "projectionAudience="+w.AudienceSource)
	}
	if f.Pod.Node != "" {
		parts = append(parts, "node="+f.Pod.Node)
	}
	if f.Pod.HasGPU {
		parts = append(parts, "HasGPU")
	}
	if f.Pod.MIGDevice != "" {
		parts = append(parts, "MIGDevice="+f.Pod.MIGDevice)
	}
	if f.Pod.ModelID != "" {
		parts = append(parts, "ModelID="+f.Pod.ModelID)
	}
	if f.Pod.SuspectAdapter != "" {
		parts = append(parts, "SuspectAdapter="+f.Pod.SuspectAdapter)
	}
	if f.Pod.RouteService != "" {
		parts = append(parts, "RouteService="+f.Pod.RouteService)
	}
	if f.Pod.Stateful {
		parts = append(parts, "Stateful")
	}
	if f.Pod.ServingEndpointReady {
		parts = append(parts, "ServingEndpointReady")
	}
	if f.Physics != nil {
		parts = append(parts, fmt.Sprintf("physics(imageRarity=%g, epss=%g, coResidency=%g, modelRarity=%g)",
			f.Physics.ImageRarity, f.Physics.EPSSMultiplier, f.Physics.CoResidency, f.Physics.ModelRarity))
	} else {
		parts = append(parts, "physics=neutral")
	}
	return strings.Join(parts, ", ")
}

func ctxSummary(c CtxSpec) string {
	s := fmt.Sprintf("assetValue=%g pHold=%g stageUrg=%g lateralUrg=%g", c.AssetValue, c.PHold, c.StageUrgency, c.LateralUrgency)
	if c.HasGPU {
		s += " HasGPU"
	}
	if c.Stateful {
		s += " Stateful"
	}
	for _, nb := range c.Neighbors {
		s += fmt.Sprintf(" nb(%s=%g)", nb.Key, nb.Value)
	}
	return s
}

func eventSummary(events []EventSpec) string {
	if len(events) == 0 {
		return "none"
	}
	var parts []string
	for _, e := range events {
		parts = append(parts, fmt.Sprintf("%s targetsPod=%t trust=%s age=%gs", e.Type, e.TargetsPod, e.Trust, e.AgeSeconds))
	}
	return strings.Join(parts, "; ")
}

func codeList(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = "`" + s + "`"
	}
	return strings.Join(out, ", ")
}

func first(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return items[0]
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
