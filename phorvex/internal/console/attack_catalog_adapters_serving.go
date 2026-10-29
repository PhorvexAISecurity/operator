package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	servingRateFamily       = "serving-rate"
	sensitiveOutputFamily   = "sensitive-output"
	servingKVFamily         = "serving-kv"
	servingRateOracle       = "serving-rate-cap-v1"
	sensitiveOutputOracle   = "sensitive-output-redaction-v1"
	servingKVOracle         = "serving-kv-flush-v1"
	servingOracleSchema     = "phorvex.attack-catalogue-serving-oracle.v1"
	servingCleanupSchema    = "phorvex.attack-catalogue-serving-cleanup.v1"
	servingProfileSchema    = "phorvex.attack-catalogue-serving-profile.v1"
	servingDefaultTarget    = defaultTargetID
	servingRateNamespace    = "p5-demo"
	servingRateOperatorNS   = "p5"
	servingOutputNamespace  = "p6-demo"
	servingOutputOperatorNS = "p6"
)

// servingCatalogueProfile is the packaged, server-owned part of a reviewed
// lane record. API callers select only CatalogueID; none of these fields is
// accepted from a request body. Incarnation identities are discovered by the
// non-mutating preflight and then kept in its run-private preparation.
type servingCatalogueProfile struct {
	Schema            string                     `json:"schema"`
	CatalogueID       string                     `json:"catalogueID"`
	Family            string                     `json:"family"`
	Lane              string                     `json:"lane"`
	Namespace         string                     `json:"namespace"`
	OperatorNamespace string                     `json:"operatorNamespace"`
	ExpectedAction    string                     `json:"expectedAction"`
	EventType         string                     `json:"eventType"`
	PolicyName        string                     `json:"policyName"`
	Deployment        string                     `json:"deployment,omitempty"`
	Service           string                     `json:"service,omitempty"`
	Selector          string                     `json:"selector"`
	PodName           string                     `json:"podName,omitempty"`
	ConfigMapName     string                     `json:"configMapName,omitempty"`
	Route             string                     `json:"route,omitempty"`
	Port              int32                      `json:"port,omitempty"`
	RuleID            string                     `json:"ruleID,omitempty"`
	ImplantKey        string                     `json:"implantKey,omitempty"`
	ImplantLabel      string                     `json:"implantLabel,omitempty"`
	ExecutionMode     AttackCatalogExecutionMode `json:"executionMode"`
	TriggerMode       AttackCatalogTriggerMode   `json:"triggerMode"`
}

func (p servingCatalogueProfile) digest() string {
	raw, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (p servingCatalogueProfile) validate() error {
	entry, found := attackcatalog.Lookup(p.CatalogueID)
	if !found || entry.ID != p.CatalogueID || entry.Family != p.Family ||
		entry.ExpectedAction != p.ExpectedAction || entry.EventType != p.EventType {
		return errors.New("serving catalogue profile differs from embedded metadata")
	}
	if p.Schema != servingProfileSchema || p.Lane == "" || p.Namespace == "" ||
		p.OperatorNamespace == "" || p.PolicyName == "" || p.Selector == "" ||
		p.ExecutionMode != AttackCatalogExecutionActive ||
		p.TriggerMode != AttackCatalogTriggerReactive || !entry.ReactiveCompatible {
		return errors.New("serving catalogue profile is incomplete")
	}
	switch p.Family {
	case servingRateFamily:
		if p.Lane != "p5" || p.Namespace != servingRateNamespace || p.OperatorNamespace != servingRateOperatorNS ||
			p.ExpectedAction != "throttle" || p.EventType != "phorvex.attack.serving-cost-harvest" ||
			p.PolicyName != "serving-rate-defense" || p.Deployment != "rate-target" ||
			p.Service != "rate-target" || p.Selector != "app=rate-target" || p.PodName != "" ||
			p.ConfigMapName != "" || p.Route != "" || p.Port != 0 || p.RuleID != "" ||
			p.ImplantKey != "" || p.ImplantLabel != "" {
			return errors.New("serving-rate profile is not the reviewed p5 contract")
		}
	case sensitiveOutputFamily:
		if p.Lane != "p6" || p.Namespace != servingOutputNamespace || p.OperatorNamespace != servingOutputOperatorNS ||
			p.ExpectedAction != "sensitive-output-policy-activate" || p.EventType != "phorvex.attack.sensitive-output" ||
			p.PolicyName != "guardrail-output-fixture" || p.Selector != "app=guardrail-fixture" ||
			!strings.HasPrefix(p.PodName, "gfx-") || p.ConfigMapName != "phorvex-output-policy-"+p.PodName ||
			p.Route != "/v1/support/case" || p.Port != 8000 || p.RuleID != "support-internal-audit-marker-v1" ||
			p.Deployment != "" || p.Service != "" || p.ImplantKey != "" || p.ImplantLabel != "" {
			return errors.New("sensitive-output profile is not the reviewed p6 contract")
		}
	case servingKVFamily:
		if p.Lane != "p6" || p.Namespace != servingOutputNamespace || p.OperatorNamespace != servingOutputOperatorNS ||
			p.ExpectedAction != "kv-reset" || p.EventType != "phorvex.attack.kv" ||
			p.PolicyName != "kv-serving-defense" || p.Deployment != "kv-serving" || p.Service != "kv-serving" ||
			p.Selector != "app.kubernetes.io/name=kv-serving" || p.Port != 8000 ||
			p.ImplantKey != "prompt_inject_implant" || p.ImplantLabel == "" || p.PodName != "" ||
			p.ConfigMapName != "" || p.Route != "" || p.RuleID != "" {
			return errors.New("serving-kv profile is not the reviewed p6 contract")
		}
	default:
		return errors.New("unknown serving catalogue family")
	}
	return nil
}

func servingCatalogueProfiles() []servingCatalogueProfile {
	base := func(id, family string) servingCatalogueProfile {
		return servingCatalogueProfile{Schema: servingProfileSchema, CatalogueID: id, Family: family,
			ExecutionMode: AttackCatalogExecutionActive, TriggerMode: AttackCatalogTriggerReactive}
	}
	profiles := make([]servingCatalogueProfile, 0, 26)
	for _, id := range []string{
		"AML.T0024", "AML.T0024.000", "AML.T0024.001", "AML.T0024.002", "AML.T0029",
		"AML.T0034", "AML.T0034.000", "AML.T0034.001", "AML.T0034.002", "AML.T0046",
		"ASI08:2026", "LLM10:2025", "MS-IM-denial-of-service", "T1110", "T1110.001",
		"T1110.003", "T1110.004", "T1499", "T1499.002", "T1499.003",
	} {
		p := base(id, servingRateFamily)
		p.Lane, p.Namespace, p.OperatorNamespace = "p5", servingRateNamespace, servingRateOperatorNS
		p.ExpectedAction, p.EventType = "throttle", "phorvex.attack.serving-cost-harvest"
		p.PolicyName, p.Deployment, p.Service, p.Selector = "serving-rate-defense", "rate-target", "rate-target", "app=rate-target"
		profiles = append(profiles, p)
	}
	for _, row := range []struct{ id, pod string }{
		{"AML.T0069", "gfx-t0069"},
		{"AML.T0069.001", "gfx-t0069-001"},
		{"AML.T0069.002", "gfx-t0069-002"},
	} {
		p := base(row.id, sensitiveOutputFamily)
		p.Lane, p.Namespace, p.OperatorNamespace = "p6", servingOutputNamespace, servingOutputOperatorNS
		p.ExpectedAction, p.EventType = "sensitive-output-policy-activate", "phorvex.attack.sensitive-output"
		p.PolicyName, p.Selector, p.PodName = "guardrail-output-fixture", "app=guardrail-fixture", row.pod
		p.ConfigMapName = "phorvex-output-policy-" + row.pod
		p.Route, p.Port, p.RuleID = "/v1/support/case", 8000, "support-internal-audit-marker-v1"
		profiles = append(profiles, p)
	}
	for _, row := range []struct{ id, label string }{
		{"AML.T0080", "t0080-agent-context"},
		{"AML.T0080.001", "t0080-001-thread"},
		{"MCP10:2025", "mcp10-context-inject"},
	} {
		p := base(row.id, servingKVFamily)
		p.Lane, p.Namespace, p.OperatorNamespace = "p6", servingOutputNamespace, servingOutputOperatorNS
		p.ExpectedAction, p.EventType = "kv-reset", "phorvex.attack.kv"
		p.PolicyName, p.Deployment, p.Service = "kv-serving-defense", "kv-serving", "kv-serving"
		p.Selector, p.Port = "app.kubernetes.io/name=kv-serving", 8000
		p.ImplantKey, p.ImplantLabel = "prompt_inject_implant", row.label
		profiles = append(profiles, p)
	}
	return profiles
}

// servingCatalogueRuntime owns the Kubernetes preparation and bounded family
// operation. Its observation types deliberately contain no free-form response
// body, command, path, credential, or sensitive marker field.
type servingCatalogueRuntime interface {
	Preflight(context.Context, servingCatalogueProfile) (any, error)
	Execute(context.Context, AttackCatalogRunContext, servingCatalogueProfile, any) (servingCatalogueRuntimeObservation, error)
	Cleanup(context.Context, AttackCatalogRunContext, servingCatalogueProfile, any) servingCatalogueRuntimeCleanup
}

type servingCatalogueSignal struct {
	Created, Observed             bool
	Name, UID, Creator, TargetUID string
	CreatedAt, ObservedAt         time.Time
}

type servingCatalogueDecision struct {
	Observed, Selected, Feasible, Actuated bool
	ID, Action, DispatchOutcome, Handler   string
	ObjectsTouched                         []string
	ObservedAt                             time.Time
}

type servingRatePhysical struct {
	OperationID                                                 string
	Baseline, ElapsedSeconds                                    float64
	AbusiveAttempted, AbusiveAdmitted, AbusiveRejected          uint64
	LegitimateAttempted, LegitimateAdmitted, LegitimateRejected uint64
	CapApplied, ProxyIdentityUnchanged                          bool
}

type sensitiveOutputPhysical struct {
	ConfigMapUID, PolicyUID, OperationID, MarkerSHA256                  string
	BenignSHA256Before, BenignSHA256After                               string
	PolicyGeneration, Revision                                          int64
	BaselineLeaked, ConfigMapActive, ProxyActive, Redacted, PodRetained bool
}

type servingKVPhysical struct {
	BystanderUID                                            string
	BaselineResetCount, AfterResetCount                     uint64
	TargetImplantBefore, TargetImplantAfter, TargetRetained bool
	BystanderImplantRetained, BystanderRetained             bool
	AvailableReplicas, DesiredReplicas                      int32
}

type servingCatalogueRuntimeObservation struct {
	MutationStarted bool
	Launched        bool
	Signal          servingCatalogueSignal
	Decision        servingCatalogueDecision
	Rate            *servingRatePhysical
	Sensitive       *sensitiveOutputPhysical
	KV              *servingKVPhysical
	Reason          string
}

type servingCatalogueRuntimeCleanup struct {
	Attempted, EventDeleted, MarkerDeleted, Restored, RetrySafe bool
	Reason                                                      string
}

type unavailableServingCatalogueRuntime struct{ reason string }

func (u unavailableServingCatalogueRuntime) Preflight(context.Context, servingCatalogueProfile) (any, error) {
	return nil, errors.New(u.reason)
}
func (u unavailableServingCatalogueRuntime) Execute(context.Context, AttackCatalogRunContext, servingCatalogueProfile, any) (servingCatalogueRuntimeObservation, error) {
	return servingCatalogueRuntimeObservation{}, errors.New(u.reason)
}
func (u unavailableServingCatalogueRuntime) Cleanup(context.Context, AttackCatalogRunContext, servingCatalogueProfile, any) servingCatalogueRuntimeCleanup {
	return servingCatalogueRuntimeCleanup{Attempted: true, Reason: u.reason}
}

type servingCatalogueAdapter struct {
	server  *Server
	cfg     Config
	profile servingCatalogueProfile
	runtime servingCatalogueRuntime
}

// newServingCatalogueAdapters returns all and only the reviewed serving/output
// family adapters. Passing the Server binds the production in-cluster runtime;
// the optional form keeps exact profile enumeration hermetic for package tests.
// Registry integration should call newServingCatalogueAdapters(s).
func newServingCatalogueAdapters(servers ...*Server) []AttackCatalogAdapter {
	var server *Server
	if len(servers) == 1 {
		server = servers[0]
	}
	cfg := Config{}
	runtime := servingCatalogueRuntime(unavailableServingCatalogueRuntime{reason: "serving catalogue runtime is not bound to an attacks server"})
	if server != nil {
		cfg = server.cfg
		runtime = newKubernetesServingCatalogueRuntime(server)
	}
	profiles := servingCatalogueProfiles()
	out := make([]AttackCatalogAdapter, 0, len(profiles))
	for _, profile := range profiles {
		if err := profile.validate(); err != nil {
			panic(err)
		}
		out = append(out, &servingCatalogueAdapter{server: server, cfg: cfg, profile: profile, runtime: runtime})
	}
	return out
}

func newServingCatalogueAdapterForTest(profile servingCatalogueProfile, cfg Config, runtime servingCatalogueRuntime) AttackCatalogAdapter {
	return &servingCatalogueAdapter{cfg: cfg, profile: profile, runtime: runtime}
}

func (a *servingCatalogueAdapter) CatalogueID() string { return a.profile.CatalogueID }

func (a *servingCatalogueAdapter) Availability() AttackCatalogAdapterAvailability {
	result := AttackCatalogAdapterAvailability{
		UnavailableReason: "reviewed serving catalogue runtime is unavailable in this deployment",
		RuntimeContext:    servingDefaultTarget,
		TargetLabel:       a.profile.Lane + " / " + a.profile.Namespace + " (server-fixed)",
		FixtureTenant:     a.profile.Namespace,
	}
	if err := a.profile.validate(); err != nil {
		result.UnavailableReason = "packaged serving catalogue profile failed validation"
		return result
	}
	if a.server == nil || a.runtime == nil {
		result.UnavailableReason = "serving catalogue adapter is not bound to an attacks server"
		return result
	}
	if !a.cfg.AttackCatalogEnabled {
		result.UnavailableReason = "serving catalogue launch adapters are disabled by this deployment"
		return result
	}
	if !a.cfg.servesAttacks() {
		result.UnavailableReason = "serving catalogue adapters execute only in the attacks service"
		return result
	}
	if a.cfg.AuditSource == nil {
		result.UnavailableReason = "serving catalogue adapters require the authenticated manager audit source"
		return result
	}
	if strings.TrimSpace(a.cfg.AttackCatalogAuthorizationTenant) == "" {
		result.UnavailableReason = "serving catalogue authorization tenant is not configured"
		return result
	}
	result.Available = true
	result.UnavailableReason = ""
	result.RunnableNote = "Server-fixed " + a.profile.Family + " profile; current object identities and clean baseline are revalidated without mutation at launch."
	return result
}

func (a *servingCatalogueAdapter) Destination() (runDestination, error) {
	if err := a.profile.validate(); err != nil {
		return runDestination{}, errors.New("serving catalogue profile is invalid")
	}
	tenant := strings.TrimSpace(a.cfg.AttackCatalogAuthorizationTenant)
	if tenant == "" {
		return runDestination{}, errors.New("serving catalogue authorization tenant is unavailable")
	}
	return runDestination{Targets: []string{servingDefaultTarget}, Tenants: []string{tenant},
		ScopeTarget: servingDefaultTarget, ScopeTenant: tenant}, nil
}

type servingCataloguePreparation struct {
	adapterID     string
	runID         string
	profile       servingCatalogueProfile
	profileDigest string
	runtime       servingCatalogueRuntime
	runtimeState  any
}

func (p *servingCataloguePreparation) ExecutionMode() AttackCatalogExecutionMode {
	return p.profile.ExecutionMode
}
func (p *servingCataloguePreparation) TriggerMode() AttackCatalogTriggerMode {
	return p.profile.TriggerMode
}
func (p *servingCataloguePreparation) EvidenceTenant() string { return p.profile.Namespace }

func (a *servingCatalogueAdapter) exactRun(run AttackCatalogRunContext) error {
	entry, found := attackcatalog.Lookup(run.CatalogueID)
	if !found || run.CatalogueID != a.profile.CatalogueID || entry.ID != a.profile.CatalogueID ||
		run.ExpectedAction != a.profile.ExpectedAction || entry.ExpectedAction != a.profile.ExpectedAction ||
		entry.Family != a.profile.Family || entry.EventType != a.profile.EventType ||
		run.RunID == "" || !run.ReactiveCompatible {
		return errors.New("serving catalogue adapter received a substituted ID, action, or trigger contract")
	}
	return nil
}

func (a *servingCatalogueAdapter) Preflight(ctx context.Context, run AttackCatalogRunContext) (AttackCatalogPreparation, error) {
	if err := a.profile.validate(); err != nil {
		return nil, errors.New("serving catalogue profile is invalid")
	}
	if err := a.exactRun(run); err != nil {
		return nil, err
	}
	if a.runtime == nil {
		return nil, errors.New("serving catalogue runtime is unavailable")
	}
	state, err := a.runtime.Preflight(ctx, a.profile)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("serving catalogue preflight returned no pinned state")
	}
	return &servingCataloguePreparation{adapterID: a.CatalogueID(), runID: run.RunID, profile: a.profile,
		profileDigest: a.profile.digest(), runtime: a.runtime, runtimeState: state}, nil
}

func (a *servingCatalogueAdapter) prepared(run AttackCatalogRunContext, prepared AttackCatalogPreparation) (*servingCataloguePreparation, error) {
	if err := a.exactRun(run); err != nil {
		return nil, err
	}
	p, ok := prepared.(*servingCataloguePreparation)
	if !ok || p == nil || p.runtimeState == nil || p.runtime == nil || p.runtime != a.runtime ||
		p.adapterID != a.CatalogueID() || p.runID != run.RunID || p.profile.CatalogueID != a.CatalogueID() ||
		p.profileDigest != a.profile.digest() || p.profile != a.profile {
		return nil, errors.New("serving catalogue preflight state changed or belongs to another ID")
	}
	return p, nil
}

func (a *servingCatalogueAdapter) Execute(ctx context.Context, run AttackCatalogRunContext, prepared AttackCatalogPreparation) (AttackCatalogObservation, error) {
	p, err := a.prepared(run, prepared)
	if err != nil {
		return AttackCatalogObservation{}, err
	}
	runtimeObservation, runtimeErr := a.runtime.Execute(ctx, run, a.profile, p.runtimeState)
	receiptObserved := acceptedServingCatalogueReceipt(a.profile, runtimeObservation.Signal, runtimeObservation.Decision)
	actuator := AttackCatalogActuatorResult{ReceiptObserved: receiptObserved,
		Handler:        runtimeObservation.Decision.Handler,
		ObjectsTouched: slices.Clone(runtimeObservation.Decision.ObjectsTouched)}
	if receiptObserved {
		actuator.AcceptedAt = attackCatalogTime(runtimeObservation.Decision.ObservedAt)
	}
	observation := AttackCatalogObservation{
		MutationStarted: runtimeObservation.MutationStarted,
		Launched:        runtimeObservation.Launched,
		Signal: AttackCatalogSignalResult{Created: runtimeObservation.Signal.Created,
			Observed: runtimeObservation.Signal.Observed, Name: runtimeObservation.Signal.Name,
			UID: runtimeObservation.Signal.UID, Creator: runtimeObservation.Signal.Creator,
			TargetUID:  runtimeObservation.Signal.TargetUID,
			CreatedAt:  attackCatalogTime(runtimeObservation.Signal.CreatedAt),
			ObservedAt: attackCatalogTime(runtimeObservation.Signal.ObservedAt)},
		Decision: AttackCatalogDecisionResult{Observed: runtimeObservation.Decision.Observed,
			ID: runtimeObservation.Decision.ID, Selected: runtimeObservation.Decision.Selected,
			Feasible: runtimeObservation.Decision.Feasible, Action: runtimeObservation.Decision.Action,
			DispatchOutcome: runtimeObservation.Decision.DispatchOutcome,
			ObservedAt:      attackCatalogTime(runtimeObservation.Decision.ObservedAt)},
		Actuator: actuator,
		Reason:   runtimeObservation.Reason,
	}
	physical, physicalErr := a.physical(run, runtimeObservation)
	observation.PhysicalValidation = physical
	if runtimeErr != nil {
		return observation, runtimeErr
	}
	if physicalErr != nil {
		return observation, physicalErr
	}
	if err = a.validateRuntimeChain(run, observation); err != nil {
		return observation, err
	}
	observation.DefensiveChainComplete = true
	return observation, nil
}

func acceptedServingCatalogueReceipt(profile servingCatalogueProfile, signal servingCatalogueSignal, decision servingCatalogueDecision) bool {
	return signal.Created && signal.Observed && decision.Observed &&
		validAttackCatalogReceiptTime(signal.ObservedAt, signal.CreatedAt) &&
		validAttackCatalogReceiptTime(decision.ObservedAt, signal.CreatedAt) &&
		!decision.ObservedAt.Before(signal.ObservedAt) &&
		decision.Selected && decision.Feasible && decision.Actuated &&
		decision.Action == profile.ExpectedAction && decision.DispatchOutcome == model.DispatchEmitted &&
		decision.Handler == profile.ExpectedAction && servingObjectReceiptMatches(profile, decision.ObjectsTouched)
}

func (a *servingCatalogueAdapter) validateRuntimeChain(run AttackCatalogRunContext, observation AttackCatalogObservation) error {
	if !observation.MutationStarted || !observation.Launched || !observation.Signal.Created || !observation.Signal.Observed ||
		observation.Signal.Name == "" || observation.Signal.UID == "" || observation.Signal.Creator == "" ||
		observation.Signal.TargetUID == "" || !observation.Decision.Observed || observation.Decision.ID == "" ||
		!observation.Decision.Selected || !observation.Decision.Feasible ||
		observation.Decision.Action != a.profile.ExpectedAction || observation.Decision.DispatchOutcome != "emitted" ||
		!observation.Actuator.ReceiptObserved || observation.Actuator.Handler != a.profile.ExpectedAction ||
		len(observation.Actuator.ObjectsTouched) == 0 || !observation.PhysicalValidation.Validated {
		return errors.New("serving catalogue signal, decision, receipt, or physical chain is incomplete")
	}
	var binding servingOracleBinding
	if err := json.Unmarshal(observation.PhysicalValidation.Evidence, &binding); err != nil {
		return errors.New("serving catalogue physical binding is malformed")
	}
	if err := a.validateBinding(binding, run.RunID, observation.Signal.UID, observation.Decision.ID, observation.Signal.TargetUID); err != nil {
		return err
	}
	return nil
}

type servingOracleBinding struct {
	Schema         string `json:"schema"`
	Family         string `json:"family"`
	CatalogueID    string `json:"catalogueID"`
	RunID          string `json:"runID"`
	ProfileSHA256  string `json:"profileSHA256"`
	SignalUID      string `json:"signalUID"`
	DecisionID     string `json:"decisionID"`
	ExpectedAction string `json:"expectedAction"`
	TargetUID      string `json:"targetUID"`
}

func (a *servingCatalogueAdapter) binding(run AttackCatalogRunContext, o servingCatalogueRuntimeObservation) servingOracleBinding {
	return servingOracleBinding{Schema: servingOracleSchema, Family: a.profile.Family,
		CatalogueID: a.profile.CatalogueID, RunID: run.RunID, ProfileSHA256: a.profile.digest(),
		SignalUID: o.Signal.UID, DecisionID: o.Decision.ID,
		ExpectedAction: a.profile.ExpectedAction, TargetUID: o.Signal.TargetUID}
}

func (a *servingCatalogueAdapter) validateBinding(b servingOracleBinding, runID, signalUID, decisionID, targetUID string) error {
	if b.Schema != servingOracleSchema || b.Family != a.profile.Family || b.CatalogueID != a.profile.CatalogueID ||
		b.RunID != runID || b.ProfileSHA256 != a.profile.digest() || b.SignalUID != signalUID ||
		b.DecisionID != decisionID || b.ExpectedAction != a.profile.ExpectedAction || b.TargetUID != targetUID ||
		runID == "" || signalUID == "" || decisionID == "" || targetUID == "" {
		return errors.New("serving catalogue oracle is not bound to the exact run, signal, decision, target, and profile")
	}
	return nil
}

type servingRateOracleEvidence struct {
	servingOracleBinding
	OperationID            string  `json:"operationID"`
	Baseline               float64 `json:"baselineReqPerSec"`
	ElapsedSeconds         float64 `json:"elapsedSeconds"`
	AbusiveAttempted       uint64  `json:"abusiveAttempted"`
	AbusiveAdmitted        uint64  `json:"abusiveAdmitted"`
	AbusiveRejected        uint64  `json:"abusiveRejected"`
	LegitimateAttempted    uint64  `json:"legitimateAttempted"`
	LegitimateAdmitted     uint64  `json:"legitimateAdmitted"`
	LegitimateRejected     uint64  `json:"legitimateRejected"`
	CapApplied             bool    `json:"capApplied"`
	ProxyIdentityUnchanged bool    `json:"proxyIdentityUnchanged"`
}

type sensitiveOutputOracleEvidence struct {
	servingOracleBinding
	ConfigMapUID       string `json:"configMapUID"`
	PolicyUID          string `json:"policyUID"`
	OperationID        string `json:"operationID"`
	MarkerSHA256       string `json:"markerSHA256"`
	BenignSHA256Before string `json:"benignSHA256Before"`
	BenignSHA256After  string `json:"benignSHA256After"`
	PolicyGeneration   int64  `json:"policyGeneration"`
	Revision           int64  `json:"revision"`
	BaselineLeaked     bool   `json:"baselineLeaked"`
	ConfigMapActive    bool   `json:"configMapActive"`
	ProxyActive        bool   `json:"proxyActive"`
	Redacted           bool   `json:"redacted"`
	PodRetained        bool   `json:"podRetained"`
}

type servingKVOracleEvidence struct {
	servingOracleBinding
	BystanderUID             string `json:"bystanderUID"`
	BaselineResetCount       uint64 `json:"baselineResetCount"`
	AfterResetCount          uint64 `json:"afterResetCount"`
	TargetImplantBefore      bool   `json:"targetImplantBefore"`
	TargetImplantAfter       bool   `json:"targetImplantAfter"`
	TargetRetained           bool   `json:"targetRetained"`
	BystanderImplantRetained bool   `json:"bystanderImplantRetained"`
	BystanderRetained        bool   `json:"bystanderRetained"`
	AvailableReplicas        int32  `json:"availableReplicas"`
	DesiredReplicas          int32  `json:"desiredReplicas"`
}

func marshalServingEvidence(v any) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

func (a *servingCatalogueAdapter) physical(run AttackCatalogRunContext, o servingCatalogueRuntimeObservation) (AttackCatalogPhysicalResult, error) {
	result := AttackCatalogPhysicalResult{PodUID: o.Signal.TargetUID}
	binding := a.binding(run, o)
	switch a.profile.Family {
	case servingRateFamily:
		if o.Rate == nil || o.Sensitive != nil || o.KV != nil {
			return result, errors.New("serving-rate runtime returned the wrong family oracle")
		}
		e := servingRateOracleEvidence{servingOracleBinding: binding, OperationID: o.Rate.OperationID,
			Baseline: o.Rate.Baseline, ElapsedSeconds: o.Rate.ElapsedSeconds,
			AbusiveAttempted: o.Rate.AbusiveAttempted, AbusiveAdmitted: o.Rate.AbusiveAdmitted,
			AbusiveRejected: o.Rate.AbusiveRejected, LegitimateAttempted: o.Rate.LegitimateAttempted,
			LegitimateAdmitted: o.Rate.LegitimateAdmitted, LegitimateRejected: o.Rate.LegitimateRejected,
			CapApplied: o.Rate.CapApplied, ProxyIdentityUnchanged: o.Rate.ProxyIdentityUnchanged}
		raw, err := marshalServingEvidence(e)
		if err != nil {
			return result, err
		}
		result.Oracle, result.Evidence = servingRateOracle, raw
		result.Validated = validateServingRateOracle(e) == nil
	case sensitiveOutputFamily:
		if o.Sensitive == nil || o.Rate != nil || o.KV != nil {
			return result, errors.New("sensitive-output runtime returned the wrong family oracle")
		}
		e := sensitiveOutputOracleEvidence{servingOracleBinding: binding,
			ConfigMapUID: o.Sensitive.ConfigMapUID, PolicyUID: o.Sensitive.PolicyUID,
			OperationID: o.Sensitive.OperationID, MarkerSHA256: o.Sensitive.MarkerSHA256,
			BenignSHA256Before: o.Sensitive.BenignSHA256Before, BenignSHA256After: o.Sensitive.BenignSHA256After,
			PolicyGeneration: o.Sensitive.PolicyGeneration, Revision: o.Sensitive.Revision,
			BaselineLeaked: o.Sensitive.BaselineLeaked, ConfigMapActive: o.Sensitive.ConfigMapActive,
			ProxyActive: o.Sensitive.ProxyActive, Redacted: o.Sensitive.Redacted,
			PodRetained: o.Sensitive.PodRetained}
		raw, err := marshalServingEvidence(e)
		if err != nil {
			return result, err
		}
		result.Oracle, result.Evidence = sensitiveOutputOracle, raw
		result.PodRetained = e.PodRetained
		result.Validated = validateSensitiveOutputOracle(e) == nil
	case servingKVFamily:
		if o.KV == nil || o.Rate != nil || o.Sensitive != nil {
			return result, errors.New("serving-kv runtime returned the wrong family oracle")
		}
		e := servingKVOracleEvidence{servingOracleBinding: binding,
			BystanderUID: o.KV.BystanderUID, BaselineResetCount: o.KV.BaselineResetCount,
			AfterResetCount: o.KV.AfterResetCount, TargetImplantBefore: o.KV.TargetImplantBefore,
			TargetImplantAfter: o.KV.TargetImplantAfter, TargetRetained: o.KV.TargetRetained,
			BystanderImplantRetained: o.KV.BystanderImplantRetained,
			BystanderRetained:        o.KV.BystanderRetained, AvailableReplicas: o.KV.AvailableReplicas,
			DesiredReplicas: o.KV.DesiredReplicas}
		raw, err := marshalServingEvidence(e)
		if err != nil {
			return result, err
		}
		result.Oracle, result.Evidence = servingKVOracle, raw
		result.PodRetained = e.TargetRetained
		result.Validated = validateServingKVOracle(e) == nil
	default:
		return result, errors.New("unknown serving catalogue family")
	}
	if !result.Validated {
		return result, errors.New("serving catalogue family physical oracle did not pass")
	}
	return result, nil
}

func validateServingRateOracle(e servingRateOracleEvidence) error {
	if e.OperationID == "" || !e.CapApplied || !e.ProxyIdentityUnchanged || e.Baseline <= 0 || e.ElapsedSeconds <= 0 ||
		e.AbusiveAttempted == 0 || e.AbusiveRejected == 0 || e.AbusiveAdmitted*20 >= e.AbusiveAttempted ||
		e.LegitimateAttempted == 0 || e.LegitimateAdmitted != e.LegitimateAttempted || e.LegitimateRejected != 0 {
		return errors.New("serving-rate cap and two-sided counter oracle required")
	}
	bound := e.Baseline*(e.ElapsedSeconds+2) + max(1, e.Baseline) + 1
	if float64(e.AbusiveAdmitted) > bound {
		return errors.New("serving-rate admitted count exceeds the measured token-bucket bound")
	}
	return nil
}

func validateSensitiveOutputOracle(e sensitiveOutputOracleEvidence) error {
	if e.ConfigMapUID == "" || e.PolicyUID == "" || e.OperationID == "" || e.PolicyGeneration <= 0 ||
		e.Revision < 1 || len(e.MarkerSHA256) != 64 || len(e.BenignSHA256Before) != 64 ||
		e.BenignSHA256Before != e.BenignSHA256After || !e.BaselineLeaked || !e.ConfigMapActive ||
		!e.ProxyActive || !e.Redacted || !e.PodRetained {
		return errors.New("sensitive-output activation, redaction, retained-Pod, and digest-only oracle required")
	}
	if _, err := hex.DecodeString(e.MarkerSHA256); err != nil {
		return errors.New("sensitive-output marker digest is invalid")
	}
	if _, err := hex.DecodeString(e.BenignSHA256Before); err != nil {
		return errors.New("sensitive-output benign response digest is invalid")
	}
	return nil
}

func validateServingKVOracle(e servingKVOracleEvidence) error {
	if e.BystanderUID == "" || !e.TargetImplantBefore || e.TargetImplantAfter || !e.TargetRetained ||
		!e.BystanderImplantRetained || !e.BystanderRetained || e.AfterResetCount <= e.BaselineResetCount ||
		e.DesiredReplicas < 2 || e.AvailableReplicas != e.DesiredReplicas {
		return errors.New("serving-kv target flush, retained Pod, bystander, and availability oracle required")
	}
	return nil
}

type servingCleanupEvidence struct {
	Schema        string `json:"schema"`
	Family        string `json:"family"`
	CatalogueID   string `json:"catalogueID"`
	RunID         string `json:"runID"`
	ProfileSHA256 string `json:"profileSHA256"`
	EventDeleted  bool   `json:"eventDeleted"`
	MarkerDeleted bool   `json:"markerDeleted"`
	Restored      bool   `json:"restored"`
	RetrySafe     bool   `json:"retrySafe"`
}

func (a *servingCatalogueAdapter) Cleanup(ctx context.Context, run AttackCatalogRunContext, prepared AttackCatalogPreparation) AttackCatalogCleanupResult {
	p, err := a.prepared(run, prepared)
	if err != nil {
		return AttackCatalogCleanupResult{Attempted: true, Reason: err.Error()}
	}
	cleaned := a.runtime.Cleanup(ctx, run, a.profile, p.runtimeState)
	evidence := servingCleanupEvidence{Schema: servingCleanupSchema, Family: a.profile.Family,
		CatalogueID: a.profile.CatalogueID, RunID: run.RunID, ProfileSHA256: a.profile.digest(),
		EventDeleted: cleaned.EventDeleted, MarkerDeleted: cleaned.MarkerDeleted,
		Restored: cleaned.Restored, RetrySafe: cleaned.RetrySafe}
	raw, marshalErr := json.Marshal(evidence)
	if marshalErr != nil {
		cleaned.Reason = "cleanup evidence could not be encoded"
	}
	verified := cleaned.Attempted && cleaned.EventDeleted && cleaned.MarkerDeleted && cleaned.Restored && cleaned.RetrySafe && marshalErr == nil
	return AttackCatalogCleanupResult{Attempted: cleaned.Attempted, EventDeleted: cleaned.EventDeleted,
		MarkerDeleted: cleaned.MarkerDeleted, Verified: verified, Reason: cleaned.Reason, Evidence: raw}
}

func (a *servingCatalogueAdapter) ValidateDefended(result AttackCatalogResult) error {
	if result.CatalogueID != a.CatalogueID() || result.ExpectedAction != a.profile.ExpectedAction ||
		result.ExecutionMode != AttackCatalogExecutionActive || result.TriggerMode != AttackCatalogTriggerReactive ||
		!result.ReactiveOnly || result.Actuator.Handler != a.profile.ExpectedAction || result.PhysicalValidation.PodUID != result.Signal.TargetUID {
		return errors.New("serving catalogue result has the wrong exact profile or runtime modes")
	}
	if !servingObjectReceiptMatches(a.profile, result.Actuator.ObjectsTouched) {
		return errors.New("serving catalogue actuator receipt does not name the fixed family object")
	}
	switch a.profile.Family {
	case servingRateFamily:
		if result.PhysicalValidation.Oracle != servingRateOracle {
			return errors.New("serving-rate physical oracle required")
		}
		var e servingRateOracleEvidence
		if json.Unmarshal(result.PhysicalValidation.Evidence, &e) != nil || validateServingRateOracle(e) != nil {
			return errors.New("serving-rate physical evidence is invalid")
		}
		if err := a.validateBinding(e.servingOracleBinding, result.RunID, result.Signal.UID, result.Decision.ID, result.Signal.TargetUID); err != nil {
			return err
		}
	case sensitiveOutputFamily:
		if result.PhysicalValidation.Oracle != sensitiveOutputOracle {
			return errors.New("sensitive-output physical oracle required")
		}
		var e sensitiveOutputOracleEvidence
		if json.Unmarshal(result.PhysicalValidation.Evidence, &e) != nil || validateSensitiveOutputOracle(e) != nil {
			return errors.New("sensitive-output physical evidence is invalid")
		}
		if err := a.validateBinding(e.servingOracleBinding, result.RunID, result.Signal.UID, result.Decision.ID, result.Signal.TargetUID); err != nil {
			return err
		}
	case servingKVFamily:
		if result.PhysicalValidation.Oracle != servingKVOracle {
			return errors.New("serving-kv physical oracle required")
		}
		var e servingKVOracleEvidence
		if json.Unmarshal(result.PhysicalValidation.Evidence, &e) != nil || validateServingKVOracle(e) != nil {
			return errors.New("serving-kv physical evidence is invalid")
		}
		if err := a.validateBinding(e.servingOracleBinding, result.RunID, result.Signal.UID, result.Decision.ID, result.Signal.TargetUID); err != nil {
			return err
		}
	default:
		return errors.New("unknown serving catalogue family")
	}
	var cleanup servingCleanupEvidence
	if json.Unmarshal(result.Cleanup.Evidence, &cleanup) != nil || cleanup.Schema != servingCleanupSchema ||
		cleanup.Family != a.profile.Family || cleanup.CatalogueID != a.profile.CatalogueID || cleanup.RunID != result.RunID ||
		cleanup.ProfileSHA256 != a.profile.digest() || !cleanup.EventDeleted || !cleanup.MarkerDeleted ||
		!cleanup.Restored || !cleanup.RetrySafe {
		return errors.New("serving catalogue exact retry-safe cleanup evidence required")
	}
	return nil
}

func servingObjectReceiptMatches(profile servingCatalogueProfile, objects []string) bool {
	wants := []string(nil)
	switch profile.Family {
	case servingRateFamily:
		wants = []string{"configmap/" + profile.Namespace + "/phorvex-serving-rate-budget", "ConfigMap/" + profile.Namespace + "/phorvex-serving-rate-budget"}
	case sensitiveOutputFamily:
		wants = []string{profile.Namespace + "/" + profile.ConfigMapName, "configmap/" + profile.Namespace + "/" + profile.ConfigMapName,
			"ConfigMap/" + profile.Namespace + "/" + profile.ConfigMapName}
	case servingKVFamily:
		wants = []string{"pod/" + profile.Namespace + "/", "Pod/" + profile.Namespace + "/"}
	}
	for _, object := range objects {
		for _, want := range wants {
			if object == want || profile.Family == servingKVFamily && strings.HasPrefix(object, want) {
				return true
			}
		}
	}
	return false
}

func (a *servingCatalogueAdapter) DefendedReason() string {
	switch a.profile.Family {
	case servingRateFamily:
		return "exact detector-bound throttle receipt, abusive cap, legitimate traffic control, release and cleanup passed"
	case sensitiveOutputFamily:
		return "exact event-bound output-policy receipt, digest-only redaction oracle, baseline restore and cleanup passed"
	case servingKVFamily:
		return "exact event-bound kv-reset receipt, target flush, retained Pod, bystander control and cleanup passed"
	default:
		return fmt.Sprintf("exact %s serving catalogue chain and cleanup passed", a.profile.Family)
	}
}
