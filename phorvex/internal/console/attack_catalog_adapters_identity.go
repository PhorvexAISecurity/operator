package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/agentdeny"
	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	"k8s.io/apimachinery/pkg/util/validation"
)

// identityCatalogueFamily is deliberately closed. These are the three reviewed
// catalogue families whose product actions have exact, typed observation and
// actuation contracts in the manager.
type identityCatalogueFamily string

const (
	identityCatalogueCredential identityCatalogueFamily = "credential"
	identityCatalogueRotation   identityCatalogueFamily = "identity-sa-rotate"
	identityCatalogueAgent      identityCatalogueFamily = "agent-action"

	identityRotationOracle = "service-account-rotation-v1"
	credentialRevokeOracle = "credential-revoke-token-rejection-v1"
	agentActionDenyOracle  = "agent-action-deny-enforcement-v1"

	identityCatalogueCleanupSchema        = "phorvex.attack-catalogue-identity-cleanup.v1"
	agentActionCatalogueUnavailableReason = "agent-action-deny catalogue profile is not installable: packaging has no digest-pinned server-owned agent-sim image, immutable fixed fixture manifest, or attacks-service fixture RBAC"
)

// identityCatalogueProfile is a review pin, not a caller-selected launch
// profile. Every field is checked against the embedded authoritative catalogue
// before an adapter can prepare a run.
type identityCatalogueProfile struct {
	ID             string
	Family         identityCatalogueFamily
	ExpectedAction string
	EventType      string
	Lane           string
}

var credentialCatalogueIDs = [...]string{
	"AML.T0035", "AML.T0055", "AML.T0082", "AML.T0083", "AML.T0098", "MCP01:2025",
	"MS-CO-images-from-a-private-", "MS-CR-access-managed-identit", "MS-CR-application-credential",
	"MS-CR-list-kubernetes-secret", "MS-CR-mount-service-principa", "MS-IN-kubeconfig-file",
	"MS-IN-using-cloud-credential", "MS-PR-access-cloud-resources", "T1059.009", "T1078.004",
	"T1098.001", "T1098.003", "T1136.003", "T1552", "T1552.001", "T1552.003", "T1552.004", "T1552.007",
}

var identityRotationCatalogueIDs = [...]string{
	// AML.T0012 is intentionally absent. The original adapter remains the sole
	// owner of that ID and is registered separately by the core runtime.
	"AML.T0073", "ASI03:2026", "MS-CO-collecting-data-from-p", "MS-EX-exec-into-container",
	"MS-PE-container-service-acco", "T1059.013", "T1078", "T1078.001", "T1528", "T1550", "T1550.001", "T1609",
}

var agentActionCatalogueIDs = [...]string{
	"AML.T0053", "AML.T0086", "AML.T0101", "ASI02:2026", "LLM06:2025", "MCP02:2025",
}

// identityCatalogueAdapterFactory keeps central registry ownership out of this
// family module. The registry binds each factory with its server/config, then
// registers the returned exact-ID adapter.
type identityCatalogueAdapterFactory struct {
	profile identityCatalogueProfile
	err     error
}

// newIdentityCatalogueAdapters returns the 42 new exact-ID factories. Together
// with the existing AML.T0012 adapter they cover the reviewed 43-ID set without
// duplicating or replacing AML.T0012.
func newIdentityCatalogueAdapters() []identityCatalogueAdapterFactory {
	profiles := make([]identityCatalogueProfile, 0, len(credentialCatalogueIDs)+len(identityRotationCatalogueIDs)+len(agentActionCatalogueIDs))
	for _, id := range credentialCatalogueIDs {
		profiles = append(profiles, identityCatalogueProfile{ID: id, Family: identityCatalogueCredential,
			ExpectedAction: string(model.ActionCredentialRevoke), EventType: model.AttackVectorCredentialTheft, Lane: "p4"})
	}
	for _, id := range identityRotationCatalogueIDs {
		profiles = append(profiles, identityCatalogueProfile{ID: id, Family: identityCatalogueRotation,
			ExpectedAction: string(model.ActionIdentityRotate), EventType: model.AttackVectorPodBoundAPIAuth, Lane: "p6"})
	}
	for _, id := range agentActionCatalogueIDs {
		profiles = append(profiles, identityCatalogueProfile{ID: id, Family: identityCatalogueAgent,
			ExpectedAction: string(model.ActionAgentActionDeny), EventType: model.AttackVectorAgentActionAbuse, Lane: "p6"})
	}
	result := make([]identityCatalogueAdapterFactory, 0, len(profiles))
	for _, profile := range profiles {
		result = append(result, identityCatalogueAdapterFactory{profile: profile, err: validateIdentityCatalogueProfile(profile)})
	}
	return result
}

func validateIdentityCatalogueProfile(profile identityCatalogueProfile) error {
	if profile.ID == "" || profile.ID == attackcatalog.FirstID || strings.TrimSpace(profile.ID) != profile.ID ||
		profile.ExpectedAction == "" || profile.EventType == "" || profile.Lane == "" {
		return errors.New("identity-family catalogue profile is incomplete or reserved")
	}
	entry, ok := attackcatalog.Lookup(profile.ID)
	if !ok || entry.ID != profile.ID || entry.Family != string(profile.Family) ||
		entry.ExpectedAction != profile.ExpectedAction || entry.EventType != profile.EventType ||
		entry.Lane != profile.Lane || entry.Mode != "lane" || entry.Expected != "DEFENDED" || !entry.ReactiveCompatible {
		return fmt.Errorf("catalogue profile %q differs from embedded review pins", profile.ID)
	}
	switch profile.Family {
	case identityCatalogueCredential:
		if err := validateCredentialCatalogueServerProfile(profile.ID); err != nil {
			return err
		}
	case identityCatalogueAgent:
		if err := validateAgentCatalogueServerProfile(profile.ID); err != nil {
			return err
		}
	}
	return nil
}

func (factory identityCatalogueAdapterFactory) bind(server *Server, cfg Config) AttackCatalogAdapter {
	adapter := &identityFamilyCatalogueAdapter{profile: factory.profile, server: server, cfg: cfg, profileErr: factory.err}
	if factory.err != nil {
		return adapter
	}
	switch factory.profile.Family {
	case identityCatalogueRotation:
		adapter.binding = &identityRotationCatalogueBinding{server: server, cfg: cfg}
	case identityCatalogueCredential:
		adapter.binding = &identityCredentialCatalogueBinding{server: server, cfg: cfg}
	case identityCatalogueAgent:
		adapter.blocker = agentActionCatalogueUnavailableReason
	default:
		adapter.blocker = "catalogue family is not supported by this runtime"
	}
	return adapter
}

// identityCatalogueBindingPreparation contains only non-secret identities that
// the adapter must bind into audit and result records. Binding-private state may
// contain a credential solely in memory; it is never formatted or serialized.
type identityCatalogueBindingPreparation struct {
	Execution        AttackCatalogExecutionMode
	Trigger          AttackCatalogTriggerMode
	EvidenceTenant   string
	Namespace        string
	PodName          string
	TargetUID        string
	PolicyName       string
	PolicyUID        string
	PolicyGeneration int64
	ReceiptObject    string
	private          any
}

type identityCatalogueBindingSignal struct {
	Name, UID, Creator string
	CreatedAt          time.Time
}

type identityCataloguePhysicalObservation struct {
	OldServiceAccountUID          string
	NewServiceAccountUID          string
	ServiceAccountUID             string
	PodUID                        string
	GuardUID                      string
	ServiceUID                    string
	CredentialAuthenticatedBefore bool
	CredentialAuthenticatedAfter  bool
	CredentialObjectAbsent        bool
	FreshCredentialAuthenticated  bool
	AvailabilityFloorRetained     bool
	PodRetained                   bool
	DeniedBefore                  bool
	DeniedAfter                   bool
	BenignAllowedAfter            bool
	ServingSetRetained            bool
}

type identityCatalogueCleanupObservation struct {
	Attempted       bool
	EventAbsent     bool
	FixtureRestored bool
}

// identityCatalogueFamilyBinding is the narrow product seam. Preflight is
// read-only with respect to persistent fixture state. Launch is the first place
// mutation may begin. Cleanup must be idempotent and verify exact absence/state.
type identityCatalogueFamilyBinding interface {
	Availability(identityCatalogueProfile) AttackCatalogAdapterAvailability
	Destination(identityCatalogueProfile) (runDestination, error)
	Preflight(context.Context, identityCatalogueProfile) (*identityCatalogueBindingPreparation, error)
	Launch(context.Context, identityCatalogueProfile, AttackCatalogRunContext, *identityCatalogueBindingPreparation) (identityCatalogueBindingSignal, bool, error)
	Physical(context.Context, identityCatalogueProfile, *identityCatalogueBindingPreparation) (identityCataloguePhysicalObservation, error)
	Cleanup(context.Context, identityCatalogueProfile, *identityCatalogueBindingPreparation, identityCatalogueBindingSignal) (identityCatalogueCleanupObservation, error)
}

type identityFamilyCatalogueAdapter struct {
	profile      identityCatalogueProfile
	server       *Server
	cfg          Config
	profileErr   error
	blocker      string
	binding      identityCatalogueFamilyBinding
	pollInterval time.Duration
	records      func(context.Context) ([]audit.Record, error)
}

func (a *identityFamilyCatalogueAdapter) CatalogueID() string { return a.profile.ID }

func (a *identityFamilyCatalogueAdapter) Availability() AttackCatalogAdapterAvailability {
	if a == nil {
		return AttackCatalogAdapterAvailability{UnavailableReason: "identity-family catalogue adapter is absent"}
	}
	if a.profileErr != nil {
		return AttackCatalogAdapterAvailability{UnavailableReason: "identity-family catalogue metadata binding is invalid"}
	}
	if a.binding == nil {
		reason := a.blocker
		if reason == "" {
			reason = "identity-family catalogue product binding is unavailable"
		}
		return AttackCatalogAdapterAvailability{UnavailableReason: reason, TargetLabel: "Unavailable reviewed fixture"}
	}
	return a.binding.Availability(a.profile)
}

func (a *identityFamilyCatalogueAdapter) Destination() (runDestination, error) {
	if a == nil || a.profileErr != nil {
		return runDestination{}, errors.New("identity-family catalogue destination is unavailable")
	}
	if a.binding == nil {
		return runDestination{}, errors.New(a.Availability().UnavailableReason)
	}
	return a.binding.Destination(a.profile)
}

type identityFamilyCataloguePreparation struct {
	adapterID string
	profile   identityCatalogueProfile
	binding   identityCatalogueFamilyBinding
	prepared  *identityCatalogueBindingPreparation
	signal    identityCatalogueBindingSignal
}

func (p *identityFamilyCataloguePreparation) ExecutionMode() AttackCatalogExecutionMode {
	if p == nil || p.prepared == nil {
		return ""
	}
	return p.prepared.Execution
}

func (p *identityFamilyCataloguePreparation) TriggerMode() AttackCatalogTriggerMode {
	if p == nil || p.prepared == nil {
		return ""
	}
	return p.prepared.Trigger
}

func (p *identityFamilyCataloguePreparation) EvidenceTenant() string {
	if p == nil || p.prepared == nil {
		return ""
	}
	return p.prepared.EvidenceTenant
}

func (a *identityFamilyCatalogueAdapter) exactRun(run AttackCatalogRunContext) error {
	if a == nil || a.profileErr != nil || run.RunID == "" || run.CatalogueID != a.profile.ID ||
		run.ExpectedAction != a.profile.ExpectedAction || !run.ReactiveCompatible {
		return errors.New("identity-family adapter received a different run identity or profile")
	}
	return validateIdentityCatalogueProfile(a.profile)
}

func (a *identityFamilyCatalogueAdapter) Preflight(ctx context.Context, run AttackCatalogRunContext) (AttackCatalogPreparation, error) {
	if err := a.exactRun(run); err != nil {
		return nil, err
	}
	if a.binding == nil || !a.Availability().Available {
		return nil, errors.New("identity-family catalogue product binding is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prepared, err := a.binding.Preflight(ctx, a.profile)
	if err != nil {
		return nil, safeIdentityCatalogueStageError(a.profile.Family, "preflight", err)
	}
	if err = validateIdentityBindingPreparation(a.profile, prepared); err != nil {
		return nil, err
	}
	return &identityFamilyCataloguePreparation{adapterID: a.profile.ID, profile: a.profile, binding: a.binding, prepared: prepared}, nil
}

func validateIdentityBindingPreparation(profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation) error {
	if prepared == nil || !validAttackCatalogModes(prepared.Execution, prepared.Trigger) ||
		prepared.EvidenceTenant == "" || prepared.Namespace == "" || prepared.EvidenceTenant != prepared.Namespace ||
		prepared.PodName == "" || prepared.TargetUID == "" || prepared.PolicyName == "" || prepared.PolicyUID == "" ||
		prepared.PolicyGeneration < 1 || prepared.ReceiptObject == "" || prepared.private == nil {
		return errors.New("identity-family preflight did not bind one exact non-secret fixture profile")
	}
	if len(validation.IsDNS1123Label(prepared.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(prepared.PodName)) != 0 ||
		len(validation.IsDNS1123Subdomain(prepared.PolicyName)) != 0 || !identityCatalogueSafeOpaqueID(prepared.TargetUID) ||
		!identityCatalogueSafeOpaqueID(prepared.PolicyUID) || !validIdentityCatalogueReceipt(profile, prepared) {
		return errors.New("identity-family preflight receipt binding is invalid")
	}
	return nil
}

func validIdentityCatalogueReceipt(profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation) bool {
	if profile.ExpectedAction == "" || prepared == nil || strings.ContainsAny(prepared.ReceiptObject, "\r\n\t=") {
		return false
	}
	parts := strings.Split(prepared.ReceiptObject, "/")
	switch profile.Family {
	case identityCatalogueRotation, identityCatalogueCredential:
		kind := "ServiceAccount"
		if profile.Family == identityCatalogueCredential {
			kind = "Secret"
		}
		return len(parts) == 3 && parts[0] == kind && parts[1] == prepared.Namespace &&
			len(validation.IsDNS1123Subdomain(parts[2])) == 0
	case identityCatalogueAgent:
		return len(parts) == 2 && parts[0] == prepared.Namespace && parts[1] == agentdeny.GuardConfigMapName
	default:
		return false
	}
}

func identityCatalogueSafeOpaqueID(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\t =")
}

func (a *identityFamilyCatalogueAdapter) Execute(ctx context.Context, run AttackCatalogRunContext, preparation AttackCatalogPreparation) (AttackCatalogObservation, error) {
	observation := AttackCatalogObservation{Reason: "bounded identity-family validation did not complete before its deadline"}
	if err := a.exactRun(run); err != nil {
		return observation, err
	}
	prepared, ok := preparation.(*identityFamilyCataloguePreparation)
	if !ok || prepared == nil || prepared.adapterID != a.profile.ID || prepared.profile != a.profile ||
		prepared.binding != a.binding || prepared.prepared == nil {
		return observation, errors.New("identity-family preparation belongs to another adapter or profile")
	}
	if err := ctx.Err(); err != nil {
		return observation, err
	}
	signal, mutationStarted, err := a.binding.Launch(ctx, a.profile, run, prepared.prepared)
	prepared.signal = signal
	observation.MutationStarted = mutationStarted
	if err != nil {
		return observation, safeIdentityCatalogueStageError(a.profile.Family, "launch", err)
	}
	if err = validateIdentityCatalogueSignal(signal); err != nil {
		return observation, err
	}
	observation.Launched = true
	observation.Signal = AttackCatalogSignalResult{Created: true, Name: signal.Name, UID: signal.UID,
		Creator: signal.Creator, TargetUID: prepared.prepared.TargetUID}

	interval := a.pollInterval
	if interval <= 0 {
		interval = a.cfg.AttackCatalogPollInterval
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		rows, readErr := a.readRecords(ctx)
		if readErr == nil {
			for _, row := range rows {
				observed, decision, receipt := identityFamilyCatalogueDecision(a.profile, row, prepared.prepared, signal)
				if observed {
					observation.Signal.Observed = true
					if !observation.Actuator.ReceiptObserved || receipt.ReceiptObserved {
						observation.Decision, observation.Actuator = decision, receipt
					}
				}
			}
		}
		physical, physicalErr := a.binding.Physical(ctx, a.profile, prepared.prepared)
		if physicalErr == nil {
			observation.PhysicalValidation = encodeIdentityCataloguePhysical(a.profile, physical)
		}
		if observation.Signal.Observed && observation.Actuator.ReceiptObserved && observation.PhysicalValidation.Validated {
			observation.DefensiveChainComplete = true
			return observation, nil
		}
		select {
		case <-ctx.Done():
			if observation.Actuator.ReceiptObserved && !observation.PhysicalValidation.Validated {
				observation.Reason = "exact actuator receipt was observed but the family physical oracle did not pass"
			} else if observation.Signal.Created && !observation.Signal.Observed {
				observation.Reason = "signal was created but no fresh exact event-bound decision observation was found"
			}
			return observation, nil
		case <-ticker.C:
		}
	}
}

func (a *identityFamilyCatalogueAdapter) readRecords(ctx context.Context) ([]audit.Record, error) {
	if a.records != nil {
		return a.records(ctx)
	}
	if a.server == nil {
		return nil, errors.New("authenticated decision source is unavailable")
	}
	return a.server.readAttackCatalogAudit(ctx)
}

func validateIdentityCatalogueSignal(signal identityCatalogueBindingSignal) error {
	if signal.Name == "" || signal.UID == "" || signal.Creator == "" || signal.CreatedAt.IsZero() ||
		len(signal.Name) > 253 || len(signal.UID) > 128 || len(signal.Creator) > 253 ||
		len(validation.IsDNS1123Subdomain(signal.Name)) != 0 || !identityCatalogueSafeOpaqueID(signal.UID) ||
		!identityCatalogueServiceAccountPrincipal(signal.Creator) {
		return errors.New("identity-family launch returned an invalid or unsafe signal identity")
	}
	return nil
}

func identityCatalogueServiceAccountPrincipal(value string) bool {
	parts := strings.Split(value, ":")
	return len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" &&
		len(validation.IsDNS1123Label(parts[2])) == 0 && len(validation.IsDNS1123Subdomain(parts[3])) == 0
}

func identityFamilyCatalogueDecision(profile identityCatalogueProfile, rec audit.Record, prepared *identityCatalogueBindingPreparation, signal identityCatalogueBindingSignal) (bool, AttackCatalogDecisionResult, AttackCatalogActuatorResult) {
	if prepared == nil || rec.Kind != "phorvex.decision" || rec.Time.Before(signal.CreatedAt) ||
		rec.Namespace != prepared.Namespace || rec.Pod != prepared.PodName || rec.DecisionTrace == nil ||
		rec.DecisionTrace.PolicyNamespace != prepared.Namespace || rec.DecisionTrace.PolicyName != prepared.PolicyName ||
		rec.DecisionTrace.PolicyUID != prepared.PolicyUID || rec.DecisionTrace.AssetUID != prepared.TargetUID ||
		rec.DecisionTrace.DecisionID == "" || rec.DecisionTrace.SelectedAction != rec.Action ||
		rec.DecisionTrace.DryRun != rec.DryRun ||
		(rec.DispatchOutcome != "" && rec.DecisionTrace.DispatchOutcome != rec.DispatchOutcome) {
		return false, AttackCatalogDecisionResult{}, AttackCatalogActuatorResult{}
	}
	matches := 0
	for _, event := range rec.Events {
		if event.EventUID == signal.UID && event.Name == signal.Name && event.Type == profile.EventType &&
			event.CreatorIdentity == signal.Creator && event.TargetPodUID == prepared.TargetUID &&
			event.TrustVerdict == "trusted" && event.TargetsPod && event.TimestampPresent {
			matches++
		}
	}
	if matches != 1 {
		return false, AttackCatalogDecisionResult{}, AttackCatalogActuatorResult{}
	}
	decision := AttackCatalogDecisionResult{Observed: true, ID: rec.DecisionTrace.DecisionID, Selected: rec.Selected,
		Feasible: rec.Feasible, Action: rec.Action, DispatchOutcome: rec.DecisionTrace.DispatchOutcome}
	receipt := AttackCatalogActuatorResult{}
	receipt.ReceiptObserved = rec.Action == profile.ExpectedAction && rec.Selected && rec.Feasible && rec.Actuated && !rec.DryRun &&
		rec.DecisionTrace.DispatchOutcome == model.DispatchEmitted && rec.Handler == profile.ExpectedAction &&
		slices.Contains(rec.ObjectsTouched, prepared.ReceiptObject)
	if receipt.ReceiptObserved {
		// Persist only the already-pinned receipt object; never copy arbitrary
		// audit strings into catalogue evidence.
		receipt.Handler = profile.ExpectedAction
		receipt.ObjectsTouched = []string{prepared.ReceiptObject}
	}
	return true, decision, receipt
}

func encodeIdentityCataloguePhysical(profile identityCatalogueProfile, observed identityCataloguePhysicalObservation) AttackCatalogPhysicalResult {
	switch profile.Family {
	case identityCatalogueRotation:
		validated := observed.OldServiceAccountUID != "" && observed.NewServiceAccountUID != "" &&
			observed.OldServiceAccountUID != observed.NewServiceAccountUID && observed.PodUID != "" &&
			observed.CredentialAuthenticatedBefore && !observed.CredentialAuthenticatedAfter && observed.PodRetained
		return AttackCatalogPhysicalResult{Validated: validated, Oracle: identityRotationOracle,
			OldServiceAccountUID: observed.OldServiceAccountUID, NewServiceAccountUID: observed.NewServiceAccountUID,
			CredentialAuthenticatedBefore: observed.CredentialAuthenticatedBefore,
			CredentialAuthenticatedAfter:  observed.CredentialAuthenticatedAfter,
			PodRetained:                   observed.PodRetained, PodUID: observed.PodUID}
	case identityCatalogueCredential:
		evidence := credentialRevokeEvidence{Schema: credentialRevokeOracle, PodUID: observed.PodUID,
			ServiceAccountUID: observed.ServiceAccountUID, AuthenticatedBefore: observed.CredentialAuthenticatedBefore,
			AuthenticatedAfter: observed.CredentialAuthenticatedAfter, CredentialObjectAbsent: observed.CredentialObjectAbsent,
			FreshCredentialAuthenticated: observed.FreshCredentialAuthenticated,
			AvailabilityFloorRetained:    observed.AvailabilityFloorRetained, PodRetained: observed.PodRetained}
		evidence.Validated = evidence.PodUID != "" && evidence.ServiceAccountUID != "" && evidence.AuthenticatedBefore &&
			!evidence.AuthenticatedAfter && evidence.CredentialObjectAbsent && evidence.FreshCredentialAuthenticated &&
			evidence.AvailabilityFloorRetained && evidence.PodRetained
		raw, _ := json.Marshal(evidence)
		return AttackCatalogPhysicalResult{Validated: evidence.Validated, Oracle: credentialRevokeOracle, Evidence: raw,
			CredentialAuthenticatedBefore: evidence.AuthenticatedBefore,
			CredentialAuthenticatedAfter:  evidence.AuthenticatedAfter, PodRetained: evidence.PodRetained, PodUID: evidence.PodUID}
	case identityCatalogueAgent:
		evidence := agentActionDenyEvidence{Schema: agentActionDenyOracle, PodUID: observed.PodUID,
			GuardUID: observed.GuardUID, ServiceUID: observed.ServiceUID, DeniedBefore: observed.DeniedBefore,
			DeniedAfter: observed.DeniedAfter, BenignAllowedAfter: observed.BenignAllowedAfter,
			ServingSetRetained: observed.ServingSetRetained}
		evidence.Validated = evidence.PodUID != "" && evidence.GuardUID != "" && evidence.ServiceUID != "" &&
			!evidence.DeniedBefore && evidence.DeniedAfter && evidence.BenignAllowedAfter && evidence.ServingSetRetained
		raw, _ := json.Marshal(evidence)
		return AttackCatalogPhysicalResult{Validated: evidence.Validated, Oracle: agentActionDenyOracle, Evidence: raw,
			PodRetained: evidence.ServingSetRetained, PodUID: evidence.PodUID}
	default:
		return AttackCatalogPhysicalResult{}
	}
}

type credentialRevokeEvidence struct {
	Schema                       string `json:"schema"`
	Validated                    bool   `json:"validated"`
	PodUID                       string `json:"podUID"`
	ServiceAccountUID            string `json:"serviceAccountUID"`
	AuthenticatedBefore          bool   `json:"authenticatedBefore"`
	AuthenticatedAfter           bool   `json:"authenticatedAfter"`
	CredentialObjectAbsent       bool   `json:"credentialObjectAbsent"`
	FreshCredentialAuthenticated bool   `json:"freshCredentialAuthenticated"`
	AvailabilityFloorRetained    bool   `json:"availabilityFloorRetained"`
	PodRetained                  bool   `json:"podRetained"`
}

type agentActionDenyEvidence struct {
	Schema             string `json:"schema"`
	Validated          bool   `json:"validated"`
	PodUID             string `json:"podUID"`
	GuardUID           string `json:"guardUID"`
	ServiceUID         string `json:"serviceUID"`
	DeniedBefore       bool   `json:"deniedBefore"`
	DeniedAfter        bool   `json:"deniedAfter"`
	BenignAllowedAfter bool   `json:"benignAllowedAfter"`
	ServingSetRetained bool   `json:"servingSetRetained"`
}

type identityCatalogueCleanupEvidence struct {
	Schema          string `json:"schema"`
	CatalogueID     string `json:"catalogueID"`
	ReceiptSHA256   string `json:"receiptSHA256"`
	EventAbsent     bool   `json:"eventAbsent"`
	FixtureRestored bool   `json:"fixtureRestored"`
}

func (a *identityFamilyCatalogueAdapter) Cleanup(ctx context.Context, _ AttackCatalogRunContext, preparation AttackCatalogPreparation) AttackCatalogCleanupResult {
	prepared, ok := preparation.(*identityFamilyCataloguePreparation)
	if !ok || prepared == nil || prepared.binding == nil || prepared.prepared == nil || prepared.adapterID != a.profile.ID {
		return AttackCatalogCleanupResult{Attempted: true, Reason: "identity-family cleanup preparation is invalid"}
	}
	cleaned, err := prepared.binding.Cleanup(ctx, prepared.profile, prepared.prepared, prepared.signal)
	evidence := identityCatalogueCleanupEvidence{Schema: identityCatalogueCleanupSchema, CatalogueID: a.profile.ID,
		ReceiptSHA256: identityCatalogueStringSHA256(prepared.prepared.ReceiptObject),
		EventAbsent:   cleaned.EventAbsent, FixtureRestored: cleaned.FixtureRestored}
	raw, _ := json.Marshal(evidence)
	result := AttackCatalogCleanupResult{Attempted: cleaned.Attempted, EventDeleted: cleaned.EventAbsent,
		MarkerDeleted: cleaned.FixtureRestored, Verified: cleaned.Attempted && cleaned.EventAbsent && cleaned.FixtureRestored,
		Evidence: raw}
	if err != nil {
		result.Reason = safeIdentityCatalogueStageError(a.profile.Family, "cleanup", err).Error()
	} else if !result.Verified {
		result.Reason = "exact identity-family cleanup could not be verified"
	}
	return result
}

func (a *identityFamilyCatalogueAdapter) ValidateDefended(result AttackCatalogResult) error {
	if a == nil || result.CatalogueID != a.profile.ID || result.ExpectedAction != a.profile.ExpectedAction ||
		result.ExecutionMode != AttackCatalogExecutionActive || result.Actuator.Handler != a.profile.ExpectedAction ||
		len(result.Actuator.ObjectsTouched) != 1 || strings.TrimSpace(result.Actuator.ObjectsTouched[0]) == "" {
		return errors.New("identity-family defended result does not match its exact adapter profile")
	}
	if err := validateIdentityFamilyPhysical(a.profile, result.PhysicalValidation); err != nil {
		return err
	}
	var cleanup identityCatalogueCleanupEvidence
	if err := decodeIdentityEvidence(result.Cleanup.Evidence, &cleanup); err != nil || cleanup.Schema != identityCatalogueCleanupSchema ||
		cleanup.CatalogueID != a.profile.ID || cleanup.ReceiptSHA256 != identityCatalogueStringSHA256(result.Actuator.ObjectsTouched[0]) ||
		!cleanup.EventAbsent || !cleanup.FixtureRestored || !result.Cleanup.EventDeleted || !result.Cleanup.MarkerDeleted {
		return errors.New("identity-family exact cleanup evidence is incomplete")
	}
	return nil
}

func validateIdentityFamilyPhysical(profile identityCatalogueProfile, result AttackCatalogPhysicalResult) error {
	if !result.Validated {
		return errors.New("identity-family physical oracle did not validate")
	}
	switch profile.Family {
	case identityCatalogueRotation:
		if result.Oracle != identityRotationOracle || result.OldServiceAccountUID == "" || result.NewServiceAccountUID == "" ||
			result.OldServiceAccountUID == result.NewServiceAccountUID || !result.CredentialAuthenticatedBefore ||
			result.CredentialAuthenticatedAfter || !result.PodRetained || result.PodUID == "" || len(result.Evidence) != 0 {
			return errors.New("ServiceAccount rotation, old-credential rejection and retained Pod oracle required")
		}
	case identityCatalogueCredential:
		var evidence credentialRevokeEvidence
		if result.Oracle != credentialRevokeOracle || decodeIdentityEvidence(result.Evidence, &evidence) != nil ||
			evidence.Schema != credentialRevokeOracle || !evidence.Validated || evidence.PodUID == "" || evidence.ServiceAccountUID == "" ||
			!evidence.AuthenticatedBefore || evidence.AuthenticatedAfter || !evidence.CredentialObjectAbsent ||
			!evidence.FreshCredentialAuthenticated || !evidence.AvailabilityFloorRetained || !evidence.PodRetained ||
			result.PodUID != evidence.PodUID || !result.CredentialAuthenticatedBefore || result.CredentialAuthenticatedAfter || !result.PodRetained {
			return errors.New("credential revocation, token rejection and retained Pod oracle required")
		}
	case identityCatalogueAgent:
		var evidence agentActionDenyEvidence
		if result.Oracle != agentActionDenyOracle || decodeIdentityEvidence(result.Evidence, &evidence) != nil ||
			evidence.Schema != agentActionDenyOracle || !evidence.Validated || evidence.PodUID == "" || evidence.GuardUID == "" || evidence.ServiceUID == "" ||
			evidence.DeniedBefore || !evidence.DeniedAfter || !evidence.BenignAllowedAfter || !evidence.ServingSetRetained ||
			result.PodUID != evidence.PodUID || !result.PodRetained {
			return errors.New("agent deny-guard enforcement, benign control and retained serving set oracle required")
		}
	default:
		return errors.New("unknown identity catalogue family")
	}
	return nil
}

func decodeIdentityEvidence(raw json.RawMessage, dst any) error {
	if len(raw) == 0 || len(raw) > 4096 {
		return errors.New("identity-family evidence is absent or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("identity-family evidence is not one exact document")
	}
	return nil
}

func identityCatalogueStringSHA256(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (a *identityFamilyCatalogueAdapter) DefendedReason() string {
	return "fresh exact signal, decision, actuator receipt, family physical oracle and retry-safe cleanup passed"
}

func safeIdentityCatalogueStageError(family identityCatalogueFamily, stage string, err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return fmt.Errorf("%s catalogue %s failed", family, stage)
}

var _ AttackCatalogAdapter = (*identityFamilyCatalogueAdapter)(nil)
var _ AttackCatalogPreparation = (*identityFamilyCataloguePreparation)(nil)
