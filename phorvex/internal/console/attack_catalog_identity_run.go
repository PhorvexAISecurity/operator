package console

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/identityfixture"
	"github.com/phorvex/phorvex/internal/model"
)

type identityAttackCatalogAdapter struct {
	server       *Server
	cfg          Config
	fixedCluster identityCatalogCluster
}

func (a *identityAttackCatalogAdapter) CatalogueID() string { return attackcatalog.FirstID }

func (a *identityAttackCatalogAdapter) Availability() AttackCatalogAdapterAvailability {
	availability := AttackCatalogAdapterAvailability{
		TargetLabel:       "This cluster (server-fixed)",
		UnavailableReason: "AML.T0012 reviewed identity-fixture profile is unavailable or invalid.",
	}
	if !a.cfg.AttackCatalogEnabled {
		availability.UnavailableReason = "AML.T0012 launch adapter is not enabled by this deployment."
		return availability
	}
	if a.cfg.Service == ServiceConsole {
		availability.UnavailableReason = "AML.T0012 is served by the attacks service; no attacks-service runtime is active here."
		return availability
	}
	if a.cfg.AuditSource == nil {
		availability.UnavailableReason = "AML.T0012 requires the authenticated manager audit source."
		return availability
	}
	profile, err := identityfixture.LoadFile(a.cfg.AttackCatalogIdentityProfilePath)
	if err != nil || a.cfg.AttackCatalogAuthorizationTenant == "" || a.cfg.AttackCatalogIdentityTenant == "" ||
		profile.Namespace != a.cfg.AttackCatalogIdentityTenant {
		return availability
	}
	availability.Available = true
	availability.UnavailableReason = ""
	availability.RunnableNote = "Server-fixed AML.T0012 identity-rotation validation; authoritative fixture and policy admission are repeated at launch."
	availability.RuntimeContext = defaultTargetID
	availability.FixtureTenant = profile.Namespace
	return availability
}

func (a *identityAttackCatalogAdapter) Destination() (runDestination, error) {
	if a.cfg.Service == ServiceConsole {
		if a.cfg.AttacksURL == "" || a.cfg.AttackCatalogAuthorizationTenant == "" {
			return runDestination{}, errors.New("AML.T0012 attacks-service proxy destination is unavailable")
		}
		return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{a.cfg.AttackCatalogAuthorizationTenant},
			ScopeTarget: defaultTargetID, ScopeTenant: a.cfg.AttackCatalogAuthorizationTenant}, nil
	}
	if !a.cfg.AttackCatalogEnabled || a.cfg.AuditSource == nil || a.cfg.AttackCatalogAuthorizationTenant == "" {
		return runDestination{}, errors.New("AML.T0012 launch adapter is unavailable in this attacks-service deployment")
	}
	profile, err := identityfixture.LoadFile(a.cfg.AttackCatalogIdentityProfilePath)
	if err != nil || profile.Namespace != a.cfg.AttackCatalogIdentityTenant {
		return runDestination{}, errors.New("AML.T0012 reviewed identity-fixture profile is unavailable")
	}
	return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{a.cfg.AttackCatalogAuthorizationTenant},
		ScopeTarget: defaultTargetID, ScopeTenant: a.cfg.AttackCatalogAuthorizationTenant}, nil
}

type identityCatalogPreparation struct {
	cluster   identityCatalogCluster
	fixture   identityCatalogFixture
	signal    identityCatalogSignal
	markerUID string
}

func (p *identityCatalogPreparation) ExecutionMode() AttackCatalogExecutionMode {
	return AttackCatalogExecutionActive
}

func (p *identityCatalogPreparation) TriggerMode() AttackCatalogTriggerMode {
	if p.fixture.ReactiveOnly {
		return AttackCatalogTriggerReactive
	}
	return AttackCatalogTriggerProactiveReactive
}

func (p *identityCatalogPreparation) EvidenceTenant() string { return p.fixture.Namespace }

func (a *identityAttackCatalogAdapter) Preflight(ctx context.Context, run AttackCatalogRunContext) (AttackCatalogPreparation, error) {
	if run.CatalogueID != a.CatalogueID() {
		return nil, errors.New("AML.T0012 adapter received a different catalogue ID")
	}
	cluster := a.fixedCluster
	if cluster == nil {
		if a.server == nil {
			return nil, errors.New("AML.T0012 server runtime is unavailable")
		}
		profile, err := identityfixture.LoadFile(a.cfg.AttackCatalogIdentityProfilePath)
		if err != nil || profile.Namespace != a.cfg.AttackCatalogIdentityTenant || !a.cfg.AttackCatalogEnabled ||
			a.cfg.AuditSource == nil || a.cfg.Service == ServiceConsole {
			return nil, errors.New("AML.T0012 launch adapter is not ready in this attacks-service deployment")
		}
		cluster, err = a.server.attackCatalogCluster(profile)
		if err != nil {
			return nil, err
		}
	}
	fixture, err := cluster.Prepare(ctx)
	if err != nil {
		return nil, err
	}
	return &identityCatalogPreparation{cluster: cluster, fixture: fixture}, nil
}

func (a *identityAttackCatalogAdapter) Execute(ctx context.Context, run AttackCatalogRunContext, prepared AttackCatalogPreparation) (AttackCatalogObservation, error) {
	p, ok := prepared.(*identityCatalogPreparation)
	if !ok || p == nil || p.cluster == nil {
		return AttackCatalogObservation{}, errors.New("AML.T0012 preflight state type changed")
	}
	observation := AttackCatalogObservation{
		Reason: "bounded validation did not complete before its deadline",
		PhysicalValidation: AttackCatalogPhysicalResult{OldServiceAccountUID: p.fixture.ServiceAccountUID,
			PodUID: p.fixture.PodUID, CredentialAuthenticatedBefore: true, CredentialAuthenticatedAfter: true},
	}
	markerUID, err := p.cluster.CreateMarker(ctx, p.fixture, time.Now().UTC())
	if err != nil {
		return observation, err
	}
	p.markerUID = markerUID
	observation.MutationStarted = true
	entry, ok := attackcatalog.Lookup(run.CatalogueID)
	if !ok || entry.ID != a.CatalogueID() || entry.ExpectedAction != run.ExpectedAction {
		return observation, errors.New("AML.T0012 embedded metadata binding changed")
	}
	signal, err := p.cluster.CreateSignal(ctx, entry, p.fixture, run.RunID)
	if err != nil {
		return observation, err
	}
	p.signal = signal
	observation.Launched = true
	observation.Signal = AttackCatalogSignalResult{Created: true, Name: signal.Name, UID: signal.UID,
		Creator: signal.Creator, TargetUID: p.fixture.PodUID}
	interval := a.cfg.AttackCatalogPollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		rows, auditErr := a.server.readAttackCatalogAudit(ctx)
		if auditErr == nil {
			for _, row := range rows {
				observed, decision, actuator := identityCatalogueDecision(row, p.fixture, signal)
				if observed {
					observation.Signal.Observed = true
					// A later event-bound noop is the expected post-defense steady
					// state; it must not erase the exact accepted receipt.
					if !observation.Actuator.ReceiptObserved || actuator.ReceiptObserved {
						observation.Decision = decision
						observation.Actuator = actuator
					}
				}
			}
		}
		physical, physicalErr := p.cluster.Physical(ctx, p.fixture)
		if physicalErr == nil {
			observation.PhysicalValidation = physical
		}
		if observation.Signal.Observed && observation.Actuator.ReceiptObserved && observation.PhysicalValidation.Validated {
			observation.DefensiveChainComplete = true
			return observation, nil
		}
		select {
		case <-ctx.Done():
			if observation.Actuator.ReceiptObserved && !observation.PhysicalValidation.Validated {
				observation.Reason = "identity-rotate receipt was observed but the physical credential oracle did not fully pass"
			} else if observation.Signal.Created && !observation.Signal.Observed {
				observation.Reason = "signal was created but no exact event-bound decision observation was found"
			}
			return observation, nil
		case <-ticker.C:
		}
	}
}

func (a *identityAttackCatalogAdapter) Cleanup(ctx context.Context, _ AttackCatalogRunContext, prepared AttackCatalogPreparation) AttackCatalogCleanupResult {
	p, ok := prepared.(*identityCatalogPreparation)
	if !ok || p == nil || p.cluster == nil {
		return AttackCatalogCleanupResult{Attempted: true, Reason: "AML.T0012 preflight state type changed"}
	}
	return p.cluster.Cleanup(ctx, p.fixture, p.signal, p.markerUID)
}

func (a *identityAttackCatalogAdapter) ValidateDefended(result AttackCatalogResult) error {
	if result.ExecutionMode != AttackCatalogExecutionActive {
		return errors.New("AML.T0012 requires active execution mode")
	}
	return result.identityDefendedRequirements()
}

func (a *identityAttackCatalogAdapter) DefendedReason() string {
	return "exact event-bound decision, actuator receipt, physical identity rotation and cleanup passed"
}

func (s *Server) attackCatalogCluster(profile identityfixture.Profile) (identityCatalogCluster, error) {
	if s.identityCatalogFactory != nil {
		return s.identityCatalogFactory(profile)
	}
	return newKubernetesIdentityCatalogCluster(s.cfg, profile)
}

// runAttackCatalogueIdentity preserves the focused AML.T0012 test seam while
// exercising the same adapter contract and shared verdict/cleanup lifecycle.
func (s *Server) runAttackCatalogueIdentity(ctx context.Context, runID string, entry attackcatalog.Entry, cluster identityCatalogCluster) AttackCatalogResult {
	adapter := &identityAttackCatalogAdapter{server: s, cfg: s.cfg, fixedCluster: cluster}
	run := AttackCatalogRunContext{RunID: runID, CatalogueID: entry.ID, ExpectedAction: entry.ExpectedAction, ReactiveCompatible: entry.ReactiveCompatible}
	started := time.Now().UTC()
	result := AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: entry.ID, RunID: runID,
		Visible: true, ExpectedAction: entry.ExpectedAction, StartedAt: started}
	prepared, err := adapter.Preflight(ctx, run)
	if err != nil {
		result.Cleanup = noMutationAttackCatalogCleanup("preflight failed before mutation")
		result.FinishedAt, result.Verdict, result.Reason = time.Now().UTC(), "ERROR", err.Error()
		return result
	}
	result.ExecutionMode, result.TriggerMode = prepared.ExecutionMode(), prepared.TriggerMode()
	result.ReactiveOnly = result.TriggerMode == AttackCatalogTriggerReactive
	if result.ReactiveOnly && !entry.ReactiveCompatible {
		result.Cleanup = noMutationAttackCatalogCleanup("no mutation started")
		result.FinishedAt, result.Verdict, result.Reason = time.Now().UTC(), "ERROR", "catalogue entry is not compatible with the fixture's reactive-only policy"
		return result
	}
	return s.executePreparedAttackCatalogueRun(ctx, run, adapter, prepared, result)
}

func (s *Server) readAttackCatalogAudit(ctx context.Context) ([]audit.Record, error) {
	if s.attackCatalogRecords != nil {
		return s.attackCatalogRecords(ctx)
	}
	rows, _, err := s.readAudit(ctx)
	return rows, err
}

func identityCatalogueDecision(rec audit.Record, f identityCatalogFixture, signal identityCatalogSignal) (bool, AttackCatalogDecisionResult, AttackCatalogActuatorResult) {
	if rec.Kind != "phorvex.decision" || rec.Time.Before(signal.CreatedAt) || rec.Namespace != f.Namespace || rec.Pod != f.PodName ||
		rec.DecisionTrace == nil || rec.DecisionTrace.PolicyNamespace != f.Namespace || rec.DecisionTrace.PolicyName != f.PolicyName ||
		rec.DecisionTrace.PolicyUID != f.PolicyUID || rec.DecisionTrace.AssetUID != f.PodUID || rec.DecisionTrace.DecisionID == "" ||
		rec.DecisionTrace.SelectedAction != rec.Action || (rec.DispatchOutcome != "" && rec.DecisionTrace.DispatchOutcome != rec.DispatchOutcome) {
		return false, AttackCatalogDecisionResult{}, AttackCatalogActuatorResult{}
	}
	matches := 0
	for _, event := range rec.Events {
		if event.EventUID == signal.UID && event.Name == signal.Name && event.Type == model.AttackVectorPodBoundAPIAuth &&
			event.CreatorIdentity == signal.Creator && event.TargetPodUID == f.PodUID && event.TrustVerdict == "trusted" &&
			event.TargetsPod && event.TimestampPresent {
			matches++
		}
	}
	if matches != 1 {
		return false, AttackCatalogDecisionResult{}, AttackCatalogActuatorResult{}
	}
	decision := AttackCatalogDecisionResult{Observed: true, ID: rec.DecisionTrace.DecisionID, Selected: rec.Selected,
		Feasible: rec.Feasible, Action: rec.Action, DispatchOutcome: rec.DecisionTrace.DispatchOutcome}
	actuator := AttackCatalogActuatorResult{Handler: rec.Handler, ObjectsTouched: slices.Clone(rec.ObjectsTouched)}
	actuator.ReceiptObserved = rec.Action == string(model.ActionIdentityRotate) && rec.Selected && rec.Feasible && rec.Actuated &&
		rec.DecisionTrace.DispatchOutcome == model.DispatchEmitted && rec.Handler == string(model.ActionIdentityRotate) &&
		slices.Contains(rec.ObjectsTouched, identityServiceAccountObject(f))
	return true, decision, actuator
}

var _ AttackCatalogAdapter = (*identityAttackCatalogAdapter)(nil)
var _ AttackCatalogPreparation = (*identityCatalogPreparation)(nil)
