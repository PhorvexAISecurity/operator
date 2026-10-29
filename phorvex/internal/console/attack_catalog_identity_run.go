package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/identityfixture"
	"github.com/phorvex/phorvex/internal/model"
)

const attackCatalogExecutionKind = "catalogue-validation"

func attackCatalogueDestination(s *Server, _ *http.Request, body scopedBody) (runDestination, error) {
	entry, ok := attackcatalog.Lookup(body.ID)
	if !ok {
		return runDestination{}, errors.New("unknown catalogue ID")
	}
	if entry.ID != attackcatalog.FirstID {
		return runDestination{}, errors.New("catalogue entry is visible but has no reviewed launch adapter")
	}
	if s.cfg.Service == ServiceConsole {
		if s.cfg.AttacksURL == "" || s.cfg.AttackCatalogAuthorizationTenant == "" {
			return runDestination{}, errors.New("AML.T0012 attacks-service proxy destination is unavailable")
		}
		return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{s.cfg.AttackCatalogAuthorizationTenant},
			ScopeTarget: defaultTargetID, ScopeTenant: s.cfg.AttackCatalogAuthorizationTenant}, nil
	}
	if !s.cfg.AttackCatalogEnabled || s.cfg.AuditSource == nil || s.cfg.AttackCatalogAuthorizationTenant == "" {
		return runDestination{}, errors.New("AML.T0012 launch adapter is unavailable in this attacks-service deployment")
	}
	profile, err := identityfixture.LoadFile(s.cfg.AttackCatalogIdentityProfilePath)
	if err != nil || profile.Namespace != s.cfg.AttackCatalogIdentityTenant {
		return runDestination{}, errors.New("AML.T0012 reviewed identity-fixture profile is unavailable")
	}
	return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{s.cfg.AttackCatalogAuthorizationTenant},
		ScopeTarget: defaultTargetID, ScopeTenant: s.cfg.AttackCatalogAuthorizationTenant}, nil
}

func (s *Server) launchAttackCatalogue(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || decoder.Decode(new(any)) != io.EOF || strings.TrimSpace(body.ID) != body.ID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "one exact catalogue ID is required"})
		return
	}
	entry, ok := attackcatalog.Lookup(body.ID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "catalogue ID is not allowlisted"})
		return
	}
	if entry.ID != attackcatalog.FirstID {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "catalogue entry is visible but no reviewed server-side launch adapter is packaged"})
		return
	}
	profile, err := identityfixture.LoadFile(s.cfg.AttackCatalogIdentityProfilePath)
	if err != nil || profile.Namespace != s.cfg.AttackCatalogIdentityTenant || !s.cfg.AttackCatalogEnabled || s.cfg.AuditSource == nil || s.cfg.Service == ServiceConsole {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "AML.T0012 launch adapter is not ready in this attacks-service deployment"})
		return
	}
	principal := principalOf(r)
	// The boundary already checked this server-owned destination. Recheck the freshly loaded
	// profile so a deployment-side projected-volume update cannot create an authorization TOCTOU.
	if principal == nil || !principal.AllowsTenant(s.cfg.AttackCatalogAuthorizationTenant) || !principal.AllowsTarget(defaultTargetID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "AML.T0012 fixture destination is outside this identity's current scope"})
		return
	}
	id, err := s.startAttackCatalogueRun(entry, profile, principalKey(principal))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "context": defaultTargetID, "catalogueID": entry.ID})
}

func (s *Server) startAttackCatalogueRun(entry attackcatalog.Entry, profile identityfixture.Profile, owner string) (string, error) {
	rm := s.runs
	rm.mu.Lock()
	for _, prior := range rm.runs {
		if prior.ExecutionKind == attackCatalogExecutionKind && (prior.State == "running" || prior.UnsafeToRetry) {
			rm.mu.Unlock()
			return "", errors.New("an AML.T0012 run is active or requires cleanup reconciliation")
		}
	}
	if err := rm.guard(time.Now()); err != nil {
		rm.mu.Unlock()
		return "", err
	}
	rm.seq++
	id := fmt.Sprintf("cat-%d", rm.seq)
	out := rm.cfg.runOutputPath(id)
	if err := os.MkdirAll(out, 0o750); err != nil {
		rm.mu.Unlock()
		return "", err
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := &RunStatus{ID: id, Config: entry.ID, State: "running", Started: time.Now().UTC().Format(time.RFC3339Nano), Date: tsNow(),
		ExpectedTrials: 1, Owner: owner, ScopeTarget: defaultTargetID, ScopeTenant: s.cfg.AttackCatalogAuthorizationTenant,
		FixtureTenant: profile.Namespace,
		Target:        defaultTargetID, TargetLabel: "This cluster (server-fixed)", Provider: "Kubernetes",
		ExecutionKind: attackCatalogExecutionKind, ClaimClass: "security"}
	rm.runs[id], rm.runOut[id], rm.attackCatalogCancels[id] = st, id, cancel
	rm.active++
	rm.lastStart = time.Now()
	if err := rm.persistStatus(st, id); err != nil {
		delete(rm.runs, id)
		delete(rm.runOut, id)
		delete(rm.attackCatalogCancels, id)
		rm.active--
		cancel()
		rm.mu.Unlock()
		return "", fmt.Errorf("persist catalogue run before launch: %w", err)
	}
	rm.mu.Unlock()
	go s.executeAttackCatalogueRun(ctx, id, entry, profile)
	return id, nil
}

func (s *Server) executeAttackCatalogueRun(parent context.Context, id string, entry attackcatalog.Entry, profile identityfixture.Profile) {
	timeout := s.cfg.AttackCatalogRunTimeout
	if timeout <= 0 {
		timeout = 4 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	startedAt := time.Now().UTC()
	prometheusEvidence, prometheusErr := s.beginPrometheusRunEvidence(ctx, id, entry.ID, profile.Namespace, entry.ExpectedAction, startedAt)
	var cluster identityCatalogCluster
	var err error
	if prometheusErr == nil {
		cluster, err = s.attackCatalogCluster(profile)
	}
	var result AttackCatalogResult
	if prometheusErr != nil {
		now := time.Now().UTC()
		result = AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: entry.ID, RunID: id, Visible: true,
			ExpectedAction: entry.ExpectedAction, StartedAt: startedAt, FinishedAt: now, Verdict: "ERROR",
			Reason:  "Prometheus evidence preflight failed before mutation: " + prometheusErr.Error(),
			Cleanup: AttackCatalogCleanupResult{EventDeleted: true, MarkerDeleted: true, Verified: true, Reason: "no cluster mutation started"}}
	} else if err != nil {
		now := time.Now().UTC()
		result = AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: entry.ID, RunID: id, Visible: true,
			ExpectedAction: entry.ExpectedAction, StartedAt: now, FinishedAt: now, Verdict: "ERROR", Reason: err.Error(),
			Cleanup: AttackCatalogCleanupResult{EventDeleted: true, MarkerDeleted: true, Verified: true, Reason: "no cluster mutation started"}}
	} else {
		result = s.runAttackCatalogueIdentity(ctx, id, entry, cluster)
	}
	if prometheusErr == nil {
		captureTimeout := s.cfg.RunPrometheusEvidence.normalized().SettleDelay + 2*time.Minute
		captureCtx, captureCancel := context.WithTimeout(context.Background(), captureTimeout)
		prometheusErr = s.completePrometheusRunEvidence(captureCtx, prometheusEvidence, result.FinishedAt)
		captureCancel()
	}
	raw, marshalErr := json.MarshalIndent(result, "", "  ")
	if marshalErr == nil {
		marshalErr = atomicWriteState(filepath.Join(s.cfg.runOutputPath(id), "catalogue-result.json"), append(raw, '\n'))
	}
	rm := s.runs
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.attackCatalogCancels, id)
	if rm.active > 0 {
		rm.active--
	}
	st := rm.runs[id]
	if st == nil {
		return
	}
	st.Finished = tsNow()
	st.Outcome = result.Verdict
	st.UnsafeToRetry = result.UnsafeToRetry || !result.Cleanup.Verified
	if result.Cleanup.Verified {
		st.CleanupStatus = "verified"
	} else {
		st.CleanupStatus = "unverified"
	}
	stopping := rm.stopping[id]
	delete(rm.stopping, id)
	switch {
	case marshalErr != nil || result.Validate() != nil:
		st.State, st.UnsafeToRetry, st.Outcome = "partial", true, ""
		st.Error = "catalogue terminal evidence missing or invalid"
	case !result.Cleanup.Verified:
		st.State, st.Error = "partial", "catalogue postflight is unverified; reconcile before retry"
	case stopping:
		st.State, st.Error = "stopped", "stopped by operator after verified cleanup"
	case result.Verdict == "ERROR":
		st.State, st.Error = "error", result.Reason
	case prometheusErr != nil:
		st.State, st.Error = "partial", "Prometheus run evidence is incomplete: "+prometheusErr.Error()
	case result.Verdict == "DEFENDED":
		st.State = "done"
	default:
		st.State, st.Error = "error", result.Reason
	}
	if err := rm.persistStatus(st, id); err != nil {
		st.State, st.UnsafeToRetry, st.Outcome = "partial", true, ""
		st.Error = "catalogue terminal status persistence failed"
	}
	rm.dequeueNextLocked()
}

func (s *Server) attackCatalogCluster(profile identityfixture.Profile) (identityCatalogCluster, error) {
	if s.identityCatalogFactory != nil {
		return s.identityCatalogFactory(profile)
	}
	return newKubernetesIdentityCatalogCluster(s.cfg, profile)
}

func (s *Server) runAttackCatalogueIdentity(ctx context.Context, runID string, entry attackcatalog.Entry, cluster identityCatalogCluster) (result AttackCatalogResult) {
	result = AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: entry.ID, RunID: runID,
		Visible: true, Available: true, ExpectedAction: entry.ExpectedAction, StartedAt: time.Now().UTC()}
	fixture, err := cluster.Prepare(ctx)
	if err != nil {
		result.Available = false
		result.Cleanup = AttackCatalogCleanupResult{EventDeleted: true, MarkerDeleted: true, Verified: true, Reason: "preflight failed before mutation"}
		result.FinishedAt, result.Verdict, result.Reason = time.Now().UTC(), "ERROR", err.Error()
		return result
	}
	result.ReactiveOnly = fixture.ReactiveOnly
	if fixture.ReactiveOnly && !entry.ReactiveCompatible {
		result.Available = false
		result.Cleanup = AttackCatalogCleanupResult{EventDeleted: true, MarkerDeleted: true, Verified: true, Reason: "no mutation started"}
		result.FinishedAt, result.Verdict, result.Reason = time.Now().UTC(), "ERROR", "catalogue entry is not compatible with the fixture's reactive-only policy"
		return result
	}
	result.PhysicalValidation = AttackCatalogPhysicalResult{OldServiceAccountUID: fixture.ServiceAccountUID,
		PodUID: fixture.PodUID, CredentialAuthenticatedBefore: true, CredentialAuthenticatedAfter: true}
	var signal identityCatalogSignal
	markerUID := ""
	defensiveChainComplete := false
	reason := "bounded validation did not complete before its deadline"
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		result.Cleanup = cluster.Cleanup(cleanupCtx, fixture, signal, markerUID)
		if defensiveChainComplete {
			if result.Cleanup.Verified {
				reason = "exact event-bound decision, actuator receipt, physical identity rotation and cleanup passed"
			} else {
				reason = "defensive signal, decision, actuator receipt and physical identity rotation passed, but exact cleanup did not pass"
			}
		}
		result.finishVerdict(reason)
	}()
	markerUID, err = cluster.CreateMarker(ctx, fixture, time.Now().UTC())
	if err != nil {
		reason = err.Error()
		return result
	}
	signal, err = cluster.CreateSignal(ctx, entry, fixture, runID)
	if err != nil {
		reason = err.Error()
		return result
	}
	result.Launched = true
	result.Signal = AttackCatalogSignalResult{Created: true, Name: signal.Name, UID: signal.UID,
		Creator: signal.Creator, TargetUID: fixture.PodUID}
	interval := s.cfg.AttackCatalogPollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		rows, auditErr := s.readAttackCatalogAudit(ctx)
		if auditErr == nil {
			for _, row := range rows {
				observed, decision, actuator := identityCatalogueDecision(row, fixture, signal)
				if observed {
					result.Signal.Observed = true
					// The event remains visible for several manager ticks. Once the exact
					// actuation receipt has been observed, a later event-bound noop is only
					// the expected post-defense steady state; it must not erase the receipt
					// that physically changed the fixture.
					if !result.Actuator.ReceiptObserved || actuator.ReceiptObserved {
						result.Decision = decision
						result.Actuator = actuator
					}
				}
			}
		}
		physical, physicalErr := cluster.Physical(ctx, fixture)
		if physicalErr == nil {
			result.PhysicalValidation = physical
		}
		if result.Signal.Observed && result.Actuator.ReceiptObserved && result.PhysicalValidation.Validated {
			defensiveChainComplete = true
			return result
		}
		select {
		case <-ctx.Done():
			if result.Actuator.ReceiptObserved && !result.PhysicalValidation.Validated {
				reason = "identity-rotate receipt was observed but the physical credential oracle did not fully pass"
			} else if result.Signal.Created && !result.Signal.Observed {
				reason = "signal was created but no exact event-bound decision observation was found"
			}
			return result
		case <-ticker.C:
		}
	}
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

func (rm *RunManager) AttackCatalogResult(id string) (*AttackCatalogResult, error) {
	rm.mu.Lock()
	st, ok := rm.runs[id]
	out := rm.runOut[id]
	rm.mu.Unlock()
	if !ok || st.ExecutionKind != attackCatalogExecutionKind {
		return nil, nil
	}
	if st.State == "running" || st.State == "queued" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(rm.cfg.runOutputPath(out), "catalogue-result.json"))
	if err != nil {
		return nil, err
	}
	var result AttackCatalogResult
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("catalogue result is malformed")
	}
	if err = result.Validate(); err != nil {
		return nil, err
	}
	return &result, nil
}
