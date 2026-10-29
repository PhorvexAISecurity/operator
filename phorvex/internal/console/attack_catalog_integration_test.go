package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/identityfixture"
	"github.com/phorvex/phorvex/internal/model"
)

func writeAttackCatalogProfile(t *testing.T) string {
	t.Helper()
	profile := identityfixture.Profile{JournalNamespace: "phorvex-test", Namespace: "console-identity-test",
		NamespaceUID: "namespace-uid", PolicyName: "console-id-fixture", PolicyUID: "policy-uid",
		PolicyGeneration: 1, Cluster: "test-cluster", Region: "us-east-2"}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity-profile.json")
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAttackCatalogueRowsExactOrderUniquenessAndAvailability(t *testing.T) {
	entries, err := attackcatalog.Entries()
	if err != nil {
		t.Fatal(err)
	}
	disabled := (&Config{}).attackCatalogueItems()
	if len(disabled) != attackcatalog.ExpectedSize || disabled[0].Available || disabled[0].UnavailableReason == "" {
		t.Fatalf("disabled deployment lost visible honest readiness: %+v", disabled[0])
	}
	cfg := Config{Service: ServiceAttacks, AttackCatalogEnabled: true, AttackCatalogAuthorizationTenant: "phorvex-test",
		AttackCatalogIdentityTenant:      "console-identity-test",
		AttackCatalogIdentityProfilePath: writeAttackCatalogProfile(t), AuditSource: &audittransport.Client{}}
	items := cfg.attackCatalogueItems()
	if len(items) != attackcatalog.ExpectedSize {
		t.Fatalf("items=%d, want %d", len(items), attackcatalog.ExpectedSize)
	}
	seen := make(map[string]bool, len(items))
	for i, item := range items {
		entry := entries[i]
		if item.CatalogueOrder != i+1 || item.CatalogueID != entry.ID || item.EntryID != entry.ID ||
			item.Description != entry.Description || item.Family != entry.Family || item.ExpectedAction != entry.ExpectedAction ||
			item.ReactiveCompatible != entry.ReactiveCompatible || seen[item.CatalogueID] {
			t.Fatalf("row %d changed or duplicated: %+v", i+1, item)
		}
		seen[item.CatalogueID] = true
		if i == 0 {
			if !item.Available || item.UnavailableReason != "" {
				t.Fatalf("reviewed first entry is not ready: %+v", item)
			}
		} else if item.Available || item.UnavailableReason == "" {
			t.Fatalf("metadata-only entry %d has dishonest readiness: %+v", i+1, item)
		}
	}
	mismatch := cfg
	mismatch.AttackCatalogIdentityTenant = "console-identity-other"
	if row := mismatch.attackCatalogueItems()[0]; row.Available || row.UnavailableReason == "" {
		t.Fatalf("profile/tenant mismatch was advertised as ready: %+v", row)
	}
}

type fakeIdentityCatalogCluster struct {
	fixture     identityCatalogFixture
	signal      identityCatalogSignal
	physical    AttackCatalogPhysicalResult
	cleanup     AttackCatalogCleanupResult
	prepareErr  error
	markerCalls atomic.Int32
	signalCalls atomic.Int32
}

func (f *fakeIdentityCatalogCluster) Prepare(context.Context) (identityCatalogFixture, error) {
	return f.fixture, f.prepareErr
}
func (f *fakeIdentityCatalogCluster) CreateMarker(context.Context, identityCatalogFixture, time.Time) (string, error) {
	f.markerCalls.Add(1)
	return "marker-uid", nil
}
func (f *fakeIdentityCatalogCluster) CreateSignal(context.Context, attackcatalog.Entry, identityCatalogFixture, string) (identityCatalogSignal, error) {
	f.signalCalls.Add(1)
	return f.signal, nil
}
func (f *fakeIdentityCatalogCluster) Physical(context.Context, identityCatalogFixture) (AttackCatalogPhysicalResult, error) {
	return f.physical, nil
}
func (f *fakeIdentityCatalogCluster) Cleanup(context.Context, identityCatalogFixture, identityCatalogSignal, string) AttackCatalogCleanupResult {
	return f.cleanup
}

func identityCatalogFixtureAndSignal() (identityCatalogFixture, identityCatalogSignal) {
	fixture := identityCatalogFixture{Namespace: "console-identity-test", PodName: "console-id-fixture-0", PodUID: "pod-uid",
		ServiceAccountName: "console-id-fixture", ServiceAccountUID: "old-sa-uid", PolicyName: "console-id-fixture",
		PolicyUID: "policy-uid", PolicyGeneration: 1, ReactiveOnly: true, Credential: "bounded-token"}
	signal := identityCatalogSignal{Name: "catalog-aml-t0012-test", UID: "event-uid", Creator: "system:serviceaccount:phorvex:attacks",
		CreatedAt: time.Now().UTC().Add(-time.Second)}
	return fixture, signal
}

func exactIdentityCatalogAudit(f identityCatalogFixture, signal identityCatalogSignal) audit.Record {
	return audit.Record{Kind: "phorvex.decision", Time: signal.CreatedAt.Add(time.Millisecond), Namespace: f.Namespace, Pod: f.PodName,
		Action: string(model.ActionIdentityRotate), Selected: true, Feasible: true, Actuated: true,
		DispatchOutcome: model.DispatchEmitted, Handler: string(model.ActionIdentityRotate),
		ObjectsTouched: []string{identityServiceAccountObject(f)},
		DecisionTrace: &model.DecisionTraceV2{DecisionID: "decision-id", PolicyNamespace: f.Namespace, PolicyName: f.PolicyName,
			PolicyUID: f.PolicyUID, AssetUID: f.PodUID, SelectedAction: string(model.ActionIdentityRotate), DispatchOutcome: model.DispatchEmitted},
		Events: []model.EventEvidence{{Name: signal.Name, EventUID: signal.UID, Type: model.AttackVectorPodBoundAPIAuth,
			CreatorIdentity: signal.Creator, TargetPodUID: f.PodUID, TrustVerdict: "trusted", TargetsPod: true, TimestampPresent: true}}}
}

func completeFakeIdentityCluster() (*fakeIdentityCatalogCluster, audit.Record) {
	fixture, signal := identityCatalogFixtureAndSignal()
	cluster := &fakeIdentityCatalogCluster{fixture: fixture, signal: signal,
		physical: AttackCatalogPhysicalResult{Validated: true, OldServiceAccountUID: fixture.ServiceAccountUID,
			NewServiceAccountUID: "new-sa-uid", CredentialAuthenticatedBefore: true, CredentialAuthenticatedAfter: false,
			PodRetained: true, PodUID: fixture.PodUID},
		cleanup: AttackCatalogCleanupResult{Attempted: true, EventDeleted: true, MarkerDeleted: true, Verified: true}}
	return cluster, exactIdentityCatalogAudit(fixture, signal)
}

func TestAttackCatalogueReactiveTruthRequiresEveryObservedStage(t *testing.T) {
	entry, ok := attackcatalog.Lookup(attackcatalog.FirstID)
	if !ok {
		t.Fatal("first entry missing")
	}
	t.Run("all exact reactive stages defend", func(t *testing.T) {
		cluster, record := completeFakeIdentityCluster()
		s := NewServer(Config{StateDir: t.TempDir(), AttackCatalogRunTimeout: 50 * time.Millisecond, AttackCatalogPollInterval: time.Millisecond})
		s.attackCatalogRecords = func(context.Context) ([]audit.Record, error) { return []audit.Record{record}, nil }
		result := s.runAttackCatalogueIdentity(context.Background(), "cat-test", entry, cluster)
		if result.Verdict != "DEFENDED" || result.Validate() != nil || !result.ReactiveOnly {
			t.Fatalf("complete exact chain did not defend: %+v", result)
		}
	})

	t.Run("later event-bound noop cannot erase an exact actuation receipt", func(t *testing.T) {
		cluster, record := completeFakeIdentityCluster()
		noop := record
		noop.Selected, noop.Feasible, noop.Actuated = false, false, false
		noop.Action, noop.Handler, noop.DispatchOutcome, noop.ObjectsTouched = "noop", "", "not-attempted", nil
		trace := *record.DecisionTrace
		trace.DecisionID, trace.SelectedAction, trace.DispatchOutcome = "later-noop", "noop", "not-attempted"
		noop.DecisionTrace = &trace
		s := NewServer(Config{StateDir: t.TempDir(), AttackCatalogRunTimeout: 50 * time.Millisecond, AttackCatalogPollInterval: time.Millisecond})
		s.attackCatalogRecords = func(context.Context) ([]audit.Record, error) { return []audit.Record{record, noop}, nil }
		result := s.runAttackCatalogueIdentity(context.Background(), "cat-test", entry, cluster)
		if result.Verdict != "DEFENDED" || !result.Actuator.ReceiptObserved || result.Decision.ID != record.DecisionTrace.DecisionID {
			t.Fatalf("later noop erased the exact actuation receipt: %+v", result)
		}
	})

	t.Run("expected metadata and event creation alone never defend", func(t *testing.T) {
		cluster, record := completeFakeIdentityCluster()
		record.Events = nil
		s := NewServer(Config{StateDir: t.TempDir(), AttackCatalogRunTimeout: 5 * time.Millisecond, AttackCatalogPollInterval: time.Millisecond})
		s.attackCatalogRecords = func(context.Context) ([]audit.Record, error) { return []audit.Record{record}, nil }
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		result := s.runAttackCatalogueIdentity(ctx, "cat-test", entry, cluster)
		if result.Verdict == "DEFENDED" || !result.Launched || result.Signal.Observed || !result.Cleanup.Verified {
			t.Fatalf("unbound event or expected action inferred defense: %+v", result)
		}
	})

	t.Run("unclean postflight never defends", func(t *testing.T) {
		cluster, record := completeFakeIdentityCluster()
		cluster.cleanup = AttackCatalogCleanupResult{Attempted: true, EventDeleted: true, Reason: "marker remains"}
		s := NewServer(Config{StateDir: t.TempDir(), AttackCatalogRunTimeout: 50 * time.Millisecond, AttackCatalogPollInterval: time.Millisecond})
		s.attackCatalogRecords = func(context.Context) ([]audit.Record, error) { return []audit.Record{record}, nil }
		result := s.runAttackCatalogueIdentity(context.Background(), "cat-test", entry, cluster)
		if result.Verdict == "DEFENDED" || !result.UnsafeToRetry || result.Cleanup.Verified ||
			result.Reason == "exact event-bound decision, actuator receipt, physical identity rotation and cleanup passed" {
			t.Fatalf("unclean postflight inferred defense: %+v", result)
		}
	})

	t.Run("reactive-only rejects incompatible entry before mutation", func(t *testing.T) {
		cluster, _ := completeFakeIdentityCluster()
		entry.ReactiveCompatible = false
		s := NewServer(Config{StateDir: t.TempDir()})
		result := s.runAttackCatalogueIdentity(context.Background(), "cat-test", entry, cluster)
		if result.Verdict != "ERROR" || result.Available || cluster.markerCalls.Load() != 0 || cluster.signalCalls.Load() != 0 {
			t.Fatalf("reactive-only incompatibility reached mutation: %+v", result)
		}
	})
}

func TestAttackCatalogueLaunchAuthorizationAndStrictAllowlist(t *testing.T) {
	profile := writeAttackCatalogProfile(t)
	base := Config{Service: ServiceAttacks, StateDir: t.TempDir(), AttackCatalogEnabled: true,
		AttackCatalogAuthorizationTenant: "phorvex-test", AttackCatalogIdentityTenant: "console-identity-test",
		AttackCatalogIdentityProfilePath: profile, AuditSource: &audittransport.Client{}, AttackCatalogRunTimeout: 5 * time.Millisecond}
	var factoryCalls atomic.Int32
	installFactory := func(f *authFixture) {
		f.srv.identityCatalogFactory = func(identityfixture.Profile) (identityCatalogCluster, error) {
			factoryCalls.Add(1)
			return nil, errors.New("test preflight unavailable")
		}
	}

	investor := newAuthFixture(t, base, investorGrant(albSubject("investor"), []string{"phorvex-test"}, []string{defaultTargetID}))
	installFactory(investor)
	if got := investor.do(investor.albReqAs(t, http.MethodPost, "/api/catalog/launch", `{"id":"AML.T0012"}`, "investor")).Code; got != http.StatusForbidden {
		t.Fatalf("investor status=%d, want 403", got)
	}

	outOfScope := newAuthFixture(t, base, operatorGrant(albSubject("operator-out"), []string{"other-tenant"}, []string{defaultTargetID}))
	installFactory(outOfScope)
	if got := outOfScope.do(outOfScope.albReqAs(t, http.MethodPost, "/api/catalog/launch", `{"id":"AML.T0012"}`, "operator-out")).Code; got != http.StatusForbidden {
		t.Fatalf("out-of-scope operator status=%d, want 403", got)
	}

	operator := newAuthFixture(t, base, operatorGrant(albSubject("operator"), []string{"phorvex-test"}, []string{defaultTargetID}))
	installFactory(operator)
	for name, body := range map[string]string{
		"unknown ID":        `{"id":"AML.T0012; arbitrary"}`,
		"unavailable entry": `{"id":"AML.T0024"}`,
		"client command":    `{"id":"AML.T0012","command":"kubectl get secrets"}`,
		"client path":       `{"id":"AML.T0012","profile":"/tmp/choice.json"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := operator.do(operator.albReqAs(t, http.MethodPost, "/api/catalog/launch", body, "operator")).Code; got != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400", got)
			}
		})
	}
	if got := factoryCalls.Load(); got != 0 {
		t.Fatalf("rejected requests reached launch factory %d times", got)
	}

	w := operator.do(operator.albReqAs(t, http.MethodPost, "/api/catalog/launch", `{"id":"AML.T0012"}`, "operator"))
	if w.Code != http.StatusOK {
		t.Fatalf("authorized launch status=%d body=%s", w.Code, w.Body.String())
	}
	var launched struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &launched); err != nil || launched.ID == "" {
		t.Fatalf("authorized launch identity missing: body=%s err=%v", w.Body.String(), err)
	}
	deadline := time.Now().Add(time.Second)
	finished := false
	for time.Now().Before(deadline) {
		operator.srv.runs.mu.Lock()
		status := operator.srv.runs.runs[launched.ID]
		finished = status != nil && status.State != "running"
		operator.srv.runs.mu.Unlock()
		if factoryCalls.Load() == 1 && finished {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if factoryCalls.Load() != 1 || !finished {
		t.Fatal("authorized launch did not finish through the fixed server-side adapter")
	}
}
