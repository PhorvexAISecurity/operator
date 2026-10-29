package console

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
)

const identityAdapterSensitiveSentinel = "SENSITIVE-MATERIAL-MUST-NOT-PERSIST"

func TestIdentityCatalogueAdapterExactReviewedCoverage(t *testing.T) {
	factories := newIdentityCatalogueAdapters()
	if len(factories) != 42 {
		t.Fatalf("new identity-family factories=%d, want 42 plus retained AML.T0012", len(factories))
	}
	want := map[string]identityCatalogueProfile{}
	entries, err := attackcatalog.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		switch entry.ExpectedAction {
		case string(model.ActionCredentialRevoke), string(model.ActionIdentityRotate), string(model.ActionAgentActionDeny):
			want[entry.ID] = identityCatalogueProfile{ID: entry.ID, Family: identityCatalogueFamily(entry.Family),
				ExpectedAction: entry.ExpectedAction, EventType: entry.EventType, Lane: entry.Lane}
		}
	}
	if len(want) != 43 {
		t.Fatalf("authoritative identity-family rows=%d, want 43", len(want))
	}
	counts := map[identityCatalogueFamily]int{}
	seen := map[string]bool{attackcatalog.FirstID: true}
	for _, factory := range factories {
		if factory.err != nil {
			t.Fatalf("factory %s: %v", factory.profile.ID, factory.err)
		}
		if seen[factory.profile.ID] {
			t.Fatalf("duplicate or retained AML.T0012 replacement: %s", factory.profile.ID)
		}
		seen[factory.profile.ID] = true
		counts[factory.profile.Family]++
		if got, ok := want[factory.profile.ID]; !ok || got != factory.profile {
			t.Fatalf("profile %s=%+v, authoritative=%+v present=%v", factory.profile.ID, factory.profile, got, ok)
		}
	}
	if len(seen) != len(want) || counts[identityCatalogueCredential] != 24 || counts[identityCatalogueRotation] != 12 || counts[identityCatalogueAgent] != 6 {
		t.Fatalf("coverage=%d counts=%v", len(seen), counts)
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("missing exact reviewed ID %s", id)
		}
	}
	if (&identityAttackCatalogAdapter{}).CatalogueID() != attackcatalog.FirstID {
		t.Fatal("the retained AML.T0012 adapter identity changed")
	}
}

func TestIdentityCatalogueProductionBindingsReportHonestBlockers(t *testing.T) {
	var rotation, credential, agent AttackCatalogAdapter
	for _, factory := range newIdentityCatalogueAdapters() {
		switch factory.profile.Family {
		case identityCatalogueRotation:
			if rotation == nil {
				rotation = factory.bind(nil, Config{})
			}
		case identityCatalogueCredential:
			if credential == nil {
				credential = factory.bind(nil, Config{})
			}
		case identityCatalogueAgent:
			if agent == nil {
				agent = factory.bind(nil, Config{})
			}
		}
	}
	if rotation == nil || rotation.Availability().Available || !strings.Contains(rotation.Availability().UnavailableReason, "not enabled") {
		t.Fatalf("identity rotation availability=%+v", rotation.Availability())
	}
	if credential == nil || credential.Availability().Available || !strings.Contains(credential.Availability().UnavailableReason, "no reviewed server-owned credential fixture") {
		t.Fatalf("credential availability=%+v", credential.Availability())
	}
	if agent == nil || agent.Availability().Available || !strings.Contains(agent.Availability().UnavailableReason, "no reviewed server-owned agent-sim fixture") {
		t.Fatalf("agent availability=%+v", agent.Availability())
	}
	if _, err := credential.Destination(); err == nil {
		t.Fatal("blocked credential adapter invented a destination")
	}
	if _, err := agent.Destination(); err == nil {
		t.Fatal("blocked agent adapter invented a destination")
	}
}

type identityRotationAdapterTestCluster struct {
	prepared  atomic.Int32
	mutations atomic.Int32
	entryID   string
}

func (c *identityRotationAdapterTestCluster) Prepare(context.Context) (identityCatalogFixture, error) {
	c.prepared.Add(1)
	return identityCatalogFixture{Namespace: "console-identity-test", PodName: "fixture-pod", PodUID: "pod-uid",
		ServiceAccountName: "fixture-sa", ServiceAccountUID: "sa-old", PolicyName: "console-id-fixture",
		PolicyUID: "policy-uid", PolicyGeneration: 1, ReactiveOnly: true, Credential: identityAdapterSensitiveSentinel}, nil
}

func (c *identityRotationAdapterTestCluster) CreateMarker(context.Context, identityCatalogFixture, time.Time) (string, error) {
	c.mutations.Add(1)
	return "marker-uid", nil
}

func (c *identityRotationAdapterTestCluster) CreateSignal(_ context.Context, entry attackcatalog.Entry, _ identityCatalogFixture, _ string) (identityCatalogSignal, error) {
	c.mutations.Add(1)
	c.entryID = entry.ID
	return identityCatalogSignal{Name: "identity-signal", UID: "signal-uid",
		Creator: "system:serviceaccount:console-identity-test:injector", CreatedAt: time.Now().UTC()}, nil
}

func (c *identityRotationAdapterTestCluster) Physical(context.Context, identityCatalogFixture) (AttackCatalogPhysicalResult, error) {
	return AttackCatalogPhysicalResult{Validated: true, OldServiceAccountUID: "sa-old", NewServiceAccountUID: "sa-new",
		CredentialAuthenticatedBefore: true, PodRetained: true, PodUID: "pod-uid"}, nil
}

func (c *identityRotationAdapterTestCluster) Cleanup(context.Context, identityCatalogFixture, identityCatalogSignal, string) AttackCatalogCleanupResult {
	c.mutations.Store(0)
	return AttackCatalogCleanupResult{Attempted: true, EventDeleted: true, MarkerDeleted: true, Verified: true}
}

func TestIdentityRotationCatalogueBindingUsesExactExistingProfileAndDestination(t *testing.T) {
	profile := identityTestProfile(t, identityCatalogueRotation)
	cluster := &identityRotationAdapterTestCluster{}
	cfg := Config{Service: ServiceAttacks, AttackCatalogEnabled: true, AttackCatalogAuthorizationTenant: "phorvex-test",
		AttackCatalogIdentityTenant: "console-identity-test", AttackCatalogIdentityProfilePath: writeAttackCatalogProfile(t),
		AuditSource: &audittransport.Client{}}
	binding := &identityRotationCatalogueBinding{cfg: cfg, fixedCluster: cluster}
	availability := binding.Availability(profile)
	if !availability.Available || availability.FixtureTenant != "console-identity-test" || availability.RuntimeContext != defaultTargetID {
		t.Fatalf("availability=%+v", availability)
	}
	destination, err := binding.Destination(profile)
	if err != nil || destination.ScopeTarget != defaultTargetID || destination.ScopeTenant != "phorvex-test" ||
		!slices.Equal(destination.Targets, []string{defaultTargetID}) || !slices.Equal(destination.Tenants, []string{"phorvex-test"}) {
		t.Fatalf("destination=%+v err=%v", destination, err)
	}
	prepared, err := binding.Preflight(context.Background(), profile)
	if err != nil || cluster.prepared.Load() != 1 || cluster.mutations.Load() != 0 {
		t.Fatalf("preflight=%+v err=%v prepared=%d mutations=%d", prepared, err, cluster.prepared.Load(), cluster.mutations.Load())
	}
	run := AttackCatalogRunContext{RunID: "cat-alias", CatalogueID: profile.ID,
		ExpectedAction: profile.ExpectedAction, ReactiveCompatible: true}
	signal, mutated, err := binding.Launch(context.Background(), profile, run, prepared)
	if err != nil || !mutated || signal.UID == "" || cluster.entryID != profile.ID || cluster.mutations.Load() != 2 {
		t.Fatalf("signal=%+v mutated=%v err=%v entry=%s mutations=%d", signal, mutated, err, cluster.entryID, cluster.mutations.Load())
	}
	physical, err := binding.Physical(context.Background(), profile, prepared)
	if err != nil || physical.OldServiceAccountUID != "sa-old" || physical.NewServiceAccountUID != "sa-new" ||
		!physical.CredentialAuthenticatedBefore || physical.CredentialAuthenticatedAfter || !physical.PodRetained {
		t.Fatalf("physical=%+v err=%v", physical, err)
	}
	cleaned, err := binding.Cleanup(context.Background(), profile, prepared, signal)
	if err != nil || !cleaned.Attempted || !cleaned.EventAbsent || !cleaned.FixtureRestored || cluster.mutations.Load() != 0 {
		t.Fatalf("cleanup=%+v err=%v mutations=%d", cleaned, err, cluster.mutations.Load())
	}
}

func TestIdentityCatalogueProfilesFailClosedOnSubstitution(t *testing.T) {
	profile := identityTestProfile(t, identityCatalogueCredential)
	for name, mutate := range map[string]func(*identityCatalogueProfile){
		"id":     func(p *identityCatalogueProfile) { p.ID = "AML.T0053" },
		"family": func(p *identityCatalogueProfile) { p.Family = identityCatalogueAgent },
		"action": func(p *identityCatalogueProfile) { p.ExpectedAction = string(model.ActionAgentActionDeny) },
		"event":  func(p *identityCatalogueProfile) { p.EventType = model.AttackVectorAgentActionAbuse },
		"lane":   func(p *identityCatalogueProfile) { p.Lane = "p6" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := profile
			mutate(&changed)
			if validateIdentityCatalogueProfile(changed) == nil {
				t.Fatalf("substituted profile accepted: %+v", changed)
			}
		})
	}
}

type identityTestPrivate struct{ secret string }

type identityTestBinding struct {
	profile       identityCatalogueProfile
	preflightErr  error
	launchErr     error
	physicalErr   error
	cleanupErr    error
	physical      identityCataloguePhysicalObservation
	signal        identityCatalogueBindingSignal
	prepared      *identityCatalogueBindingPreparation
	preflightCall atomic.Int32
	launchCall    atomic.Int32
	physicalCall  atomic.Int32
	cleanupCall   atomic.Int32
	mutated       atomic.Bool
}

func newIdentityTestBinding(profile identityCatalogueProfile) *identityTestBinding {
	receipt := "ServiceAccount/fixture-ns/fixture-sa"
	switch profile.Family {
	case identityCatalogueCredential:
		receipt = "Secret/fixture-ns/revoked-token-object"
	case identityCatalogueAgent:
		receipt = "fixture-ns/agent-deny-guard"
	}
	prepared := &identityCatalogueBindingPreparation{Execution: AttackCatalogExecutionActive,
		Trigger: AttackCatalogTriggerReactive, EvidenceTenant: "fixture-ns", Namespace: "fixture-ns",
		PodName: "fixture-pod", TargetUID: "pod-uid", PolicyName: "fixture-policy", PolicyUID: "policy-uid",
		PolicyGeneration: 7, ReceiptObject: receipt, private: &identityTestPrivate{secret: identityAdapterSensitiveSentinel}}
	physical := identityCataloguePhysicalObservation{PodUID: "pod-uid", PodRetained: true}
	switch profile.Family {
	case identityCatalogueRotation:
		physical.OldServiceAccountUID, physical.NewServiceAccountUID = "sa-old", "sa-new"
		physical.CredentialAuthenticatedBefore = true
	case identityCatalogueCredential:
		physical.ServiceAccountUID = "sa-uid"
		physical.CredentialAuthenticatedBefore = true
		physical.CredentialObjectAbsent = true
	case identityCatalogueAgent:
		physical.GuardUID, physical.ServiceUID = "guard-uid", "service-uid"
		physical.DeniedAfter, physical.BenignAllowedAfter, physical.ServingSetRetained = true, true, true
	}
	return &identityTestBinding{profile: profile, prepared: prepared, physical: physical,
		signal: identityCatalogueBindingSignal{Name: "signal-name", UID: "signal-uid", Creator: "system:serviceaccount:fixture-ns:injector",
			CreatedAt: time.Now().UTC()}}
}

func (b *identityTestBinding) Availability(profile identityCatalogueProfile) AttackCatalogAdapterAvailability {
	return AttackCatalogAdapterAvailability{Available: profile == b.profile, RuntimeContext: defaultTargetID,
		TargetLabel: "hermetic fixture", FixtureTenant: "fixture-ns", RunnableNote: "hermetic identity-family fixture"}
}

func (b *identityTestBinding) Destination(profile identityCatalogueProfile) (runDestination, error) {
	if profile != b.profile {
		return runDestination{}, errors.New("profile mismatch")
	}
	return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{"fixture-auth"},
		ScopeTarget: defaultTargetID, ScopeTenant: "fixture-auth"}, nil
}

func (b *identityTestBinding) Preflight(_ context.Context, profile identityCatalogueProfile) (*identityCatalogueBindingPreparation, error) {
	b.preflightCall.Add(1)
	if profile != b.profile {
		return nil, errors.New("profile mismatch")
	}
	if b.preflightErr != nil {
		return nil, b.preflightErr
	}
	copy := *b.prepared
	return &copy, nil
}

func (b *identityTestBinding) Launch(_ context.Context, profile identityCatalogueProfile, run AttackCatalogRunContext, _ *identityCatalogueBindingPreparation) (identityCatalogueBindingSignal, bool, error) {
	b.launchCall.Add(1)
	if profile != b.profile || run.CatalogueID != b.profile.ID || run.ExpectedAction != b.profile.ExpectedAction {
		return identityCatalogueBindingSignal{}, false, errors.New("profile mismatch")
	}
	b.mutated.Store(true)
	if b.launchErr != nil {
		return b.signal, true, b.launchErr
	}
	return b.signal, true, nil
}

func (b *identityTestBinding) Physical(_ context.Context, profile identityCatalogueProfile, _ *identityCatalogueBindingPreparation) (identityCataloguePhysicalObservation, error) {
	b.physicalCall.Add(1)
	if profile != b.profile {
		return identityCataloguePhysicalObservation{}, errors.New("profile mismatch")
	}
	return b.physical, b.physicalErr
}

func (b *identityTestBinding) Cleanup(_ context.Context, profile identityCatalogueProfile, _ *identityCatalogueBindingPreparation, signal identityCatalogueBindingSignal) (identityCatalogueCleanupObservation, error) {
	b.cleanupCall.Add(1)
	if profile != b.profile || signal != b.signal {
		return identityCatalogueCleanupObservation{Attempted: true}, errors.New("profile or signal mismatch")
	}
	b.mutated.Store(false)
	return identityCatalogueCleanupObservation{Attempted: true, EventAbsent: true, FixtureRestored: true}, b.cleanupErr
}

func identityTestProfile(t *testing.T, family identityCatalogueFamily) identityCatalogueProfile {
	t.Helper()
	for _, factory := range newIdentityCatalogueAdapters() {
		if factory.profile.Family == family {
			return factory.profile
		}
	}
	t.Fatalf("no profile for family %s", family)
	return identityCatalogueProfile{}
}

func identityTestAdapter(t *testing.T, family identityCatalogueFamily) (*identityFamilyCatalogueAdapter, *identityTestBinding, AttackCatalogRunContext) {
	t.Helper()
	profile := identityTestProfile(t, family)
	binding := newIdentityTestBinding(profile)
	adapter := &identityFamilyCatalogueAdapter{profile: profile, binding: binding, pollInterval: time.Millisecond}
	adapter.records = func(context.Context) ([]audit.Record, error) {
		return []audit.Record{identityTestDecision(profile, binding.prepared, binding.signal)}, nil
	}
	run := AttackCatalogRunContext{RunID: "cat-family-test", CatalogueID: profile.ID,
		ExpectedAction: profile.ExpectedAction, ReactiveCompatible: true}
	return adapter, binding, run
}

func identityTestDecision(profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation, signal identityCatalogueBindingSignal) audit.Record {
	event := model.EventEvidence{Name: signal.Name, EventUID: signal.UID, Type: profile.EventType, TrustVerdict: "trusted",
		CreatorIdentity: signal.Creator, TargetPodUID: prepared.TargetUID, TargetsPod: true, TimestampPresent: true}
	return audit.Record{Kind: "phorvex.decision", Time: signal.CreatedAt.Add(time.Millisecond), Namespace: prepared.Namespace,
		Pod: prepared.PodName, Action: profile.ExpectedAction, Selected: true, Feasible: true, Actuated: true,
		DispatchOutcome: model.DispatchEmitted, Handler: profile.ExpectedAction, ObjectsTouched: []string{prepared.ReceiptObject},
		Events: []model.EventEvidence{event}, DecisionTrace: &model.DecisionTraceV2{DecisionID: "decision-id",
			PolicyNamespace: prepared.Namespace, PolicyName: prepared.PolicyName, PolicyUID: prepared.PolicyUID,
			AssetUID: prepared.TargetUID, SelectedAction: profile.ExpectedAction, DispatchOutcome: model.DispatchEmitted}}
}

func TestIdentityCatalogueWrongIDIsolationAndPreflightNoMutation(t *testing.T) {
	adapter, binding, run := identityTestAdapter(t, identityCatalogueCredential)
	wrong := run
	wrong.CatalogueID = identityTestProfile(t, identityCatalogueAgent).ID
	if _, err := adapter.Preflight(context.Background(), wrong); err == nil {
		t.Fatal("wrong catalogue ID reached family preflight")
	}
	if binding.preflightCall.Load() != 0 || binding.launchCall.Load() != 0 || binding.mutated.Load() {
		t.Fatalf("wrong ID touched binding: preflight=%d launch=%d mutated=%v", binding.preflightCall.Load(), binding.launchCall.Load(), binding.mutated.Load())
	}
	prepared, err := adapter.Preflight(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil || binding.preflightCall.Load() != 1 || binding.launchCall.Load() != 0 || binding.mutated.Load() {
		t.Fatalf("preflight mutated fixture: prepared=%T preflight=%d launch=%d mutated=%v", prepared, binding.preflightCall.Load(), binding.launchCall.Load(), binding.mutated.Load())
	}
	other, _, otherRun := identityTestAdapter(t, identityCatalogueAgent)
	if _, err = other.Execute(context.Background(), otherRun, prepared); err == nil || binding.launchCall.Load() != 0 {
		t.Fatal("cross-profile preparation reached launch")
	}
}

func TestIdentityCatalogueStaleAndCrossRunDecisionRejection(t *testing.T) {
	for _, family := range []identityCatalogueFamily{identityCatalogueCredential, identityCatalogueRotation, identityCatalogueAgent} {
		t.Run(string(family), func(t *testing.T) {
			profile := identityTestProfile(t, family)
			binding := newIdentityTestBinding(profile)
			good := identityTestDecision(profile, binding.prepared, binding.signal)
			if observed, _, receipt := identityFamilyCatalogueDecision(profile, good, binding.prepared, binding.signal); !observed || !receipt.ReceiptObserved {
				t.Fatal("positive exact decision/receipt was rejected")
			}
			cases := map[string]func(*audit.Record){
				"stale":        func(r *audit.Record) { r.Time = binding.signal.CreatedAt.Add(-time.Nanosecond) },
				"cross-run":    func(r *audit.Record) { r.Events[0].EventUID = "other-signal-uid" },
				"wrong-policy": func(r *audit.Record) { r.DecisionTrace.PolicyUID = "other-policy" },
				"wrong-target": func(r *audit.Record) { r.DecisionTrace.AssetUID = "other-pod" },
				"wrong-event":  func(r *audit.Record) { r.Events[0].Type = "other-event" },
				"duplicate":    func(r *audit.Record) { r.Events = append(r.Events, r.Events[0]) },
			}
			for name, mutate := range cases {
				t.Run(name, func(t *testing.T) {
					row := good
					row.Events = slices.Clone(good.Events)
					trace := *good.DecisionTrace
					row.DecisionTrace = &trace
					mutate(&row)
					if observed, _, receipt := identityFamilyCatalogueDecision(profile, row, binding.prepared, binding.signal); observed || receipt.ReceiptObserved {
						t.Fatalf("%s decision was accepted", name)
					}
				})
			}
			dry := good
			dryTrace := *good.DecisionTrace
			dry.DecisionTrace = &dryTrace
			dry.DryRun = true
			dry.DecisionTrace.DryRun = true
			if observed, _, receipt := identityFamilyCatalogueDecision(profile, dry, binding.prepared, binding.signal); !observed || receipt.ReceiptObserved {
				t.Fatal("dry-run decision was treated as an execution receipt")
			}
			wrongReceipt := good
			wrongReceipt.ObjectsTouched = []string{"Secret/other/other"}
			if observed, _, receipt := identityFamilyCatalogueDecision(profile, wrongReceipt, binding.prepared, binding.signal); !observed || receipt.ReceiptObserved {
				t.Fatal("wrong physical receipt object was accepted")
			}
		})
	}
}

func TestIdentityCatalogueFamilyOraclesPositiveAndNegative(t *testing.T) {
	for _, family := range []identityCatalogueFamily{identityCatalogueCredential, identityCatalogueRotation, identityCatalogueAgent} {
		t.Run(string(family), func(t *testing.T) {
			profile := identityTestProfile(t, family)
			binding := newIdentityTestBinding(profile)
			positive := encodeIdentityCataloguePhysical(profile, binding.physical)
			if err := validateIdentityFamilyPhysical(profile, positive); err != nil {
				t.Fatalf("positive oracle: %v, result=%+v", err, positive)
			}
			negative := binding.physical
			switch family {
			case identityCatalogueRotation:
				negative.CredentialAuthenticatedAfter = true
			case identityCatalogueCredential:
				negative.CredentialObjectAbsent = false
			case identityCatalogueAgent:
				negative.DeniedAfter = false
			}
			failed := encodeIdentityCataloguePhysical(profile, negative)
			if failed.Validated || validateIdentityFamilyPhysical(profile, failed) == nil {
				t.Fatalf("negative oracle defended: %+v", failed)
			}
			if len(positive.Evidence) > 0 {
				var document map[string]any
				if err := json.Unmarshal(positive.Evidence, &document); err != nil {
					t.Fatal(err)
				}
				document["unexpected"] = true
				tampered, _ := json.Marshal(document)
				positive.Evidence = tampered
				if validateIdentityFamilyPhysical(profile, positive) == nil {
					t.Fatal("oracle evidence with an unknown field was accepted")
				}
			}
		})
	}
}

func TestIdentityCatalogueCleanupRetryAndCancellation(t *testing.T) {
	adapter, binding, run := identityTestAdapter(t, identityCatalogueAgent)
	prepared, err := adapter.Preflight(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if observation, err := adapter.Execute(cancelled, run, prepared); !errors.Is(err, context.Canceled) || observation.MutationStarted || binding.launchCall.Load() != 0 {
		t.Fatalf("cancel-before-launch observation=%+v err=%v launches=%d", observation, err, binding.launchCall.Load())
	}
	// A real launch is then cleaned twice. The binding's idempotent result stays
	// verified and no mutation survives either reconciliation.
	observation, err := adapter.Execute(context.Background(), run, prepared)
	if err != nil || !observation.DefensiveChainComplete || !binding.mutated.Load() {
		t.Fatalf("execution observation=%+v err=%v mutated=%v", observation, err, binding.mutated.Load())
	}
	for i := 0; i < 2; i++ {
		cleanup := adapter.Cleanup(context.Background(), run, prepared)
		if !cleanup.Attempted || !cleanup.Verified || !cleanup.EventDeleted || !cleanup.MarkerDeleted || binding.mutated.Load() {
			t.Fatalf("cleanup %d=%+v mutated=%v", i, cleanup, binding.mutated.Load())
		}
	}
	if binding.cleanupCall.Load() != 2 {
		t.Fatalf("cleanup calls=%d", binding.cleanupCall.Load())
	}
}

func TestIdentityCatalogueErrorsAndEvidenceNeverPersistCredentialMaterial(t *testing.T) {
	adapter, binding, run := identityTestAdapter(t, identityCatalogueCredential)
	binding.preflightErr = errors.New(identityAdapterSensitiveSentinel)
	if _, err := adapter.Preflight(context.Background(), run); err == nil || strings.Contains(err.Error(), identityAdapterSensitiveSentinel) {
		t.Fatalf("preflight error was not safely reduced: %v", err)
	}
	binding.preflightErr = nil
	prepared, err := adapter.Preflight(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	binding.launchErr = errors.New(identityAdapterSensitiveSentinel)
	if _, err = adapter.Execute(context.Background(), run, prepared); err == nil || strings.Contains(err.Error(), identityAdapterSensitiveSentinel) {
		t.Fatalf("launch error was not safely reduced: %v", err)
	}
	binding.launchErr = nil
	observation, err := adapter.Execute(context.Background(), run, prepared)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := adapter.Cleanup(context.Background(), run, prepared)
	raw, err := json.Marshal(struct {
		Observation AttackCatalogObservation   `json:"observation"`
		Cleanup     AttackCatalogCleanupResult `json:"cleanup"`
	}{observation, cleanup})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), identityAdapterSensitiveSentinel) {
		t.Fatalf("credential material escaped into evidence: %s", raw)
	}
	if strings.Contains(strings.Join(observation.Actuator.ObjectsTouched, " "), identityAdapterSensitiveSentinel) {
		t.Fatal("credential material escaped through receipt objects")
	}
}

func identityFinishedResult(t *testing.T, adapter *identityFamilyCatalogueAdapter, binding *identityTestBinding, run AttackCatalogRunContext) AttackCatalogResult {
	t.Helper()
	prepared, err := adapter.Preflight(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	observation, err := adapter.Execute(context.Background(), run, prepared)
	if err != nil {
		t.Fatal(err)
	}
	result := AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: run.CatalogueID, RunID: run.RunID,
		Visible: true, Available: true, Launched: observation.Launched, ReactiveOnly: true,
		ExecutionMode: prepared.ExecutionMode(), TriggerMode: prepared.TriggerMode(), ExpectedAction: run.ExpectedAction,
		StartedAt: started, Signal: observation.Signal, Decision: observation.Decision,
		Actuator: observation.Actuator, PhysicalValidation: observation.PhysicalValidation,
		Cleanup: adapter.Cleanup(context.Background(), run, prepared)}
	result.finishVerdict(adapter, observation.Reason)
	if result.Verdict != "DEFENDED" || result.Validate() != nil || result.defendedRequirements(adapter) != nil || binding.mutated.Load() {
		t.Fatalf("strict positive result=%+v", result)
	}
	return result
}

func TestIdentityCatalogueStrictResultRecordAndRuntimeModes(t *testing.T) {
	for _, family := range []identityCatalogueFamily{identityCatalogueCredential, identityCatalogueRotation, identityCatalogueAgent} {
		t.Run(string(family), func(t *testing.T) {
			adapter, binding, run := identityTestAdapter(t, family)
			run.RunID = "cat-strict-" + string(family)
			result := identityFinishedResult(t, adapter, binding, run)
			if result.ExecutionMode != AttackCatalogExecutionActive || result.TriggerMode != AttackCatalogTriggerReactive || !result.ReactiveOnly {
				t.Fatalf("execution and trigger modes were merged: %+v", result)
			}

			stateDir := t.TempDir()
			server := NewServer(Config{Service: ServiceAttacks, StateDir: stateDir})
			if err := server.attackCatalogAdapters.Register(adapter); err != nil {
				t.Fatal(err)
			}
			out := server.cfg.runOutputPath(run.RunID)
			if err := os.MkdirAll(out, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := server.persistAttackCatalogRunArtifacts(adapter, result, nil); err != nil {
				t.Fatal(err)
			}
			server.runs.mu.Lock()
			server.runs.runs[run.RunID] = &RunStatus{ID: run.RunID, Config: run.CatalogueID, State: "done", ExecutionKind: attackCatalogExecutionKind}
			server.runs.runOut[run.RunID] = run.RunID
			server.runs.mu.Unlock()
			record, err := server.runs.AttackCatalogRunRecord(run.RunID)
			if err != nil || record == nil || record.Schema != attackCatalogRunRecordSchema ||
				record.RunID != run.RunID || record.CatalogueID != run.CatalogueID || record.Result.Verdict != "DEFENDED" ||
				record.ExecutionMode != result.ExecutionMode || record.TriggerMode != result.TriggerMode {
				t.Fatalf("record=%+v err=%v", record, err)
			}
			for _, name := range []string{attackCatalogResultFile, attackCatalogRunRecordFile} {
				raw, readErr := os.ReadFile(filepath.Join(out, name))
				if readErr != nil {
					t.Fatal(readErr)
				}
				if strings.Contains(string(raw), identityAdapterSensitiveSentinel) {
					t.Fatalf("%s persisted credential material", name)
				}
			}

			tampered := result
			tampered.Actuator.Handler = "other-action"
			if tampered.defendedRequirements(adapter) == nil {
				t.Fatal("strict result accepted a mismatched handler")
			}
			tampered = result
			tampered.Actuator.ObjectsTouched = []string{"Secret/other/other"}
			if tampered.defendedRequirements(adapter) == nil {
				t.Fatal("strict result accepted a receipt object not bound to cleanup evidence")
			}
			tampered = result
			tampered.ExecutionMode = AttackCatalogExecutionDryRun
			if tampered.defendedRequirements(adapter) == nil {
				t.Fatal("strict result accepted dry-run as defended execution")
			}
		})
	}
}

var _ identityCatalogueFamilyBinding = (*identityTestBinding)(nil)
