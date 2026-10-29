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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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

func TestIdentityCatalogueConstructorErrorFailsClosed(t *testing.T) {
	factories := newIdentityCatalogueAdapters()
	factories[0].err = errors.New("review pin mismatch")
	adapters, err := bindIdentityCatalogueAdapters(nil, Config{}, factories)
	if err == nil || adapters != nil || !strings.Contains(err.Error(), "construct identity catalogue adapter") {
		t.Fatalf("adapters=%v err=%v", adapters, err)
	}
}

type identityFarmSpec struct {
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	Family    string `json:"family"`
	Lane      string `json:"lane"`
	Actuator  string `json:"actuator"`
	EventType string `json:"event_type"`
	Expected  string `json:"expected"`
	Target    struct {
		Namespace        string `json:"ns"`
		Deployment       string `json:"deployment"`
		Selector         string `json:"selector"`
		PodPrefix        string `json:"prefix"`
		PodSubstring     string `json:"pod_substr"`
		ServiceAccount   string `json:"service_account"`
		CredentialSecret string `json:"credential_secret"`
		AgentName        string `json:"agent_name"`
		GuardConfigMap   string `json:"guard_configmap"`
		Service          string `json:"service"`
	} `json:"target"`
	Arm struct {
		ServiceAccount string `json:"leak_service_account"`
		TokenSecret    string `json:"token_secret"`
		SecretType     string `json:"secret_type"`
		CallerID       string `json:"caller_id"`
		ActionID       string `json:"action_id"`
		AbusedPair     string `json:"abused_pair"`
		Grant          struct {
			APIGroups []string `json:"apiGroups"`
			Resources []string `json:"resources"`
			Verbs     []string `json:"verbs"`
		} `json:"grant"`
	} `json:"arm"`
	Oracle struct {
		ObservationAnnotation string `json:"observation_annotation"`
		PolicyName            string `json:"policy_name"`
		Objective             string `json:"objective"`
		GuardKey              string `json:"guard_key"`
		ReadbackPath          string `json:"readback_path"`
	} `json:"oracle"`
}

func TestIdentityCatalogueExactThirtyFarmSpecsMatchServerProfiles(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tools", "live-attack-runner", "runner", "fires.d")
	seen := map[string]bool{}
	for _, id := range append(slices.Clone(credentialCatalogueIDs[:]), agentActionCatalogueIDs[:]...) {
		raw, err := os.ReadFile(filepath.Join(root, id+".json"))
		if err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		var spec identityFarmSpec
		if err = json.Unmarshal(raw, &spec); err != nil {
			t.Fatalf("decode %s: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("duplicate blocked-ID spec %s", id)
		}
		seen[id] = true
		if profile, ok := credentialCatalogueServerProfiles[id]; ok {
			deployment, policyName := spec.Target.Deployment, spec.Oracle.PolicyName
			if deployment == "" {
				deployment = credentialCatalogueDeployment
			}
			if policyName == "" {
				policyName = credentialCataloguePolicy
			}
			if spec.Name != id || spec.Mode != "lane" || spec.Expected != "DEFENDED" ||
				spec.Family != "credential" || spec.Lane != "p4" ||
				spec.Actuator != string(model.ActionCredentialRevoke) || spec.EventType != model.AttackVectorCredentialTheft ||
				spec.Target.Namespace != profile.Namespace ||
				deployment != profile.Deployment || policyName != profile.PolicyName ||
				spec.Target.Selector != profile.SelectorKey+"="+profile.SelectorValue ||
				spec.Target.PodPrefix != profile.PodPrefix || spec.Target.PodSubstring != profile.Deployment ||
				spec.Target.ServiceAccount != profile.ServiceAccount || spec.Target.CredentialSecret != profile.TokenSecret ||
				spec.Arm.ServiceAccount != profile.ServiceAccount || spec.Arm.TokenSecret != profile.TokenSecret ||
				spec.Arm.SecretType != string(corev1.SecretTypeServiceAccountToken) ||
				!slices.Equal(spec.Arm.Grant.APIGroups, []string{""}) ||
				!slices.Equal(spec.Arm.Grant.Resources, []string{profile.GrantResource}) ||
				!slices.Equal(spec.Arm.Grant.Verbs, profile.GrantVerbs[:]) ||
				spec.Oracle.ObservationAnnotation != profile.ObservationKey {
				t.Fatalf("credential spec %s differs from server profile: spec=%+v profile=%+v", id, spec, profile)
			}
			continue
		}
		profile, ok := agentCatalogueServerProfiles[id]
		if !ok || spec.Name != id || spec.Mode != "lane" || spec.Expected != "DEFENDED" ||
			spec.Family != "agent-action" || spec.Lane != "p6" ||
			spec.Actuator != string(model.ActionAgentActionDeny) || spec.EventType != model.AttackVectorAgentActionAbuse ||
			spec.Target.Namespace != profile.Namespace ||
			spec.Target.Selector != profile.SelectorKey+"="+profile.SelectorVal || spec.Target.PodPrefix != profile.Service+"-" ||
			spec.Target.PodSubstring != profile.Service || spec.Target.AgentName != profile.AgentName ||
			spec.Target.GuardConfigMap != profile.GuardConfigMap || spec.Target.Service != profile.Service ||
			spec.Arm.CallerID != profile.CallerID || spec.Arm.ActionID != profile.ActionID ||
			spec.Arm.AbusedPair != profile.CallerID+"::"+profile.ActionID ||
			spec.Oracle.ObservationAnnotation != profile.ObservationKey || spec.Oracle.Objective != profile.Objective ||
			spec.Oracle.GuardKey != profile.GuardKey || spec.Oracle.ReadbackPath != profile.ReadbackPath {
			t.Fatalf("agent spec %s differs from server profile: spec=%+v profile=%+v", id, spec, profile)
		}
	}
	if len(seen) != 30 {
		t.Fatalf("exact blocked-ID specs=%d, want 30", len(seen))
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
	if credential == nil || credential.Availability().Available || !strings.Contains(credential.Availability().UnavailableReason, "not enabled") {
		t.Fatalf("credential availability=%+v", credential.Availability())
	}
	if agent == nil || agent.Availability().Available || !strings.Contains(agent.Availability().UnavailableReason, "not enabled") {
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

type identityCredentialAdapterTestCluster struct {
	prepared  atomic.Int32
	mutations atomic.Int32
	cleanups  atomic.Int32
	profile   identityCredentialServerProfile
}

func (c *identityCredentialAdapterTestCluster) Prepare(_ context.Context, profile identityCredentialServerProfile) (identityCredentialCatalogueFixture, error) {
	c.prepared.Add(1)
	c.profile = profile
	return identityCredentialCatalogueFixture{Profile: profile, PodName: "demo-api-fixed", PodUID: "pod-uid",
		DeploymentUID: "deployment-uid", PolicyUID: "policy-uid", PolicyGeneration: 9,
		MinimumAvailableReplicas: 2, ReactiveOnly: true}, nil
}

func (c *identityCredentialAdapterTestCluster) Launch(_ context.Context, profile identityCatalogueProfile, fixture identityCredentialCatalogueFixture, runID string, state *identityCredentialCatalogueRunState) (identityCatalogueBindingSignal, bool, error) {
	if profile.ID != fixture.Profile.CatalogueID || runID == "" || state == nil {
		return identityCatalogueBindingSignal{}, false, errors.New("profile mismatch")
	}
	c.mutations.Add(4)
	state.serviceAccountUID, state.roleUID, state.roleBindingUID, state.secretUID = "sa-uid", "role-uid", "binding-uid", "secret-uid"
	state.credential = identityAdapterSensitiveSentinel
	signal := identityCatalogueBindingSignal{Name: "credential-signal", UID: "signal-uid",
		Creator: "system:serviceaccount:p4:injector", CreatedAt: time.Now().UTC()}
	state.signal = signal
	return signal, true, nil
}

func (c *identityCredentialAdapterTestCluster) Physical(_ context.Context, fixture identityCredentialCatalogueFixture, state *identityCredentialCatalogueRunState) (identityCataloguePhysicalObservation, error) {
	if state == nil || state.credential == "" || fixture.Profile != c.profile {
		return identityCataloguePhysicalObservation{}, errors.New("state mismatch")
	}
	return identityCataloguePhysicalObservation{ServiceAccountUID: state.serviceAccountUID, PodUID: fixture.PodUID,
		CredentialAuthenticatedBefore: true, CredentialObjectAbsent: true, FreshCredentialAuthenticated: true,
		AvailabilityFloorRetained: true, PodRetained: true}, nil
}

func (c *identityCredentialAdapterTestCluster) Cleanup(_ context.Context, fixture identityCredentialCatalogueFixture, state *identityCredentialCatalogueRunState) (identityCatalogueCleanupObservation, error) {
	if state == nil || fixture.Profile != c.profile {
		return identityCatalogueCleanupObservation{Attempted: true}, errors.New("state mismatch")
	}
	c.cleanups.Add(1)
	c.mutations.Store(0)
	state.credential = ""
	return identityCatalogueCleanupObservation{Attempted: true, EventAbsent: true, FixtureRestored: true}, nil
}

func TestIdentityCredentialCatalogueBindingUsesExactServerProfileWithoutPreflightMutation(t *testing.T) {
	profile := identityTestProfile(t, identityCatalogueCredential)
	cluster := &identityCredentialAdapterTestCluster{}
	cfg := Config{Service: ServiceAttacks, AttackCatalogEnabled: true, AttackCatalogAuthorizationTenant: "phorvex-test",
		AuditSource: &audittransport.Client{}}
	binding := &identityCredentialCatalogueBinding{cfg: cfg, fixedCluster: cluster}
	availability := binding.Availability(profile)
	if !availability.Available || availability.FixtureTenant != credentialCatalogueNamespace || availability.RuntimeContext != defaultTargetID {
		t.Fatalf("availability=%+v", availability)
	}
	destination, err := binding.Destination(profile)
	if err != nil || destination.ScopeTarget != defaultTargetID || destination.ScopeTenant != "phorvex-test" ||
		!slices.Equal(destination.Targets, []string{defaultTargetID}) || !slices.Equal(destination.Tenants, []string{"phorvex-test"}) {
		t.Fatalf("destination=%+v err=%v", destination, err)
	}
	prepared, err := binding.Preflight(context.Background(), profile)
	serverProfile := credentialCatalogueServerProfiles[profile.ID]
	if err != nil || cluster.prepared.Load() != 1 || cluster.mutations.Load() != 0 || cluster.profile != serverProfile ||
		prepared.Namespace != serverProfile.Namespace || prepared.ReceiptObject != "Secret/"+serverProfile.Namespace+"/"+serverProfile.TokenSecret {
		t.Fatalf("preflight=%+v err=%v profile=%+v prepared=%d mutations=%d", prepared, err, cluster.profile, cluster.prepared.Load(), cluster.mutations.Load())
	}
	run := AttackCatalogRunContext{RunID: "cat-credential", CatalogueID: profile.ID,
		ExpectedAction: profile.ExpectedAction, ReactiveCompatible: true}
	signal, mutated, err := binding.Launch(context.Background(), profile, run, prepared)
	if err != nil || !mutated || signal.UID == "" || cluster.mutations.Load() != 4 {
		t.Fatalf("signal=%+v mutated=%v err=%v mutations=%d", signal, mutated, err, cluster.mutations.Load())
	}
	physical, err := binding.Physical(context.Background(), profile, prepared)
	if err != nil || !encodeIdentityCataloguePhysical(profile, physical).Validated {
		t.Fatalf("physical=%+v err=%v", physical, err)
	}
	wrongSignal := signal
	wrongSignal.UID = "other-signal-uid"
	if cleaned, cleanupErr := binding.Cleanup(context.Background(), profile, prepared, wrongSignal); cleanupErr == nil ||
		!cleaned.Attempted || cluster.cleanups.Load() != 0 || cluster.mutations.Load() != 4 {
		t.Fatalf("substituted cleanup signal was accepted: cleaned=%+v err=%v", cleaned, cleanupErr)
	}
	for i := 0; i < 2; i++ {
		cleaned, cleanupErr := binding.Cleanup(context.Background(), profile, prepared, signal)
		if cleanupErr != nil || !cleaned.Attempted || !cleaned.EventAbsent || !cleaned.FixtureRestored || cluster.mutations.Load() != 0 {
			t.Fatalf("cleanup %d=%+v err=%v mutations=%d", i, cleaned, cleanupErr, cluster.mutations.Load())
		}
	}
	if cluster.cleanups.Load() != 2 {
		t.Fatalf("cleanup calls=%d", cluster.cleanups.Load())
	}
}

func TestIdentityCredentialCleanupRefusesCrossRunNameReuseAndAcceptsRetry(t *testing.T) {
	current := types.UID("foreign-run-uid")
	deleted := false
	get := func() (types.UID, error) {
		if current == "" {
			return "", apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "credential-token")
		}
		return current, nil
	}
	del := func(types.UID) error {
		deleted = true
		current = ""
		return nil
	}
	if exactCredentialDelete(context.Background(), "owned-run-uid", get, del) || deleted {
		t.Fatal("cleanup deleted a same-name object owned by another run")
	}
	current = "owned-run-uid"
	if !exactCredentialDelete(context.Background(), "owned-run-uid", get, del) || !deleted || current != "" {
		t.Fatal("cleanup did not delete its exact UID-owned object")
	}
	deleted = false
	if !exactCredentialDelete(context.Background(), "owned-run-uid", get, del) || deleted {
		t.Fatal("cleanup retry did not accept already-absent exact object")
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
		physical.FreshCredentialAuthenticated = true
		physical.AvailabilityFloorRetained = true
	case identityCatalogueAgent:
		physical.GuardUID, physical.ServiceUID = "guard-uid", "service-uid"
		physical.DeniedAfter, physical.BenignAllowedAfter, physical.SurgicalAllowedAfter, physical.ServingSetRetained = true, true, true, true
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
			if family == identityCatalogueAgent {
				extraReceipt := good
				extraReceipt.ObjectsTouched = append(slices.Clone(good.ObjectsTouched), "fixture-ns/other")
				if observed, _, receipt := identityFamilyCatalogueDecision(profile, extraReceipt, binding.prepared, binding.signal); !observed || receipt.ReceiptObserved {
					t.Fatal("agent receipt with an additional touched object was accepted")
				}
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

func TestIdentityCredentialOracleRequiresBothPositiveControls(t *testing.T) {
	profile := identityTestProfile(t, identityCatalogueCredential)
	baseline := newIdentityTestBinding(profile).physical
	for name, mutate := range map[string]func(*identityCataloguePhysicalObservation){
		"fresh-token":        func(o *identityCataloguePhysicalObservation) { o.FreshCredentialAuthenticated = false },
		"availability-floor": func(o *identityCataloguePhysicalObservation) { o.AvailabilityFloorRetained = false },
		"same-pod":           func(o *identityCataloguePhysicalObservation) { o.PodRetained = false },
		"stolen-token":       func(o *identityCataloguePhysicalObservation) { o.CredentialAuthenticatedAfter = true },
	} {
		t.Run(name, func(t *testing.T) {
			observed := baseline
			mutate(&observed)
			result := encodeIdentityCataloguePhysical(profile, observed)
			if result.Validated || validateIdentityFamilyPhysical(profile, result) == nil {
				t.Fatalf("credential oracle accepted missing %s control: %+v", name, result)
			}
		})
	}
}

func TestIdentityAgentOracleRequiresBothAllowControls(t *testing.T) {
	profile := identityTestProfile(t, identityCatalogueAgent)
	baseline := newIdentityTestBinding(profile).physical
	for name, mutate := range map[string]func(*identityCataloguePhysicalObservation){
		"abused-deny":    func(o *identityCataloguePhysicalObservation) { o.DeniedAfter = false },
		"benign-pair":    func(o *identityCataloguePhysicalObservation) { o.BenignAllowedAfter = false },
		"surgical-pair":  func(o *identityCataloguePhysicalObservation) { o.SurgicalAllowedAfter = false },
		"serving-set":    func(o *identityCataloguePhysicalObservation) { o.ServingSetRetained = false },
		"clean-baseline": func(o *identityCataloguePhysicalObservation) { o.DeniedBefore = true },
	} {
		t.Run(name, func(t *testing.T) {
			observed := baseline
			mutate(&observed)
			result := encodeIdentityCataloguePhysical(profile, observed)
			if result.Validated || validateIdentityFamilyPhysical(profile, result) == nil {
				t.Fatalf("agent oracle accepted missing %s control: %+v", name, result)
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
	for _, family := range []identityCatalogueFamily{identityCatalogueCredential, identityCatalogueRotation, identityCatalogueAgent} {
		t.Run(string(family), func(t *testing.T) {
			adapter, binding, run := identityTestAdapter(t, family)
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
				t.Fatalf("private material escaped into evidence: %s", raw)
			}
			if strings.Contains(strings.Join(observation.Actuator.ObjectsTouched, " "), identityAdapterSensitiveSentinel) {
				t.Fatal("private material escaped through receipt objects")
			}
		})
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
			registry := NewAttackCatalogAdapterRegistry()
			server.attackCatalogAdapters = registry
			server.runs.attackCatalogAdapters = registry
			if err := registry.Register(adapter); err != nil {
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
