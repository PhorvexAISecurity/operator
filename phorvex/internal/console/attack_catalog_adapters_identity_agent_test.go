package console

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/agentdeny"
	"github.com/phorvex/phorvex/internal/audittransport"
)

const testAgentFixtureImage = "registry.example.test/phorvex/agent-sim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func agentCatalogueTestConfig() Config {
	return Config{Service: ServiceAttacks, AttackCatalogEnabled: true, AttackCatalogAuthorizationTenant: "phorvex-test",
		AttackCatalogAgentActionEnabled: true, AttackCatalogAgentActionImage: testAgentFixtureImage,
		AttackCatalogAgentManagerPrincipal:  "system:serviceaccount:p6:p6-phorvex-manager",
		AttackCatalogAgentSensorPrincipal:   "system:serviceaccount:p6:p6-sensor",
		AttackCatalogAgentActuatorPrincipal: "system:serviceaccount:p6:p6-actuator",
		AuditSource:                         &audittransport.Client{}}
}

func TestAgentCatalogueSixExactIDsAreCentrallyWired(t *testing.T) {
	server := NewServer(agentCatalogueTestConfig())
	want := []string{"AML.T0053", "AML.T0086", "AML.T0101", "ASI02:2026", "LLM06:2025", "MCP02:2025"}
	if !slices.Equal(agentActionCatalogueIDs[:], want) {
		t.Fatalf("agent-action membership=%v want=%v", agentActionCatalogueIDs, want)
	}
	for _, id := range want {
		adapter, ok := server.attackCatalogAdapters.Lookup(id)
		if !ok || adapter.CatalogueID() != id || !adapter.Availability().Available ||
			adapter.Availability().FixtureTenant != agentCatalogueNamespace {
			t.Fatalf("adapter %s wiring/availability=%v %+v", id, ok, adapter.Availability())
		}
	}
	if _, ok := server.attackCatalogAdapters.Lookup("AML.T0053 "); ok {
		t.Fatal("whitespace alias reached the central registry")
	}
	if _, ok := server.attackCatalogAdapters.Lookup("AML.T0012"); !ok {
		t.Fatal("retained AML.T0012 adapter was displaced")
	}
}

func TestImmutableAgentFixtureImageValidation(t *testing.T) {
	for name, candidate := range map[string]string{
		"tag":          "registry.example.test/phorvex/agent-sim:latest",
		"tag-digest":   "registry.example.test/phorvex/agent-sim:v1@sha256:" + strings.Repeat("a", 64),
		"short digest": "registry.example.test/phorvex/agent-sim@sha256:abcd",
		"scheme":       "https://registry.example.test/phorvex/agent-sim@sha256:" + strings.Repeat("a", 64),
		"shell":        "registry.example.test/phorvex/agent-sim@sha256:" + strings.Repeat("a", 64) + ";id",
	} {
		t.Run(name, func(t *testing.T) {
			if ValidAttackCatalogAgentActionImage(candidate) {
				t.Fatalf("mutable or unsafe image accepted: %q", candidate)
			}
		})
	}
	if !ValidAttackCatalogAgentActionImage(testAgentFixtureImage) {
		t.Fatal("valid immutable image was rejected")
	}
}

type identityAgentAdapterTestCluster struct {
	prepared  atomic.Int32
	mutations atomic.Int32
	binds     atomic.Int32
	cleanups  atomic.Int32
	profile   identityAgentServerProfile
	fixture   identityAgentCatalogueFixture
	signal    identityCatalogueBindingSignal
}

func (c *identityAgentAdapterTestCluster) Prepare(_ context.Context, profile identityAgentServerProfile) (identityAgentCatalogueFixture, error) {
	c.prepared.Add(1)
	c.profile = profile
	c.fixture = identityAgentCatalogueFixture{Profile: profile, DeploymentUID: "deployment-uid", PolicyUID: "policy-uid",
		PolicyGeneration: 3, TargetPodName: "agent-sim-fixed", TargetPodUID: "pod-a", ServiceUID: "service-uid",
		GuardUID: "guard-uid", PodUIDs: []string{"pod-a", "pod-b"}, ReactiveOnly: true}
	return c.fixture, nil
}

func (c *identityAgentAdapterTestCluster) Launch(_ context.Context, profile identityCatalogueProfile, fixture identityAgentCatalogueFixture, runID string, state *identityAgentCatalogueRunState) (identityCatalogueBindingSignal, bool, error) {
	if state == nil || runID == "" || profile.ID != fixture.Profile.CatalogueID || !sameAgentCatalogueFixture(fixture, c.fixture) {
		return identityCatalogueBindingSignal{}, false, errors.New("profile mismatch")
	}
	c.mutations.Add(1)
	c.signal = identityCatalogueBindingSignal{Name: "agent-signal", UID: "signal-uid",
		Creator: "system:serviceaccount:p6:p6-attacks", CreatedAt: time.Now().UTC()}
	state.runID, state.signal = runID, c.signal
	return c.signal, true, nil
}

func (c *identityAgentAdapterTestCluster) BindAcceptedReceipt(fixture identityAgentCatalogueFixture, state *identityAgentCatalogueRunState, signal identityCatalogueBindingSignal, decisionID string) error {
	if !sameAgentCatalogueFixture(fixture, c.fixture) || state == nil || signal != c.signal || decisionID == "" {
		return errors.New("receipt mismatch")
	}
	if state.acceptedDecisionID != "" && state.acceptedDecisionID != decisionID {
		return errors.New("cross-run decision")
	}
	state.acceptedDecisionID = decisionID
	c.binds.Add(1)
	return nil
}

func (c *identityAgentAdapterTestCluster) Physical(_ context.Context, fixture identityAgentCatalogueFixture, state *identityAgentCatalogueRunState) (identityCataloguePhysicalObservation, error) {
	if !sameAgentCatalogueFixture(fixture, c.fixture) || state == nil || state.acceptedDecisionID != "decision-id" {
		return identityCataloguePhysicalObservation{}, errors.New("accepted decision missing")
	}
	return identityCataloguePhysicalObservation{PodUID: fixture.TargetPodUID, GuardUID: fixture.GuardUID,
		ServiceUID: fixture.ServiceUID, DeniedAfter: true, BenignAllowedAfter: true,
		SurgicalAllowedAfter: true, ServingSetRetained: true}, nil
}

func (c *identityAgentAdapterTestCluster) Cleanup(_ context.Context, fixture identityAgentCatalogueFixture, state *identityAgentCatalogueRunState) (identityCatalogueCleanupObservation, error) {
	if !sameAgentCatalogueFixture(fixture, c.fixture) || state == nil {
		return identityCatalogueCleanupObservation{Attempted: true}, errors.New("cleanup mismatch")
	}
	c.cleanups.Add(1)
	c.mutations.Store(0)
	return identityCatalogueCleanupObservation{Attempted: true, EventAbsent: true, FixtureRestored: true}, nil
}

func TestAgentCatalogueBindingPreflightReceiptOracleAndCleanup(t *testing.T) {
	profile := identityTestProfile(t, identityCatalogueAgent)
	cluster := &identityAgentAdapterTestCluster{}
	binding := &identityAgentCatalogueBinding{cfg: agentCatalogueTestConfig(), fixedCluster: cluster}
	if !binding.Availability(profile).Available {
		t.Fatalf("agent binding unavailable: %+v", binding.Availability(profile))
	}
	destination, err := binding.Destination(profile)
	if err != nil || destination.ScopeTenant != "phorvex-test" || destination.ScopeTarget != defaultTargetID {
		t.Fatalf("destination=%+v err=%v", destination, err)
	}
	prepared, err := binding.Preflight(context.Background(), profile)
	if err != nil || cluster.prepared.Load() != 1 || cluster.mutations.Load() != 0 ||
		prepared.Namespace != agentCatalogueNamespace || prepared.ReceiptObject != agentCatalogueNamespace+"/"+agentdeny.GuardConfigMapName {
		t.Fatalf("preflight=%+v err=%v prepared=%d mutations=%d", prepared, err, cluster.prepared.Load(), cluster.mutations.Load())
	}
	run := AttackCatalogRunContext{RunID: "cat-agent", CatalogueID: profile.ID,
		ExpectedAction: profile.ExpectedAction, ReactiveCompatible: true}
	signal, mutated, err := binding.Launch(context.Background(), profile, run, prepared)
	if err != nil || !mutated || signal.UID == "" || cluster.mutations.Load() != 1 {
		t.Fatalf("signal=%+v mutated=%v err=%v", signal, mutated, err)
	}
	if _, err = binding.Physical(context.Background(), profile, prepared); err == nil {
		t.Fatal("physical oracle passed without an accepted decision receipt")
	}
	if err = binding.BindAcceptedReceipt(profile, prepared, signal, "decision-id"); err != nil {
		t.Fatal(err)
	}
	physical, err := binding.Physical(context.Background(), profile, prepared)
	if err != nil || !encodeIdentityCataloguePhysical(profile, physical).Validated {
		t.Fatalf("physical=%+v err=%v", physical, err)
	}
	if err = binding.BindAcceptedReceipt(profile, prepared, signal, "other-decision"); err == nil {
		t.Fatal("cross-run accepted decision replaced the bound receipt")
	}
	wrong := signal
	wrong.UID = "other-signal"
	if cleaned, cleanupErr := binding.Cleanup(context.Background(), profile, prepared, wrong); cleanupErr == nil || cleaned.FixtureRestored {
		t.Fatal("cleanup accepted a substituted signal")
	}
	for i := 0; i < 2; i++ {
		cleaned, cleanupErr := binding.Cleanup(context.Background(), profile, prepared, signal)
		if cleanupErr != nil || !cleaned.EventAbsent || !cleaned.FixtureRestored || cluster.mutations.Load() != 0 {
			t.Fatalf("cleanup %d=%+v err=%v", i, cleaned, cleanupErr)
		}
	}
}

func TestAgentCatalogueCleanupGuardIsRetrySafeAndCrossRunSafe(t *testing.T) {
	empty := map[string]string{agentdeny.GuardKey: `{"denied_agent_actions":[]}`}
	if _, changed, err := agentCatalogueCleanGuardData(empty, "caller-a::action-a", "decision-a"); err != nil || changed {
		t.Fatalf("clean retry changed state: changed=%v err=%v", changed, err)
	}
	guard, err := (agentdeny.Guard{Version: 2, Entries: []agentdeny.Entry{}}).Append("caller-a::action-a", "decision-a")
	if err != nil {
		t.Fatal(err)
	}
	state, err := agentdeny.EncodeState(guard)
	if err != nil {
		t.Fatal(err)
	}
	dirty := map[string]string{agentdeny.GuardKey: guard.EncodeAppGuard(), agentdeny.StateKey: state}
	if _, _, err = agentCatalogueCleanGuardData(dirty, "caller-a::action-a", "other-decision"); err == nil {
		t.Fatal("cleanup accepted a cross-run operation ID")
	}
	next, changed, err := agentCatalogueCleanGuardData(dirty, "caller-a::action-a", "decision-a")
	if err != nil || !changed || next[agentdeny.StateKey] != "" || next[agentdeny.GuardKey] != `{"denied_agent_actions":[]}` {
		t.Fatalf("own cleanup next=%v changed=%v err=%v", next, changed, err)
	}
	if _, changed, err = agentCatalogueCleanGuardData(next, "caller-a::action-a", "decision-a"); err != nil || changed {
		t.Fatalf("cleanup retry next changed=%v err=%v", changed, err)
	}
}

var _ identityAgentCatalogueCluster = (*identityAgentAdapterTestCluster)(nil)
