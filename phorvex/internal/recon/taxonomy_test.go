package recon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
)

// taxonomy_test.go — PHVX-77 / PHORVEXSEC-133.

func aiPod() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "llm", Node: "node-a", HasGPU: true, ModelID: "m", Stateful: true,
		RouteService: "infer", GuardrailVariants: 2, ServingEndpointReady: true,
	}}
}

func aiCover(t *testing.T) map[model.Action][]string {
	t.Helper()
	return ucwRecon{}.AssetFacts(aiPod(),
		FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true, Stateful: true}).CoverByAction
}

func kindsOf(t *testing.T, keys []string) []string {
	t.Helper()
	af := ucwRecon{}.AssetFacts(aiPod(),
		FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true, Stateful: true})
	byKey := map[string]string{}
	for _, f := range af.Facts {
		byKey[f.Key()] = f.Kind
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

// TestKVMigrateInvalidateCoversSessionNotRoute is item 3. Invalidating a KV cache destroys in-pod
// session state; it does not change the inference route the attacker learned. Granting it
// endpointPath claimed a defence it does not perform.
func TestKVMigrateInvalidateCoversSessionNotRoute(t *testing.T) {
	got := kindsOf(t, aiCover(t)[model.ActionKVMigrateInvalidate])
	if len(got) == 0 {
		t.Fatal("kv-migrate-invalidate has no cover at all on an AI pod")
	}
	for _, kind := range got {
		if kind == FactEndpointPath {
			t.Fatalf("kv-migrate-invalidate still claims %q — a KV flush does not stale a learned "+
				"route; endpointPath must remain audit-only", FactEndpointPath)
		}
	}
	found := false
	for _, kind := range got {
		if kind == FactSession {
			found = true
		}
	}
	if !found {
		t.Fatalf("kv-migrate-invalidate should cover %q; got %v", FactSession, got)
	}
}

func TestTierTwoAndThreeCarryNoCover(t *testing.T) {
	af := ucwRecon{}.AssetFacts(aiPod(), FactContext{
		AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true, Stateful: true,
	})
	covered := map[string]bool{}
	for _, keys := range af.CoverByAction {
		for _, key := range keys {
			covered[key] = true
		}
	}
	expected := map[string]FactScope{
		FactNodeFoothold:            ScopeNode,
		FactModelIdentity:           ScopeModel,
		FactGuardrailVariant:        ScopeService,
		FactCredential:              ScopePod,
		FactRetrievalState:          ScopePod,
		FactArtifactProvenance:      ScopePod,
		FactControlPlanePersistence: ScopePod,
	}
	seen := map[string]bool{}
	for _, fact := range af.Facts {
		scope, tracked := expected[fact.Kind]
		if !tracked {
			continue
		}
		seen[fact.Kind] = true
		if fact.Scope != scope {
			t.Errorf("%s scope = %q, want %q", fact.Kind, fact.Scope, scope)
		}
		if covered[fact.Key()] {
			t.Errorf("audit-only fact %s leaked into an action cover as %q", fact.Kind, fact.Key())
		}
	}
	for kind := range expected {
		if !seen[kind] {
			t.Errorf("audit taxonomy fact %s was not emitted by the rich workload fixture", kind)
		}
	}
}

func TestEveryEmittedFactDeclaresScope(t *testing.T) {
	for _, profile := range Registry.All() {
		for _, archetype := range coverArchetypes() {
			for _, fact := range profile.AssetFacts(archetype.view, archetype.fctx).Facts {
				if fact.Scope == "" {
					t.Errorf("%s/%s emitted unscoped fact %s", profile.Name(), archetype.name, fact.Kind)
				}
			}
		}
	}
}

func TestNoOrphanedCover(t *testing.T) {
	for _, profile := range Registry.All() {
		for _, archetype := range coverArchetypes() {
			af := profile.AssetFacts(archetype.view, archetype.fctx)
			facts := map[string]bool{}
			for _, fact := range af.Facts {
				facts[fact.Key()] = true
			}
			for action, keys := range af.CoverByAction {
				for _, key := range keys {
					if !facts[key] {
						t.Errorf("%s/%s action %s claims orphaned cover key %q",
							profile.Name(), archetype.name, action, key)
					}
				}
			}
		}
	}
}

// TestNoDeadFactKinds is item 1, generalised: a declared fact kind that no profile ever emits is
// dead weight that reads as capability. FactNodePlacement was exactly that — two repo-wide
// references, both its own comment and declaration.
//
// The declared set is parsed from facts.go rather than hand-listed. A hand-list can only catch the
// kind you already knew about: the first version of this test kept one, and re-declaring
// FactNodePlacement did NOT fail it, which made it useless for the thing it is named for.
func TestNoDeadFactKinds(t *testing.T) {
	declared := declaredFactKinds(t)
	if len(declared) < 8 {
		t.Fatalf("parsed only %d fact kinds from facts.go; the parser has drifted from the source", len(declared))
	}

	emitted := map[string]bool{}
	fctx := FactContext{
		AssetValue: 10, PHold: 1, StageUrgency: 1, LateralUrgency: 1,
		HasGPU: true, Stateful: true,
		Neighbors: []NeighborRef{{Key: "ns/neighbour", Value: 1}},
	}
	views := []*model.WorkloadView{
		aiPod(),
		{Pod: model.Pod{Namespace: "ns", Name: "web"}},
		{Pod: model.Pod{Namespace: "ns", Name: "db", Stateful: true}},
		{Pod: model.Pod{Namespace: "ns", Name: "lora", HasGPU: true, ModelID: "m", SuspectAdapter: "evil"}},
		{Pod: model.Pod{Namespace: "ns", Name: "api", UID: "api-uid", PodResourceVersion: "10", ServiceAccount: "reader",
			PodBoundKubeAPIAuth: &model.PodBoundKubeAPIAuthProjection{PodUID: "api-uid", PodResourceVersion: "10",
				ServiceAccountName: "reader", ServiceAccountUID: "sa-uid", VolumeName: "api-token", MountedContainer: "api",
				AudienceSource: "kube-apiserver-default", EvidenceSource: "admitted-pod-and-serviceaccount"}}},
		{Pod: model.Pod{Namespace: "ns", Name: "output", UID: "output-uid", OutputPolicyConfigMap: "policy-cm",
			OutputPolicyRuleSHA256: "rule-hash", OutputProxySourceSHA256: "proxy-hash",
			OutputSupportSourceSHA256: "support-hash", OutputEventCreator: "console-creator",
			OutputPolicyObservation: &model.SensitiveOutputObservation{EventName: "observed", EventUID: "event-uid",
				CreatorIdentity: "console-creator", TargetPodUID: "output-uid", ConfigMapUID: "cm-uid",
				PolicyName: "guardrail-output-fixture", PolicyUID: "policy-uid", PolicyGeneration: 1,
				RuleSHA256: "rule-hash", ProxySourceSHA256: "proxy-hash", SupportSourceSHA256: "support-hash",
				ProxyImageID: "proxy-image", SupportImageID: "support-image"}}},
		{Pod: model.Pod{Namespace: "voice", Name: "voice", UID: "voice-uid", VoiceMemoryConfigMap: "voice-memory-policy",
			VoiceMemorySourceSHA256: "source-sha", VoiceMemoryDeploymentUID: "deployment-uid", VoiceMemoryEventCreator: "console-creator",
			VoiceMemoryObservation: &model.VoiceMemoryObservation{EventName: "observed", EventUID: "voice-event-uid", CreatorIdentity: "console-creator",
				ScenarioID: "voice-live", CaseID: "owned-memory",
				TargetPodUID: "voice-uid", DeploymentUID: "deployment-uid", ConfigMapUID: "voice-cm-uid", SourceSHA256: "source-sha",
				CallerID: "+15551234567", NoteSHA256: "note-sha", PolicyUID: "policy-uid", PolicyGeneration: 1}}},
		{Pod: model.Pod{Namespace: "voice", Name: "voice-refund", UID: "refund-uid", VoiceRefundConfigMap: "voice-refund-policy",
			VoiceRefundSourceSHA256: "source-sha", VoiceRefundDeploymentUID: "deployment-uid", VoiceRefundEventCreator: "console-creator",
			VoiceRefundObservation: &model.VoiceRefundObservation{EventName: "observed", EventUID: "refund-event-uid", CreatorIdentity: "console-creator",
				ScenarioID: "voice-agency", CaseID: "owned-refund", TargetPodUID: "refund-uid", DeploymentUID: "deployment-uid",
				ConfigMapUID: "refund-cm-uid", SourceSHA256: "source-sha", AssertedCallerSHA256: "caller-sha", OrderSHA256: "order-sha",
				PolicyUID: "policy-uid", PolicyGeneration: 1}}},
		{Pod: model.Pod{Namespace: "voice", Name: "voice-output", UID: "output-uid", VoiceOutputConfigMap: "voice-output-policy",
			VoiceOutputSourceSHA256: "source-sha", VoiceOutputDeploymentUID: "deployment-uid", VoiceOutputEventCreator: "console-creator",
			VoiceOutputObservation: &model.VoiceOutputObservation{EventName: "observed", EventUID: "output-event-uid", CreatorIdentity: "console-creator",
				ScenarioID: "ai2-system-prompt-leakage", EvidenceSource: "TEST_INJECTED", TargetPodUID: "output-uid", DeploymentUID: "deployment-uid",
				ConfigMapUID: "output-cm-uid", SourceSHA256: "source-sha", MarkerSHA256: "marker-sha", PolicyName: "voice-defense", PolicyUID: "policy-uid",
				PolicyGeneration: 1, RawModelMarkerObserved: true, AssistantOutputMarkerObserved: true}}},
		{Pod: model.Pod{Namespace: "litellm", Name: "owned-client", UID: "owned-uid",
			LiteLLMClientObservation: &model.LiteLLMClientObservation{EventName: "event", EventUID: "event-uid",
				CreatorIdentity: "console", TargetPodUID: "owned-uid", PeerPodUID: "peer-uid",
				ClientSHA256: "client-hash", ConfigMapUID: "cm-uid", ClientsConfigMapUID: "clients-cm-uid",
				SeedSHA256: "seed-hash", ServiceUID: "service-uid",
				GatewaySourceSHA256: "source-hash", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1}}},
		{Pod: model.Pod{Namespace: "crm", Name: "crm", UID: "crm-uid",
			CRMRefundObservation: &model.CRMRefundObservation{EventName: "event", EventUID: "crm-event-uid",
				CreatorIdentity: "console", TargetPodUID: "crm-uid", PeerPodUID: "crm-peer-uid",
				OrderID: "OR-5002", OrderAccountID: "AC-1002", CallerAccountID: "AC-1001",
				GuardConfigMapUID: "guard-uid", ServiceUID: "service-uid",
				PolicyName: "crm-defense", PolicyUID: "policy-uid", PolicyGeneration: 1}}},
		boundVoiceMCPView(),
		boundVoiceAdmissionView(),
		endpointLeaseView(),
	}
	detectorAdapter(&views[3].Pod, "evil")
	for _, p := range Registry.All() {
		for _, v := range views {
			for _, f := range p.AssetFacts(v, fctx).Facts {
				emitted[f.Kind] = true
			}
		}
	}
	for name, value := range declared {
		if !emitted[value] {
			t.Errorf("%s = %q is declared but no registered profile emits it across any archetype — "+
				"dead taxonomy reads as capability", name, value)
		}
	}
}

func TestVoiceMCPObservedDescriptorProducesDistinctCover(t *testing.T) {
	view := boundVoiceMCPView()
	if !view.Pod.HasBoundVoiceMCPObservation() {
		t.Fatal("representative source-bound MCP observation is incomplete")
	}
	af := ucwRecon{}.AssetFacts(view, FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1})
	keys := af.CoverByAction[model.ActionVoiceMCPToolPin]
	if len(keys) != 1 {
		t.Fatalf("MCP descriptor observation has %d covers, want one", len(keys))
	}
	for _, fact := range af.Facts {
		if fact.Key() == keys[0] {
			if fact.Kind != FactVoiceMCPDescriptorSteering || fact.SteeredBy == nil ||
				fact.SteeredBy.RuleType != model.AttackVectorVoiceMCP || len(fact.SteeredBy.Events) != 1 ||
				fact.SteeredBy.Events[0].EventUID != view.Pod.VoiceMCPObservation.EventUID {
				t.Fatalf("MCP fact lost exact observed-event attribution: %+v", fact)
			}
			return
		}
	}
	t.Fatal("MCP cover refers to no emitted fact")
}

// declaredFactKinds reads every Fact* string constant straight out of facts.go, so a newly-added
// dead kind is caught without anyone remembering to update a list here.
func declaredFactKinds(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "facts.go", nil, 0)
	if err != nil {
		t.Fatalf("parse facts.go: %v", err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if !strings.HasPrefix(name.Name, "Fact") || i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			out[name.Name] = strings.Trim(lit.Value, `"`)
		}
		return true
	})
	return out
}

func boundVoiceAdmissionView() *model.WorkloadView {
	uid := "11111111-1111-4111-8111-111111111111"
	sha := strings.Repeat("a", 64)
	a := voiceadmissionpolicy.EventAssertion{Version: 1, ScenarioID: voiceadmissionpolicy.ScenarioID, CaseID: "unsigned-audio", RunSHA256: sha, SessionID: uid, DeploymentUID: uid, PodUID: uid, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, PolicyCMUID: uid, PolicyResourceVersion: "1", RuleSHA256: sha, SecurityPolicyUID: uid, SecurityPolicyGeneration: 1, ObservedAtUnixMs: 1, EvidenceSource: "TEST_INJECTED", Observed: true, SentAudioFrames: 1, SentAudioBytes: 1, ReceiptSHA256: sha, ProviderEvidenceSHA256: sha}
	return &model.WorkloadView{Pod: model.Pod{Namespace: "voice", Name: "voice", UID: uid, VoiceAdmissionConfigMap: voiceadmissionpolicy.ConfigMapName, VoiceAdmissionDeploymentUID: uid, VoiceAdmissionSourceSHA256: sha, VoiceAdmissionEventCreator: voiceadmissionpolicy.Creator, VoiceAdmissionObservation: &model.VoiceAdmissionObservation{EventName: "observed", EventUID: uid, CreatorIdentity: voiceadmissionpolicy.Creator, ScenarioID: voiceadmissionpolicy.ScenarioID, EvidenceSource: "TEST_INJECTED", TargetPodUID: uid, DeploymentUID: uid, ConfigMapUID: uid, ConfigMapResourceVersion: "1", SourceSHA256: sha, RuleSHA256: sha, PolicyName: "voice-defense", PolicyUID: uid, PolicyGeneration: 1, SessionID: uid, Assertion: a}}}
}

func TestVoiceAdmissionActualAccessHasDedicatedCover(t *testing.T) {
	v := boundVoiceAdmissionView()
	if !v.Pod.HasBoundVoiceAdmissionObservation() {
		t.Fatal("bound admission fixture incomplete")
	}
	facts := ucwRecon{}.AssetFacts(v, FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1})
	if len(facts.CoverByAction[model.ActionVoiceSessionAdmissionEnforce]) == 0 {
		t.Fatal("actual unauthorized admission has no enforce cover")
	}
	v.Pod.VoiceAdmissionObservation.Assertion.SentAudioBytes = 0
	facts = ucwRecon{}.AssetFacts(v, FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1})
	if len(facts.CoverByAction[model.ActionVoiceSessionAdmissionEnforce]) != 0 {
		t.Fatal("handshake-only observation creates admission cover")
	}
}
