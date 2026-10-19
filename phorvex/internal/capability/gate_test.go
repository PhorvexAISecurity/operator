package capability

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/authz"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	"github.com/phorvex/phorvex/internal/voicemcppolicy"
)

// okActuator is a capability-transport stub that always says wired (isolates the CONFIG
// predicates from the M-79 transport check, which has its own test via the real actuator).
type okActuator struct{}

func (okActuator) Name() string                                              { return "ok" }
func (okActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }
func (okActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return actuator.Result{}, nil
}
func (okActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}

// capFleet returns a fully-capable AI fleet + a witness built over it (transport stubbed
// wired, no installability gaps, no SSAR checker — the config/pool leg in isolation).
func capFleet() ([]*model.WorkloadView, Witness) {
	leader := model.Pod{
		Namespace: "ns", Name: "leader", HasGPU: true, MIGDevice: "1g.10gb", ModelID: "model",
		Node: "gpu-a", UID: "uid-leader", SuspectAdapter: "adapter-a",
		AdapterObservation: &model.AdapterObservation{EventName: "detected", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:ns:detector", TargetPodUID: "uid-leader", AdapterName: "adapter-a"},
		Ready:              true, ServingEndpointReady: true, RouteService: "infer", GuardrailVariants: 2,
		WarmPoolConfigured: true, WarmPoolOwnerUID: "pool-uid",
		Labels: map[string]string{
			"app": "infer", labelServing: "true", labelLoRAEnabled: "true", labelGuardrailTier: "true",
			labelWarmRole: "leader", labelSwapGroup: "swap-a", labelModelShard: "shard-a",
		},
	}
	swap := model.Pod{Namespace: "ns", Name: "swap-shadow", HasGPU: true, ModelID: "model", Ready: true, RouteService: "infer", WarmPoolConfigured: true, WarmPoolOwnerUID: "pool-uid",
		Labels: map[string]string{labelWarmRole: warmShadowRole, labelModelLoaded: "true", labelSwapGroup: "swap-a"}}
	shard := model.Pod{Namespace: "ns", Name: "shard-shadow", HasGPU: true, ModelID: "model", Ready: true, RouteService: "infer", WarmPoolConfigured: true, WarmPoolOwnerUID: "pool-uid",
		Labels: map[string]string{labelWarmRole: warmShadowRole, labelModelLoaded: "true", labelModelShard: "shard-a"}}
	fleet := []model.Pod{leader, swap, shard}
	views := []*model.WorkloadView{{Pod: leader}, {Pod: swap}, {Pod: shard}}
	nodes := []ingest.NodeInfo{{Name: "gpu-a", Schedulable: true, AllocatableGPU: 1}, {Name: "gpu-b", Schedulable: true, AllocatableGPU: 1}}
	svcs := []ingest.ServiceInfo{{Namespace: "ns", Name: "infer", Selector: map[string]string{"app": "infer", labelServing: "true", labelWarmRole: "leader", labelSwapGroup: "swap-a", labelModelShard: "shard-a"}}}
	wit := BuildWitness(context.Background(), BuildIndex(fleet, nodes, svcs), nil, nil, localActuator(okActuator{}))
	return views, wit
}

func mcpCapableFixture() (*model.WorkloadView, Witness) {
	p := model.Pod{Namespace: "voice", Name: "bot", UID: "11111111-1111-4111-8111-111111111111", HasGPU: true, ModelID: "voice-model",
		VoiceMCPConfigMap: "voice-mcp-tool-policy", VoiceMCPDeploymentUID: "22222222-2222-4222-8222-222222222222",
		VoiceMCPSourceSHA256: strings.Repeat("a", 64), VoiceMCPEventCreator: "system:serviceaccount:phorvex-system:console"}
	p.VoiceMCPObservation = &model.VoiceMCPObservation{EventName: "mcp-event", EventUID: "33333333-3333-4333-8333-333333333333",
		CreatorIdentity: p.VoiceMCPEventCreator, ScenarioID: "ai2-mcp-tool-poisoning", RunSHA256: strings.Repeat("b", 64),
		TargetPodUID: p.UID, DeploymentUID: p.VoiceMCPDeploymentUID, ConfigMapUID: "44444444-4444-4444-8444-444444444444",
		SourceConfigMapUID: "55555555-5555-4555-8555-555555555555", SourceSHA256: p.VoiceMCPSourceSHA256,
		ToolName: voicemcppolicy.StoreDirectory, GoodDescriptorSHA256: voicemcppolicy.StoreDirectoryGoodSHA256,
		ObservedDescriptorSHA256: strings.Repeat("c", 64), MCPServiceName: voicemcppolicy.MCPServiceName,
		MCPServiceUID: "66666666-6666-4666-8666-666666666666", MCPPodName: "mcp-server-1",
		MCPPodUID: "77777777-7777-4777-8777-777777777777", MCPDeploymentUID: "88888888-8888-4888-8888-888888888888",
		MCPConfigMapUID: "99999999-9999-4999-8999-999999999999", MCPSourceSHA256: voicemcppolicy.ReviewedMCPSourceSHA256,
		PolicyName: "voice-defense", PolicyUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PolicyGeneration: 1}
	view := &model.WorkloadView{Pod: p}
	witness := BuildWitness(context.Background(), BuildIndex([]model.Pod{p}, nil, nil), nil, nil, localActuator(okActuator{})).
		WithPolicyIdentity("voice-defense", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	return view, witness
}

func endpointLeaseCapableFixture() (*model.WorkloadView, Witness) {
	p := model.Pod{Namespace: "vllm", Name: "vllm-0", UID: "11111111-1111-4111-8111-111111111111"}
	p.EndpointLeaseObservation = &model.EndpointLeaseObservation{
		EventName: "lease-event", EventUID: "22222222-2222-4222-8222-222222222222",
		CreatorIdentity: "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
		ScenarioID:      "ai2-endpoint-security", EvidenceSource: "TEST_INJECTED",
		PolicyName: "vllm-defense", PolicyUID: "33333333-3333-4333-8333-333333333333", PolicyGeneration: 1,
		TargetPodUID: p.UID, ServiceUID: "44444444-4444-4444-8444-444444444444",
		PolicyConfigMapUID: "55555555-5555-4555-8555-555555555555", ProxySourceSHA256: strings.Repeat("a", 64),
		SecretUID: "66666666-6666-4666-8666-666666666666", SeedSHA256: strings.Repeat("b", 64),
		RevokedClientHMAC: strings.Repeat("c", 64), RetainedClientHMAC: strings.Repeat("d", 64),
		AcceptedStatus: 200, AcceptedResponseSHA256: strings.Repeat("e", 64),
		RetainedBaselineStatus: 200, RetainedBaselineResponseSHA256: strings.Repeat("f", 64),
		ObservedAt: time.Now().UTC(),
	}
	view := &model.WorkloadView{Pod: p}
	witness := BuildWitness(context.Background(), BuildIndex([]model.Pod{p}, nil, nil), nil, nil, localActuator(okActuator{})).
		WithOperatorNamespace("phorvex-system").
		WithPolicyIdentity("vllm-defense", p.EndpointLeaseObservation.PolicyUID)
	return view, witness
}

// TestCapable_AllPredicatesGreen uses the generic leader for ordinary AI moves
// and an exact observed Voice target for MCP descriptor pinning.
func TestCapable_AllPredicatesGreen(t *testing.T) {
	views, wit := capFleet()
	for action := range AICapabilityActions {
		if action == model.ActionEndpointLeaseRevoke {
			lease, scoped := endpointLeaseCapableFixture()
			if ok, why := scoped.Capable(lease, action); !ok {
				t.Errorf("source-bound vLLM endpoint lease target not capable: %s", why)
			}
			continue
		}
		if action == model.ActionVoiceMCPToolPin {
			voice, scoped := mcpCapableFixture()
			if ok, why := scoped.Capable(voice, action); !ok {
				t.Errorf("source-bound Voice MCP target not capable: %s", why)
			}
			continue
		}
		if action == model.ActionVoiceSessionAdmissionEnforce || action == model.ActionSensitiveOutputPolicyActivate || action == model.ActionVoiceMemoryNoteRevoke || action == model.ActionVoiceRefundPairDeny || action == model.ActionVoiceOutputPolicyActivate || action == model.ActionLiteLLMClientRevoke || action == model.ActionCRMRefundRevoke {
			continue // unlike generic AI actions, this requires an exact trusted event
		}
		if ok, why := wit.Capable(views[0], action); !ok {
			t.Errorf("leader not capable for %s: %s", action, why)
		}
	}
}

func TestEndpointLeaseCapabilityRequiresBoundObservationAndPolicyIdentity(t *testing.T) {
	view, witness := endpointLeaseCapableFixture()
	if ok, why := witness.Capable(view, model.ActionEndpointLeaseRevoke); !ok {
		t.Fatalf("complete observed lease source excluded: %s", why)
	}
	missing := *view
	missing.Pod = view.Pod
	missing.Pod.EndpointLeaseObservation = nil
	if ok, _ := witness.Capable(&missing, model.ActionEndpointLeaseRevoke); ok {
		t.Fatal("absent endpoint lease observation accepted")
	}
	if ok, _ := witness.WithPolicyIdentity("other", "77777777-7777-4777-8777-777777777777").Capable(view, model.ActionEndpointLeaseRevoke); ok {
		t.Fatal("wrong selecting policy accepted")
	}
}

func TestVoiceMCPCapabilityRequiresCompleteSourceAndPolicyJoin(t *testing.T) {
	view, witness := mcpCapableFixture()
	if ok, why := witness.Capable(view, model.ActionVoiceMCPToolPin); !ok {
		t.Fatalf("complete observed source excluded: %s", why)
	}
	missingSource := *view
	missingSource.Pod = view.Pod
	copyObservation := *view.Pod.VoiceMCPObservation
	copyObservation.SourceConfigMapUID = ""
	missingSource.Pod.VoiceMCPObservation = &copyObservation
	if ok, _ := witness.Capable(&missingSource, model.ActionVoiceMCPToolPin); ok {
		t.Fatal("missing immutable Voice source UID accepted")
	}
	if ok, _ := witness.WithPolicyIdentity("other", "other-uid").Capable(view, model.ActionVoiceMCPToolPin); ok {
		t.Fatal("different selecting policy accepted")
	}
}

func TestSensitiveOutputCapabilityRequiresExactPolicyObservation(t *testing.T) {
	p := model.Pod{Namespace: "ns", Name: "fixture", UID: "pod-uid", ServingDeclared: true,
		OutputPolicyConfigMap: "policy-cm", OutputPolicyRuleSHA256: "rule", OutputProxySourceSHA256: "proxy",
		OutputSupportSourceSHA256: "support", OutputEventCreator: "creator"}
	v := &model.WorkloadView{Pod: p}
	w := BuildWitness(context.Background(), BuildIndex([]model.Pod{p}, nil, nil), nil, nil, localActuator(okActuator{})).
		WithPolicyIdentity("guardrail-output-fixture", "policy-uid")
	if ok, _ := w.Capable(v, model.ActionSensitiveOutputPolicyActivate); ok {
		t.Fatal("missing event accepted")
	}
	v.Pod.OutputPolicyObservation = &model.SensitiveOutputObservation{EventName: "event", EventUID: "event-uid",
		CreatorIdentity: "creator", TargetPodUID: "pod-uid", ConfigMapUID: "cm-uid",
		PolicyName: "guardrail-output-fixture", PolicyUID: "policy-uid", PolicyGeneration: 1,
		RuleSHA256: "rule", ProxySourceSHA256: "proxy", SupportSourceSHA256: "support",
		ProxyImageID: "image-a", SupportImageID: "image-b"}
	if ok, why := w.Capable(v, model.ActionSensitiveOutputPolicyActivate); !ok {
		t.Fatalf("bound event excluded: %s", why)
	}
	w = w.WithPolicyIdentity("other", "other-uid")
	if ok, _ := w.Capable(v, model.ActionSensitiveOutputPolicyActivate); ok {
		t.Fatal("wrong policy accepted")
	}
}

func TestM033RouteCapabilityRequiresActualServiceContract(t *testing.T) {
	base := model.Pod{Namespace: "ns", Name: "target", Ready: true, RouteService: "route",
		Labels: map[string]string{"app": "web", "phorvex.ai/route-key": "old"}}
	peer := base
	peer.Name = "peer"
	service := ingest.ServiceInfo{Namespace: "ns", Name: "route", Selector: map[string]string{"app": "web", "phorvex.ai/route-key": "old"}}
	check := func(target model.Pod, fleet []model.Pod, services []ingest.ServiceInfo) (bool, string) {
		w := BuildWitness(context.Background(), BuildIndex(fleet, nil, services), nil, nil, localActuator(okActuator{}))
		return w.Capable(&model.WorkloadView{Pod: target}, model.ActionRouteRotate)
	}
	if ok, why := check(base, []model.Pod{base, peer}, []ingest.ServiceInfo{service}); !ok {
		t.Fatalf("valid route excluded: %s", why)
	}
	for _, tc := range []struct {
		name     string
		pod      model.Pod
		fleet    []model.Pod
		services []ingest.ServiceInfo
	}{
		{"no declaration", func() model.Pod { p := base; p.RouteService = ""; return p }(), []model.Pod{base, peer}, []ingest.ServiceInfo{service}},
		{"absent Service", base, []model.Pod{base, peer}, nil},
		{"selector mismatch", base, []model.Pod{base, peer}, []ingest.ServiceInfo{{Namespace: "ns", Name: "route", Selector: map[string]string{"app": "other", "phorvex.ai/route-key": "old"}}}},
		{"single backend", base, []model.Pod{base}, []ingest.ServiceInfo{service}},
		{"target unready", func() model.Pod { p := base; p.Ready = false; return p }(), []model.Pod{base, peer}, []ingest.ServiceInfo{service}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ok, why := check(tc.pod, tc.fleet, tc.services); ok || why == "" {
				t.Fatalf("invalid route capable=%v why=%q", ok, why)
			}
		})
	}
}

func TestM033UnrelatedServicesDoNotBuildRouteBackendCounts(t *testing.T) {
	fleet := []model.Pod{{Namespace: "ns", Name: "ordinary", Ready: true, Labels: map[string]string{"app": "web"}}}
	services := []ingest.ServiceInfo{{Namespace: "ns", Name: "unrelated", Selector: map[string]string{"app": "web"}}}
	idx := BuildIndex(fleet, nil, services)
	if len(idx.readyByService) != 0 || len(idx.servingByNS["ns"]) != 1 {
		t.Fatalf("unrelated Service built route count=%v or disappeared from ordinary Service index", idx.readyByService)
	}
}

func TestM033RouteCapabilityRequiresEmptySelectorLabelPresence(t *testing.T) {
	selected := model.Pod{Namespace: "ns", Name: "selected-a", Ready: true, RouteService: "route",
		Labels: map[string]string{"app": "web", "phorvex.ai/route-key": "old", "track": ""}}
	other := selected
	other.Name = "selected-b"
	service := ingest.ServiceInfo{Namespace: "ns", Name: "route", Selector: map[string]string{
		"app": "web", "phorvex.ai/route-key": "old", "track": "",
	}}
	for _, present := range []bool{false, true} {
		name := "missing"
		if present {
			name = "present-empty"
		}
		t.Run(name, func(t *testing.T) {
			target := selected
			target.Name = "target"
			target.Labels = map[string]string{"app": "web", "phorvex.ai/route-key": "old"}
			if present {
				target.Labels["track"] = ""
			}
			fleet := []model.Pod{target, selected, other}
			idx := BuildIndex(fleet, nil, []ingest.ServiceInfo{service})
			want := 2
			if present {
				want = 3
			}
			if idx.readyByService[poolKey("ns", "route")] != want {
				t.Fatalf("Ready selected backends=%d, want %d", idx.readyByService[poolKey("ns", "route")], want)
			}
			w := BuildWitness(context.Background(), idx, nil, nil, localActuator(okActuator{}))
			ok, why := w.Capable(&model.WorkloadView{Pod: target}, model.ActionRouteRotate)
			if present && (!ok || why != "") {
				t.Fatalf("present-empty selected target capable=%v why=%q", ok, why)
			}
			if !present && (ok || !strings.Contains(why, "does not select")) {
				t.Fatalf("missing label target capable=%v why=%q", ok, why)
			}
		})
	}
}

// TestCapable_ConfigPredicates ports the per-action config predicates (M-20 era) onto the
// extracted per-pod predicate: break one fixture on the leader (rebuild the witness so a
// pool break re-indexes), assert exactly that action goes uncapable.
func TestCapable_ConfigPredicates(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Pod, *[]ingest.NodeInfo)
		action model.Action
	}{
		{"mig-device", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.MIGDevice = "" }, model.ActionMIGRebind},
		{"mig-node", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.Node = "" }, model.ActionMIGRebind},
		{"serving-endpoint", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.ServingEndpointReady = false }, model.ActionKVReset},
		{"lora", func(p *model.Pod, _ *[]ingest.NodeInfo) { delete(p.Labels, labelLoRAEnabled) }, model.ActionAdapterRotate},
		{"guardrail-variants", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.GuardrailVariants = 1 }, model.ActionGuardrailRotate},
		{"guardrail-tier", func(p *model.Pod, _ *[]ingest.NodeInfo) { delete(p.Labels, labelGuardrailTier) }, model.ActionGuardrailRotate},
		{"route-service", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.RouteService = "" }, model.ActionEndpointRotate},
		{"gpu-nodes-model-shard", func(_ *model.Pod, n *[]ingest.NodeInfo) { *n = (*n)[:1] }, model.ActionModelShardReplace},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			views, _ := capFleet()
			leader := &views[0].Pod
			fleet := []model.Pod{views[0].Pod, views[1].Pod, views[2].Pod}
			nodes := []ingest.NodeInfo{{Name: "gpu-a", Schedulable: true, AllocatableGPU: 1}, {Name: "gpu-b", Schedulable: true, AllocatableGPU: 1}}
			tc.mutate(leader, &nodes)
			fleet[0] = *leader
			svcs := []ingest.ServiceInfo{{Namespace: "ns", Name: "infer", Selector: map[string]string{"app": "infer", labelServing: "true"}}}
			wit := BuildWitness(context.Background(), BuildIndex(fleet, nodes, svcs), nil, nil, localActuator(okActuator{}))
			if ok, _ := wit.Capable(&model.WorkloadView{Pod: *leader}, tc.action); ok {
				t.Fatalf("%s: leader still capable for %s after breaking %s", tc.name, tc.action, tc.name)
			}
		})
	}
}

// TestEligible_CheapestFirstOrder walks the four checks in order (a,b,d,g) + rbac.
func TestEligible_CheapestFirstOrder(t *testing.T) {
	views, wit := capFleet()
	v, action := views[0], model.ActionRotate // rotate: no AI capability, so isolates installable/cover
	cover := []string{"fact-1"}

	// baseline: eligible.
	if r := wit.Eligible(v, action, cover); r != nil {
		t.Fatalf("baseline rotate not eligible: %+v", r)
	}
	// (b) no-cover.
	if r := wit.Eligible(v, action, nil); r == nil || r.Kind != ReasonNoCover {
		t.Fatalf("empty cover: want no-cover, got %+v", r)
	}
	// (a) not-installable beats no-cover (cheapest-first): even with empty cover, an
	// uninstallable action reports not-installable.
	niWit := BuildWitness(context.Background(), wit.idx, model.InstallSet{model.ActionRotate: {}}, nil, localActuator(okActuator{}))
	if r := niWit.Eligible(v, action, nil); r == nil || r.Kind != ReasonNotInstallable {
		t.Fatalf("not-installable must win over no-cover: got %+v", r)
	}
	// (d/g) capability-unsupported: guardrail-rotate on a non-guardrail pod (the M-19 shape).
	plain := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "x", HasGPU: true, ModelID: "m"}}
	if r := wit.Eligible(plain, model.ActionGuardrailRotate, cover); r == nil || r.Kind != ReasonCapability {
		t.Fatalf("guardrail-rotate on non-guardrail pod: want capability-unsupported, got %+v", r)
	}
}

func witOver(fleet []model.Pod, nodes []ingest.NodeInfo, svcs []ingest.ServiceInfo) Witness {
	return BuildWitness(context.Background(), BuildIndex(fleet, nodes, svcs), nil, nil, localActuator(okActuator{}))
}

func twoGPUNodes() []ingest.NodeInfo {
	return []ingest.NodeInfo{{Name: "gpu-a", Schedulable: true, AllocatableGPU: 1}, {Name: "gpu-b", Schedulable: true, AllocatableGPU: 1}}
}

// TestCapable_ServingSelector covers request-drain's servingServiceSelects — NEW logic in
// the extraction. A Service selecting on phorvex.ai/serving that matches the pod ⇒ capable;
// drop the serving key from the selector ⇒ uncapable.
func TestCapable_ServingSelector(t *testing.T) {
	views, _ := capFleet()
	leader := views[0].Pod
	fleet := []model.Pod{leader}
	svcMatch := []ingest.ServiceInfo{{Namespace: "ns", Name: "infer", Selector: map[string]string{"app": "infer", labelServing: "true"}}}
	if ok, why := witOver(fleet, twoGPUNodes(), svcMatch).Capable(&model.WorkloadView{Pod: leader}, model.ActionRequestDrain); !ok {
		t.Fatalf("request-drain should be capable when a serving Service selects the pod: %s", why)
	}
	svcNoServing := []ingest.ServiceInfo{{Namespace: "ns", Name: "infer", Selector: map[string]string{"app": "infer"}}}
	if ok, _ := witOver(fleet, twoGPUNodes(), svcNoServing).Capable(&model.WorkloadView{Pod: leader}, model.ActionRequestDrain); ok {
		t.Fatal("request-drain must be uncapable when no Service selects on phorvex.ai/serving")
	}
}

// TestCapable_ZeroMIGCapacityNotAGPUNode: warm-swap retires an old process and therefore
// supports a one-node pool; model-shard retains its independent two-GPU-node floor.
func TestCapable_ZeroMIGCapacityNotAGPUNode(t *testing.T) {
	views, _ := capFleet()
	fleet := []model.Pod{views[0].Pod, views[1].Pod, views[2].Pod}
	nodes := []ingest.NodeInfo{
		{Name: "gpu-a", Schedulable: true, AllocatableGPU: 1},
		{Name: "gpu-b", Schedulable: true, AllocatableGPU: 0, MIGResources: map[string]int64{"nvidia.com/mig-1g.10gb": 0}},
	}
	svcs := []ingest.ServiceInfo{{Namespace: "ns", Name: "infer", Selector: map[string]string{"app": "infer", labelServing: "true"}}}
	wit := witOver(fleet, nodes, svcs)
	if ok, why := wit.Capable(views[0], model.ActionWarmSwap); !ok {
		t.Fatalf("warm-swap should support a verified one-node pool: %s", why)
	}
	if ok, _ := wit.Capable(views[0], model.ActionModelShardReplace); ok {
		t.Fatal("model-shard should remain uncapable with only 1 real GPU node (zero-MIG node must not count)")
	}
}

func TestM034ConfiguredPoolReconCapabilityAndOptimizer(t *testing.T) {
	views, wit := capFleet()
	view := views[0]
	view.Phase = model.PhaseWarm
	view.Telemetry.ReqRate = model.PresentSignal(0, "fixture-measured")
	view.Physics = model.NeutralPhysics()
	view.ExposureByVariable = map[string]time.Duration{model.VarPodIdentity: 2 * time.Hour, model.VarSession: 2 * time.Hour}
	engine := decision.NewCoverageEngine()
	engine.Capability = func(v *model.WorkloadView, a model.Action, cover []string) *actionset.Eligibility {
		r := wit.Eligible(v, a, cover)
		if r == nil {
			return nil
		}
		return &actionset.Eligibility{Excluded: r.Excluded, Kind: r.Kind, Detail: r.Detail, RBACUnknown: r.RBACUnknown}
	}
	pol := model.Policy{Tenant: "m034", Namespace: "ns", Lambda: cost.DefaultLambdaSeed, MaxMovesPerTick: 1,
		ProactiveFloor: time.Minute, AntiOverRotationWindow: time.Second, MinAvailableReplicas: 1,
		EnabledActions: map[model.Action]bool{model.ActionWarmSwap: true}}
	set, _ := engine.AssembleSet([]*model.WorkloadView{view}, pol)
	if len(set.Candidates) != 1 || set.Candidates[0].Action != model.ActionWarmSwap || len(set.Candidates[0].CoverKeys) != 3 {
		t.Fatalf("recon/capability action set = %+v exclusions=%+v", set.Candidates, set.Excluded)
	}
	ds, err := engine.DecideChecked([]*model.WorkloadView{view}, pol)
	if err != nil || len(ds) != 1 || ds[0].Action != model.ActionWarmSwap || !ds[0].Feasible {
		t.Fatalf("optimizer warm-swap decision = %+v err=%v", ds, err)
	}

	// A CPU served-model pool has the same process retirement guarantee. One node is
	// enough; the stale relocation floor must not reappear through capability indexing.
	leader, shadow := views[0].Pod, views[1].Pod
	leader.HasGPU, leader.MIGDevice, leader.Node = false, "", "cpu-a"
	shadow.HasGPU, shadow.Node = false, "cpu-a"
	cpuWit := BuildWitness(context.Background(), BuildIndex([]model.Pod{leader, shadow}, []ingest.NodeInfo{{Name: "cpu-a", Schedulable: true}}, nil), nil, nil, localActuator(okActuator{}))
	if ok, why := cpuWit.Capable(&model.WorkloadView{Pod: leader}, model.ActionWarmSwap); !ok {
		t.Fatalf("CPU served-model one-node pool rejected: %s", why)
	}
}

func TestM034RotatePositiveControl(t *testing.T) {
	views, wit := capFleet()
	view := views[0]
	view.Phase = model.PhaseWarm
	view.Telemetry.ReqRate = model.PresentSignal(0, "fixture-measured")
	view.Physics = model.NeutralPhysics()
	view.ExposureByVariable = map[string]time.Duration{model.VarPodIdentity: 2 * time.Hour, model.VarSession: 2 * time.Hour}
	engine := decision.NewCoverageEngine()
	engine.Capability = func(v *model.WorkloadView, a model.Action, cover []string) *actionset.Eligibility {
		r := wit.Eligible(v, a, cover)
		if r == nil {
			return nil
		}
		return &actionset.Eligibility{Excluded: r.Excluded, Kind: r.Kind, Detail: r.Detail, RBACUnknown: r.RBACUnknown}
	}
	pol := model.Policy{Tenant: "m034-rotate", Namespace: "ns", Lambda: cost.DefaultLambdaSeed, MaxMovesPerTick: 1,
		ProactiveFloor: time.Minute, AntiOverRotationWindow: time.Second, MinAvailableReplicas: 1,
		EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	set, _ := engine.AssembleSet([]*model.WorkloadView{view}, pol)
	if len(set.Candidates) != 1 || set.Candidates[0].Action != model.ActionRotate || len(set.Candidates[0].CoverKeys) != 3 {
		t.Fatalf("rotate positive control = %+v exclusions=%+v", set.Candidates, set.Excluded)
	}
}

func TestM034WarmSwapAndRotateCompeteOnCost(t *testing.T) {
	views, wit := capFleet()
	view := views[0]
	view.Phase = model.PhaseWarm
	view.Telemetry.ReqRate = model.PresentSignal(0, "fixture-measured")
	view.Physics = model.NeutralPhysics()
	view.ExposureByVariable = map[string]time.Duration{model.VarPodIdentity: 2 * time.Hour, model.VarSession: 2 * time.Hour}
	pol := model.Policy{Tenant: "m034-cost", Namespace: "ns", Lambda: cost.DefaultLambdaSeed, MaxMovesPerTick: 1,
		FlowDisruption: 1, CostCeiling: 100, ProactiveFloor: time.Minute, AntiOverRotationWindow: time.Second,
		MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionWarmSwap: true, model.ActionRotate: true}}
	newEngine := func() *decision.CoverageEngine {
		engine := decision.NewCoverageEngine()
		engine.Capability = func(v *model.WorkloadView, a model.Action, cover []string) *actionset.Eligibility {
			r := wit.Eligible(v, a, cover)
			if r == nil {
				return nil
			}
			return &actionset.Eligibility{Excluded: r.Excluded, Kind: r.Kind, Detail: r.Detail, RBACUnknown: r.RBACUnknown}
		}
		return engine
	}
	defaultEngine := newEngine()
	set, _ := defaultEngine.AssembleSet([]*model.WorkloadView{view}, pol)
	if len(set.Candidates) != 2 {
		t.Fatalf("both physical erasers must compete: candidates=%+v exclusions=%+v", set.Candidates, set.Excluded)
	}
	if strings.Join(set.Candidates[0].CoverKeys, "\x00") != strings.Join(set.Candidates[1].CoverKeys, "\x00") {
		t.Fatalf("warm-swap and rotate must compete on the same real process facts: %+v", set.Candidates)
	}
	defaultDecision, err := defaultEngine.DecideChecked([]*model.WorkloadView{view}, pol)
	if err != nil || len(defaultDecision) != 1 || defaultDecision[0].Action != model.ActionWarmSwap {
		t.Fatalf("default cost should prefer cutover: decision=%+v err=%v candidates=%+v", defaultDecision, err, set.Candidates)
	}

	trained := newEngine()
	for i := 0; i < 32; i++ {
		trained.Cost.ObserveRotation(view, 0)
	}
	trainedDecision, err := trained.DecideChecked([]*model.WorkloadView{view}, pol)
	if err != nil || len(trainedDecision) != 1 || trainedDecision[0].Action != model.ActionRotate {
		t.Fatalf("measured cheap rotation should flip the same-cover choice: decision=%+v err=%v", trainedDecision, err)
	}
}

// TestCapable_LabelCanonicality: capability labels must match exactly ("TRUE" != "true").
func TestCapable_LabelCanonicality(t *testing.T) {
	views, _ := capFleet()
	leader := views[0].Pod
	leader.Labels = cloneMap(leader.Labels)
	leader.Labels[labelLoRAEnabled] = "TRUE"
	leader.Labels[labelGuardrailTier] = "TRUE"
	fleet := []model.Pod{leader, views[1].Pod, views[2].Pod}
	wit := witOver(fleet, twoGPUNodes(), nil)
	if ok, _ := wit.Capable(&model.WorkloadView{Pod: leader}, model.ActionAdapterRotate); ok {
		t.Fatal("adapter-rotate must reject a non-canonical lora-enabled=TRUE")
	}
	if ok, _ := wit.Capable(&model.WorkloadView{Pod: leader}, model.ActionGuardrailRotate); ok {
		t.Fatal("guardrail-rotate must reject a non-canonical guardrail-tier=TRUE")
	}
}

// TestCapable_UnrelatedPoolRejected: a shadow in a DIFFERENT swap-group / model-shard is not
// a usable pool for this target.
func TestCapable_UnrelatedPoolRejected(t *testing.T) {
	views, _ := capFleet()
	swap := views[1].Pod
	swap.Labels = cloneMap(swap.Labels)
	swap.Labels[labelSwapGroup] = "unrelated"
	shard := views[2].Pod
	shard.Labels = cloneMap(shard.Labels)
	shard.Labels[labelModelShard] = "unrelated"
	fleet := []model.Pod{views[0].Pod, swap, shard}
	wit := witOver(fleet, twoGPUNodes(), nil)
	if ok, _ := wit.Capable(views[0], model.ActionWarmSwap); ok {
		t.Fatal("warm-swap must reject an unrelated-swap-group shadow")
	}
	if ok, _ := wit.Capable(views[0], model.ActionModelShardReplace); ok {
		t.Fatal("model-shard-replace must reject an unrelated-shard shadow")
	}
}

func TestCapable_ScalarWarmPoolRequiresVerifiedSameController(t *testing.T) {
	views, _ := capFleet()
	leader := views[0].Pod
	shadow := views[1].Pod
	for _, tc := range []struct {
		name   string
		change func(*model.Pod, *model.Pod)
	}{
		{"unverified-target", func(l, _ *model.Pod) { l.WarmPoolConfigured = false }},
		{"unverified-shadow", func(_ *model.Pod, s *model.Pod) { s.WarmPoolConfigured = false }},
		{"different-owner", func(_ *model.Pod, s *model.Pod) { s.WarmPoolOwnerUID = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, s := leader, shadow
			tc.change(&l, &s)
			fleet := []model.Pod{l, s, views[2].Pod}
			wit := witOver(fleet, twoGPUNodes(), nil)
			if ok, _ := wit.Capable(&model.WorkloadView{Pod: l}, model.ActionWarmSwap); ok {
				t.Fatal("unsupported scalar pool advertised")
			}
		})
	}
}

// TestCapable_ParallelShardGroup: label/count/Ready observations cannot establish
// distributed group readiness, atomic activation, or replenishment. Every grouped
// declaration is therefore refused consistently by candidate and status paths.
func TestCapable_ParallelShardGroup(t *testing.T) {
	base, _ := capFleet()
	mkLeader := func(size int, group string) model.Pod {
		l := base[0].Pod
		l.Labels = cloneMap(l.Labels)
		l.Labels[labelParallelGroup] = group
		l.ParallelSize = size
		return l
	}
	mkRank := func(name, group, rank string) model.Pod {
		return model.Pod{Namespace: "ns", Name: name, HasGPU: true, ModelID: "model", Ready: true,
			Labels: map[string]string{labelWarmRole: warmShadowRole, labelModelLoaded: "true",
				labelModelShard: "shard-a", labelParallelGroup: group, labelRank: rank}}
	}
	for _, tc := range []struct {
		name  string
		size  int
		ranks []model.Pod
	}{
		{name: "invalid-size", ranks: []model.Pod{mkRank("r0", "par-a", "0")}},
		{name: "incomplete", size: 2, ranks: []model.Pod{mkRank("r0", "par-a", "0")}},
		{name: "duplicate", size: 2, ranks: []model.Pod{mkRank("r0", "par-a", "0"), mkRank("r0dup", "par-a", "0")}},
		{name: "complete", size: 2, ranks: []model.Pod{mkRank("r0", "par-a", "0"), mkRank("r1", "par-a", "1")}},
		{name: "extra", size: 2, ranks: []model.Pod{mkRank("r0", "par-a", "0"), mkRank("r1", "par-a", "1"), mkRank("r2", "par-a", "2")}},
		{name: "foreign-group", size: 2, ranks: []model.Pod{mkRank("r0", "par-b", "0"), mkRank("r1", "par-b", "1")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leader := mkLeader(tc.size, "par-a")
			fleet := append([]model.Pod{leader}, tc.ranks...)
			witness := witOver(fleet, twoGPUNodes(), nil)
			view := &model.WorkloadView{Pod: leader}
			if ok, why := witness.Capable(view, model.ActionModelShardReplace); ok || why != actuator.ReasonParallelGroupUnavailable {
				t.Fatalf("grouped capability = (%v, %q), want stable unsupported reason", ok, why)
			}
			if ok, why := witness.CapableAndAuthorized(view, model.ActionModelShardReplace); ok || why != actuator.ReasonParallelGroupUnavailable {
				t.Fatalf("grouped status capability = (%v, %q), want stable unsupported reason", ok, why)
			}
			reason := witness.Eligible(view, model.ActionModelShardReplace, []string{"model-fingerprint"})
			if reason == nil || !reason.Excluded || reason.Kind != ReasonCapability || reason.Detail != actuator.ReasonParallelGroupUnavailable {
				t.Fatalf("grouped candidate reason = %+v", reason)
			}
		})
	}

	leader := base[0].Pod
	fleet := []model.Pod{leader, base[1].Pod, base[2].Pod}
	witness := witOver(fleet, twoGPUNodes(), nil)
	view := &model.WorkloadView{Pod: leader}
	if ok, why := witness.Capable(view, model.ActionModelShardReplace); !ok || why != "" {
		t.Fatalf("scalar model-shard capability = (%v, %q)", ok, why)
	}
	if reason := witness.Eligible(view, model.ActionModelShardReplace, []string{"model-fingerprint"}); reason != nil {
		t.Fatalf("scalar model-shard candidate excluded: %+v", reason)
	}
}

// TestCapable_NonAIPodUncapableForAllAIActions: a plain CPU pod is uncapable for every AI
// action (the "no GPU or model identity" base gate).
func TestCapable_NonAIPodUncapableForAllAIActions(t *testing.T) {
	wit := witOver(nil, nil, nil)
	cpu := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "cpu"}}
	for a := range AICapabilityActions {
		if ok, _ := wit.Capable(cpu, a); ok {
			t.Errorf("non-AI pod reported capable for %s", a)
		}
	}
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// TestTransportUnwired_M79: mig-rebind on a MIG-configured pod is capability-unsupported
// while the node-exec transport is unwired — the real native actuator answers the
// transport leg. This is the M-79 fix (old status reported it supported).
func TestTransportUnwired_M79(t *testing.T) {
	views, base := capFleet()
	native := actuator.NewNativeActuator(nil)
	legacy, _ := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	native.SetServingSecurity(legacy)
	wit := BuildWitness(context.Background(), base.idx, nil, nil, localActuator(native)) // NodeExecWired()==false by default
	ok, why := wit.Capable(views[0], model.ActionMIGRebind)
	if ok || !strings.Contains(why, "transport-unwired") {
		t.Fatalf("mig-rebind with unwired transport: want capability-unsupported transport-unwired, got ok=%v why=%q", ok, why)
	}
}

// --- M-160: CapableAndAuthorized (Capable + the no-rbac leg, for the status condition) ---

type denySSAR struct{ denyNS, errNS map[string]bool }

func (d denySSAR) Create(_ context.Context, sar *authzv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authzv1.SelfSubjectAccessReview, error) {
	ns := sar.Spec.ResourceAttributes.Namespace
	if d.errNS[ns] {
		return nil, errors.New("apiserver blip")
	}
	sar.Status.Allowed = !d.denyNS[ns]
	return sar, nil
}

func TestCapableAndAuthorized(t *testing.T) {
	capable := model.Pod{Namespace: "denied", HasGPU: true, ServingEndpointReady: true}
	az := authz.NewCheckerWithClient(denySSAR{denyNS: map[string]bool{"denied": true}}, authz.DefaultTTL)
	wit := BuildWitness(context.Background(), BuildIndex([]model.Pod{capable}, nil, nil), nil, CheckerAccess(az), localActuator(okActuator{}))

	// Capable but RBAC-denied -> the condition sees a no-rbac gap (M-160).
	if ok, why := wit.CapableAndAuthorized(&model.WorkloadView{Pod: capable}, model.ActionKVReset); ok || !strings.HasPrefix(why, "no-rbac:") {
		t.Fatalf("capable-but-denied must be no-rbac, got ok=%v why=%q", ok, why)
	}
	// Capable AND authorized (different ns) -> supported.
	okPod := model.Pod{Namespace: "allowed", HasGPU: true, ServingEndpointReady: true}
	witA := BuildWitness(context.Background(), BuildIndex([]model.Pod{okPod}, nil, nil), nil, CheckerAccess(az), localActuator(okActuator{}))
	if ok, _ := witA.CapableAndAuthorized(&model.WorkloadView{Pod: okPod}, model.ActionKVReset); !ok {
		t.Fatal("capable + authorized must be supported")
	}
	// A capability failure short-circuits BEFORE the RBAC leg (no wasted SSAR, capability why wins).
	noEP := model.Pod{Namespace: "allowed", HasGPU: true, ServingEndpointReady: false}
	if ok, why := witA.CapableAndAuthorized(&model.WorkloadView{Pod: noEP}, model.ActionKVReset); ok || strings.HasPrefix(why, "no-rbac") {
		t.Fatalf("capability failure must win before RBAC, got ok=%v why=%q", ok, why)
	}
	// RBAC-unknown fails OPEN (never a status gap; criterion 3).
	azErr := authz.NewCheckerWithClient(denySSAR{errNS: map[string]bool{"denied": true}}, authz.DefaultTTL)
	witE := BuildWitness(context.Background(), BuildIndex([]model.Pod{capable}, nil, nil), nil, CheckerAccess(azErr), localActuator(okActuator{}))
	if ok, _ := witE.CapableAndAuthorized(&model.WorkloadView{Pod: capable}, model.ActionKVReset); !ok {
		t.Fatal("rbac-unknown must fail open (ok=true)")
	}
}

type endpointLeaseScopeSSAR struct {
	attributes     []authzv1.ResourceAttributes
	allowJournalNS string
}

func (s *endpointLeaseScopeSSAR) Create(_ context.Context, sar *authzv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authzv1.SelfSubjectAccessReview, error) {
	a := *sar.Spec.ResourceAttributes
	s.attributes = append(s.attributes, a)
	sar.Status.Allowed = a.Name != "phorvex-endpoint-lease-journal" || a.Namespace == s.allowJournalNS
	sar.Status.Denied = !sar.Status.Allowed
	return sar, nil
}

func TestEndpointLeaseRuntimeAuthorizationUsesOperatorNamespace(t *testing.T) {
	view, base := endpointLeaseCapableFixture()
	for _, tc := range []struct {
		name, allowedNS, operatorNS string
		wantAllowed                 bool
	}{
		{name: "operator allowed", allowedNS: "control-plane", operatorNS: "control-plane", wantAllowed: true},
		{name: "tenant only allowed", allowedNS: "vllm", operatorNS: "control-plane"},
		{name: "different operator namespace", allowedNS: "control-plane", operatorNS: "other-operator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reviews := &endpointLeaseScopeSSAR{allowJournalNS: tc.allowedNS}
			w := base.WithOperatorNamespace(tc.operatorNS)
			w.az = CheckerAccess(authz.NewCheckerWithClient(reviews, time.Minute))
			ok, why := w.CapableAndAuthorized(view, model.ActionEndpointLeaseRevoke)
			if ok != tc.wantAllowed {
				t.Fatalf("status allowed=%t want=%t: %s", ok, tc.wantAllowed, why)
			}
			result := w.Eligible(view, model.ActionEndpointLeaseRevoke, []string{"lease-cover"})
			if tc.wantAllowed && result != nil {
				t.Fatalf("eligible action excluded: %+v", result)
			}
			if !tc.wantAllowed && (result == nil || !result.Excluded || result.Kind != ReasonNoRBAC) {
				t.Fatalf("denied action eligible: %+v", result)
			}
			observed := w.EligibleObserved(view, model.ActionEndpointLeaseRevoke, []string{"lease-cover"})
			if tc.wantAllowed && observed != nil {
				t.Fatalf("observed allowed action excluded: %+v", observed)
			}
			if !tc.wantAllowed && (observed == nil || !observed.Excluded || observed.Kind != ReasonNoRBAC) {
				t.Fatalf("observed denied action eligible: %+v", observed)
			}
			journalChecks := map[string]bool{}
			for _, a := range reviews.attributes {
				if a.Name == "phorvex-endpoint-lease-journal" {
					journalChecks[a.Verb] = true
					if a.Namespace != tc.operatorNS {
						t.Fatalf("journal checked in %q", a.Namespace)
					}
				}
			}
			if !journalChecks["get"] || (tc.wantAllowed && !journalChecks["update"]) {
				t.Fatal("journal was not authorized")
			}
		})
	}
}

func TestEndpointLeaseJournalAuthorizationCacheIsolatedByOperatorNamespace(t *testing.T) {
	view, base := endpointLeaseCapableFixture()
	reviews := &endpointLeaseScopeSSAR{allowJournalNS: "operator-a"}
	base.az = CheckerAccess(authz.NewCheckerWithClient(reviews, time.Minute))
	for _, tc := range []struct {
		ns      string
		allowed bool
	}{{"operator-a", true}, {"operator-b", false}, {"operator-a", true}} {
		ok, why := base.WithOperatorNamespace(tc.ns).CapableAndAuthorized(view, model.ActionEndpointLeaseRevoke)
		if ok != tc.allowed {
			t.Fatalf("operator %s allowed=%t want=%t: %s", tc.ns, ok, tc.allowed, why)
		}
	}
	var aChecks, bChecks int
	for _, a := range reviews.attributes {
		if a.Name == "phorvex-endpoint-lease-journal" && a.Verb == "get" {
			if a.Namespace == "operator-a" {
				aChecks++
			}
			if a.Namespace == "operator-b" {
				bChecks++
			}
		}
	}
	if aChecks != 1 || bChecks != 1 {
		t.Fatalf("journal cache scopes: operator-a=%d operator-b=%d", aChecks, bChecks)
	}
}

func TestEndpointLeaseMissingOperatorNamespaceExcludesBeforeAuthorization(t *testing.T) {
	view, base := endpointLeaseCapableFixture()
	reviews := &endpointLeaseScopeSSAR{allowJournalNS: "vllm"}
	w := base.WithOperatorNamespace("")
	w.az = CheckerAccess(authz.NewCheckerWithClient(reviews, time.Minute))
	if ok, why := w.CapableAndAuthorized(view, model.ActionEndpointLeaseRevoke); ok || !strings.Contains(why, "operator journal namespace") {
		t.Fatalf("status accepted missing namespace: ok=%t why=%q", ok, why)
	}
	result := w.Eligible(view, model.ActionEndpointLeaseRevoke, []string{"lease-cover"})
	if result == nil || !result.Excluded || result.Kind != ReasonCapability || result.RBACUnknown {
		t.Fatalf("generator accepted missing namespace: %+v", result)
	}
	if len(reviews.attributes) != 0 {
		t.Fatalf("missing operator namespace triggered SSAR: %+v", reviews.attributes)
	}
}

func boundVoiceAdmissionView() *model.WorkloadView {
	uid := "11111111-1111-4111-8111-111111111111"
	sha := strings.Repeat("a", 64)
	a := voiceadmissionpolicy.EventAssertion{Version: 1, ScenarioID: voiceadmissionpolicy.ScenarioID, CaseID: "unsigned-audio", RunSHA256: sha, SessionID: uid, DeploymentUID: uid, PodUID: uid, AdmissionSourceSHA256: sha, LegacyBundleSHA256: sha, AuthProfileSHA256: sha, PolicyCMUID: uid, PolicyResourceVersion: "1", RuleSHA256: sha, SecurityPolicyUID: uid, SecurityPolicyGeneration: 1, ObservedAtUnixMs: 1, EvidenceSource: "TEST_INJECTED", Observed: true, SentAudioFrames: 1, SentAudioBytes: 1, ReceiptSHA256: sha, ProviderEvidenceSHA256: sha}
	return &model.WorkloadView{Pod: model.Pod{Namespace: "voice", Name: "voice", UID: uid, VoiceAdmissionConfigMap: voiceadmissionpolicy.ConfigMapName, VoiceAdmissionDeploymentUID: uid, VoiceAdmissionSourceSHA256: sha, VoiceAdmissionEventCreator: voiceadmissionpolicy.Creator, VoiceAdmissionObservation: &model.VoiceAdmissionObservation{EventName: "observed", EventUID: uid, CreatorIdentity: voiceadmissionpolicy.Creator, ScenarioID: voiceadmissionpolicy.ScenarioID, EvidenceSource: "TEST_INJECTED", TargetPodUID: uid, DeploymentUID: uid, ConfigMapUID: uid, ConfigMapResourceVersion: "1", SourceSHA256: sha, RuleSHA256: sha, PolicyName: "voice-defense", PolicyUID: uid, PolicyGeneration: 1, SessionID: uid, Assertion: a}}}
}

func TestVoiceAdmissionCapabilityRequiresActualSourceBoundObservation(t *testing.T) {
	views, wit := capFleet()
	v := boundVoiceAdmissionView()
	v.Pod.Node = views[0].Pod.Node
	wit = wit.WithPolicyIdentity("voice-defense", v.Pod.VoiceAdmissionObservation.PolicyUID)
	if ok, why := wit.Capable(v, model.ActionVoiceSessionAdmissionEnforce); !ok {
		t.Fatalf("actual source-bound admission excluded: %s", why)
	}
	v.Pod.VoiceAdmissionObservation.Assertion.Authenticated = true
	if ok, _ := wit.Capable(v, model.ActionVoiceSessionAdmissionEnforce); ok {
		t.Fatal("signed session accepted as unsigned loss")
	}
}
