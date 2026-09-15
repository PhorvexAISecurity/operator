package capability

import (
	"context"
	"errors"
	"strings"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/authz"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
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
		Node: "gpu-a", MIGGPUID: "0", MIGTargetProfile: "2g.20gb", SuspectAdapter: "adapter-a",
		Ready: true, ServingEndpointReady: true, RouteService: "infer", GuardrailVariants: 2,
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
	wit := BuildWitness(context.Background(), BuildIndex(fleet, nodes, svcs), nil, nil, okActuator{})
	return views, wit
}

// TestCapable_AllPredicatesGreen: the leader pod is fully capable for every AI action.
func TestCapable_AllPredicatesGreen(t *testing.T) {
	views, wit := capFleet()
	for action := range AICapabilityActions {
		if ok, why := wit.Capable(views[0], action); !ok {
			t.Errorf("leader not capable for %s: %s", action, why)
		}
	}
}

func TestM033RouteCapabilityRequiresActualServiceContract(t *testing.T) {
	base := model.Pod{Namespace: "ns", Name: "target", Ready: true, RouteService: "route",
		Labels: map[string]string{"app": "web", "phorvex.ai/route-key": "old"}}
	peer := base
	peer.Name = "peer"
	service := ingest.ServiceInfo{Namespace: "ns", Name: "route", Selector: map[string]string{"app": "web", "phorvex.ai/route-key": "old"}}
	check := func(target model.Pod, fleet []model.Pod, services []ingest.ServiceInfo) (bool, string) {
		w := BuildWitness(context.Background(), BuildIndex(fleet, nil, services), nil, nil, okActuator{})
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
			w := BuildWitness(context.Background(), idx, nil, nil, okActuator{})
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
		{"mig-gpu-id", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.MIGGPUID = "" }, model.ActionMIGRebind},
		{"mig-profile", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.MIGTargetProfile = "" }, model.ActionMIGRebind},
		{"serving-endpoint", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.ServingEndpointReady = false }, model.ActionKVReset},
		{"lora", func(p *model.Pod, _ *[]ingest.NodeInfo) { delete(p.Labels, labelLoRAEnabled) }, model.ActionAdapterRotate},
		{"guardrail-variants", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.GuardrailVariants = 1 }, model.ActionGuardrailRotate},
		{"guardrail-tier", func(p *model.Pod, _ *[]ingest.NodeInfo) { delete(p.Labels, labelGuardrailTier) }, model.ActionGuardrailRotate},
		{"route-service", func(p *model.Pod, _ *[]ingest.NodeInfo) { p.RouteService = "" }, model.ActionEndpointRotate},
		{"gpu-nodes", func(_ *model.Pod, n *[]ingest.NodeInfo) { *n = (*n)[:1] }, model.ActionWarmSwap},
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
			wit := BuildWitness(context.Background(), BuildIndex(fleet, nodes, svcs), nil, nil, okActuator{})
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
	niWit := BuildWitness(context.Background(), wit.idx, model.InstallSet{model.ActionRotate: {}}, nil, okActuator{})
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
	return BuildWitness(context.Background(), BuildIndex(fleet, nodes, svcs), nil, nil, okActuator{})
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

// TestCapable_ZeroMIGCapacityNotAGPUNode: a node with 0 allocatable GPU and only zero-count
// MIG resources must NOT count toward the ≥2 GPU-node floor (warm-swap/model-shard).
func TestCapable_ZeroMIGCapacityNotAGPUNode(t *testing.T) {
	views, _ := capFleet()
	fleet := []model.Pod{views[0].Pod, views[1].Pod, views[2].Pod}
	nodes := []ingest.NodeInfo{
		{Name: "gpu-a", Schedulable: true, AllocatableGPU: 1},
		{Name: "gpu-b", Schedulable: true, AllocatableGPU: 0, MIGResources: map[string]int64{"nvidia.com/mig-1g.10gb": 0}},
	}
	svcs := []ingest.ServiceInfo{{Namespace: "ns", Name: "infer", Selector: map[string]string{"app": "infer", labelServing: "true"}}}
	wit := witOver(fleet, nodes, svcs)
	for _, a := range []model.Action{model.ActionWarmSwap, model.ActionModelShardReplace} {
		if ok, _ := wit.Capable(views[0], a); ok {
			t.Fatalf("%s should be uncapable with only 1 real GPU node (zero-MIG node must not count)", a)
		}
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

// TestCapable_ParallelShardGroup: a tensor/pipeline-parallel target needs a valid parallel
// size AND one distinct Ready shadow rank per member; otherwise uncapable.
func TestCapable_ParallelShardGroup(t *testing.T) {
	base, _ := capFleet()
	mkLeader := func(size int) model.Pod {
		l := base[0].Pod
		l.Labels = cloneMap(l.Labels)
		l.Labels[labelParallelGroup] = "par-a"
		l.ParallelSize = size
		return l
	}
	mkRank := func(name, rank string) model.Pod {
		return model.Pod{Namespace: "ns", Name: name, HasGPU: true, ModelID: "model", Ready: true,
			Labels: map[string]string{labelWarmRole: warmShadowRole, labelModelLoaded: "true",
				labelModelShard: "shard-a", labelParallelGroup: "par-a", labelRank: rank}}
	}

	// no valid parallel-size ⇒ uncapable.
	{
		l := mkLeader(0)
		wit := witOver([]model.Pod{l, mkRank("r0", "0")}, twoGPUNodes(), nil)
		if ok, _ := wit.Capable(&model.WorkloadView{Pod: l}, model.ActionModelShardReplace); ok {
			t.Fatal("parallel group without a valid parallel-size must be uncapable")
		}
	}
	// incomplete ranks (size 2, one rank) ⇒ uncapable; duplicate rank doesn't complete it.
	{
		l := mkLeader(2)
		wit := witOver([]model.Pod{l, mkRank("r0", "0"), mkRank("r0dup", "0")}, twoGPUNodes(), nil)
		if ok, _ := wit.Capable(&model.WorkloadView{Pod: l}, model.ActionModelShardReplace); ok {
			t.Fatal("incomplete parallel rank set (duplicate rank) must be uncapable")
		}
	}
	// complete distinct ranks (size 2, ranks 0 and 1) ⇒ capable.
	{
		l := mkLeader(2)
		wit := witOver([]model.Pod{l, mkRank("r0", "0"), mkRank("r1", "1")}, twoGPUNodes(), nil)
		if ok, why := wit.Capable(&model.WorkloadView{Pod: l}, model.ActionModelShardReplace); !ok {
			t.Fatalf("complete parallel shadow group must be capable: %s", why)
		}
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
	wit := BuildWitness(context.Background(), base.idx, nil, nil, actuator.NewNativeActuator(nil)) // NodeExecWired()==false by default
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
	wit := BuildWitness(context.Background(), BuildIndex([]model.Pod{capable}, nil, nil), nil, az, okActuator{})

	// Capable but RBAC-denied -> the condition sees a no-rbac gap (M-160).
	if ok, why := wit.CapableAndAuthorized(&model.WorkloadView{Pod: capable}, model.ActionKVReset); ok || !strings.HasPrefix(why, "no-rbac:") {
		t.Fatalf("capable-but-denied must be no-rbac, got ok=%v why=%q", ok, why)
	}
	// Capable AND authorized (different ns) -> supported.
	okPod := model.Pod{Namespace: "allowed", HasGPU: true, ServingEndpointReady: true}
	witA := BuildWitness(context.Background(), BuildIndex([]model.Pod{okPod}, nil, nil), nil, az, okActuator{})
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
	witE := BuildWitness(context.Background(), BuildIndex([]model.Pod{capable}, nil, nil), nil, azErr, okActuator{})
	if ok, _ := witE.CapableAndAuthorized(&model.WorkloadView{Pod: capable}, model.ActionKVReset); !ok {
		t.Fatal("rbac-unknown must fail open (ok=true)")
	}
}
