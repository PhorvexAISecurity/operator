package sensorsvc

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	amtd "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/graph"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/sensorapi"
)

// fixture is a namespace with web and db Pods, a Pod elsewhere, and events: a
// high-severity foothold on the db Pod and an unbound console event.
func fixture() *ingest.Snapshot {
	pods := []model.Pod{
		{Namespace: "a", Name: "web-1", UID: "u1", Labels: map[string]string{"app": "web"}, MountedSecrets: []string{"s"}},
		{Namespace: "a", Name: "web-2", UID: "u2", Labels: map[string]string{"app": "web"}, Stateful: true},
		{Namespace: "a", Name: "db", UID: "u3", Labels: map[string]string{"app": "db"}},
		{Namespace: "b", Name: "other", UID: "u4", Labels: map[string]string{"app": "web"}},
	}
	byKey := map[string]*model.Pod{}
	nodes := make([]graph.PodNode, 0, len(pods))
	for i := range pods {
		p := &pods[i]
		byKey[p.Namespace+"/"+p.Name] = p
		nodes = append(nodes, graph.PodNode{Namespace: p.Namespace, Name: p.Name, Labels: p.Labels, AssetValue: GenericAssetValue(p)})
	}
	foothold := model.SecurityEventInfo{Name: "foothold", UID: "e1", Type: "Exploit", ThreatLevel: "critical", TargetsPod: true}
	own := model.SecurityEventInfo{Name: "own", UID: "e2", Type: "Anomaly", ThreatLevel: "low", TargetsPod: true}
	unbound := model.SecurityEventInfo{Name: "unbound", UID: "e3", TargetBindingReason: "console-target-uid-malformed"}
	return &ingest.Snapshot{
		Now: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC), Pods: pods, PodByKey: byKey,
		Graph:  graph.Build(graph.Input{Pods: nodes}),
		Events: []model.SecurityEventInfo{foothold, own, unbound},
		EventByPod: map[string][]model.SecurityEventInfo{
			"a/db": {foothold}, "a/web-1": {own},
		},
		PodInventoryComplete: true, PolicyInventoryComplete: true, EventInventoryComplete: true,
		Policies: []v1alpha1.PhorvexPolicy{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "web"}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: "t-web",
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "broken"}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: "t-broken",
				Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Near"}}}}},
		},
	}
}

func TestFromSnapshotDerivesContextForScopedPods(t *testing.T) {
	snap := fixture()
	obs, err := FromSnapshot(snap, []sensorapi.Scope{{Namespace: "a", Selector: "app=web"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Context) != 2 {
		t.Fatalf("context for %d Pods, want the two scoped web Pods: %v", len(obs.Context), obs.Context)
	}
	for _, key := range []string{"a/web-1", "a/web-2"} {
		c, ok := obs.Context[key]
		if !ok {
			t.Fatalf("no context for scoped %s", key)
		}
		ns, name := "a", key[2:]
		if c.BlastRadius != snap.Graph.BlastRadius(ns, name) || c.NeighborCount != snap.Graph.NeighborCount(ns, name) {
			t.Fatalf("%s graph facts differ from the graph", key)
		}
		neighbors := snap.Graph.Neighbors(ns, name)
		if len(c.Neighbors) != len(neighbors) {
			t.Fatalf("%s neighbours %v, graph %v", key, c.Neighbors, neighbors)
		}
		sawFoothold := false
		for i, nb := range neighbors {
			if c.Neighbors[i] != (model.NeighborRef{Key: nb, Value: GenericAssetValue(snap.PodByKey[nb])}) {
				t.Fatalf("%s neighbour %d = %+v", key, i, c.Neighbors[i])
			}
			sawFoothold = sawFoothold || nb == "a/db"
		}
		if !sawFoothold {
			t.Fatalf("fixture graph does not connect %s to the foothold", key)
		}
		if c.InfectionFrontier != 1.5 {
			t.Fatalf("%s next to a critical foothold has frontier %v", key, c.InfectionFrontier)
		}
		for _, e := range c.Events {
			if e.Name == "foothold" && e.TargetsPod {
				t.Fatalf("%s carries its neighbour's event as targeting itself", key)
			}
		}
	}
	if own := obs.Context["a/web-1"].Events; len(own) == 0 || own[0].Name != "own" || !own[0].TargetsPod {
		t.Fatalf("own event must come first and keep TargetsPod: %+v", own)
	}
	if snap.EventByPod["a/db"][0].TargetsPod != true {
		t.Fatal("deriving the context changed the snapshot's events")
	}
	if events := obs.Context["a/web-2"].Events; events == nil {
		t.Fatal("a Pod's events must be an empty list, never nil")
	}
}

func TestFromSnapshotCarriesTheSnapshotAndItsDerivations(t *testing.T) {
	snap := fixture()
	obs, err := FromSnapshot(snap, nil)
	if err != nil {
		t.Fatal(err)
	}
	platformName, physics := platform.Derive(snap)
	if obs.Platform != platformName || !reflect.DeepEqual(obs.Physics, physics) {
		t.Fatal("physics differ from the platform derivation")
	}
	if !reflect.DeepEqual(obs.EvidenceEvents, ingest.EvidenceEvents(snap.Events)) || len(obs.EvidenceEvents) != 2 {
		t.Fatalf("evidence events = %+v", obs.EvidenceEvents)
	}
	if !reflect.DeepEqual(obs.PolicyMembership, map[string][]string{"a/web-1": {"t-web"}, "a/web-2": {"t-web"}}) {
		t.Fatalf("membership = %v", obs.PolicyMembership)
	}
	if obs.PolicySelectorsValid {
		t.Fatal("an unparsable policy selector must mark the membership incomplete")
	}
	if !obs.Now.Equal(snap.Now) || len(obs.Pods) != len(snap.Pods) || !obs.PodInventoryComplete || len(obs.Context) != 0 {
		t.Fatalf("observation does not carry the snapshot: %+v", obs)
	}
}

func TestScopeSelectorsSelectWhatThePolicySelectorSelects(t *testing.T) {
	selectors := []metav1.LabelSelector{
		{},
		{MatchLabels: map[string]string{"app": "web", "tier": "front"}},
		{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"web", "api"}},
			{Key: "canary", Operator: metav1.LabelSelectorOpDoesNotExist},
		}},
		{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "tier", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"db"}},
			{Key: "phorvex.ai/serving", Operator: metav1.LabelSelectorOpExists},
		}},
	}
	podLabels := []map[string]string{
		nil, {"app": "web"}, {"app": "web", "tier": "front"}, {"app": "api", "canary": "1"},
		{"tier": "db", "phorvex.ai/serving": "true"}, {"tier": "edge", "phorvex.ai/serving": ""},
	}
	for i, ls := range selectors {
		sel, err := metav1.LabelSelectorAsSelector(&ls)
		if err != nil {
			t.Fatal(err)
		}
		scopes, err := parseScopes([]sensorapi.Scope{{Namespace: "ns", Selector: sel.String()}})
		if err != nil {
			t.Fatalf("selector %d %q does not parse back: %v", i, sel.String(), err)
		}
		for _, l := range podLabels {
			if got, want := scopes.selects("ns", l), sel.Matches(labels.Set(l)); got != want {
				t.Fatalf("selector %d %q on %v: scope %v, policy %v", i, sel.String(), l, got, want)
			}
		}
		if scopes.selects("other", map[string]string{"app": "web", "tier": "front"}) {
			t.Fatal("a scope selected a Pod in another namespace")
		}
	}
	if _, err := parseScopes([]sensorapi.Scope{{Namespace: "ns", Selector: "app in (("}}); err == nil {
		t.Fatal("an unparsable scope was accepted")
	}
}

type fakeSource struct {
	health *model.SourceHealth
	err    error
}

func (fakeSource) Name() string { return "fake-prometheus" }
func (f fakeSource) PodMetrics(context.Context, string, []string) (map[string]model.Telemetry, error) {
	return map[string]model.Telemetry{"web-1": {ReqRate: model.PresentSignal(3, "fake")}}, f.err
}

type reportingSource struct{ fakeSource }

func (r reportingSource) LastHealth() model.SourceHealth { return *r.health }

func TestTelemetryReportsTheSourceVerdict(t *testing.T) {
	if got := (&Local{}).Telemetry(context.Background(), sensorapi.TelemetryRequest{}); got.Configured {
		t.Fatal("no source configured, yet telemetry reported as configured")
	}
	partial := errors.New("reqRate: 500")
	got := (&Local{Metrics: fakeSource{err: partial}}).Telemetry(context.Background(), sensorapi.TelemetryRequest{Namespace: "a", Pods: []string{"web-1"}})
	if !got.Configured || got.Error != "reqRate: 500" || got.Health != (model.SourceHealth{Source: "fake-prometheus", Total: 1, Failed: 1}) ||
		got.Telemetry["web-1"].ReqRate.Value != 3 {
		t.Fatalf("partial read without a health reporter = %+v", got)
	}
	health := model.SourceHealth{Source: "fake-prometheus", Total: 4, Failed: 4, Reason: model.ReasonSourceUnreachable}
	got = (&Local{Metrics: reportingSource{fakeSource{health: &health, err: partial}}}).Telemetry(context.Background(), sensorapi.TelemetryRequest{})
	if got.Health != health {
		t.Fatalf("the source's own verdict was replaced: %+v", got.Health)
	}
	healthy := model.SourceHealth{Source: "fake-prometheus", Total: 4}
	got = (&Local{Metrics: reportingSource{fakeSource{health: &healthy}}}).Telemetry(context.Background(), sensorapi.TelemetryRequest{})
	if got.Error != "" || got.Health != healthy {
		t.Fatalf("healthy read = %+v", got)
	}
}

func TestObserveCollectsTheClusterForTheScopes(t *testing.T) {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	pod := func(name, app string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: name, UID: types.UID("uid-" + name), Labels: map[string]string{"app": app}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "a"}}, pod("web-1", "web"), pod("db", "db")).Build()
	now := time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)
	obs, err := (&Local{Client: c}).Observe(context.Background(), sensorapi.ObserveRequest{Now: now,
		Scopes: []sensorapi.Scope{{Namespace: "a", Selector: "app=web"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !obs.Now.Equal(now) || len(obs.Pods) != 2 || !obs.PodInventoryComplete {
		t.Fatalf("observation = %+v", obs)
	}
	if _, ok := obs.Context["a/web-1"]; !ok || len(obs.Context) != 1 {
		t.Fatalf("context = %v, want only the scoped Pod", obs.Context)
	}
	if obs.PhoenixReceiptInventoryComplete || len(obs.PhoenixReceipts) != 0 {
		t.Fatal("receipts reported without a boundary reader")
	}
	if _, err := (&Local{Client: c}).Observe(context.Background(), sensorapi.ObserveRequest{Now: now,
		Scopes: []sensorapi.Scope{{Namespace: "a", Selector: "app in (("}}}); err == nil {
		t.Fatal("an unparsable scope was observed")
	}
}
