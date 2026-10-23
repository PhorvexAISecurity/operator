/*
 * Phorvex — M-18 incident reproduction: Phoenix forensic identifiers must survive the
 * complete record path (adapter Result -> Manager.actuate -> audit.Logger.Record ->
 * canonical v2 JSONL -> reader).
 *
 * DELIBERATE DESIGN NOTE (baseline/head discrimination): this file asserts against the
 * RAW SERIALIZED JSON, never against a Go field that only exists after the fix. That is
 * what makes it a genuine before/after fixture — the SAME source compiles at baseline
 * f0348b3 (where it FAILS: the identifiers are absent from the record) and at head
 * (where it PASSES). A test written against a new typed field could not fail at
 * baseline, because it would not compile there, and so could not witness the defect.
 *
 * The fake API Create assigns BOTH a server name (via GenerateName) and a distinct UID.
 * Verified empirically at this SHA: controller-runtime v0.21.0's fake client honors
 * GenerateName but does NOT assign a UID, so without this interceptor a UID assertion
 * would pass vacuously by comparing "" to "".
 */

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

// m018CreatedObject is one recorded API Create, as the server would have acknowledged it.
type m018CreatedObject struct {
	GVK       string
	Namespace string
	Name      string
	UID       string
}

// m018RecordingAPI is a fake API server that assigns a distinct UID to every created
// object and records what it acknowledged, so a test can compare the SOURCE OF TRUTH
// (what the API returned) against the saved audit record.
type m018RecordingAPI struct {
	mu      sync.Mutex
	created []m018CreatedObject
	nextUID int
}

func (r *m018RecordingAPI) record(obj client.Object) types.UID {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextUID++
	uid := types.UID(fmt.Sprintf("uid-%04d-%s", r.nextUID, obj.GetName()))
	r.created = append(r.created, m018CreatedObject{
		GVK:       fmt.Sprintf("%T", obj),
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
		UID:       string(uid),
	})
	return uid
}

func (r *m018RecordingAPI) securityEvents() []m018CreatedObject {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []m018CreatedObject
	for _, c := range r.created {
		if strings.Contains(c.GVK, "SecurityEvent") {
			out = append(out, c)
		}
	}
	return out
}

// m018PhoenixClient builds a fake client whose Create assigns a server UID, exactly as a
// real API server does when it decodes its response back into the passed object.
func m018PhoenixClient(t *testing.T, api *m018RecordingAPI, objects ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(s); err != nil {
		t.Fatalf("add phoenix scheme: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := c.Create(ctx, obj, opts...); err != nil {
				return err
			}
			obj.SetUID(api.record(obj)) // server-assigned identity, written back into the caller's object
			// Persist the acknowledged UID so later protected-capacity inventory sees
			// the same exact event identity returned to the producer.
			return c.Update(ctx, obj)
		},
	}).Build()
	return &m012CapacityClient{Client: base}
}

func m018PhoenixObjects(targets ...types.NamespacedName) []client.Object {
	objects := []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m018-operator", UID: "m018-operator-uid"}}}
	seenNamespace := map[string]bool{}
	for _, target := range targets {
		if !seenNamespace[target.Namespace] {
			objects = append(objects, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: target.Namespace, UID: types.UID("namespace-uid-" + target.Namespace)}})
			seenNamespace[target.Namespace] = true
		}
		objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: target.Namespace, Name: target.Name, UID: types.UID("test-uid-" + target.Namespace + "-" + target.Name)}})
	}
	return objects
}

func m018PhoenixCapacity(t *testing.T, c client.Client) *actuator.QuarantineCapacity {
	t.Helper()
	capacity, err := actuator.NewQuarantineCapacity(c, c, "m018-operator", 128)
	if err != nil {
		t.Fatal(err)
	}
	return capacity
}

func m018PhoenixManager(t *testing.T, api *m018RecordingAPI, targets ...types.NamespacedName) *Manager {
	t.Helper()
	c := m018PhoenixClient(t, api, m018PhoenixObjects(targets...)...)
	return &Manager{Local: &inprocess.Services{Actuator: actuator.NewPhoenixActuator(c), QuarantineCapacity: m018PhoenixCapacity(t, c)}, Log: logr.Discard()}
}

// m018PolicyEntry is a minimal entry whose selector satisfies EnsurePolicy's
// matchLabels precondition (P0 active mode requires an expressible guest list).
func m018PolicyEntry(namespace string) *policyEntry {
	return &policyEntry{
		key: types.NamespacedName{Namespace: namespace, Name: "policy"}, uid: "policy-uid", tenant: "team-a", namespace: namespace,
		spec: v1alpha1.PhorvexPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}},
		},
	}
}

func m018SelectedDecision(namespace, pod string) []model.Decision {
	return []model.Decision{{
		Selected: true, Feasible: true, Action: model.ActionRotate,
		Namespace: namespace, Pod: pod,
		Trace: &model.DecisionTraceV2{
			DispatchOutcome: model.DispatchNotAttempted, DispatchReason: "pending-dispatch",
		},
	}}
}

func m018TickView(namespace, pod string) map[string]*model.WorkloadView {
	return map[string]*model.WorkloadView{
		namespace + "/" + pod: {Pod: model.Pod{
			Namespace: namespace, Name: pod, UID: "test-uid-" + namespace + "-" + pod,
			DesiredReplicas: 3, ReadyReplicas: 3, Ready: true,
		}},
	}
}

// m018RecordJSON runs one audit write and returns the decoded raw JSON object of the
// single emitted decision record.
func m018RecordJSON(t *testing.T, m *Manager, buf *bytes.Buffer, d model.Decision) map[string]any {
	t.Helper()
	buf.Reset()
	if err := m.Audit.Record(d); err != nil {
		t.Fatalf("audit record: %v", err)
	}
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("audit wrote no record")
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		t.Fatalf("decode audit line: %v\nline: %s", err, line)
	}
	return raw
}

// TestM018PhoenixForensicIdentifiersReachTheAuditRecord is the INCIDENT REPRODUCTION.
//
// A real PhoenixActuator emits a controlled SecurityEvent through a fake API that
// assigns a distinct name and UID. The runner maps the result into the decision, the
// audit logger serializes it, and an investigator reads the saved record back. Every
// forensic identifier the adapter actually returned must be present in that record with
// its exact value, so the decision can be linked to the Phoenix resources without
// guessing from timestamps or pod names.
//
// BASELINE f0348b3: FAILS — the record carries none of them.
func TestM018PhoenixForensicIdentifiersReachTheAuditRecord(t *testing.T) {
	api := &m018RecordingAPI{}
	var buf bytes.Buffer
	m := m018PhoenixManager(t, api, types.NamespacedName{Namespace: "ns", Name: "p1"})
	m.Audit = audit.New(logr.Discard(), &buf)
	pol := m018PhoenixPolicy("team-a")
	ds := m018SelectedPhoenixDecision("ns", "p1")

	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), pol, ds, m018TickView("ns", "p1")); n != 1 {
		t.Fatalf("actuated %d moves, want 1", n)
	}
	if !ds[0].Actuated {
		t.Fatal("decision not marked actuated")
	}

	// The source of truth: what the API server actually acknowledged.
	events := api.securityEvents()
	if len(events) != 1 {
		t.Fatalf("recorded %d SecurityEvent creates, want 1", len(events))
	}
	created := events[0]
	if created.Name == "" || created.UID == "" {
		t.Fatalf("fake API assigned no identity: %+v", created)
	}

	raw := m018RecordJSON(t, m, &buf, ds[0])
	phoenix, ok := raw["phoenix"].(map[string]any)
	if !ok {
		t.Fatalf("M-18 DEFECT: audit record carries no \"phoenix\" forensic payload.\n"+
			"The adapter returned AMTD/event/rule identifiers for SecurityEvent %q (uid %q), "+
			"and the investigator cannot link the decision to it.\nrecord keys: %v",
			created.Name, created.UID, m018SortedKeys(raw))
	}

	// Each identifier must carry the adapter's ACTUAL value, not a placeholder.
	want := map[string]string{
		"amtdName":        "phorvex-ns-team-a", // amtdName(namespace, tenant)
		"amtdNamespace":   "ns",                // the AMTD is namespaced; the event is cluster-scoped
		"eventName":       created.Name,        // server-assigned via GenerateName
		"eventUID":        created.UID,         // server-assigned; the only same-name-safe identity
		"ruleType":        amtdv1beta1.PhorvexRuleTypeQuarantine,
		"ruleThreatLevel": amtdv1beta1.PhorvexRuleThreatLevel,
		"ruleSource":      amtdv1beta1.PhorvexRuleSource,
	}
	for key, expected := range want {
		got, present := phoenix[key]
		if !present {
			t.Errorf("phoenix.%s absent from the audit record (want %q)", key, expected)
			continue
		}
		if got != expected {
			t.Errorf("phoenix.%s = %v, want %q", key, got, expected)
		}
	}
}

func m018SortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------------
// PARTIAL / ABSENT — a result carried alongside an error keeps the facts the
// adapter supplied, with the failure outcome unchanged; nothing is fabricated.
// ---------------------------------------------------------------------------

// m018PartialActuator returns a populated Result AND an error: the "partial" shape where
// the adapter learned real identifiers but the attempt still failed.
type m018PartialActuator struct {
	res actuator.Result
	err error
}

func (f *m018PartialActuator) Name() string { return "m018-partial" }
func (f *m018PartialActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error {
	return nil
}
func (f *m018PartialActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return f.res, f.err
}
func (f *m018PartialActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}

func m018Policy() model.Policy {
	return model.Policy{Tenant: "team-a", PolicyName: "policy", PolicyUID: "policy-uid", MinAvailableReplicas: 1,
		EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
}

func m018PhoenixPolicy(tenant string) model.Policy {
	return model.Policy{Tenant: tenant, PolicyName: "policy", PolicyUID: "policy-uid", MinAvailableReplicas: 1,
		EnabledActions: map[model.Action]bool{model.ActionQuarantine: true}}
}

func m018SelectedPhoenixDecision(namespace, pod string) []model.Decision {
	d := m018SelectedDecision(namespace, pod)
	d[0].Action = model.ActionQuarantine
	return d
}

func TestM018PartialResultWithErrorKeepsFactsAndFailureOutcome(t *testing.T) {
	fa := &m018PartialActuator{
		res: actuator.Result{
			Actuator: "phoenix", AMTDName: "phorvex-ns-team-a",
			EventName: "phorvex-rotate-abc12", EventUID: "uid-partial-1",
			RuleType: amtdv1beta1.PhorvexRuleTypeRotate, RuleThreatLevel: amtdv1beta1.PhorvexRuleThreatLevel,
			RuleSource: amtdv1beta1.PhorvexRuleSource,
			Emitted:    false,
		},
		err: errors.New("emit SecurityEvent: connection reset after acknowledgement"),
	}
	m := &Manager{Local: &inprocess.Services{Actuator: fa}, Log: logr.Discard()}
	ds := m018SelectedDecision("ns", "p1")

	n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, m018TickView("ns", "p1"))

	// The OUTCOME is untouched by M-18: still a failed dispatch, still not actuated.
	if n != 0 {
		t.Fatalf("actuated %d moves on an error return, want 0", n)
	}
	if ds[0].Actuated {
		t.Fatal("M-18 must not upgrade a failed attempt to actuated")
	}
	if got := ds[0].Trace.DispatchOutcome; got != model.DispatchError {
		t.Fatalf("dispatch outcome = %q, want %q (unchanged failure semantics)", got, model.DispatchError)
	}
	// The FACTS the adapter supplied are retained.
	if ds[0].Phoenix == nil {
		t.Fatal("M-18: supplied identifiers were discarded on the error path")
	}
	if got, want := ds[0].Phoenix.EventUID, "uid-partial-1"; got != want {
		t.Errorf("eventUID = %q, want %q", got, want)
	}
	if got, want := ds[0].Phoenix.AMTDNamespace, "ns"; got != want {
		t.Errorf("amtdNamespace = %q, want %q", got, want)
	}
}

// A REJECTED create must fabricate nothing: no name, no UID, no payload at all.
func TestM018RejectedCreateFabricatesNoIdentity(t *testing.T) {
	s := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(s); err != nil {
		t.Fatalf("add phoenix scheme: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(m018PhoenixObjects(types.NamespacedName{Namespace: "ns", Name: "p1"})...).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, isEvent := obj.(*amtdv1beta1.SecurityEvent); isEvent {
				return apierrors.NewForbidden(
					schema.GroupResource{Group: "amtd.r6security.com", Resource: "securityevents"},
					"", errors.New("denied by admission"))
			}
			return c.Create(ctx, obj, opts...) // AMTD and protected capacity still use the real fake API
		},
	}).Build()
	c := &m012CapacityClient{Client: base}

	var buf bytes.Buffer
	m := &Manager{Local: &inprocess.Services{Actuator: actuator.NewPhoenixActuator(c), QuarantineCapacity: m018PhoenixCapacity(t, c)}, Log: logr.Discard(),
		Audit: audit.New(logr.Discard(), &buf)}
	ds := m018SelectedPhoenixDecision("ns", "p1")

	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018PhoenixPolicy("team-a"), ds, m018TickView("ns", "p1")); n != 0 {
		t.Fatalf("actuated %d moves on a rejected create, want 0", n)
	}
	if ds[0].Phoenix != nil {
		t.Fatalf("M-18: fabricated identity for a rejected create: %+v", *ds[0].Phoenix)
	}
	raw := m018RecordJSON(t, m, &buf, ds[0])
	if _, present := raw["phoenix"]; present {
		t.Fatalf("rejected create produced a phoenix payload in the record: %v", raw["phoenix"])
	}
}

// A move refused by a pre-Actuate guard never attempted anything, so it must carry no
// payload even when the decision struct is reused from an earlier successful attempt.
func TestM018NotAttemptedMoveCarriesNoStalePayload(t *testing.T) {
	api := &m018RecordingAPI{}
	m := m018PhoenixManager(t, api, types.NamespacedName{Namespace: "ns", Name: "p1"})
	ds := m018SelectedPhoenixDecision("ns", "p1")

	// Attempt 1 succeeds and stamps a real payload onto the decision.
	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018PhoenixPolicy("team-a"), ds, m018TickView("ns", "p1")); n != 1 {
		t.Fatalf("first attempt actuated %d, want 1", n)
	}
	if ds[0].Phoenix == nil {
		t.Fatal("first attempt produced no payload; fixture is not discriminating")
	}
	firstUID := ds[0].Phoenix.EventUID

	// Attempt 2 reuses the SAME decision but is vetoed before Actuate (empty tick view).
	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018PhoenixPolicy("team-a"), ds, map[string]*model.WorkloadView{}); n != 0 {
		t.Fatalf("map-miss attempt actuated %d, want 0", n)
	}
	if ds[0].Phoenix != nil {
		t.Fatalf("M-18: not-attempted move inherited a stale reference to %q: %+v",
			firstUID, *ds[0].Phoenix)
	}
	if ds[0].Actuated || ds[0].Handler != "" || len(ds[0].ObjectsTouched) != 0 || ds[0].RollbackRef != "" || ds[0].MutationKind != "" {
		t.Fatalf("not-attempted decision retained prior success/native evidence: %+v", ds[0])
	}
	if ds[0].DispatchOutcome != model.DispatchNotAttempted || ds[0].DispatchReason != "no-tick-view" ||
		ds[0].Trace.DispatchOutcome != model.DispatchNotAttempted || ds[0].Trace.DispatchReason != "no-tick-view" {
		t.Fatalf("not-attempted current-call outcome = %+v", ds[0])
	}
	if got := ds[0].Trace.DispatchOutcome; got != model.DispatchNotAttempted {
		t.Fatalf("dispatch outcome = %q, want %q", got, model.DispatchNotAttempted)
	}
}

// ---------------------------------------------------------------------------
// ISOLATION — no cross-record carryover or substitution across decisions,
// namespaces, tenants or same-name objects.
// ---------------------------------------------------------------------------

// Several targets actuated in ONE call must each carry their OWN event identity. A
// shared or last-write-wins payload would make every record point at one event.
func TestM018EachDecisionOwnsItsOwnEventIdentity(t *testing.T) {
	api := &m018RecordingAPI{}
	pods := []string{"p1", "p2", "p3"}
	targets := make([]types.NamespacedName, 0, len(pods))
	for _, pod := range pods {
		targets = append(targets, types.NamespacedName{Namespace: "ns", Name: pod})
	}
	m := m018PhoenixManager(t, api, targets...)

	ds := make([]model.Decision, 0, len(pods))
	view := map[string]*model.WorkloadView{}
	for _, pod := range pods {
		ds = append(ds, m018SelectedPhoenixDecision("ns", pod)[0])
		for k, v := range m018TickView("ns", pod) {
			view[k] = v
		}
	}
	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018PhoenixPolicy("team-a"), ds, view); n != len(pods) {
		t.Fatalf("actuated %d, want %d", n, len(pods))
	}

	seen := map[string]string{} // uid -> pod that claimed it
	for i, d := range ds {
		if d.Phoenix == nil {
			t.Fatalf("decision %d (%s) lost its payload", i, d.Pod)
		}
		if d.Phoenix.EventUID == "" || d.Phoenix.EventName == "" {
			t.Fatalf("decision %d (%s) has empty identity: %+v", i, d.Pod, *d.Phoenix)
		}
		if prior, dup := seen[d.Phoenix.EventUID]; dup {
			t.Fatalf("SUBSTITUTION: pods %s and %s both claim event uid %q",
				prior, d.Pod, d.Phoenix.EventUID)
		}
		seen[d.Phoenix.EventUID] = d.Pod
		// Each payload must be a distinct allocation, not a shared pointer.
		for j := range ds[:i] {
			if ds[j].Phoenix == d.Phoenix {
				t.Fatalf("ALIASING: decisions %d and %d share one payload pointer", j, i)
			}
		}
	}
}

// Two DIFFERENT events that happen to share a name must stay distinguishable. This is
// the trap the ticket calls out: a name alone cannot separate a recreated object from
// the original, so the UID must be what carries identity.
func TestM018SameNameDifferentUIDStayDistinct(t *testing.T) {
	s := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(s); err != nil {
		t.Fatalf("add phoenix scheme: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	uids := []string{"uid-original", "uid-recreated"}
	var creates int
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(m018PhoenixObjects(
		types.NamespacedName{Namespace: "ns", Name: "p1"}, types.NamespacedName{Namespace: "ns", Name: "p2"},
	)...).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := c.Create(ctx, obj, opts...); err != nil {
				return err
			}
			if _, isEvent := obj.(*amtdv1beta1.SecurityEvent); isEvent {
				obj.SetUID(types.UID(uids[creates%len(uids)]))
				creates++
				if err := c.Update(ctx, obj); err != nil { // persist UID for protected-capacity inventory
					return err
				}
				obj.SetName("phorvex-quarantine-collide") // same acknowledged name both times
			}
			return nil
		},
	}).Build()
	c := &m012CapacityClient{Client: base}
	m := &Manager{Local: &inprocess.Services{Actuator: actuator.NewPhoenixActuator(c), QuarantineCapacity: m018PhoenixCapacity(t, c)}, Log: logr.Discard()}
	got := make([]model.PhoenixForensics, 0, 2)
	for _, pod := range []string{"p1", "p2"} {
		ds := m018SelectedPhoenixDecision("ns", pod)
		if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018PhoenixPolicy("team-a"), ds, m018TickView("ns", pod)); n != 1 {
			t.Fatalf("pod %s actuated %d, want 1", pod, n)
		}
		if ds[0].Phoenix == nil {
			t.Fatalf("pod %s lost its payload", pod)
		}
		got = append(got, *ds[0].Phoenix)
	}
	if got[0].EventName != got[1].EventName {
		t.Fatalf("fixture broken: names differ (%q vs %q); the collision is untested",
			got[0].EventName, got[1].EventName)
	}
	if got[0].EventUID == got[1].EventUID {
		t.Fatalf("same-name events are indistinguishable: both uid %q", got[0].EventUID)
	}
}

// Interleaved tenants/namespaces must not leak a reference across the boundary.
func TestM018NoCarryoverAcrossTenantsAndNamespaces(t *testing.T) {
	api := &m018RecordingAPI{}
	type run struct{ ns, tenant, pod string }
	runs := []run{{"ns-a", "team-a", "p1"}, {"ns-b", "team-b", "p1"}, {"ns-a", "team-a", "p2"}}
	targets := make([]types.NamespacedName, 0, len(runs))
	for _, r := range runs {
		targets = append(targets, types.NamespacedName{Namespace: r.ns, Name: r.pod})
	}
	m := m018PhoenixManager(t, api, targets...)
	payloads := make([]model.PhoenixForensics, 0, len(runs))
	for _, r := range runs {
		pol := m018PhoenixPolicy(r.tenant)
		ds := m018SelectedPhoenixDecision(r.ns, r.pod)
		if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry(r.ns), pol, ds, m018TickView(r.ns, r.pod)); n != 1 {
			t.Fatalf("%s/%s actuated %d, want 1", r.ns, r.tenant, n)
		}
		if ds[0].Phoenix == nil {
			t.Fatalf("%s/%s lost its payload", r.ns, r.tenant)
		}
		p := *ds[0].Phoenix
		// The AMTD context must be THIS run's namespace and tenant, never the previous one.
		if want := "phorvex-" + r.ns + "-" + r.tenant; p.AMTDName != want {
			t.Errorf("amtdName = %q, want %q (leaked from another tenant?)", p.AMTDName, want)
		}
		if p.AMTDNamespace != r.ns {
			t.Errorf("amtdNamespace = %q, want %q", p.AMTDNamespace, r.ns)
		}
		payloads = append(payloads, p)
	}
	if payloads[0].EventUID == payloads[2].EventUID {
		t.Fatal("the repeated tenant reused the first run's event identity")
	}
}

// The AMTD namespace is CONTEXT attached to an AMTD that actually exists — never guessed.
// A result with an event but no AMTD name must not acquire a namespace out of thin air.
func TestM018AMTDNamespaceIsNotGuessedWithoutAnAMTD(t *testing.T) {
	fa := &m018PartialActuator{
		res: actuator.Result{
			Actuator: "phoenix", EventName: "phorvex-rotate-noamtd", EventUID: "uid-no-amtd",
			RuleType: amtdv1beta1.PhorvexRuleTypeRotate, Emitted: true,
		},
	}
	m := &Manager{Local: &inprocess.Services{Actuator: fa}, Log: logr.Discard()}
	ds := m018SelectedDecision("ns", "p1")
	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, m018TickView("ns", "p1")); n != 1 {
		t.Fatalf("actuated %d, want 1", n)
	}
	if ds[0].Phoenix == nil {
		t.Fatal("payload dropped")
	}
	if got := ds[0].Phoenix.AMTDNamespace; got != "" {
		t.Fatalf("amtdNamespace = %q with no AMTD name; the namespace was guessed", got)
	}
	if ds[0].Phoenix.EventUID != "uid-no-amtd" {
		t.Errorf("the event identity that WAS supplied got lost: %+v", *ds[0].Phoenix)
	}
}

// ---------------------------------------------------------------------------
// R1-1 (codex-lead independent review): stale Phoenix evidence must not survive
// a PRE-DISPATCH exit. Both arms below start from GENUINE prior metadata
// produced by the real Phoenix actuator, then re-enter actuate on a path that
// never attempts an emission. A retained identifier would be a forensic
// falsehood: the later record would point at an earlier tick's SecurityEvent.
// ---------------------------------------------------------------------------

// m018EnsureFailActuator fails policy setup, so actuate returns before any attempt.
type m018EnsureFailActuator struct{ err error }

func (f *m018EnsureFailActuator) Name() string { return "m018-ensure-fail" }
func (f *m018EnsureFailActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error {
	return f.err
}
func (f *m018EnsureFailActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	panic("EnsurePolicy failed; Actuate must not be reached")
}
func (f *m018EnsureFailActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}

// m018SeedRealPayload runs one genuine Phoenix emission and returns the decision
// carrying the real event identity it produced.
func m018SeedRealPayload(t *testing.T) []model.Decision {
	t.Helper()
	api := &m018RecordingAPI{}
	m := m018PhoenixManager(t, api, types.NamespacedName{Namespace: "ns", Name: "p1"})
	ds := m018SelectedPhoenixDecision("ns", "p1")
	ds[0].Existential = &model.ExistentialDecision{Present: true, EffectStatus: "not-attempted"}
	ds[0].Trace.Existential = ds[0].Existential
	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018PhoenixPolicy("team-a"), ds, m018TickView("ns", "p1")); n != 1 {
		t.Fatalf("seeding emission actuated %d, want 1", n)
	}
	if ds[0].Phoenix == nil || ds[0].Phoenix.EventUID == "" {
		t.Fatal("seed produced no real payload; the fixture would not be discriminating")
	}
	if ds[0].Existential.EffectStatus != "attempted-unconfirmed" {
		t.Fatalf("seed did not produce attempted effect evidence: %+v", ds[0].Existential)
	}
	return ds
}

// ARM (a): EnsurePolicy fails. actuate returns before the per-decision loop, so a
// reused decision must still be stripped of the previous tick's event identity.
func TestM018EnsurePolicyFailureClearsStalePhoenixEvidence(t *testing.T) {
	ds := m018SeedRealPayload(t)
	stale := *ds[0].Phoenix

	var buf bytes.Buffer
	m := &Manager{
		Local: &inprocess.Services{Actuator: &m018EnsureFailActuator{err: errors.New("rbac denied")}},
		Log:   logr.Discard(), Audit: audit.New(logr.Discard(), &buf),
	}
	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, m018TickView("ns", "p1")); n != 0 {
		t.Fatalf("actuated %d under EnsurePolicy failure, want 0", n)
	}

	if ds[0].Phoenix != nil {
		t.Fatalf("STALE EVIDENCE: a tick that never attempted an emission kept event %q (uid %q)",
			stale.EventName, stale.EventUID)
	}
	if ds[0].Actuated || ds[0].Handler != "" || len(ds[0].ObjectsTouched) != 0 || ds[0].RollbackRef != "" || ds[0].MutationKind != "" {
		t.Fatalf("not-attempted decision retained prior success/native evidence: %+v", ds[0])
	}
	if ds[0].DispatchOutcome != model.DispatchNotAttempted || ds[0].DispatchReason != "ensure-policy-failed" {
		t.Fatalf("top-level outcome disagrees with trace: %+v", ds[0])
	}
	if ds[0].Existential.EffectStatus != "not-attempted" || ds[0].Trace.Existential.EffectStatus != "not-attempted" {
		t.Fatalf("not-attempted decision retained prior existential effect: %+v", ds[0].Existential)
	}
	// The record an investigator reads must not carry it either.
	raw := m018RecordJSON(t, m, &buf, ds[0])
	if _, present := raw["phoenix"]; present {
		t.Fatalf("audit record for a not-attempted tick carries %v", raw["phoenix"])
	}
	// Outcome semantics unchanged by the clear.
	if got := ds[0].Trace.DispatchOutcome; got != model.DispatchNotAttempted {
		t.Errorf("dispatch outcome = %q, want %q", got, model.DispatchNotAttempted)
	}
	if got := ds[0].Trace.DispatchReason; got != "ensure-policy-failed" {
		t.Errorf("dispatch reason = %q, want ensure-policy-failed", got)
	}
}

// ARM (b): the decision is no longer selected. Audit.Record still serializes it —
// writeRecord runs unconditionally and OnlySelected gates only the structured log
// line — so a retained payload would reach the saved record.
func TestM018UnselectedDecisionClearsStalePhoenixEvidence(t *testing.T) {
	ds := m018SeedRealPayload(t)
	stale := *ds[0].Phoenix
	ds[0].Selected = false

	api := &m018RecordingAPI{}
	var buf bytes.Buffer
	m := m018PhoenixManager(t, api, types.NamespacedName{Namespace: "ns", Name: "p1"})
	m.Audit = audit.New(logr.Discard(), &buf)
	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018PhoenixPolicy("team-a"), ds, m018TickView("ns", "p1")); n != 0 {
		t.Fatalf("actuated %d for an unselected decision, want 0", n)
	}
	if ds[0].Phoenix != nil {
		t.Fatalf("STALE EVIDENCE: unselected decision kept event %q (uid %q)",
			stale.EventName, stale.EventUID)
	}
	if ds[0].Actuated || ds[0].Handler != "" || len(ds[0].ObjectsTouched) != 0 || ds[0].RollbackRef != "" || ds[0].MutationKind != "" {
		t.Fatalf("unselected decision retained prior success/native evidence: %+v", ds[0])
	}
	if ds[0].DispatchOutcome != model.DispatchNotAttempted || ds[0].DispatchReason != "unselected" ||
		ds[0].Trace.DispatchOutcome != model.DispatchNotAttempted || ds[0].Trace.DispatchReason != "unselected" {
		t.Fatalf("unselected current-call outcome = %+v", ds[0])
	}
	if ds[0].Existential.EffectStatus != "not-attempted" || ds[0].Trace.Existential.EffectStatus != "not-attempted" {
		t.Fatalf("unselected decision retained prior existential effect: %+v", ds[0].Existential)
	}
	raw := m018RecordJSON(t, m, &buf, ds[0])
	if _, present := raw["phoenix"]; present {
		t.Fatalf("audit record for an unselected decision carries %v", raw["phoenix"])
	}
	if raw["selected"] == true {
		t.Error("fixture broken: decision should be unselected")
	}
}

// CONTROL: the clear must not be indiscriminate. A successful Phoenix emission in the
// SAME call still records its identity, and a native result still maps its own fields.
func TestM018ClearDoesNotSuppressGenuineEvidence(t *testing.T) {
	// Phoenix control: a real emission after a reused decision still gets its payload.
	ds := m018SeedRealPayload(t)
	first := *ds[0].Phoenix
	api := &m018RecordingAPI{}
	m := m018PhoenixManager(t, api, types.NamespacedName{Namespace: "ns", Name: "p1"})
	if n := actuateWithBoundary(t, m, context.Background(), m018PolicyEntry("ns"), m018PhoenixPolicy("team-a"), ds, m018TickView("ns", "p1")); n != 1 {
		t.Fatalf("re-actuation actuated %d, want 1", n)
	}
	if ds[0].Phoenix == nil {
		t.Fatal("the clear suppressed a genuine new emission")
	}
	if ds[0].Phoenix.EventUID == first.EventUID {
		t.Fatalf("re-actuation reused the previous event identity %q", first.EventUID)
	}

	// Native control: native forensic fields are unaffected by the Phoenix clear.
	native := &m018PartialActuator{res: actuator.Result{
		Handler: "kv-reset", ObjectsTouched: []string{"secret/ns/creds"},
		RollbackRef: "rb-1", MutationKind: "reversible", Emitted: true,
	}}
	nd := m018SelectedDecision("ns", "p2")
	mn := &Manager{Local: &inprocess.Services{Actuator: native}, Log: logr.Discard()}
	if n := actuateWithBoundary(t, mn, context.Background(), m018PolicyEntry("ns"), m018Policy(), nd, m018TickView("ns", "p2")); n != 1 {
		t.Fatalf("native actuation actuated %d, want 1", n)
	}
	if nd[0].Handler != "kv-reset" || nd[0].MutationKind != "reversible" ||
		nd[0].RollbackRef != "rb-1" || len(nd[0].ObjectsTouched) != 1 || !nd[0].Actuated ||
		nd[0].DispatchOutcome != model.DispatchEmitted {
		t.Fatalf("native forensic mapping changed: %+v", nd[0])
	}
	if nd[0].Phoenix != nil {
		t.Fatalf("native result produced a phoenix payload: %+v", *nd[0].Phoenix)
	}
}
