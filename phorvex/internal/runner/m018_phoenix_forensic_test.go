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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
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
func m018PhoenixClient(t *testing.T, api *m018RecordingAPI) client.WithWatch {
	t.Helper()
	s := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(s); err != nil {
		t.Fatalf("add phoenix scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := c.Create(ctx, obj, opts...); err != nil {
				return err
			}
			obj.SetUID(api.record(obj)) // server-assigned identity, written back into the caller's object
			return nil
		},
	}).Build()
}

// m018PolicyEntry is a minimal entry whose selector satisfies EnsurePolicy's
// matchLabels precondition (P0 active mode requires an expressible guest list).
func m018PolicyEntry(namespace string) *policyEntry {
	return &policyEntry{
		namespace: namespace,
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
			Namespace: namespace, Name: pod, DesiredReplicas: 3, ReadyReplicas: 3, Ready: true,
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
	pa := actuator.NewPhoenixActuator(m018PhoenixClient(t, api))

	var buf bytes.Buffer
	m := &Manager{Actuator: pa, Log: logr.Discard(), Audit: audit.New(logr.Discard(), &buf)}
	pol := model.Policy{
		Tenant: "team-a", MinAvailableReplicas: 1,
		EnabledActions: map[model.Action]bool{model.ActionRotate: true},
	}
	ds := m018SelectedDecision("ns", "p1")

	if n := m.actuate(context.Background(), m018PolicyEntry("ns"), pol, ds, m018TickView("ns", "p1")); n != 1 {
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
		"ruleType":        actuator.RuleTypeRotate,
		"ruleThreatLevel": actuator.RuleThreatLevel,
		"ruleSource":      actuator.RuleSource,
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
	return model.Policy{Tenant: "team-a", MinAvailableReplicas: 1,
		EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
}

func TestM018PartialResultWithErrorKeepsFactsAndFailureOutcome(t *testing.T) {
	fa := &m018PartialActuator{
		res: actuator.Result{
			Actuator: "phoenix", AMTDName: "phorvex-ns-team-a",
			EventName: "phorvex-rotate-abc12", EventUID: "uid-partial-1",
			RuleType: actuator.RuleTypeRotate, RuleThreatLevel: actuator.RuleThreatLevel,
			RuleSource: actuator.RuleSource,
			Emitted:    false,
		},
		err: errors.New("emit SecurityEvent: connection reset after acknowledgement"),
	}
	m := &Manager{Actuator: fa, Log: logr.Discard()}
	ds := m018SelectedDecision("ns", "p1")

	n := m.actuate(context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, m018TickView("ns", "p1"))

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
	c := fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, isEvent := obj.(*amtdv1beta1.SecurityEvent); isEvent {
				return apierrors.NewForbidden(
					schema.GroupResource{Group: "amtd.r6security.com", Resource: "securityevents"},
					"", errors.New("denied by admission"))
			}
			return c.Create(ctx, obj, opts...) // the AMTD (policy setup) still succeeds
		},
	}).Build()

	var buf bytes.Buffer
	m := &Manager{Actuator: actuator.NewPhoenixActuator(c), Log: logr.Discard(),
		Audit: audit.New(logr.Discard(), &buf)}
	ds := m018SelectedDecision("ns", "p1")

	if n := m.actuate(context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, m018TickView("ns", "p1")); n != 0 {
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
	m := &Manager{Actuator: actuator.NewPhoenixActuator(m018PhoenixClient(t, api)), Log: logr.Discard()}
	ds := m018SelectedDecision("ns", "p1")

	// Attempt 1 succeeds and stamps a real payload onto the decision.
	if n := m.actuate(context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, m018TickView("ns", "p1")); n != 1 {
		t.Fatalf("first attempt actuated %d, want 1", n)
	}
	if ds[0].Phoenix == nil {
		t.Fatal("first attempt produced no payload; fixture is not discriminating")
	}
	firstUID := ds[0].Phoenix.EventUID

	// Attempt 2 reuses the SAME decision but is vetoed before Actuate (empty tick view).
	if n := m.actuate(context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, map[string]*model.WorkloadView{}); n != 0 {
		t.Fatalf("map-miss attempt actuated %d, want 0", n)
	}
	if ds[0].Phoenix != nil {
		t.Fatalf("M-18: not-attempted move inherited a stale reference to %q: %+v",
			firstUID, *ds[0].Phoenix)
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
	m := &Manager{Actuator: actuator.NewPhoenixActuator(m018PhoenixClient(t, api)), Log: logr.Discard()}

	pods := []string{"p1", "p2", "p3"}
	ds := make([]model.Decision, 0, len(pods))
	view := map[string]*model.WorkloadView{}
	for _, pod := range pods {
		ds = append(ds, m018SelectedDecision("ns", pod)[0])
		for k, v := range m018TickView("ns", pod) {
			view[k] = v
		}
	}
	if n := m.actuate(context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, view); n != len(pods) {
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
	uids := []string{"uid-original", "uid-recreated"}
	var creates int
	c := fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := c.Create(ctx, obj, opts...); err != nil {
				return err
			}
			if _, isEvent := obj.(*amtdv1beta1.SecurityEvent); isEvent {
				obj.SetName("phorvex-rotate-collide") // same name both times
				obj.SetUID(types.UID(uids[creates%len(uids)]))
				creates++
			}
			return nil
		},
	}).Build()

	m := &Manager{Actuator: actuator.NewPhoenixActuator(c), Log: logr.Discard()}
	got := make([]model.PhoenixForensics, 0, 2)
	for _, pod := range []string{"p1", "p2"} {
		ds := m018SelectedDecision("ns", pod)
		if n := m.actuate(context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, m018TickView("ns", pod)); n != 1 {
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
	m := &Manager{Actuator: actuator.NewPhoenixActuator(m018PhoenixClient(t, api)), Log: logr.Discard()}

	type run struct{ ns, tenant string }
	runs := []run{{"ns-a", "team-a"}, {"ns-b", "team-b"}, {"ns-a", "team-a"}}
	payloads := make([]model.PhoenixForensics, 0, len(runs))
	for _, r := range runs {
		pol := model.Policy{Tenant: r.tenant, MinAvailableReplicas: 1,
			EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
		ds := m018SelectedDecision(r.ns, "p1")
		if n := m.actuate(context.Background(), m018PolicyEntry(r.ns), pol, ds, m018TickView(r.ns, "p1")); n != 1 {
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
			RuleType: actuator.RuleTypeRotate, Emitted: true,
		},
	}
	m := &Manager{Actuator: fa, Log: logr.Discard()}
	ds := m018SelectedDecision("ns", "p1")
	if n := m.actuate(context.Background(), m018PolicyEntry("ns"), m018Policy(), ds, m018TickView("ns", "p1")); n != 1 {
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
