package actuator

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

// handlers_ai_identity_test.go — [M-69] fake-client coverage of the identity contract on the
// three destructive AI paths (warm-swap, mig-rebind, model-shard-replace single + TP/PP group):
// pre-mutation trigger refusals, the UID precondition every Delete carries, and honest
// non-success when the API rejects a Delete. The fake client does NOT enforce UID
// preconditions, so the actual name-reuse survival is proven against a real API server in
// m069_apiserver_test.go; here the rejection is injected through an interceptor.

// m069Delete records every Delete's options and can reject a named Pod with a Conflict (the
// API server's answer to a UID precondition that names a replaced object).
type m069Delete struct {
	opts       map[string][]*client.DeleteOptions
	conflictOn map[string]bool
}

func (d *m069Delete) fn() func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
	return func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		if _, ok := obj.(*corev1.Pod); !ok {
			return c.Delete(ctx, obj, opts...)
		}
		o := &client.DeleteOptions{}
		o.ApplyOptions(opts)
		if d.opts == nil {
			d.opts = map[string][]*client.DeleteOptions{}
		}
		d.opts[obj.GetName()] = append(d.opts[obj.GetName()], o)
		if d.conflictOn[obj.GetName()] {
			return apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, obj.GetName(), errors.New("the UID in the precondition does not match the UID in record"))
		}
		return c.Delete(ctx, obj, opts...)
	}
}

func m069Client(d *m069Delete, fns interceptor.Funcs, objs ...client.Object) client.Client {
	var old, next *corev1.Pod
	for _, obj := range objs {
		p, ok := obj.(*corev1.Pod)
		if !ok {
			continue
		}
		if p.Labels[labelRole] == roleLeader {
			old = p
		}
		if p.Labels[labelRole] == roleShadow {
			next = p
		}
	}
	if old != nil && next != nil && old.Labels[labelParallelGroup] == "" && next.Labels[labelParallelGroup] == "" {
		for _, key := range []string{labelSwapGroup, labelModelShard} {
			if old.Labels[key] != "" && old.Labels[key] == next.Labels[key] {
				objs = append(objs, m066FakePool(old, next, key)...)
				break
			}
		}
	}
	fns.Delete = d.fn()
	originalCreate := fns.Create
	fns.Create = func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if obj.GetUID() == "" {
			obj.SetUID(types.UID("created-" + obj.GetName()))
		}
		if originalCreate != nil {
			return originalCreate(ctx, c, obj, opts...)
		}
		return c.Create(ctx, obj, opts...)
	}
	objs = append(objs, &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "phorvex.ai/fixture-never", Operator: metav1.LabelSelectorOpDoesNotExist}}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap), v1alpha1.ActionType(model.ActionModelShardReplace)}}}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}})
	return fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objs...).WithInterceptorFuncs(fns).Build()
}

func m069Get(t *testing.T, c client.Client, ns, name string) (*corev1.Pod, bool) {
	t.Helper()
	p, ok, err := getPod(context.Background(), c, ns, name)
	if err != nil {
		t.Fatalf("get %s/%s: %v", ns, name, err)
	}
	return p, ok
}

func m069CountRole(t *testing.T, c client.Client, ns, role string) int {
	t.Helper()
	var pods corev1.PodList
	if err := c.List(context.Background(), &pods, client.InNamespace(ns), client.MatchingLabels{labelRole: role}); err != nil {
		t.Fatal(err)
	}
	return len(pods.Items)
}

// m069Case drives one destructive handler against a fresh fixture and reports what mutated.
type m069Case struct {
	name    string
	handler ActionHandler
	action  model.Action
	// build returns the fixture objects; the first object is the trigger Pod.
	build func() []client.Object
	// untouched asserts nothing destructive happened (fail-closed / refused).
	untouched func(t *testing.T, c client.Client, mm *mockMIG)
}

func m069Cases() []m069Case {
	return []m069Case{
		{
			name: "warm-swap", handler: warmSwapHandler{}, action: model.ActionWarmSwap,
			build: func() []client.Object {
				return []client.Object{
					aiPod("ns", "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader}),
					aiPod("ns", "shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"}),
				}
			},
			untouched: func(t *testing.T, c client.Client, _ *mockMIG) {
				if l, ok := m069Get(t, c, "ns", "leader"); !ok || l.Labels[labelRole] != roleLeader {
					t.Errorf("refusal must leave the old leader serving: present=%v labels=%v", ok, l)
				}
				if s, _ := m069Get(t, c, "ns", "shadow"); s.Labels[labelRole] != roleShadow {
					t.Errorf("refusal must not promote the shadow: role=%q", s.Labels[labelRole])
				}
				if n := m069CountRole(t, c, "ns", roleShadow); n != 1 {
					t.Errorf("refusal must not rewarm: %d shadows", n)
				}
			},
		},
		{
			name: "mig-rebind", handler: migRebindHandler{}, action: model.ActionMIGRebind,
			build: func() []client.Object { return []client.Object{migPod("ns", "infer")} },
			untouched: func(t *testing.T, c client.Client, mm *mockMIG) {
				if p, ok := m069Get(t, c, "ns", "infer"); !ok || p.Labels[labelRole] != roleLeader {
					t.Errorf("refusal must leave the pod untouched: present=%v", ok)
				}
				if len(mm.calls) != 0 {
					t.Errorf("refusal must not repartition: %v", mm.calls)
				}
			},
		},
		{
			name: "model-shard-replace", handler: modelShardReplaceHandler{}, action: model.ActionModelShardReplace,
			build: func() []client.Object {
				return []client.Object{
					aiPod("ns", "shard0", map[string]string{labelModelShard: "s", labelRole: roleLeader}),
					aiPod("ns", "shard0b", map[string]string{labelModelShard: "s", labelRole: roleShadow, labelModelLoaded: "true"}),
				}
			},
			untouched: func(t *testing.T, c client.Client, _ *mockMIG) {
				if l, ok := m069Get(t, c, "ns", "shard0"); !ok || l.Labels[labelRole] != roleLeader {
					t.Errorf("refusal must leave the old shard serving: present=%v", ok)
				}
				if s, _ := m069Get(t, c, "ns", "shard0b"); s.Labels[labelRole] != roleShadow {
					t.Errorf("refusal must not promote the replacement shard: role=%q", s.Labels[labelRole])
				}
			},
		},
		{
			name: "model-shard-replace-group", handler: modelShardReplaceHandler{}, action: model.ActionModelShardReplace,
			build: func() []client.Object {
				return []client.Object{
					tpPod("ns", "l0", "g", "0", roleLeader, true, 2),
					tpPod("ns", "l1", "g", "1", roleLeader, true, 2),
					tpPod("ns", "s0", "g", "0", roleShadow, true, 2),
					tpPod("ns", "s1", "g", "1", roleShadow, true, 2),
				}
			},
			untouched: func(t *testing.T, c client.Client, _ *mockMIG) {
				if n := m069CountRole(t, c, "ns", roleLeader); n != 2 {
					t.Errorf("refusal must leave exactly the 2 old leaders serving, got %d", n)
				}
				if n := m069CountRole(t, c, "ns", roleShadow); n != 2 {
					t.Errorf("refusal must not promote any shadow rank, %d shadows remain", n)
				}
			},
		},
	}
}

func m069Stack() (EnactCtx, *mockMIG) {
	mm := &mockMIG{}
	return EnactCtx{VLLM: &mockVLLM{loaded: true, readyErr: nil}, MIG: mm}, mm
}

// A request without a bound identity, with a mismatched identity, or an observed Pod that
// carries no UID is refused BEFORE any mutation, in native rotate's refusal shape: not emitted,
// reason in the Note, no error. The direct callers (runner, native demo) always bind TargetUID.
func TestM069TriggerIdentityRefusedBeforeMutation(t *testing.T) {
	for _, tc := range m069Cases() {
		for _, r := range []struct {
			name, want string
			mutate     func(req *Request, trig *corev1.Pod)
		}{
			{"missing-request-uid", reasonTargetUIDUnavailable, func(req *Request, _ *corev1.Pod) { req.TargetUID = "" }},
			{"mismatched-request-uid", reasonTargetUIDMismatch, func(req *Request, _ *corev1.Pod) { req.TargetUID = "uid-of-a-replacement" }},
			{"observed-pod-without-uid", reasonObservedUIDUnavailable, func(_ *Request, trig *corev1.Pod) { trig.UID = "" }},
		} {
			t.Run(tc.name+"/"+r.name, func(t *testing.T) {
				objs := tc.build()
				trig := objs[0].(*corev1.Pod)
				req := boundReq(trig, tc.action)
				r.mutate(&req, trig)
				d := &m069Delete{}
				c := m069Client(d, interceptor.Funcs{}, objs...)
				ec, mm := m069Stack()
				ec.Client = c
				hr, err := tc.handler.Enact(context.Background(), ec, req)
				if err != nil {
					t.Fatalf("refusal must not be an error (native rotate convention): %v", err)
				}
				if hr.Emitted || !strings.Contains(hr.Note, "not performed: "+r.want) {
					t.Fatalf("expected refusal %q, got %+v", r.want, hr)
				}
				if len(d.opts) != 0 {
					t.Fatalf("refusal must issue no Delete, got %v", d.opts)
				}
				tc.untouched(t, c, mm)
			})
		}
	}
}

// The bound identity (matching the observed trigger) is the positive control: every path
// still performs its retirement, and EVERY Delete it issues carries the observed object's UID
// as a precondition (and no stale ResourceVersion, which the handler's own relabel would
// invalidate).
func TestM069DeleteCarriesObservedUIDPrecondition(t *testing.T) {
	for _, tc := range m069Cases() {
		t.Run(tc.name, func(t *testing.T) {
			objs := tc.build()
			observed := map[string]string{}
			for _, o := range objs {
				observed[o.GetName()] = string(o.GetUID())
			}
			d := &m069Delete{}
			c := m069Client(d, interceptor.Funcs{}, objs...)
			ec, _ := m069Stack()
			ec.Client = c
			ec.Reader, ec.JournalNamespace = c, "operator"
			hr, err := tc.handler.Enact(context.Background(), ec, boundReq(objs[0].(*corev1.Pod), tc.action))
			scalarPending := tc.name == "warm-swap" || tc.name == "model-shard-replace"
			if (!scalarPending && (err != nil || !hr.Emitted)) || (scalarPending && (err == nil || hr.MutationKind != "swap")) {
				t.Fatalf("positive control: %+v %v", hr, err)
			}
			if len(d.opts) == 0 {
				t.Fatal("positive control issued no Delete")
			}
			for name, calls := range d.opts {
				for _, o := range calls {
					if o.Preconditions == nil || o.Preconditions.UID == nil || string(*o.Preconditions.UID) != observed[name] || observed[name] == "" {
						t.Errorf("Delete %s must carry the observed UID %q as a precondition, got %+v", name, observed[name], o.Preconditions)
					}
					if (tc.name == "warm-swap" || tc.name == "model-shard-replace") && (o.Preconditions == nil || o.Preconditions.ResourceVersion == nil) {
						t.Errorf("scalar recovery retirement must pin the freshly read ResourceVersion for %s, got %+v", name, o.Preconditions)
					}
				}
			}
		})
	}
}

// A Delete the API rejects (UID precondition failed: same-name replacement) is a non-success
// that describes the partial state honestly: the shadow IS promoted, nothing is rolled back,
// no rewarm is provisioned, and the runner-visible ObjectsTouched carries the partial writes.
func TestM069WarmCutoverRejectedDeleteIsHonestNonSuccess(t *testing.T) {
	leader := aiPod("ns", "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	shadow := aiPod("ns", "shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	d := &m069Delete{conflictOn: map[string]bool{"leader": true}}
	c := m069Client(d, interceptor.Funcs{}, leader, shadow)
	ec, _ := m069Stack()
	ec.Client = c
	ec.Reader, ec.JournalNamespace = c, "operator"
	hr, err := warmSwapHandler{}.Enact(context.Background(), ec, boundReq(leader, model.ActionWarmSwap))
	if err == nil || !errors.Is(err, errPodReplaced) {
		t.Fatalf("rejected retire must propagate errPodReplaced, got err=%v hr=%+v", err, hr)
	}
	if hr.Emitted {
		t.Fatalf("rejected retire must not be emitted: %+v", hr)
	}
	for _, want := range []string{"partial", "shadow shadow promoted", "NOT deleted", "no rewarm", "uid-leader"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must describe the partial state (%q): %v", want, err)
		}
	}
	if len(hr.ObjectsTouched) != 2 {
		t.Errorf("partial writes must be reported for the runner: %v", hr.ObjectsTouched)
	}
	if s, _ := m069Get(t, c, "ns", "shadow"); s.Labels[labelRole] != roleLeader {
		t.Errorf("honesty: the shadow WAS promoted before the rejected delete, role=%q", s.Labels[labelRole])
	}
	if l, ok := m069Get(t, c, "ns", "leader"); !ok || l.Labels[labelRole] != roleRetiring {
		t.Errorf("honesty: the leader name WAS relabeled retiring and is not deleted: present=%v", ok)
	}
	if n := m069CountRole(t, c, "ns", roleShadow); n != 0 {
		t.Errorf("no rewarm after a rejected retire, got %d shadows", n)
	}
}

// A rejected eviction means the GPU was NOT freed by this move: Repartition is never called.
func TestM069MIGRebindRejectedDeleteSkipsRepartition(t *testing.T) {
	pod := migPod("ns", "infer")
	d := &m069Delete{conflictOn: map[string]bool{"infer": true}}
	c := m069Client(d, interceptor.Funcs{}, pod)
	ec, mm := m069Stack()
	ec.Client = c
	hr, err := migRebindHandler{}.Enact(context.Background(), ec, boundReq(pod, model.ActionMIGRebind))
	if err == nil || !errors.Is(err, errPodReplaced) || hr.Emitted {
		t.Fatalf("rejected eviction must be a non-success wrapping errPodReplaced: err=%v hr=%+v", err, hr)
	}
	if len(mm.calls) != 0 {
		t.Fatalf("Repartition must NOT run after a rejected eviction, got %v", mm.calls)
	}
	if !strings.Contains(err.Error(), "repartition NOT attempted") {
		t.Errorf("error must state the repartition was not attempted: %v", err)
	}
	if p, ok := m069Get(t, c, "ns", "infer"); !ok || p.Labels[labelRole] != roleRetiring {
		t.Errorf("honesty: the pod name was relabeled retiring and remains: present=%v", ok)
	}
}

// A group cutover whose Delete of one old leader is rejected never claims the whole old group
// retired: it reports which members were and were not retired, keeps the promoted shadows as
// they are (no rollback claim) and returns a non-success.
func TestM069GroupCutoverRejectedDeleteIsHonestNonSuccess(t *testing.T) {
	objs := []client.Object{
		tpPod("ns", "l0", "g", "0", roleLeader, true, 2),
		tpPod("ns", "l1", "g", "1", roleLeader, true, 2),
		tpPod("ns", "s0", "g", "0", roleShadow, true, 2),
		tpPod("ns", "s1", "g", "1", roleShadow, true, 2),
	}
	d := &m069Delete{conflictOn: map[string]bool{"l1": true}}
	c := m069Client(d, interceptor.Funcs{}, objs...)
	ec, _ := m069Stack()
	ec.Client = c
	hr, err := modelShardReplaceHandler{}.Enact(context.Background(), ec, boundReq(objs[0].(*corev1.Pod), model.ActionModelShardReplace))
	if err == nil || !errors.Is(err, errPodReplaced) || hr.Emitted {
		t.Fatalf("group cutover with a rejected member delete must be a non-success: err=%v hr=%+v", err, hr)
	}
	for _, want := range []string{"PARTIAL", "no rollback", "2 shadow ranks promoted", "retired [l0]", "NOT retired [l1]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must describe the partial group state (%q): %v", want, err)
		}
	}
	if _, ok := m069Get(t, c, "ns", "l0"); ok {
		t.Error("l0's identity-bound delete was accepted and must have happened")
	}
	if l1, ok := m069Get(t, c, "ns", "l1"); !ok || l1.Labels[labelRole] != roleRetiring {
		t.Errorf("l1 is not deleted after the rejected delete (name relabeled retiring): present=%v", ok)
	}
	for _, s := range []string{"s0", "s1"} {
		if p, _ := m069Get(t, c, "ns", s); p.Labels[labelRole] != roleLeader {
			t.Errorf("honesty: shadow %s WAS promoted (no rollback), role=%q", s, p.Labels[labelRole])
		}
	}
	if len(hr.ObjectsTouched) != 4 {
		t.Errorf("partial writes (2 old names + 2 promoted) must be reported: %v", hr.ObjectsTouched)
	}
}

// The trigger's retirement is bound to the identity verified up front. If the retire-time
// list shows the trigger's name under another UID (replaced between the check and the list),
// that object is a replacement: it is neither relabeled nor deleted, and the move is a
// non-success naming it.
func TestM069GroupCutoverTriggerReplacedBeforeRetireListIsNotDeleted(t *testing.T) {
	objs := []client.Object{
		tpPod("ns", "l0", "g", "0", roleLeader, true, 2),
		tpPod("ns", "l1", "g", "1", roleLeader, true, 2),
		tpPod("ns", "s0", "g", "0", roleShadow, true, 2),
		tpPod("ns", "s1", "g", "1", roleShadow, true, 2),
	}
	lists := 0
	fns := interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if err := c.List(ctx, list, opts...); err != nil {
			return err
		}
		lists++
		if pl, ok := list.(*corev1.PodList); ok && lists == 2 { // the retire-time list, after the flip
			for i := range pl.Items {
				if pl.Items[i].Name == "l0" {
					pl.Items[i].UID = "uid-l0-replacement"
				}
			}
		}
		return nil
	}}
	d := &m069Delete{}
	c := m069Client(d, fns, objs...)
	ec, _ := m069Stack()
	ec.Client = c
	hr, err := modelShardReplaceHandler{}.Enact(context.Background(), ec, boundReq(objs[0].(*corev1.Pod), model.ActionModelShardReplace))
	if err == nil || !errors.Is(err, errPodReplaced) || hr.Emitted {
		t.Fatalf("replaced trigger must be a non-success: err=%v hr=%+v", err, hr)
	}
	if !strings.Contains(err.Error(), "NOT retired [l0]") || !strings.Contains(err.Error(), "retired [l1]") {
		t.Errorf("error must name the replaced trigger as not retired: %v", err)
	}
	if _, issued := d.opts["l0"]; issued {
		t.Errorf("no Delete may be issued for the replaced trigger name, got %v", d.opts["l0"])
	}
	if l0, ok := m069Get(t, c, "ns", "l0"); !ok || l0.Labels[labelRole] != roleLeader {
		t.Errorf("replacement under the trigger's name must be untouched (not relabeled, not deleted): present=%v labels=%v", ok, l0.Labels)
	}
	if _, ok := m069Get(t, c, "ns", "l1"); ok {
		t.Error("the other old leader, listed under its observed UID, is retired")
	}
}

// deleteObservedPod's own contract: NotFound is "already gone" (truthful: a same-name
// replacement is never NotFound), a Conflict wraps errPodReplaced, and an observed object
// without a UID is refused before any Delete is issued.
func TestM069DeleteObservedPodOutcomes(t *testing.T) {
	pod := aiPod("ns", "p", nil)
	t.Run("already-gone", func(t *testing.T) {
		d := &m069Delete{}
		c := m069Client(d, interceptor.Funcs{})
		gone, err := deleteObservedPod(context.Background(), c, pod)
		if err != nil || !gone {
			t.Fatalf("NotFound must be reported as already gone: gone=%v err=%v", gone, err)
		}
	})
	t.Run("conflict", func(t *testing.T) {
		d := &m069Delete{conflictOn: map[string]bool{"p": true}}
		c := m069Client(d, interceptor.Funcs{}, pod)
		gone, err := deleteObservedPod(context.Background(), c, pod)
		if gone || !errors.Is(err, errPodReplaced) {
			t.Fatalf("Conflict must wrap errPodReplaced: gone=%v err=%v", gone, err)
		}
	})
	t.Run("observed-without-uid", func(t *testing.T) {
		d := &m069Delete{}
		bare := aiPod("ns", "p", nil)
		bare.UID = ""
		c := m069Client(d, interceptor.Funcs{}, bare)
		gone, err := deleteObservedPod(context.Background(), c, bare)
		if gone || !errors.Is(err, errObservedUIDMissing) || len(d.opts) != 0 {
			t.Fatalf("missing observed UID must refuse before any Delete: gone=%v err=%v deletes=%v", gone, err, d.opts)
		}
	})
}
