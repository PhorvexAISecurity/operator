package actuator

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/internal/model"
)

// m069_apiserver_test.go — [M-69] API-server evidence that the destructive AI paths retire
// exactly the Pod they observed. Each real handler runs against a local kube-apiserver
// (envtest: no kubelet, no GC, no scheduler); immediately before the handler's own Delete the
// observed Pod is replaced by a same-namespace/name object, as an owner respawn would. The
// API-enforced UID precondition rejects the Delete and the replacement survives; the baseline
// (no precondition) deleted it. The serving-stack and MIG callbacks are local fakes: no GPU
// effect is proven here, only the Kubernetes identity contract.

func m069Env(t *testing.T) client.WithWatch {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API-server binaries")
	}
	e := &envtest.Environment{}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// m069Create creates the fixture Pod through the API (server-assigned UID/ResourceVersion) and
// marks it Ready through the status subresource, which is what the shadow gate reads.
func m069Create(t *testing.T, c client.Client, p *corev1.Pod) *corev1.Pod {
	t.Helper()
	ctx := context.Background()
	p = p.DeepCopy()
	p.UID, p.ResourceVersion = "", ""
	status := p.Status
	if err := c.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	p.Status = status
	if err := c.Status().Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	if p.UID == "" {
		t.Fatalf("fixture %s has no server-assigned UID", p.Name)
	}
	return p
}

func m069Namespace(t *testing.T, c client.Client, name string) string {
	t.Helper()
	if err := c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
		t.Fatal(err)
	}
	return name
}

// m069Replacer replaces the named Pod with a same-name object the moment the handler issues
// its Delete for that name — the respawn race the identity contract exists for. The
// replacement keeps the original's labels/annotations/spec, so nothing but the UID differs.
type m069Replacer struct {
	target      string
	replacement *corev1.Pod
	t           *testing.T
}

func (r *m069Replacer) funcs() interceptor.Funcs {
	return interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		if obj.GetName() == r.target && r.replacement == nil {
			cur := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
				r.t.Fatalf("replacer get: %v", err)
			}
			if err := c.Delete(ctx, cur, client.GracePeriodSeconds(0)); err != nil {
				r.t.Fatalf("replacer delete: %v", err)
			}
			next := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: cur.Namespace, Name: cur.Name, Labels: cur.Labels, Annotations: cur.Annotations}, Spec: cur.Spec, Status: cur.Status}
			r.replacement = m069Create(r.t, c, next)
			if r.replacement.UID == cur.UID {
				r.t.Fatalf("replacement reused UID %s", cur.UID)
			}
		}
		return c.Delete(ctx, obj, opts...)
	}}
}

func m069Wrap(t *testing.T, c client.WithWatch, target string) (client.Client, *m069Replacer) {
	r := &m069Replacer{target: target, t: t}
	return interceptor.NewClient(c, r.funcs()), r
}

func m069Live(t *testing.T, c client.Client, ns, name string) *corev1.Pod {
	t.Helper()
	p := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, p); err != nil {
		t.Fatalf("get %s/%s: %v", ns, name, err)
	}
	return p
}

func m069Retired(t *testing.T, c client.Client, ns, name string, uid types.UID) {
	t.Helper()
	p := &corev1.Pod{}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, p)
	switch {
	case apierrors.IsNotFound(err):
		return
	case err != nil:
		t.Fatal(err)
	case p.UID != uid:
		t.Fatalf("%s: a different object (%s) is under the observed name %s", name, p.UID, uid)
	case p.DeletionTimestamp.IsZero():
		t.Fatalf("%s (uid %s) was not retired", name, uid)
	}
}

func m069Survived(t *testing.T, c client.Client, r *m069Replacer) {
	t.Helper()
	if r.replacement == nil {
		t.Fatal("fixture: the handler never issued the Delete the replacement race is built on")
	}
	live := m069Live(t, c, r.replacement.Namespace, r.replacement.Name)
	if live.UID != r.replacement.UID || !live.DeletionTimestamp.IsZero() {
		t.Fatalf("same-name replacement %s (uid %s) did not survive: live uid=%s deletionTimestamp=%v", live.Name, r.replacement.UID, live.UID, live.DeletionTimestamp)
	}
}

func m069Rejected(t *testing.T, hr HandlerResult, err error) {
	t.Helper()
	if err == nil || !errors.Is(err, errPodReplaced) || hr.Emitted {
		t.Fatalf("a replaced target must be a non-success wrapping errPodReplaced: err=%v hr=%+v", err, hr)
	}
	t.Logf("API-server rejection: %v", err)
}

func TestM069APIServerNameReuse(t *testing.T) {
	c := m069Env(t)
	ctx := context.Background()

	t.Run("warm-swap", func(t *testing.T) {
		ns := m069Namespace(t, c, "m069-warm")
		leader := m069Create(t, c, aiPod(ns, "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader}))
		shadow := m069Create(t, c, aiPod(ns, "shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"}))
		wc, r := m069Wrap(t, c, "leader")
		hr, err := warmSwapHandler{}.Enact(ctx, EnactCtx{Client: wc, VLLM: &mockVLLM{loaded: true}}, boundReq(leader, model.ActionWarmSwap))
		m069Rejected(t, hr, err)
		m069Survived(t, c, r)
		// honest partial state: the shadow was promoted before the rejected retire; no rewarm.
		if s := m069Live(t, c, ns, "shadow"); s.Labels[labelRole] != roleLeader || s.UID != shadow.UID {
			t.Errorf("shadow promotion is real partial state: %v", s.Labels)
		}
		var pods corev1.PodList
		if err := c.List(ctx, &pods, client.InNamespace(ns)); err != nil || len(pods.Items) != 2 {
			t.Errorf("no rewarm after a rejected retire: %d pods, %v", len(pods.Items), err)
		}
	})

	t.Run("warm-swap-positive-control", func(t *testing.T) {
		ns := m069Namespace(t, c, "m069-warm-ok")
		leader := m069Create(t, c, aiPod(ns, "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader}))
		m069Create(t, c, aiPod(ns, "shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"}))
		hr, err := warmSwapHandler{}.Enact(ctx, EnactCtx{Client: c, VLLM: &mockVLLM{loaded: true}}, boundReq(leader, model.ActionWarmSwap))
		if err != nil || !hr.Emitted || !strings.Contains(hr.Note, "retired (uid "+string(leader.UID)+")") {
			t.Fatalf("unchanged identity must retire: %+v %v", hr, err)
		}
		m069Retired(t, c, ns, "leader", leader.UID)
		if s := m069Live(t, c, ns, "shadow"); s.Labels[labelRole] != roleLeader {
			t.Errorf("shadow not promoted: %v", s.Labels)
		}
		var pods corev1.PodList
		if err := c.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels{labelRole: roleShadow}); err != nil || len(pods.Items) != 1 {
			t.Errorf("rewarm expected exactly one new shadow: %d %v", len(pods.Items), err)
		}
	})

	t.Run("warm-swap-mismatched-request-identity", func(t *testing.T) {
		ns := m069Namespace(t, c, "m069-warm-mismatch")
		leader := m069Create(t, c, aiPod(ns, "leader", map[string]string{labelSwapGroup: "g", labelRole: roleLeader}))
		m069Create(t, c, aiPod(ns, "shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"}))
		req := boundReq(leader, model.ActionWarmSwap)
		req.TargetUID = string(types.UID("00000000-0000-4000-8000-000000000069")) // a previous incarnation's identity
		hr, err := warmSwapHandler{}.Enact(ctx, EnactCtx{Client: c, VLLM: &mockVLLM{loaded: true}}, req)
		if err != nil || hr.Emitted || !strings.Contains(hr.Note, reasonTargetUIDMismatch) {
			t.Fatalf("stale request identity must be refused untouched: %+v %v", hr, err)
		}
		if l := m069Live(t, c, ns, "leader"); l.UID != leader.UID || l.Labels[labelRole] != roleLeader || !l.DeletionTimestamp.IsZero() {
			t.Errorf("refused move must not touch the live pod: %v %v", l.Labels, l.DeletionTimestamp)
		}
		if s := m069Live(t, c, ns, "shadow"); s.Labels[labelRole] != roleShadow {
			t.Errorf("refused move must not promote the shadow: %v", s.Labels)
		}
	})

	t.Run("mig-rebind", func(t *testing.T) {
		ns := m069Namespace(t, c, "m069-mig")
		pod := m069Create(t, c, migPod(ns, "infer"))
		wc, r := m069Wrap(t, c, "infer")
		mm := &mockMIG{}
		hr, err := migRebindHandler{}.Enact(ctx, EnactCtx{Client: wc, MIG: mm, VLLM: &mockVLLM{}}, boundReq(pod, model.ActionMIGRebind))
		m069Rejected(t, hr, err)
		m069Survived(t, c, r)
		if len(mm.calls) != 0 {
			t.Fatalf("Repartition must not run after the rejected eviction: %v", mm.calls)
		}
	})

	t.Run("mig-rebind-positive-control", func(t *testing.T) {
		ns := m069Namespace(t, c, "m069-mig-ok")
		pod := m069Create(t, c, migPod(ns, "infer"))
		mm := &mockMIG{}
		hr, err := migRebindHandler{}.Enact(ctx, EnactCtx{Client: c, MIG: mm, VLLM: &mockVLLM{}}, boundReq(pod, model.ActionMIGRebind))
		if err != nil || !hr.Emitted || len(mm.calls) != 1 {
			t.Fatalf("unchanged identity must evict and repartition: %+v %v calls=%v", hr, err, mm.calls)
		}
		m069Retired(t, c, ns, "infer", pod.UID)
	})

	t.Run("model-shard-replace-single", func(t *testing.T) {
		ns := m069Namespace(t, c, "m069-shard")
		leader := m069Create(t, c, aiPod(ns, "shard0", map[string]string{labelModelShard: "s", labelRole: roleLeader}))
		m069Create(t, c, aiPod(ns, "shard0b", map[string]string{labelModelShard: "s", labelRole: roleShadow, labelModelLoaded: "true"}))
		wc, r := m069Wrap(t, c, "shard0")
		hr, err := modelShardReplaceHandler{}.Enact(ctx, EnactCtx{Client: wc, VLLM: &mockVLLM{loaded: true}}, boundReq(leader, model.ActionModelShardReplace))
		m069Rejected(t, hr, err)
		m069Survived(t, c, r)
	})

	t.Run("model-shard-replace-group", func(t *testing.T) {
		ns := m069Namespace(t, c, "m069-group")
		l0 := m069Create(t, c, tpPod(ns, "l0", "g", "0", roleLeader, true, 2))
		l1 := m069Create(t, c, tpPod(ns, "l1", "g", "1", roleLeader, true, 2))
		for _, s := range []string{"s0", "s1"} {
			m069Create(t, c, tpPod(ns, s, "g", s[1:], roleShadow, true, 2))
		}
		wc, r := m069Wrap(t, c, "l1") // a non-trigger member is respawned under its name
		hr, err := modelShardReplaceHandler{}.Enact(ctx, EnactCtx{Client: wc, VLLM: &mockVLLM{loaded: true}}, boundReq(l0, model.ActionModelShardReplace))
		m069Rejected(t, hr, err)
		m069Survived(t, c, r)
		if !strings.Contains(err.Error(), "retired [l0]") || !strings.Contains(err.Error(), "NOT retired [l1]") {
			t.Errorf("group result must name the retired and not-retired members: %v", err)
		}
		m069Retired(t, c, ns, "l0", l0.UID) // the observed trigger, whose identity was unchanged
		if live := m069Live(t, c, ns, "l1"); live.UID == l1.UID {
			t.Errorf("fixture: l1 was not replaced")
		}
		for _, s := range []string{"s0", "s1"} {
			if p := m069Live(t, c, ns, s); p.Labels[labelRole] != roleLeader {
				t.Errorf("honest partial state: shadow %s was promoted, role=%q", s, p.Labels[labelRole])
			}
		}
	})

	t.Run("model-shard-replace-group-positive-control", func(t *testing.T) {
		ns := m069Namespace(t, c, "m069-group-ok")
		l0 := m069Create(t, c, tpPod(ns, "l0", "g", "0", roleLeader, true, 2))
		l1 := m069Create(t, c, tpPod(ns, "l1", "g", "1", roleLeader, true, 2))
		for _, s := range []string{"s0", "s1"} {
			m069Create(t, c, tpPod(ns, s, "g", s[1:], roleShadow, true, 2))
		}
		hr, err := modelShardReplaceHandler{}.Enact(ctx, EnactCtx{Client: c, VLLM: &mockVLLM{loaded: true}}, boundReq(l0, model.ActionModelShardReplace))
		if err != nil || !hr.Emitted || !strings.Contains(hr.Note, "(2 old leaders)") {
			t.Fatalf("unchanged group identities must retire coherently: %+v %v", hr, err)
		}
		m069Retired(t, c, ns, "l0", l0.UID)
		m069Retired(t, c, ns, "l1", l1.UID)
	})
}
