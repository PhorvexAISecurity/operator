package actuator

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

// API-server evidence only: envtest has neither a GC controller nor a CNI.
func TestM048APIServerLifecycle(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires envtest assets")
	}
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: qtnScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m048"}}
	if err = c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if err = c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}); err != nil {
		t.Fatal(err)
	}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionQuarantine)}}}}
	if err = c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	makePod := func(name string) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: name, Labels: map[string]string{"app": "x"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "fixture", Image: "unused:test"}}}}
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Run("long-pod-name", func(t *testing.T) {
		p := makePod(strings.Repeat("a", 253))
		r, err := m048Dispatch(c, p)
		if err != nil || !r.Emitted {
			t.Fatal(r, err)
		}
		np := m048GetPolicy(t, c, p)
		if np.OwnerReferences[0].Name != p.Name || len(np.Labels["phorvex.ai/quarantine-of"]) > 63 {
			t.Fatal("lost full target identity")
		}
	})
	t.Run("same-name-repair-idempotence-cleanup-isolation", func(t *testing.T) {
		p := makePod("reuse")
		r, err := m048Dispatch(c, p)
		if err != nil || !r.Emitted {
			t.Fatal(r, err)
		}
		oldPolicy := m048GetPolicy(t, c, p)
		if oldPolicy.UID == "" || oldPolicy.ResourceVersion == "" || oldPolicy.OwnerReferences[0].BlockOwnerDeletion != nil {
			t.Fatal("invalid server identity/owner", oldPolicy)
		}
		t.Logf("old PodUID=%s policy=%s policyUID=%s resourceVersion=%s", p.UID, oldPolicy.Name, oldPolicy.UID, oldPolicy.ResourceVersion)
		if err = c.Delete(ctx, p, client.GracePeriodSeconds(0)); err != nil {
			t.Fatal(err)
		}
		next := makePod(p.Name)
		r, err = m048Dispatch(c, next)
		if err != nil || !r.Emitted {
			t.Fatal(r, err)
		}
		np := m048GetPolicy(t, c, next)
		if np.UID == oldPolicy.UID || np.Name == oldPolicy.Name {
			t.Fatal("identity reused")
		}
		t.Logf("new PodUID=%s policy=%s policyUID=%s resourceVersion=%s", next.UID, np.Name, np.UID, np.ResourceVersion)
		np.Annotations = map[string]string{"keep": "yes"}
		np.Spec.PodSelector = metav1.LabelSelector{}
		np.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{}}
		m048Update(t, c, np)
		r, err = m048Dispatch(c, next)
		if err != nil || !r.Emitted {
			t.Fatal("repair", r, err)
		}
		repaired := m048GetPolicy(t, c, next)
		if repaired.Annotations["keep"] != "yes" {
			t.Fatal("metadata lost")
		}
		before := m048GetPod(t, c, next)
		r, err = m048Dispatch(c, next)
		if err != nil || r.Emitted || before.ResourceVersion != m048GetPod(t, c, next).ResourceVersion {
			t.Fatal("false fresh actuation", r, err)
		}
		// Actual apiserver rejects resourceVersion and UID precondition mismatches.
		stale := repaired.DeepCopy()
		repaired.Annotations["race"] = "keep"
		m048Update(t, c, repaired)
		if err = deleteQuarantinePolicy(ctx, EnactCtx{Client: c, Reader: c}, stale); !apierrors.IsConflict(err) {
			t.Fatal("stale version delete accepted", err)
		}
		wrong := repaired.DeepCopy()
		wrong.UID = oldPolicy.UID
		if err = deleteQuarantinePolicy(ctx, EnactCtx{Client: c, Reader: c}, wrong); !apierrors.IsConflict(err) {
			t.Fatal("wrong UID delete accepted", err)
		}
		if err = deleteQuarantinePolicy(ctx, EnactCtx{Client: c, Reader: c}, oldPolicy); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(repaired, m048GetPolicy(t, c, next)) {
			t.Fatal("old cleanup changed replacement")
		}
		t.Log("positive manual deletion control succeeded; both UID and resourceVersion negative controls conflicted; new policy survived")
	})
	t.Run("legacy-old-uid-fresh-target", func(t *testing.T) {
		p := makePod("legacy-reuse")
		old := p.DeepCopy()
		old.UID = "old-incarnation"
		legacy := quarantinePolicy(old)
		legacy.Name = "phorvex-quarantine-" + p.Name
		legacy.OwnerReferences = nil
		if err := c.Create(ctx, legacy); err != nil {
			t.Fatal(err)
		}
		before := legacy.DeepCopy()
		r, err := m048Dispatch(c, p)
		if err != nil || !r.Emitted || !strings.Contains(r.Note, "cleanup unresolved") {
			t.Fatal(r, err)
		}
		if err = verifyQuarantineTarget(ctx, EnactCtx{Client: c, Reader: c}, m048GetPod(t, c, p), m048GetPolicy(t, c, p)); err != nil {
			t.Fatal(err)
		}
		after := &networkingv1.NetworkPolicy{}
		if err = c.Get(ctx, client.ObjectKeyFromObject(legacy), after); err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("legacy changed", err)
		}
		t.Logf("legacy UID=%s retained selecting old-incarnation; canonical targets PodUID=%s; %s", legacy.UID, p.UID, r.Note)
	})
	t.Run("migration-checkpoint-retains-legacy-until-explicit-release", func(t *testing.T) {
		p := makePod("migration")
		if _, err := m048Dispatch(c, p); err != nil {
			t.Fatal(err)
		}
		got := m048GetPod(t, c, p)
		s := m048Snapshot(t, got)
		canonical := m048GetPolicy(t, c, p)
		legacy := quarantinePolicy(p)
		legacy.Name = "phorvex-quarantine-" + p.Name
		legacy.OwnerReferences = nil
		if err := c.Create(ctx, legacy); err != nil {
			t.Fatal(err)
		}
		if err := c.Delete(ctx, canonical); err != nil {
			t.Fatal(err)
		}
		s.Version, s.PolicyName, s.PolicyUID = 2, legacy.Name, legacy.UID
		m048PutSnapshot(t, c, got, s)
		r, err := m048Dispatch(c, p)
		if err != nil || !r.Emitted || !strings.Contains(r.Note, "retained") {
			t.Fatal(r, err)
		}
		progress := m048Snapshot(t, m048GetPod(t, c, p))
		if progress.Version != 3 || progress.LegacyUID != legacy.UID || progress.PolicyUID == "" {
			t.Fatal("checkpoint absent", progress)
		}
		t.Logf("durable canonicalUID=%s legacyUID=%s; retry retains unproven legacy", progress.PolicyUID, progress.LegacyUID)
		if err := verifyQuarantineTarget(ctx, EnactCtx{Client: c, Reader: c}, m048GetPod(t, c, p), m048GetPolicy(t, c, p)); err != nil {
			t.Fatal(err)
		}
		r, err = m048Dispatch(c, p)
		if err != nil || r.Emitted {
			t.Fatal(r, err)
		}
		if err = c.Get(ctx, client.ObjectKeyFromObject(legacy), &networkingv1.NetworkPolicy{}); err != nil {
			t.Fatal("retry deleted legacy without administrative authority", err)
		}
		if err = (quarantineHandler{}).Rollback(ctx, EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, Request{Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID)}, r.RollbackRef); err != nil {
			t.Fatal(err)
		}
		if err = c.Get(ctx, client.ObjectKeyFromObject(legacy), &networkingv1.NetworkPolicy{}); !apierrors.IsNotFound(err) {
			t.Fatal("explicit rollback did not finish historical cleanup", err)
		}
	})
	t.Run("in-flight-release-conflicts-repair", func(t *testing.T) {
		p := makePod("release")
		r, err := m048Dispatch(c, p)
		if err != nil {
			t.Fatal(err)
		}
		np := m048GetPolicy(t, c, p)
		np.Spec.PodSelector = metav1.LabelSelector{}
		m048Update(t, c, np)
		raced := false
		wrapped := interceptor.NewClient(c, interceptor.Funcs{Update: func(ctx context.Context, base client.WithWatch, o client.Object, opts ...client.UpdateOption) error {
			if _, ok := o.(*networkingv1.NetworkPolicy); ok && !raced {
				raced = true
				if err := (quarantineHandler{}).Rollback(ctx, EnactCtx{Client: c, Reader: c}, Request{Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID)}, r.RollbackRef); err != nil {
					t.Fatal(err)
				}
			}
			return base.Update(ctx, o, opts...)
		}})
		result, err := m048Dispatch(wrapped, p)
		if err == nil || !raced {
			t.Fatal("stale repair succeeded", result, err)
		}
		if m048GetPod(t, c, p).Labels[quarantineLabel] != "" {
			t.Fatal("release overwritten")
		}
		if err = c.Get(ctx, client.ObjectKeyFromObject(np), &networkingv1.NetworkPolicy{}); !apierrors.IsNotFound(err) {
			t.Fatal("released policy recreated", err)
		}
	})
	t.Run("replacement-between-read-and-update-is-not-adopted", func(t *testing.T) {
		p := makePod("policy-replace")
		if _, err := m048Dispatch(c, p); err != nil {
			t.Fatal(err)
		}
		np := m048GetPolicy(t, c, p)
		np.Spec.PodSelector = metav1.LabelSelector{}
		m048Update(t, c, np)
		raced := false
		wrapped := interceptor.NewClient(c, interceptor.Funcs{Update: func(ctx context.Context, base client.WithWatch, o client.Object, opts ...client.UpdateOption) error {
			if _, ok := o.(*networkingv1.NetworkPolicy); ok && !raced {
				raced = true
				if err := c.Delete(ctx, np); err != nil {
					t.Fatal(err)
				}
				foreign := quarantinePolicy(p)
				foreign.OwnerReferences = nil
				if err := c.Create(ctx, foreign); err != nil {
					t.Fatal(err)
				}
			}
			return base.Update(ctx, o, opts...)
		}})
		result, err := m048Dispatch(wrapped, p)
		if err == nil {
			t.Fatal("adopted replacement", result)
		}
		got := m048GetPolicy(t, c, p)
		if got.UID == np.UID || len(got.OwnerReferences) != 0 {
			t.Fatal("replacement changed")
		}
	})
}
