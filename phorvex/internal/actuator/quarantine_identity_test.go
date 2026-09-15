package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

func m048Pod() *corev1.Pod {
	return ownedPod("ns", "same", map[string]string{"app": "x"}, metav1.OwnerReference{})
}
func m048Dispatch(c client.Client, p *corev1.Pod) (Result, error) {
	ctx := context.Background()
	pol := &v1alpha1.PhorvexPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: "policy"}, pol); err != nil {
		return Result{}, err
	}
	return dispatch(ctx, EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, Request{Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID), Action: "quarantine", PolicyName: pol.Name, PolicyUID: string(pol.UID)})
}
func m048GetPod(t *testing.T, c client.Client, p *corev1.Pod) *corev1.Pod {
	t.Helper()
	got := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(p), got); err != nil {
		t.Fatal(err)
	}
	return got
}
func m048GetPolicy(t *testing.T, c client.Client, p *corev1.Pod) *networkingv1.NetworkPolicy {
	t.Helper()
	got := &networkingv1.NetworkPolicy{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(quarantinePolicy(p)), got); err != nil {
		t.Fatal(err)
	}
	return got
}
func m048Update(t *testing.T, c client.Client, o client.Object) {
	t.Helper()
	if err := c.Update(context.Background(), o); err != nil {
		t.Fatal(err)
	}
}
func m048Snapshot(t *testing.T, p *corev1.Pod) qtnSnapshot {
	t.Helper()
	var s qtnSnapshot
	if err := json.Unmarshal([]byte(p.Annotations[quarantineSnapAnno]), &s); err != nil {
		t.Fatal(err)
	}
	return s
}
func m048PutSnapshot(t *testing.T, c client.Client, p *corev1.Pod, s qtnSnapshot) {
	t.Helper()
	b, _ := json.Marshal(s)
	p.Annotations = ensureMap(p.Annotations)
	p.Annotations[quarantineSnapAnno] = string(b)
	m048Update(t, c, p)
}

func TestM048IdentityNames(t *testing.T) {
	p := m048Pod()
	p.UID = types.UID(strings.Repeat("UID/Long!", 100))
	n := quarantinePolicy(p).Name
	if len(validation.IsDNS1123Subdomain(n)) != 0 || len(n) > 253 || n != quarantinePolicy(p).Name {
		t.Fatal(n)
	}
	p.UID += "x"
	if n == quarantinePolicy(p).Name {
		t.Fatal("identity collision")
	}
}
func TestM048RetryRepairsPolicyAndLabel(t *testing.T) {
	for _, mode := range []string{"correct", "spec", "missing", "owner-absent", "label-absent", "label-stale"} {
		t.Run(mode, func(t *testing.T) {
			p := m048Pod()
			c := qtnClient(p)
			r, err := m048Dispatch(c, p)
			if err != nil || !r.Emitted {
				t.Fatal(r, err)
			}
			before := m048GetPod(t, c, p)
			epoch := before.Labels[quarantineEpochLabel]
			snapshot := m048Snapshot(t, before)
			np := m048GetPolicy(t, c, p)
			np.Annotations = map[string]string{"unrelated": "keep"}
			m048Update(t, c, np)
			switch mode {
			case "spec":
				np.Spec.PodSelector = metav1.LabelSelector{}
				np.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
				np.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{}}
				m048Update(t, c, np)
			case "missing":
				if err = c.Delete(context.Background(), np); err != nil {
					t.Fatal(err)
				}
			case "owner-absent":
				np.OwnerReferences = nil
				m048Update(t, c, np)
			case "label-absent":
				delete(before.Labels, quarantineLabel)
				m048Update(t, c, before)
			case "label-stale":
				before.Labels[quarantineLabel] = "stale"
				m048Update(t, c, before)
			}
			r, err = m048Dispatch(c, p)
			if err != nil || r.Emitted != (mode != "correct") {
				t.Fatal(r, err)
			}
			after := m048GetPod(t, c, p)
			np = m048GetPolicy(t, c, p)
			if after.Labels[quarantineEpochLabel] != epoch || !reflect.DeepEqual(snapshot.Before, m048Snapshot(t, after).Before) {
				t.Fatal("retry changed detach baseline/epoch")
			}
			if err = verifyQuarantineTarget(context.Background(), EnactCtx{Client: c, Reader: c}, after, np); err != nil {
				t.Fatal(err)
			}
			if mode != "missing" && np.Annotations["unrelated"] != "keep" {
				t.Fatal("metadata lost")
			}
			r, err = m048Dispatch(c, p)
			if err != nil || r.Emitted {
				t.Fatal("not idempotent", r, err)
			}
		})
	}
}
func TestM048ForeignPoliciesUntouched(t *testing.T) {
	for _, mode := range []string{"forged-label", "foreign-owner", "shared", "wrong-management", "wrong-target", "deleting"} {
		t.Run(mode, func(t *testing.T) {
			p := m048Pod()
			np := quarantinePolicy(p)
			switch mode {
			case "forged-label":
				np.OwnerReferences = nil
			case "foreign-owner":
				np.OwnerReferences[0].UID = "foreign"
			case "shared":
				np.OwnerReferences = append(np.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "Pod", Name: "other", UID: "other"})
			case "wrong-management":
				np.Labels["app.kubernetes.io/managed-by"] = "customer"
			case "wrong-target":
				np.Labels["phorvex.ai/quarantine-of"] = "other"
			case "deleting":
				now := metav1.Now()
				np.DeletionTimestamp = &now
				np.Finalizers = []string{"fixture"}
			}
			c := qtnClient(p, np)
			before := m048GetPolicy(t, c, p)
			r, err := m048Dispatch(c, p)
			if err == nil || r.Emitted {
				t.Fatal("collision accepted", r, err)
			}
			if !reflect.DeepEqual(before, m048GetPolicy(t, c, p)) {
				t.Fatal("foreign object changed")
			}
			if m048GetPod(t, c, p).Labels[quarantineLabel] != "" {
				t.Fatal("detached on collision")
			}
		})
	}
}
func TestM048CopiedLabelAndAmbiguousSnapshotRefused(t *testing.T) {
	for _, mode := range []string{"copied", "marker", "empty-policy-uid", "missing-applied"} {
		t.Run(mode, func(t *testing.T) {
			p := m048Pod()
			c := qtnClient(p)
			if mode == "copied" {
				other := m048Pod()
				other.Name = "other"
				other.ResourceVersion = ""
				other.UID = "other"
				other.Labels[quarantineLabel] = string(p.UID)
				if err := c.Create(context.Background(), other); err != nil {
					t.Fatal(err)
				}
			} else {
				if mode != "marker" {
					if _, err := m048Dispatch(c, p); err != nil {
						t.Fatal(err)
					}
				}
				got := m048GetPod(t, c, p)
				got.Labels[quarantineLabel] = string(p.UID)
				if mode == "marker" {
					m048Update(t, c, got)
				} else {
					s := m048Snapshot(t, got)
					if mode == "empty-policy-uid" {
						s.PolicyUID = ""
					} else {
						s.Applied = nil
					}
					m048PutSnapshot(t, c, got, s)
				}
			}
			r, err := m048Dispatch(c, p)
			if err == nil || r.Emitted {
				t.Fatal(r, err)
			}
		})
	}
}
func TestM048PolicyRacesAndPartialResults(t *testing.T) {
	for _, mode := range []string{"alreadyexists-owned", "alreadyexists-foreign", "create-denied", "create-response-lost", "readback-lost", "pod-replaced", "update-conflict", "read-denied"} {
		t.Run(mode, func(t *testing.T) {
			p := m048Pod()
			base := qtnClient(p)
			created := false
			if mode == "update-conflict" {
				np := quarantinePolicy(p)
				np.Spec.PodSelector = metav1.LabelSelector{}
				if err := base.Create(context.Background(), np); err != nil {
					t.Fatal(err)
				}
			}
			c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
					if _, ok := o.(*networkingv1.NetworkPolicy); !ok {
						return c.Create(ctx, o, opts...)
					}
					if mode == "create-denied" {
						return apierrors.NewForbidden(schema.GroupResource{Resource: "networkpolicies"}, o.GetName(), errors.New("denied"))
					}
					if mode == "alreadyexists-foreign" {
						o.SetOwnerReferences(nil)
					}
					if err := c.Create(ctx, o, opts...); err != nil {
						return err
					}
					created = true
					if mode == "alreadyexists-owned" || mode == "alreadyexists-foreign" {
						return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "networkpolicies"}, o.GetName())
					}
					if mode == "create-response-lost" {
						return errors.New("response lost")
					}
					if mode == "pod-replaced" {
						old := m048GetPod(t, base, p)
						if err := base.Delete(ctx, old); err != nil {
							t.Fatal(err)
						}
						next := p.DeepCopy()
						next.ResourceVersion = ""
						next.UID = "replacement"
						if err := base.Create(ctx, next); err != nil {
							t.Fatal(err)
						}
					}
					return nil
				},
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, o client.Object, opts ...client.GetOption) error {
					if _, ok := o.(*networkingv1.NetworkPolicy); ok && ((mode == "readback-lost" && created) || mode == "read-denied") {
						return errors.New("read denied")
					}
					return c.Get(ctx, key, o, opts...)
				},
				Update: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.UpdateOption) error {
					if _, ok := o.(*networkingv1.NetworkPolicy); ok && mode == "update-conflict" {
						return apierrors.NewConflict(schema.GroupResource{Resource: "networkpolicies"}, o.GetName(), errors.New("race"))
					}
					return c.Update(ctx, o, opts...)
				},
			})
			r, err := m048Dispatch(c, p)
			if mode == "alreadyexists-owned" {
				if err != nil || !r.Emitted {
					t.Fatal(r, err)
				}
				return
			}
			if err == nil {
				t.Fatal("race/failure accepted", r)
			}
			if (mode == "readback-lost" || mode == "pod-replaced") && !r.Emitted {
				t.Fatal("accepted policy lost", r, err)
			}
			if mode == "create-response-lost" && !strings.Contains(r.Note, "unknown") {
				t.Fatal("uncertainty lost", r)
			}
			if m048GetPod(t, base, p).Labels[quarantineLabel] != "" {
				t.Fatal("detached after failure")
			}
		})
	}
}

// Construct the exact v2 installed shape, with a real recorded policy identity.
func m048Legacy(t *testing.T) (client.Client, *corev1.Pod, qtnSnapshot) {
	t.Helper()
	p := m048Pod()
	c := qtnClient(p)
	if _, err := m048Dispatch(c, p); err != nil {
		t.Fatal(err)
	}
	got := m048GetPod(t, c, p)
	s := m048Snapshot(t, got)
	canonical := m048GetPolicy(t, c, p)
	legacy := canonical.DeepCopy()
	legacy.Name = "phorvex-quarantine-" + p.Name
	legacy.UID = ""
	legacy.ResourceVersion = ""
	legacy.OwnerReferences = nil
	if err := c.Create(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), canonical); err != nil {
		t.Fatal(err)
	}
	s.Version, s.PolicyName, s.PolicyUID = 2, legacy.Name, legacy.UID
	m048PutSnapshot(t, c, got, s)
	return c, p, s
}
func TestM048MigrationCrashRetryAndRelease(t *testing.T) {
	// Retry establishes canonical isolation but retains legacy policy inventory.
	// Only explicit rollback performs the historical UID-checked cleanup.
	for _, mode := range []string{"normal", "checkpoint-failed", "rollback-before-checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			base, p, original := m048Legacy(t)
			fail := true
			c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
				Update: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.UpdateOption) error {
					if _, ok := o.(*corev1.Pod); ok && fail && (mode == "checkpoint-failed" || mode == "rollback-before-checkpoint") {
						return errors.New("checkpoint failed")
					}
					return c.Update(ctx, o, opts...)
				},
			})
			r, err := m048Dispatch(c, p)
			if mode == "normal" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !r.Emitted {
				t.Fatal("partial migration lost", r, err)
			}
			canonical := m048GetPolicy(t, base, p)
			if err = verifyQuarantinePolicy(canonical, quarantinePolicy(p)); err != nil {
				t.Fatal(err)
			}
			if mode == "checkpoint-failed" || mode == "rollback-before-checkpoint" {
				var legacy networkingv1.NetworkPolicy
				if err = base.Get(context.Background(), client.ObjectKey{Namespace: p.Namespace, Name: original.PolicyName}, &legacy); err != nil {
					t.Fatal("protection retired before checkpoint")
				}
			}
			fail = false
			if mode != "rollback-before-checkpoint" {
				r, err = m048Dispatch(c, p)
				if err != nil {
					t.Fatal(r, err)
				}
				got := m048GetPod(t, base, p)
				s := m048Snapshot(t, got)
				if s.Version != 3 || s.LegacyUID != original.PolicyUID || !reflect.DeepEqual(s.Before, original.Before) {
					t.Fatal("migration lost baseline", s)
				}
				var legacy networkingv1.NetworkPolicy
				if err = base.Get(context.Background(), client.ObjectKey{Namespace: p.Namespace, Name: original.PolicyName}, &legacy); err != nil || legacy.UID != original.PolicyUID {
					t.Fatal("retry adopted or deleted unproven legacy policy", err)
				}
			}
			err = (quarantineHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, Request{Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID)}, p.Namespace+"/"+p.Name+"@"+string(p.UID))
			if err != nil {
				t.Fatal(err)
			}
			got := m048GetPod(t, base, p)
			if got.Annotations[quarantineSnapAnno] != "" || got.Labels[quarantineLabel] != "" {
				t.Fatal("release incomplete")
			}
			var list networkingv1.NetworkPolicyList
			_ = base.List(context.Background(), &list)
			if len(list.Items) != 0 {
				t.Fatal("cleanup missed recorded policies", list.Items)
			}
		})
	}
}
func TestM048LegacyIdentityRefusals(t *testing.T) {
	for _, mode := range []string{"uid", "owner", "selector", "management"} {
		t.Run(mode, func(t *testing.T) {
			c, p, s := m048Legacy(t)
			var np networkingv1.NetworkPolicy
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: p.Namespace, Name: s.PolicyName}, &np); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "uid":
				got := m048GetPod(t, c, p)
				s.PolicyUID = "wrong"
				m048PutSnapshot(t, c, got, s)
			case "owner":
				np.OwnerReferences = quarantinePolicy(p).OwnerReferences
				m048Update(t, c, &np)
			case "selector":
				np.Spec.PodSelector = metav1.LabelSelector{}
				m048Update(t, c, &np)
			case "management":
				np.Labels["app.kubernetes.io/managed-by"] = "foreign"
				m048Update(t, c, &np)
			}
			legacyBefore := &networkingv1.NetworkPolicy{}
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: p.Namespace, Name: s.PolicyName}, legacyBefore); err != nil {
				t.Fatal(err)
			}
			r, err := m048Dispatch(c, p)
			if err != nil || !r.Emitted || !strings.Contains(r.Note, "retained") {
				t.Fatal("authorized canonical retry lost legacy refusal boundary", r, err)
			}
			legacyAfter := &networkingv1.NetworkPolicy{}
			if err := c.Get(context.Background(), client.ObjectKey{Namespace: p.Namespace, Name: s.PolicyName}, legacyAfter); err != nil || !reflect.DeepEqual(legacyBefore, legacyAfter) {
				t.Fatal("retry changed unproven legacy policy", err)
			}
			if err := (quarantineHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, Request{Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID)}, r.RollbackRef); err == nil {
				t.Fatal("explicit historical cleanup accepted altered legacy identity")
			}
			var list networkingv1.NetworkPolicyList
			_ = c.List(context.Background(), &list)
			if len(list.Items) != 2 {
				t.Fatal("retry failed canonical isolation or deleted legacy", list.Items)
			}
		})
	}
}
func TestM048RollbackPreconditionsAndRetry(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "canonical", true: "legacy"}[legacy], func(t *testing.T) {
			p := m048Pod()
			base := qtnClient(p)
			if legacy {
				base, p, _ = m048Legacy(t)
			} else if _, err := m048Dispatch(base, p); err != nil {
				t.Fatal(err)
			}
			fail := true
			deletes := 0
			c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.DeleteOption) error {
				if _, ok := o.(*corev1.ConfigMap); ok {
					return c.Delete(ctx, o, opts...)
				}
				options := &client.DeleteOptions{}
				for _, opt := range opts {
					opt.ApplyToDelete(options)
				}
				if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != o.GetUID() || options.Preconditions.ResourceVersion == nil || *options.Preconditions.ResourceVersion != o.GetResourceVersion() {
					t.Fatal("unsafe delete", options)
				}
				deletes++
				if fail {
					return errors.New("delete denied")
				}
				return c.Delete(ctx, o, opts...)
			}})
			req := Request{Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID)}
			ref := p.Namespace + "/" + p.Name + "@" + string(p.UID)
			if err := (quarantineHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, req, ref); err == nil {
				t.Fatal("ignored deletion failure")
			}
			got := m048GetPod(t, base, p)
			if !m048Snapshot(t, got).Released || got.Labels[quarantineLabel] != "" {
				t.Fatal("lost release progress")
			}
			if _, err := m048Dispatch(c, p); err == nil {
				t.Fatal("new quarantine bypassed pending cleanup")
			}
			fail = false
			if err := (quarantineHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, req, ref); err != nil {
				t.Fatal(err)
			}
			if deletes != 2 || m048GetPod(t, base, p).Annotations[quarantineSnapAnno] != "" {
				t.Fatal("cleanup not resumed")
			}
		})
	}
}
func TestM048OldRollbackCannotReleaseReplacement(t *testing.T) {
	p := m048Pod()
	c := qtnClient(p)
	r, err := m048Dispatch(c, p)
	if err != nil {
		t.Fatal(err)
	}
	old := m048GetPod(t, c, p)
	if err = c.Delete(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := p.DeepCopy()
	next.UID = "new"
	next.ResourceVersion = ""
	if err = c.Create(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if _, err = m048Dispatch(c, next); err != nil {
		t.Fatal(err)
	}
	before := m048GetPolicy(t, c, next)
	if err = (quarantineHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, Request{Namespace: p.Namespace, Pod: p.Name}, r.RollbackRef); err == nil {
		t.Fatal("old release authorized replacement")
	}
	if !reflect.DeepEqual(before, m048GetPolicy(t, c, next)) {
		t.Fatal("replacement policy changed")
	}
}

func TestM048AcceptedPodWriteReadbackFailure(t *testing.T) {
	p := m048Pod()
	base := qtnClient(p)
	updated := false
	c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.UpdateOption) error {
			err := c.Update(ctx, o, opts...)
			if _, ok := o.(*corev1.Pod); ok && err == nil {
				updated = true
			}
			return err
		},
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, o client.Object, opts ...client.GetOption) error {
			if _, ok := o.(*corev1.Pod); ok && updated {
				return errors.New("Pod readback unavailable")
			}
			return c.Get(ctx, key, o, opts...)
		},
	})
	r, err := m048Dispatch(c, p)
	if err == nil || !r.Emitted || len(r.ObjectsTouched) != 2 || !strings.Contains(r.Note, "partial") {
		t.Fatal("accepted writes lost", r, err)
	}
	if m048GetPod(t, base, p).Labels[quarantineLabel] != string(p.UID) {
		t.Fatal("positive accepted-write control missing")
	}
	r, err = m048Dispatch(base, p)
	if err != nil || r.Emitted {
		t.Fatal("retry duplicated accepted write", r, err)
	}
}
func TestM048RetryRefusesCopiedLabelsAndDetachDrift(t *testing.T) {
	for _, mode := range []string{"copied", "detach-label", "owner"} {
		t.Run(mode, func(t *testing.T) {
			p := m048Pod()
			svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: "front"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "x"}}}
			c := qtnClient(p, svc)
			if _, err := m048Dispatch(c, p); err != nil {
				t.Fatal(err)
			}
			got := m048GetPod(t, c, p)
			switch mode {
			case "copied":
				other := p.DeepCopy()
				other.Name = "copy"
				other.UID = "copied-uid"
				other.ResourceVersion = ""
				other.Labels[quarantineLabel] = string(p.UID)
				if err := c.Create(context.Background(), other); err != nil {
					t.Fatal(err)
				}
			case "detach-label":
				got.Labels["app"] = "manual"
				m048Update(t, c, got)
			case "owner":
				got.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "manual", UID: "manual"}}
				m048Update(t, c, got)
			}
			before := m048GetPolicy(t, c, p)
			r, err := m048Dispatch(c, p)
			if err == nil || r.Emitted {
				t.Fatal("unsafe retry accepted", r, err)
			}
			if !reflect.DeepEqual(before, m048GetPolicy(t, c, p)) {
				t.Fatal("policy changed on refusal")
			}
		})
	}
}

func TestM048FreshTargetCoexistsWithUnprovenLegacy(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign", true: "historical-managed"}[managed], func(t *testing.T) {
			p := m048Pod()
			p.UID = "new-uid"
			old := p.DeepCopy()
			old.UID = "old-uid"
			legacy := quarantinePolicy(old)
			legacy.Name = "phorvex-quarantine-" + p.Name
			legacy.OwnerReferences = nil
			if !managed {
				legacy.Labels["app.kubernetes.io/managed-by"] = "customer"
			}
			c := qtnClient(p, legacy)
			before := &networkingv1.NetworkPolicy{}
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(legacy), before); err != nil {
				t.Fatal(err)
			}
			r, err := m048Dispatch(c, p)
			if err != nil || !r.Emitted || !strings.Contains(r.Note, "cleanup unresolved") {
				t.Fatal(r, err)
			}
			if err = verifyQuarantineTarget(context.Background(), EnactCtx{Client: c, Reader: c}, m048GetPod(t, c, p), m048GetPolicy(t, c, p)); err != nil {
				t.Fatal(err)
			}
			r, err = m048Dispatch(c, p)
			if err != nil || r.Emitted || !strings.Contains(r.Note, "cleanup unresolved") {
				t.Fatal("retry lost legacy disposition", r, err)
			}
			if err = (quarantineHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, Request{Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID)}, r.RollbackRef); err != nil {
				t.Fatal(err)
			}
			after := &networkingv1.NetworkPolicy{}
			if err = c.Get(context.Background(), client.ObjectKeyFromObject(legacy), after); err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("adopted/deleted/retargeted old policy", err)
			}
		})
	}
}
