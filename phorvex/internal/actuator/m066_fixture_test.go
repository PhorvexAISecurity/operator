package actuator

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"testing"
)

// m066FakePool configures a complete *synthetic* snapshot for authority and
// partial-failure unit tests. It cannot prove ReplicaSet reconciliation; the
// real local KCM test supplies that positive control.
func m066FakePool(old, next *corev1.Pod, groupKey string) []client.Object {
	group := old.Labels[groupKey]
	base := "m066-pool"
	for _, p := range []*corev1.Pod{old, next} {
		if p.Labels == nil {
			p.Labels = map[string]string{}
		}
		p.Labels["app"] = base
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		p.Annotations[annoRouteService] = "m066-serving"
	}
	count := int32(2)
	templateSpec := *old.Spec.DeepCopy()
	templateSpec.NodeName = ""
	templateSpec.EphemeralContainers = nil
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "m066-rs", Namespace: old.Namespace, UID: types.UID("m066-rs-uid"), ResourceVersion: "8", Generation: 1}, Spec: appsv1.ReplicaSetSpec{Replicas: &count, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": base, groupKey: group}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": base, groupKey: group, labelRole: roleShadow, labelModelLoaded: "false"}, Annotations: map[string]string{annoRouteService: "m066-serving"}}, Spec: templateSpec}}, Status: appsv1.ReplicaSetStatus{ObservedGeneration: 1, Replicas: 2}}
	for _, p := range []*corev1.Pod{old, next} {
		p.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "m066-serving", Namespace: old.Namespace, UID: types.UID("m066-service-uid"), ResourceVersion: "9"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": base, groupKey: group, labelRole: roleLeader}, Ports: []corev1.ServicePort{{Port: 8000}}}}
	return []client.Object{rs, svc}
}

func TestM066StableServingSpecDetectsWrongRuntimeAndVolumeSource(t *testing.T) {
	want := corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "test:unused", Command: []string{"serve"}, Args: []string{"--port=8000"}, Env: []corev1.EnvVar{{Name: "MODEL", Value: "v1"}}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m")}}, VolumeMounts: []corev1.VolumeMount{{Name: "weights", MountPath: "/weights"}}}}, InitContainers: []corev1.Container{{Name: "prepare", Image: "test:unused", Command: []string{"prepare"}}}, Volumes: []corev1.Volume{{Name: "weights", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "model-v1"}}}}}
	valid := *want.DeepCopy()
	valid.NodeName = "scheduled"
	valid.ServiceAccountName = "default"
	valid.Volumes = append(valid.Volumes, corev1.Volume{Name: "kube-api-access-test", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}}}}})
	valid.Containers[0].VolumeMounts = append(valid.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "kube-api-access-test", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true})
	if err := warmPoolStableSpec(want, valid); err != nil {
		t.Fatalf("ordinary API default/projection refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*corev1.PodSpec)
	}{
		{"command", func(p *corev1.PodSpec) { p.Containers[0].Command = []string{"sleep"} }},
		{"args", func(p *corev1.PodSpec) { p.Containers[0].Args = []string{"--port=9999"} }},
		{"env", func(p *corev1.PodSpec) { p.Containers[0].Env[0].Value = "v2" }},
		{"resources", func(p *corev1.PodSpec) {
			p.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("100m")
		}},
		{"volume-source", func(p *corev1.PodSpec) { p.Volumes[0].PersistentVolumeClaim.ClaimName = "wrong-pvc" }},
		{"mount", func(p *corev1.PodSpec) { p.Containers[0].VolumeMounts[0].MountPath = "/elsewhere" }},
		{"init", func(p *corev1.PodSpec) { p.InitContainers[0].Command = []string{"skip"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := *valid.DeepCopy()
			tc.change(&got)
			if err := warmPoolStableSpec(want, got); err == nil {
				t.Fatal("stable serving configuration drift accepted")
			}
		})
	}
}

func TestM066LegacyWarmReceiptNeverCreatesClone(t *testing.T) {
	for _, phase := range []string{"prepared", "retiring", "retired", "rewarm-intent", "rewarmed"} {
		t.Run(phase, func(t *testing.T) {
			old := aiPod("ns", "legacy-old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
			nextRole := roleShadow
			if phase != "prepared" {
				nextRole = roleLeader
			}
			next := aiPod("ns", "legacy-new", map[string]string{labelSwapGroup: "g", labelRole: nextRole, labelModelLoaded: "true"})
			r := operationReceipt{Version: 1, Kind: "warm-swap", Phase: phase, PolicyNamespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", TargetName: old.Name, TargetUID: string(old.UID), TargetLabels: copyLabels(old.Labels), OldName: old.Name, OldUID: string(old.UID), NewName: next.Name, NewUID: string(next.UID), GroupKey: labelSwapGroup, GroupValue: "g"}
			if phase == "rewarm-intent" || phase == "rewarmed" {
				r.RewarmName = "legacy-clone"
				r.RewarmSpecHash = "legacy-spec"
			}
			if phase == "rewarmed" {
				r.RewarmUID = "legacy-clone-uid"
			}
			if !r.valid() {
				t.Fatal("invalid fixture receipt")
			}
			b, _ := json.Marshal(r)
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: receiptName(r), UID: "cm-uid", ResourceVersion: "4", Labels: map[string]string{journalLabel: "v1"}}, Data: map[string]string{"receipt": string(b)}}
			pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{labelSwapGroup: "g"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap)}}}}
			base := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(old, next, cm, pol, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).Build()
			n := NewNativeActuator(base)
			n.Reader = base
			n.JournalNamespace = "operator"
			events, err := n.RecoverOperations(context.Background(), false)
			if err != nil || len(events) != 1 {
				t.Fatalf("legacy journal lost: events=%+v err=%v", events, err)
			}
			if phase == "prepared" {
				if events[0].Err != nil {
					t.Fatalf("safe unpromoted pair not finished: %+v", events[0])
				}
			} else if events[0].Err == nil {
				t.Fatalf("unsafe legacy phase certified: %+v", events[0])
			}
			var pods corev1.PodList
			if err := base.List(context.Background(), &pods, client.InNamespace("ns")); err != nil || len(pods.Items) != 2 {
				t.Fatalf("legacy recovery mutated/cloned pods: count=%d err=%v", len(pods.Items), err)
			}
		})
	}
}

func TestM066BareWarmPairRefusedBeforeMutation(t *testing.T) {
	old := aiPod("ns", "bare-old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	next := aiPod("ns", "bare-shadow", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{labelSwapGroup: "g"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap)}}}}
	base := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(old, next, pol,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).Build()
	result, err := (warmSwapHandler{}).Enact(context.Background(), EnactCtx{Client: base, Reader: base, JournalNamespace: "operator"}, boundReq(old, model.ActionWarmSwap))
	if err != nil || result.NoEffect != NoEffectRefused || result.Emitted {
		t.Fatalf("bare warm pair was not cleanly refused: result=%+v err=%v", result, err)
	}
	got := &corev1.Pod{}
	if e := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: old.Name}, got); e != nil || got.Labels[labelRole] != roleLeader {
		t.Fatalf("bare old changed: %v %+v", e, got)
	}
}

func TestM066PoolCaptureRejectsOwnershipAndRouteDrift(t *testing.T) {
	makePair := func() (*corev1.Pod, *corev1.Pod, []client.Object) {
		old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
		next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
		return old, next, m066FakePool(old, next, labelSwapGroup)
	}
	for _, tc := range []struct {
		name   string
		change func(*corev1.Pod, *corev1.Pod, []client.Object)
	}{
		{"valid", nil},
		{"different-controller-uid", func(_ *corev1.Pod, next *corev1.Pod, _ []client.Object) { next.OwnerReferences[0].UID = "other-rs" }},
		{"mutable-role-selector", func(_ *corev1.Pod, _ *corev1.Pod, objects []client.Object) {
			objects[0].(*appsv1.ReplicaSet).Spec.Selector.MatchLabels[labelRole] = roleLeader
		}},
		{"warm-route", func(_ *corev1.Pod, _ *corev1.Pod, objects []client.Object) {
			objects[1].(*corev1.Service).Spec.Selector[labelRole] = roleShadow
		}},
		{"missing-owner", func(_ *corev1.Pod, next *corev1.Pod, _ []client.Object) { next.OwnerReferences = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old, next, objects := makePair()
			if tc.change != nil {
				tc.change(old, next, objects)
			}
			all := append([]client.Object{old, next}, objects...)
			c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(all...).Build()
			_, err := warmPoolCapture(context.Background(), c, old, next, labelSwapGroup, "g")
			if tc.change == nil && err != nil {
				t.Fatalf("valid pool refused: %v", err)
			}
			if tc.change != nil && err == nil {
				t.Fatal("drift accepted")
			}
		})
	}
}

func m066ValidV2Receipt(old, next *corev1.Pod, p warmPoolIntent) operationReceipt {
	return operationReceipt{Version: 2, Kind: "warm-swap", Phase: "prepared", PolicyNamespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", TargetName: old.Name, TargetUID: string(old.UID), OldName: old.Name, OldUID: string(old.UID), NewName: next.Name, NewUID: string(next.UID), GroupKey: labelSwapGroup, GroupValue: "g", Pool: &p}
}

func TestM066V2ReceiptRejectsAmbiguousIdentity(t *testing.T) {
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow})
	p := warmPoolIntent{RSName: "rs", RSUID: "rsuid", RSGeneration: 1, Desired: 2, RSTemplateHash: "t", RSSelectorHash: "s", ServiceName: "svc", ServiceUID: "suid", ServiceSelectorHash: "ss", Members: []string{string(old.UID), string(next.UID)}}
	base := m066ValidV2Receipt(old, next, p)
	if !base.valid() {
		t.Fatal("valid v2 prepared receipt refused")
	}
	for _, tc := range []struct {
		name   string
		change func(*operationReceipt)
	}{
		{"same-name", func(r *operationReceipt) { r.NewName = r.OldName }},
		{"duplicate-member", func(r *operationReceipt) { r.Pool.Members[1] = r.Pool.Members[0] }},
		{"empty-member", func(r *operationReceipt) { r.Pool.Members[1] = "" }},
		{"missing-old", func(r *operationReceipt) { r.Pool.Members[0] = "other" }},
		{"prepared-half-name", func(r *operationReceipt) { r.RewarmName = "new-member" }},
		{"prepared-half-uid", func(r *operationReceipt) { r.RewarmUID = "new-uid" }},
		{"observed-half", func(r *operationReceipt) { r.Phase = "pool-observed"; r.RewarmName = "new-member" }},
		{"observed-reuses-old", func(r *operationReceipt) {
			r.Phase = "pool-observed"
			r.RewarmName = "new-member"
			r.RewarmUID = r.OldUID
		}},
		{"observed-reuses-name", func(r *operationReceipt) {
			r.Phase = "pool-observed"
			r.RewarmName = r.NewName
			r.RewarmUID = "brand-new"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.Pool = &warmPoolIntent{}
			*r.Pool = *base.Pool
			r.Pool.Members = append([]string(nil), base.Pool.Members...)
			tc.change(&r)
			if r.valid() {
				t.Fatal("ambiguous v2 receipt accepted")
			}
		})
	}
	ok := base
	ok.Phase = "pool-observed"
	ok.RewarmName = "controller-new"
	ok.RewarmUID = "controller-new-uid"
	if !ok.valid() {
		t.Fatal("valid v2 observed receipt refused")
	}
}

func TestM066RecordedPoolRecheckRejectsGenerationAndFullRouteDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]client.Object)
	}{
		{"positive", nil},
		{"generation", func(o []client.Object) { o[0].(*appsv1.ReplicaSet).Generation++ }},
		{"service-extra-label", func(o []client.Object) { o[1].(*corev1.Service).Spec.Selector["track"] = "required" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
			next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
			objects := m066FakePool(old, next, labelSwapGroup)
			pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m066-pool"}}}}
			all := append([]client.Object{old, next, pol}, objects...)
			c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(all...).Build()
			intent, err := warmPoolCapture(context.Background(), c, old, next, labelSwapGroup, "g")
			if err != nil {
				t.Fatal(err)
			}
			r := m066ValidV2Receipt(old, next, intent)
			if tc.change != nil {
				tc.change(objects)
				for _, o := range objects {
					if err := c.Update(context.Background(), o); err != nil {
						t.Fatal(err)
					}
				}
			}
			err = warmPoolRecheck(context.Background(), c, r, old, next)
			if tc.change == nil && err != nil {
				t.Fatalf("positive recheck refused: %v", err)
			}
			if tc.change != nil && err == nil {
				t.Fatal("recorded contract drift accepted")
			}
		})
	}
}

func TestM066PostDeleteObservationRequiresExactReplacementShape(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		oldPresent, survivorPresent bool
		newCount                    int
		wantOK                      bool
	}{
		{"positive", false, true, 1, true},
		{"old-uid-still-present", true, true, 0, false},
		{"missing-survivor", false, false, 2, false},
		{"multiple-new-uids", false, true, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
			next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow, labelModelLoaded: "true"})
			objects := m066FakePool(old, next, labelSwapGroup)
			pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m066-pool"}}}}
			captureObjects := append([]client.Object{old, next, pol}, objects...)
			capture := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(captureObjects...).Build()
			intent, err := warmPoolCapture(context.Background(), capture, old, next, labelSwapGroup, "g")
			if err != nil {
				t.Fatal(err)
			}
			r := m066ValidV2Receipt(old, next, intent)
			r.Phase = "retired-awaiting-controller"
			live := append([]client.Object{pol}, objects...)
			if tc.oldPresent {
				live = append(live, old)
			}
			if tc.survivorPresent {
				live = append(live, next)
			}
			for i := 0; i < tc.newCount; i++ {
				p := next.DeepCopy()
				p.Name = fmt.Sprintf("controller-new-%d", i)
				p.UID = types.UID(fmt.Sprintf("controller-new-uid-%d", i))
				p.ResourceVersion = "10"
				p.Labels[labelModelLoaded] = "false"
				live = append(live, p)
			}
			c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(live...).Build()
			candidate, err := warmPoolObserve(context.Background(), c, r)
			if tc.wantOK && (err != nil || candidate == nil || string(candidate.UID) != "controller-new-uid-0") {
				t.Fatalf("positive observation refused: candidate=%+v err=%v", candidate, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("ambiguous postdelete inventory accepted: %+v", candidate)
			}
		})
	}
}

func TestM066MembershipListRejectsPaginationAndOverflow(t *testing.T) {
	sel := labels.SelectorFromSet(map[string]string{"app": "pool"})
	base := fake.NewClientBuilder().WithScheme(p4bScheme()).Build()
	paged := fake.NewClientBuilder().WithScheme(p4bScheme()).WithInterceptorFuncs(interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if err := c.List(ctx, list, opts...); err != nil {
			return err
		}
		list.(*corev1.PodList).Continue = "next-page"
		return nil
	}}).Build()
	if _, err := warmPoolListMembers(context.Background(), paged, "ns", sel); err == nil {
		t.Fatal("paginated inventory accepted")
	}
	objects := make([]client.Object, 0, warmPoolMaxMembers+1)
	for i := 0; i < warmPoolMaxMembers+1; i++ {
		objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: fmt.Sprintf("p-%03d", i), Labels: map[string]string{"app": "pool"}}})
	}
	overflow := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objects...).Build()
	if _, err := warmPoolListMembers(context.Background(), overflow, "ns", sel); err == nil {
		t.Fatal("overflow inventory accepted")
	}
	if _, err := warmPoolListMembers(context.Background(), base, "ns", sel); err != nil {
		t.Fatalf("empty complete inventory control failed: %v", err)
	}
}
