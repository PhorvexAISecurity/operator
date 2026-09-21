package actuator

import (
	"context"
	"os"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	policyv1 "k8s.io/api/policy/v1"
 "k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

func TestLeadVoicePDBActualAPIRefusal(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API-server binaries")
	}
	localOnly:=false
 env := &envtest.Environment{UseExistingCluster:&localOnly,CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, policyv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	base, err := client.NewWithWatch(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m054-native"}}
	if err := base.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	replicas := int32(2)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "web"}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "unused:test"}}}}}}
	if err := base.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	cap, workloadGrace := int64(3), int64(120)
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		Budget: v1alpha1.BudgetSpec{
			MaxGracePeriodSeconds:  &cap,
			TickInterval:           metav1.Duration{Duration: 20 * time.Second},
			AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute},
			ProactiveFloor:         metav1.Duration{Duration: time.Hour},
		},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}},
	}}
	if err := base.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns.Name, Name: "web-0", Labels: map[string]string{"app": "web"}, Finalizers: []string{"m054.test/hold"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}},
	}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &workloadGrace, Containers: []corev1.Container{{Name: "web", Image: "unused:test"}}}}
	if err := base.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}

 pod.Status.Phase=corev1.PodRunning
 pod.Status.Conditions=[]corev1.PodCondition{{Type:corev1.PodReady,Status:corev1.ConditionTrue}}
 if err:=base.Status().Update(ctx,pod);err!=nil{t.Fatal(err)}
 if err:=base.Get(ctx,client.ObjectKeyFromObject(pod),pod);err!=nil{t.Fatal(err)}
 minimum:=intstr.FromInt(2)
 pdb:=&policyv1.PodDisruptionBudget{ObjectMeta:metav1.ObjectMeta{Namespace:ns.Name,Name:"voice-budget"},Spec:policyv1.PodDisruptionBudgetSpec{MinAvailable:&minimum,Selector:&metav1.LabelSelector{MatchLabels:map[string]string{"app":"web"}}}}
 if err:=base.Create(ctx,pdb);err!=nil{t.Fatal(err)}
 // Isolated API has no disruption controller; status is deliberately seeded
 // to the observed dev condition. Admission remains the real API implementation.
 pdb.Status.ObservedGeneration=pdb.Generation
 pdb.Status.CurrentHealthy=2;pdb.Status.DesiredHealthy=2;pdb.Status.ExpectedPods=3;pdb.Status.DisruptionsAllowed=0
 if err:=base.Status().Update(ctx,pdb);err!=nil{t.Fatal(err)}
 uid,rv:=pod.UID,pod.ResourceVersion
 eviction:=&policyv1.Eviction{ObjectMeta:metav1.ObjectMeta{Namespace:ns.Name,Name:pod.Name},DeleteOptions:&metav1.DeleteOptions{GracePeriodSeconds:&cap,Preconditions:&metav1.Preconditions{UID:&uid,ResourceVersion:&rv}}}
 err=base.SubResource("eviction").Create(ctx,pod,eviction)
 if !apierrors.IsTooManyRequests(err){t.Fatalf("control: expected real API budget refusal, got %v",err)}
 t.Log("positive: actual Eviction API refuses healthy target with zero PDB headroom")
 result,err:=dispatch(ctx,EnactCtx{Client:base,Reader:base},m054Request(pod,policy,cap))
 fresh:=&corev1.Pod{}
 if getErr:=base.Get(ctx,client.ObjectKeyFromObject(pod),fresh);getErr!=nil{t.Fatal(getErr)}
 deleted:=fresh.DeletionTimestamp!=nil
 // Release only our local test finalizer, preserving the deletion observation.
 fresh.Finalizers=nil
 if cleanupErr:=base.Update(ctx,fresh);cleanupErr!=nil&&!apierrors.IsNotFound(cleanupErr){t.Fatal(cleanupErr)}
 if result.Emitted||deleted{t.Fatalf("BUG: native rotate bypassed real PDB refusal: emitted=%v deleted=%v err=%v",result.Emitted,deleted,err)}
}
