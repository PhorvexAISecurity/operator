package actuator

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func routeKCMWait(t *testing.T, within time.Duration, check func() (bool, error), log *m066BoundedLog) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		ok, err := check()
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for EndpointSlice controller: %s", log.String())
}

func routeKCMObserveZero(ctx context.Context, c client.Client, svc *corev1.Service) func() bool {
	observeCtx, cancel := context.WithCancel(ctx)
	var sawZero atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-observeCtx.Done():
				return
			case <-ticker.C:
				current := &corev1.Service{}
				if err := c.Get(observeCtx, client.ObjectKeyFromObject(svc), current); err != nil {
					continue
				}
				members, err := routeEndpointMembers(observeCtx, c, current)
				if err == nil && len(members) == 0 {
					sawZero.Store(true)
				}
			}
		}
	}()
	return func() bool {
		cancel()
		<-done
		return sawZero.Load()
	}
}

type routeKCMPhaseFailure struct {
	client.Client
	configMapUpdates int
}

func (c *routeKCMPhaseFailure) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok {
		c.configMapUpdates++
		if c.configMapUpdates == 2 {
			return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, obj.GetName(), errors.New("injected phase acknowledgement conflict"))
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestRouteCutoverActualAPIAndKCMEndpointSliceLifecycle(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	kcm := os.Getenv("KUBE_CONTROLLER_MANAGER")
	if kcm == "" {
		var err error
		kcm, err = exec.LookPath("kube-controller-manager")
		if err != nil {
			t.Skip("requires pinned Kubernetes v1.34.0 kube-controller-manager")
		}
	}
	version, err := exec.Command(kcm, "--version").Output()
	if err != nil || !strings.Contains(string(version), "v1.34.0") {
		t.Fatalf("kube-controller-manager must be v1.34.0: %q err=%v", version, err)
	}
	localOnly := false
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, UseExistingCluster: &localOnly}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	kubeconfig := m066Kubeconfig(t, cfg)
	cmd := exec.CommandContext(ctx, kcm, "--kubeconfig="+kubeconfig, "--controllers=endpointslice", "--leader-elect=false", "--use-service-account-credentials=false", "--bind-address=127.0.0.1", "--secure-port=0")
	cmd.Env = []string{"KUBECONFIG=" + kubeconfig}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "KUBECONFIG=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	var kcmLog m066BoundedLog
	cmd.Stdout, cmd.Stderr = &kcmLog, &kcmLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	c, err := client.New(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "route-kcm"}}
	op := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "route-kcm-operator"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, op); err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "route-kcm-node"}}
	if err := c.Create(ctx, node); err != nil {
		t.Fatal(err)
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "route"}, Spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone, Selector: map[string]string{"app": "route-kcm", labelRouteKey: "old", "foreign": "keep"}, Ports: []corev1.ServicePort{{Name: "http", Port: 80}}}}
	if err := c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	pods := []*corev1.Pod{}
	for i, address := range []string{"10.44.0.10"} {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "route-" + string(rune('a'+i)), Labels: map[string]string{"app": "route-kcm", labelRouteKey: "old", "foreign": "keep"}, Annotations: map[string]string{annoRouteService: svc.Name, "unrelated": "keep"}}, Spec: corev1.PodSpec{NodeName: node.Name, Containers: []corev1.Container{{Name: "app", Image: "registry.k8s.io/pause:3.10"}}}}
		if err := c.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		pod.Status.Phase = corev1.PodRunning
		pod.Status.PodIP = address
		pod.Status.PodIPs = []corev1.PodIP{{IP: address}}
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		if err := c.Status().Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			t.Fatal(err)
		}
		pods = append(pods, pod)
	}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "route-kcm"}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, SLO: v1alpha1.SLOSpec{MinAvailableReplicas: 1}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRouteRotate, v1alpha1.ActionEndpointRotate}}}}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	routeKCMWait(t, 20*time.Second, func() (bool, error) {
		members, err := routeEndpointMembers(ctx, c, svc)
		return err == nil && len(members) == 1, nil
	}, &kcmLog)
	native := &NativeActuator{Client: c, Reader: c, JournalNamespace: op.Name, RouteObservationTimeout: 15 * time.Second, RouteObservationInterval: 100 * time.Millisecond}
	for i, action := range []model.Action{model.ActionRouteRotate, model.ActionEndpointRotate} {
		req := Request{Namespace: ns.Name, Pod: pods[0].Name, TargetUID: string(pods[0].UID), Action: action, PolicyName: pol.Name, PolicyUID: string(pol.UID), OperationID: strings.Repeat(string(rune('a'+i)), 40)}
		stopObservation := routeKCMObserveZero(ctx, c, svc)
		result, err := native.Actuate(ctx, req)
		if err != nil || !result.Emitted || result.MutationKind != "reversible" {
			stopObservation()
			t.Fatalf("%s actual API/KCM result=%+v err=%v kcm=%s", action, result, err, kcmLog.String())
		}
		gotPod, gotSvc := &corev1.Pod{}, &corev1.Service{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pods[0]), gotPod); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(svc), gotSvc); err != nil {
			t.Fatal(err)
		}
		if gotPod.Labels[labelRouteKey] == "old" || gotSvc.Spec.Selector[labelRouteKey] != gotPod.Labels[labelRouteKey] || gotPod.Labels[routeBridgeLabel] != "" || gotPod.Annotations["unrelated"] != "keep" || gotSvc.Spec.Selector["foreign"] != "keep" {
			t.Fatalf("%s final state Pod=%v/%v Service=%v", action, gotPod.Labels, gotPod.Annotations, gotSvc.Spec.Selector)
		}
		members, err := routeEndpointMembers(ctx, c, gotSvc)
		if err != nil || len(members) != 1 || members[0] != string(gotPod.UID) {
			t.Fatalf("%s final EndpointSlice members=%v err=%v", action, members, err)
		}
		if err := native.Rollback(ctx, req, result.RollbackRef); err != nil {
			stopObservation()
			t.Fatalf("%s rollback: %v", action, err)
		}
		routeKCMWait(t, 15*time.Second, func() (bool, error) {
			if err := c.Get(ctx, client.ObjectKeyFromObject(svc), svc); err != nil {
				return false, err
			}
			members, err := routeEndpointMembers(ctx, c, svc)
			return err == nil && len(members) == 1, nil
		}, &kcmLog)
		if stopObservation() {
			t.Fatalf("%s forward or rollback exposed a controller-observed zero-member Service", action)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pods[0]), pods[0]); err != nil {
			t.Fatal(err)
		}
	}
	phaseReq := Request{Namespace: ns.Name, Pod: pods[0].Name, TargetUID: string(pods[0].UID), Action: model.ActionEndpointRotate, PolicyName: pol.Name, PolicyUID: string(pol.UID), OperationID: strings.Repeat("d", 40)}
	phaseWriter := &routeKCMPhaseFailure{Client: c}
	stopObservation := routeKCMObserveZero(ctx, c, svc)
	interrupted := &NativeActuator{Client: phaseWriter, Reader: c, JournalNamespace: op.Name, RouteObservationTimeout: 15 * time.Second, RouteObservationInterval: 100 * time.Millisecond}
	partial, partialErr := interrupted.Actuate(ctx, phaseReq)
	if partialErr == nil || !partial.Emitted || partial.MutationKind != "partial" || phaseWriter.configMapUpdates != 2 {
		stopObservation()
		t.Fatalf("actual accepted-write/lost-phase result=%+v err=%v updates=%d", partial, partialErr, phaseWriter.configMapUpdates)
	}
	resumed, resumeErr := native.Actuate(ctx, phaseReq)
	if resumeErr != nil || !resumed.Emitted || resumed.MutationKind != "reversible" || resumed.RollbackRef == "" {
		stopObservation()
		t.Fatalf("actual same-ID resume result=%+v err=%v kcm=%s", resumed, resumeErr, kcmLog.String())
	}
	reconciled, retryErr := native.Actuate(ctx, phaseReq)
	if retryErr != nil || reconciled.Emitted || reconciled.RollbackRef == "" || !strings.Contains(reconciled.Note, "already applied") {
		stopObservation()
		t.Fatalf("actual terminal retry result=%+v err=%v", reconciled, retryErr)
	}
	if err := native.Rollback(ctx, phaseReq, resumed.RollbackRef); err != nil {
		stopObservation()
		t.Fatalf("actual recovered rollback: %v", err)
	}
	if stopObservation() {
		t.Fatal("actual accepted-write recovery or rollback exposed a controller-observed zero-member Service")
	}
	var guards corev1.ConfigMapList
	if err := c.List(ctx, &guards, client.InNamespace(op.Name)); err != nil {
		t.Fatal(err)
	}
	if len(guards.Items) != 0 {
		t.Fatalf("successful rollbacks retained protected records: %+v", guards.Items)
	}
	var slices discoveryv1.EndpointSliceList
	if err := c.List(ctx, &slices, client.InNamespace(ns.Name)); err != nil || len(slices.Items) == 0 {
		t.Fatalf("real EndpointSlice controller produced no slices: len=%d err=%v", len(slices.Items), err)
	}
}
