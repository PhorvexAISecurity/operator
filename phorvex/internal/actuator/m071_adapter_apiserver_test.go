package actuator

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

// This is an isolated local kube-apiserver/etcd control. The serving side remains
// a real bounded HTTP producer; real vLLM compatibility and traffic behavior are L3 debt.
func TestM071RealAPIJournalBindsServingOperation(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	localOnly := false
	e := &envtest.Environment{
		UseExistingCluster: &localOnly,
		CRDDirectoryPaths: []string{
			"../../config/crd/bases",
			"../../../build/phoenix-extended/config/crd/bases",
		},
	}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	c, err := client.New(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{"m071-operator", "m071-tenant"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	state := &m71Serving{loaded: true, unloadStatus: http.StatusAccepted, disappearAfter: 1}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "m071-tenant", Name: "infer",
			Labels:      map[string]string{"app": "m071", labelLoRAEnabled: "true"},
			Annotations: map[string]string{annoServingPort: strconv.Itoa(port)},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}},
	}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.PodIP = host
	if err := c.Status().Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	pol := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "policy"},
		Spec: v1alpha1.PhorvexPolicySpec{
			Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m071"}},
			Budget:  v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionAdapterRotate)}},
		},
	}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	const creator = "system:serviceaccount:m071-tenant:detector"
	event := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]interface{}{
			"name": "detected", "annotations": map[string]interface{}{
				"phorvex.ai/creator-identity": creator,
				"phorvex.ai/target-pod-uid":   string(pod.UID),
				"phorvex.ai/adapter-name":     "actual-poison",
			},
		},
		"spec": map[string]interface{}{
			"description": "trusted adapter detector fixture",
			"rule":        map[string]interface{}{"type": model.AttackVectorAdapter, "source": "fixture-detector"},
			"targets":     []interface{}{pod.Namespace + "/" + pod.Name},
		},
	}}
	if err := c.Create(ctx, event); err != nil {
		t.Fatal(err)
	}
	eventCreatedAt := event.GetCreationTimestamp()
	if event.GetUID() == "" || eventCreatedAt.IsZero() {
		t.Fatal("real API did not assign detector event identity")
	}
	ConfigureAdapterDetectorIdentities([]string{creator})
	t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
	observation := &model.AdapterObservation{
		EventName: event.GetName(), EventUID: string(event.GetUID()), CreatorIdentity: creator,
		TargetPodUID: string(pod.UID), AdapterName: "actual-poison", CreatedAt: event.GetCreationTimestamp().Time,
	}
	ec := EnactCtx{
		Client: c, Reader: c, JournalNamespace: "m071-operator", VLLM: &httpVLLM{hc: server.Client()},
		AdapterObservationTimeout: 2 * time.Second, AdapterObservationInterval: 10 * time.Millisecond,
	}
	req := Request{
		Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionAdapterRotate,
		PolicyName: pol.Name, PolicyUID: string(pol.UID), AdapterObservation: observation,
	}
	result, err := (adapterRotateHandler{}).Enact(ctx, ec, req)
	if err != nil || !result.Emitted {
		t.Fatalf("real API operation result=%+v err=%v", result, err)
	}
	name := receiptName(operationReceipt{Kind: "adapter-rotate", PolicyUID: string(pol.UID), TargetUID: string(pod.UID)})
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "m071-operator", Name: name}, cm); err != nil {
		t.Fatal(err)
	}
	if cm.UID == "" || cm.ResourceVersion == "" || cm.Labels[journalLabel] != "v1" {
		t.Fatalf("journal lacks server identity: %+v", cm.ObjectMeta)
	}
	var receipt operationReceipt
	if err := json.Unmarshal([]byte(cm.Data["receipt"]), &receipt); err != nil || !receipt.valid() {
		t.Fatalf("persisted receipt invalid: %+v err=%v", receipt, err)
	}
	if receipt.Phase != "completed" || receipt.TargetUID != string(pod.UID) || receipt.PolicyUID != string(pol.UID) ||
		receipt.AdapterEventUID != string(event.GetUID()) || receipt.AdapterEventCreatedAt != event.GetCreationTimestamp().Time.UTC().Format(time.RFC3339Nano) || receipt.AdapterName != "actual-poison" {
		t.Fatalf("journal bindings drifted: %+v", receipt)
	}
	duplicate := cm.DeepCopy()
	duplicate.UID, duplicate.ResourceVersion = "", ""
	if err := c.Create(ctx, duplicate); !apierrors.IsAlreadyExists(err) {
		t.Fatalf("API admitted duplicate canonical receipt: %v", err)
	}
	current := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), current); err != nil {
		t.Fatal(err)
	}
	if current.Annotations["phorvex.ai/adapter-epoch"] != string(event.GetUID()) {
		t.Fatalf("terminal membership was not bound to event epoch: %v", current.Annotations)
	}
}
