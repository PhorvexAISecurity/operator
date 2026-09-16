package actuator

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type m040DrainHTTP struct {
	mu       sync.Mutex
	abort    chan struct{}
	active   int
	aborted  bool
	entered  chan struct{}
	enterOne sync.Once
}

func newM040DrainHTTP() *m040DrainHTTP {
	return &m040DrainHTTP{abort: make(chan struct{}), entered: make(chan struct{})}
}

func (s *m040DrainHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/hold":
		s.mu.Lock()
		s.active++
		abort := s.abort
		s.enterOne.Do(func() { close(s.entered) })
		s.mu.Unlock()
		select {
		case <-abort:
			http.Error(w, "aborted", http.StatusServiceUnavailable)
		case <-r.Context().Done():
		}
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	case defaultDrainPath:
		s.mu.Lock()
		aborted := s.active
		if aborted > 0 && !s.aborted {
			close(s.abort)
			s.aborted = true
		}
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"aborted": aborted})
	case "/benign":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("available"))
	default:
		http.NotFound(w, r)
	}
}

// startM040EndpointController emulates only the Kubernetes EndpointSlice controller:
// it copies the Service selector result into a slice after each Pod label change. Envtest
// has no controller-manager, kube-proxy or CNI, so this is control-plane evidence only.
func startM040EndpointController(ctx context.Context, c client.Client, podKey, sliceKey client.ObjectKey, address string) <-chan error {
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-ticker.C:
				pod := &corev1.Pod{}
				if err := c.Get(ctx, podKey, pod); err != nil {
					if ctx.Err() != nil {
						done <- nil
						return
					}
					done <- err
					return
				}
				slice := &discoveryv1.EndpointSlice{}
				if err := c.Get(ctx, sliceKey, slice); err != nil {
					if ctx.Err() != nil {
						done <- nil
						return
					}
					done <- err
					return
				}
				wantPresent := pod.Labels[labelServing] != "drained"
				hasEndpoint := len(slice.Endpoints) == 1
				if wantPresent == hasEndpoint {
					continue
				}
				if wantPresent {
					ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
					slice.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{address}, TargetRef: &ref}}
				} else {
					slice.Endpoints = nil
				}
				if err := c.Update(ctx, slice); err != nil && !apierrors.IsConflict(err) {
					done <- err
					return
				}
			}
		}
	}()
	return done
}

func createM040APIObjects(t *testing.T, ctx context.Context, c client.Client, namespace, name, address string) (*v1alpha1.PhorvexPolicy, *corev1.Pod, *corev1.Service, *discoveryv1.EndpointSlice) {
	t.Helper()
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": name}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionRequestDrain)}}}}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: map[string]string{"app": name, labelServing: "standby"}, Annotations: map[string]string{annoRouteService: name, annoServingPort: "1"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "fixture", Image: "unused:test"}}}}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.PodIP = address
	if err := c.Status().Update(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": name, labelServing: "standby"}, Ports: []corev1.ServicePort{{Port: 8000}}}}
	if err := c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: namespace, Name: name, UID: pod.UID}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name + "-a", Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID}}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{address}, TargetRef: &ref}}}
	if err := c.Create(ctx, slice); err != nil {
		t.Fatal(err)
	}
	return pol, pod, svc, slice
}

// This test uses a real local kube-apiserver/etcd and the shipped HTTP producer.
// EndpointSlice reconciliation is explicitly emulated and proves no network dataplane.
func TestM040RequestDrainAPIServerLifecycleAndRecovery(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires envtest assets")
	}
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := e.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	}()
	c, err := client.New(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, namespace := range []string{"operator", "m040-lifecycle", "m040-recovery"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("native-producer-confirms-abort-and-restoration", func(t *testing.T) {
		const address = "10.23.0.9"
		stack := newM040DrainHTTP()
		server := httptest.NewServer(stack)
		defer server.Close()
		longCtx, cancelLong := context.WithCancel(ctx)
		defer cancelLong()
		destination := strings.TrimPrefix(server.URL, "http://")
		transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, destination)
		}}
		defer transport.CloseIdleConnections()
		oldVLLM := pkgVLLM
		pkgVLLM = &httpVLLM{hc: &http.Client{Transport: transport, Timeout: 3 * time.Second}}
		defer func() { pkgVLLM = oldVLLM }()

		pol, pod, _, slice := createM040APIObjects(t, ctx, c, "m040-lifecycle", "infer", address)
		controllerCtx, stopController := context.WithCancel(ctx)
		controllerDone := startM040EndpointController(controllerCtx, c, client.ObjectKeyFromObject(pod), client.ObjectKeyFromObject(slice), address)
		defer func() {
			stopController()
			if controllerErr := <-controllerDone; controllerErr != nil {
				t.Errorf("EndpointSlice controller emulation: %v", controllerErr)
			}
		}()

		longDone := make(chan int, 1)
		go func() {
			request, requestErr := http.NewRequestWithContext(longCtx, http.MethodGet, server.URL+"/hold", nil)
			if requestErr != nil {
				longDone <- 0
				return
			}
			longClient := server.Client()
			longClient.Timeout = 5 * time.Second
			resp, requestErr := longClient.Do(request)
			if requestErr != nil {
				longDone <- 0
				return
			}
			defer resp.Body.Close()
			longDone <- resp.StatusCode
		}()
		select {
		case <-stack.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("long-lived request did not enter serving fixture")
		}

		native := NewNativeActuator(c)
		native.Reader, native.JournalNamespace = c, "operator"
		result, enactErr := native.Actuate(ctx, Request{Tenant: "tenant", Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionRequestDrain, PolicyName: pol.Name, PolicyUID: string(pol.UID)})
		if enactErr != nil || !result.Emitted || !strings.Contains(result.Note, "1 in-flight aborted") {
			t.Fatalf("native request-drain result=%+v err=%v", result, enactErr)
		}
		select {
		case status := <-longDone:
			if status != http.StatusServiceUnavailable {
				t.Fatalf("long-lived request status=%d, want aborted 503", status)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("confirmed drain did not terminate the long-lived request")
		}
		current := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), current); err != nil {
			t.Fatal(err)
		}
		if current.Labels[labelServing] != "standby" || current.Labels[labelDrainEpoch] == "" {
			t.Fatalf("exact serving state not restored: %v", current.Labels)
		}
		if response, err := server.Client().Get(server.URL + "/benign"); err != nil {
			t.Fatalf("benign request after restoration: %v", err)
		} else {
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("benign request status=%d", response.StatusCode)
			}
		}
		var receipts corev1.ConfigMapList
		if err := c.List(ctx, &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 0 {
			t.Fatalf("completed lifecycle receipt count=%d err=%v", len(receipts.Items), err)
		}
	})

	t.Run("restart-restores-without-replaying-http-abort", func(t *testing.T) {
		const address = "10.23.0.10"
		pol, pod, svc, slice := createM040APIObjects(t, ctx, c, "m040-recovery", "infer", address)
		r := operationReceipt{Version: requestDrainReceiptVersion, Kind: "request-drain", Phase: "stack-confirmed", PolicyNamespace: pod.Namespace, PolicyName: pol.Name, PolicyUID: string(pol.UID), TargetName: pod.Name, TargetUID: string(pod.UID), TargetLabels: copyLabels(pod.Labels), OperationToken: "00112233445566778899aabbccddeeff", ServiceName: svc.Name, ServiceUID: string(svc.UID), ServiceSelector: copyLabels(svc.Spec.Selector), PriorServingPresent: true, PriorServingValue: "standby", EndpointAddresses: []string{address}, EndpointConfigSHA256: drainEndpointConfigDigest(pod), Aborted: 1}
		ec := EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", DrainObservationTimeout: 2 * time.Second, DrainObservationInterval: 10 * time.Millisecond}
		if _, err := journalWrite(ctx, ec, r); err != nil {
			t.Fatal(err)
		}
		current := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), current); err != nil {
			t.Fatal(err)
		}
		current.Labels[labelServing], current.Labels[labelDrainEpoch] = "drained", r.OperationToken
		if err := c.Update(ctx, current); err != nil {
			t.Fatal(err)
		}
		currentSlice := &discoveryv1.EndpointSlice{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(slice), currentSlice); err != nil {
			t.Fatal(err)
		}
		currentSlice.Endpoints = nil
		if err := c.Update(ctx, currentSlice); err != nil {
			t.Fatal(err)
		}
		controllerCtx, stopController := context.WithCancel(ctx)
		controllerDone := startM040EndpointController(controllerCtx, c, client.ObjectKeyFromObject(pod), client.ObjectKeyFromObject(slice), address)
		defer func() {
			stopController()
			if controllerErr := <-controllerDone; controllerErr != nil {
				t.Errorf("EndpointSlice controller emulation: %v", controllerErr)
			}
		}()
		noReplay := &mockVLLM{}
		native := &NativeActuator{Client: c, Reader: c, JournalNamespace: "operator", RecoveryVLLM: noReplay}
		events, recoverErr := native.RecoverOperations(ctx, false)
		if recoverErr != nil || len(events) != 1 || events[0].Outcome != "confirmed" || noReplay.drainCalls != 0 {
			t.Fatalf("restart recovery events=%+v drainCalls=%d err=%v", events, noReplay.drainCalls, recoverErr)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), current); err != nil {
			t.Fatal(err)
		}
		if current.Labels[labelServing] != "standby" || current.Labels[labelDrainEpoch] != r.OperationToken {
			t.Fatalf("restart did not restore exact state: %v", current.Labels)
		}
		cm := &corev1.ConfigMap{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: receiptName(r)}, cm); !apierrors.IsNotFound(err) {
			t.Fatalf("restart recovery retained completed receipt: %v", err)
		}
	})
}
