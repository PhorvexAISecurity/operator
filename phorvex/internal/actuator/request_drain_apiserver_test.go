package actuator

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
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
	mu                 sync.Mutex
	abort              chan struct{}
	active             int
	aborted            bool
	entered            chan struct{}
	enterOne           sync.Once
	podUID             string
	bearer             string
	status             drainV11StatusResponse
	capabilityRequests int
	createRequests     int
	statusRequests     int
	reopenRequests     int
}

func newM040DrainHTTP() *m040DrainHTTP {
	return &m040DrainHTTP{abort: make(chan struct{}), entered: make(chan struct{}), bearer: "m040-trusted-token"}
}

func m040NonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var candidates []string
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsLoopback() {
				candidates = append(candidates, ip.String())
			}
		}
	}
	if len(candidates) == 0 {
		t.Fatal("actual TLS producer requires a non-loopback IPv4 address accepted by EndpointSlice")
	}
	sort.Strings(candidates)
	return candidates[0]
}

func m040SignDrainStatus(status *drainV11StatusResponse) error {
	body := map[string]any{
		"schema": status.Schema, "operation_id": status.OperationID,
		"operation_generation": status.OperationGeneration, "attempt": status.Attempt,
		"owner_digest": status.OwnerDigest, "backend_incarnation_digest": status.BackendIncarnationDigest,
		"revision": status.Revision, "state": status.State, "admission": status.Admission,
		"admission_generation": status.AdmissionGeneration, "engine_boot_id": status.EngineBootID,
		"virtual_engine_ids": status.VirtualEngineIDs,
		"engine_snapshot":    status.EngineSnapshot, "terminal_dispositions": status.TerminalDispositions,
		"proxy_snapshot": status.ProxySnapshot, "observations": status.Observations,
		"deadline": status.Deadline, "cancellation_grace_deadline": status.CancellationGraceDeadline,
		"transition_reason": status.TransitionReason, "cancel_boundary_revision": status.CancelBoundaryRevision,
		"last_transition": status.LastTransition, "query_nonce": status.QueryNonce,
	}
	var err error
	status.ReceiptSHA256, err = drainV11Digest("phorvex-drain-status-v1", body)
	return err
}

func m040DrainStatus(request drainV11CreateRequest, state, admission, revision string, nonce *string) (drainV11StatusResponse, error) {
	ownerDigest, err := drainV11OwnerDigest(request.Owner)
	if err != nil {
		return drainV11StatusResponse{}, err
	}
	zero := drainV11Queues{Waiting: []string{}, Running: []string{}, Swapped: []string{}, Cached: []string{}}
	status := drainV11StatusResponse{
		Schema: drainV11Schema, OperationID: request.OperationID, OperationGeneration: request.OperationGeneration,
		Attempt: request.Attempt, OwnerDigest: ownerDigest, BackendIncarnationDigest: strings.Repeat("2", 64),
		Revision: revision, State: state, Admission: admission, AdmissionGeneration: request.OperationGeneration,
		EngineBootID: strings.Repeat("3", 32), VirtualEngineIDs: []int{0},
		EngineSnapshot:       map[string]drainV11Queues{"0": {Waiting: []string{"request-a"}, Running: []string{}, Swapped: []string{}, Cached: []string{}}},
		TerminalDispositions: map[string]string{"request-a": "aborted"},
		ProxySnapshot: map[string]json.RawMessage{
			"before_engine_begin": json.RawMessage(`{"active":1}`),
			"after_engine_begin":  json.RawMessage(`{"cancelled":1,"remaining":0}`),
		},
		Observations: []drainV11Observation{
			{Nonce: strings.Repeat("4", 32), Sequence: "10", Queues: map[string]drainV11Queues{"0": zero}, Hash: strings.Repeat("a", 64)},
			{Nonce: strings.Repeat("5", 32), Sequence: "11", Queues: map[string]drainV11Queues{"0": zero}, Hash: strings.Repeat("b", 64)},
		},
		Deadline: request.Deadline, TransitionReason: "none", CancelBoundaryRevision: "0",
		LastTransition: "2026-09-22T00:00:00Z", QueryNonce: nonce,
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.Deadline)
	if err != nil {
		return drainV11StatusResponse{}, err
	}
	status.CancellationGraceDeadline = drainV11Time(deadline.Add(drainV11CancelGrace))
	err = m040SignDrainStatus(&status)
	return status, err
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
	case defaultDrainPath + "/capability":
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+s.bearer {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.mu.Lock()
		s.capabilityRequests++
		podUID := s.podUID
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(drainV11CapabilityResponse{
			Schema: drainV11Schema, Capability: drainV11Capability, PodUID: podUID,
			LedgerID: strings.Repeat("1", 32), ProxyBootID: strings.Repeat("2", 32), EngineBootID: strings.Repeat("3", 32),
			IncarnationDigest: strings.Repeat("2", 64), ProxySource: "m040-proxy-source", EngineSource: "m040-engine-source",
			EngineMode: "v0-frontend-multiprocessing", VirtualEngineIDs: []int{0}, GenerationHighWater: "0",
			NextOperationGeneration: "1", Admission: "OPEN",
		})
	case defaultDrainPath + "/operations":
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+s.bearer {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request drainV11CreateRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Schema != drainV11Schema ||
			request.Mode != "abort-and-quiesce" || request.Owner.PodUID != s.podUID ||
			request.ExpectedIncarnationDigest != strings.Repeat("2", 64) {
			http.Error(w, "invalid operation", http.StatusBadRequest)
			return
		}
		status, err := m040DrainStatus(request, "QUIESCENT", "CLOSED", "3", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.mu.Lock()
		aborted := s.active
		if aborted > 0 && !s.aborted {
			close(s.abort)
			s.aborted = true
		}
		s.createRequests++
		s.status = status
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(status)
	case "/benign":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("available"))
	default:
		prefix := defaultDrainPath + "/operations/"
		if !strings.HasPrefix(r.URL.Path, prefix) || r.Header.Get("Authorization") != "Bearer "+s.bearer {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		status := s.status
		s.mu.Unlock()
		base := prefix + status.OperationGeneration + "/" + status.OperationID
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			nonce := r.URL.Query().Get("observation_nonce")
			if nonce == "" {
				http.Error(w, "missing observation nonce", http.StatusBadRequest)
				return
			}
			status.QueryNonce = &nonce
			if err := m040SignDrainStatus(&status); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.mu.Lock()
			s.statusRequests++
			s.mu.Unlock()
		case r.Method == http.MethodPost && r.URL.Path == base+"/reopen":
			var intent drainV11IntentRequest
			if err := json.NewDecoder(r.Body).Decode(&intent); err != nil || intent.OwnerDigest != status.OwnerDigest ||
				intent.ExpectedIncarnationDigest != status.BackendIncarnationDigest || intent.ExpectedRevision != status.Revision {
				http.Error(w, "invalid reopen intent", http.StatusBadRequest)
				return
			}
			status.State, status.Admission, status.Revision, status.QueryNonce = "OPENED", "OPEN", "4", nil
			if err := m040SignDrainStatus(&status); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.mu.Lock()
			s.reopenRequests++
			s.status = status
			s.mu.Unlock()
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
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

func createM040APIObjects(t *testing.T, ctx context.Context, c client.Client, namespace, name, address string, port int) (*v1alpha1.PhorvexPolicy, *corev1.Pod, *corev1.Service, *discoveryv1.EndpointSlice) {
	t.Helper()
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": name}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionRequestDrain)}}}}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: map[string]string{"app": name, labelServing: "standby"}, Annotations: map[string]string{annoRouteService: name, annoServingPort: strconv.Itoa(port), annoDrainProxySource: "m040-proxy-source", annoDrainEngineSource: "m040-engine-source"}}, Spec: corev1.PodSpec{ServiceAccountName: "model-sa", Containers: []corev1.Container{{Name: "guardrail", Image: "unused:test"}, {Name: "vllm", Image: "unused:test"}}}}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.PodIP = address
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "guardrail", ContainerID: "containerd://guardrail", Ready: true}, {Name: "vllm", ContainerID: "containerd://vllm", Ready: true}}
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
		stack := newM040DrainHTTP()
		listener, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(stack)
		server.Listener = listener
		server.StartTLS()
		defer server.Close()
		longCtx, cancelLong := context.WithCancel(ctx)
		defer cancelLong()
		address := m040NonLoopbackIPv4(t)
		port := server.Listener.Addr().(*net.TCPAddr).Port
		serverURL := "https://" + net.JoinHostPort(address, strconv.Itoa(port))
		pol, pod, _, slice := createM040APIObjects(t, ctx, c, "m040-lifecycle", "infer", address, port)
		stack.mu.Lock()
		stack.podUID = string(pod.UID)
		stack.mu.Unlock()
		certificate := server.Certificate()
		serverName := address
		if len(certificate.DNSNames) != 0 {
			serverName = certificate.DNSNames[0]
		}
		userTransport := server.Client().Transport.(*http.Transport).Clone()
		userTransport.Proxy = nil
		userTransport.TLSClientConfig = userTransport.TLSClientConfig.Clone()
		userTransport.TLSClientConfig.ServerName = serverName
		defer userTransport.CloseIdleConnections()
		userClient := &http.Client{Transport: userTransport, Timeout: 5 * time.Second}
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: "m040-serving"}, Data: map[string][]byte{"bearer": []byte(stack.bearer), "ca.crt": caPEM}}
		if err := c.Create(ctx, secret); err != nil {
			t.Fatal(err)
		}
		security := writeServingSecurityConfig(t, ServingSecuritySecureRequired, "operator", []ServingSecurityBinding{{
			Namespace: pod.Namespace, PolicyName: pol.Name, PolicyUID: string(pol.UID), ServiceAccount: pod.Spec.ServiceAccountName,
			ProfileID: "m040-v11", SecretName: secret.Name, BearerKey: "bearer", CAKey: "ca.crt", ServerName: serverName,
		}})
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
			request, requestErr := http.NewRequestWithContext(longCtx, http.MethodGet, serverURL+"/hold", nil)
			if requestErr != nil {
				longDone <- 0
				return
			}
			resp, requestErr := userClient.Do(request)
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

		request := Request{Tenant: "tenant", Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionRequestDrain, PolicyName: pol.Name, PolicyUID: string(pol.UID)}
		legacy := NewNativeActuator(c)
		legacy.Reader, legacy.JournalNamespace = c, "operator"
		legacy.SetServingSecurity(legacyServingSecurityForTest(t))
		legacyResult, legacyErr := legacy.Actuate(ctx, request)
		if legacyErr == nil || legacyResult.Emitted || !strings.Contains(legacyErr.Error(), "operation-bound v11 requires secure serving credentials") {
			t.Fatalf("legacy request-drain was not refused before effect: result=%+v err=%v", legacyResult, legacyErr)
		}
		stack.mu.Lock()
		legacyRequests := stack.capabilityRequests + stack.createRequests + stack.statusRequests + stack.reopenRequests
		stack.mu.Unlock()
		if legacyRequests != 0 {
			t.Fatalf("legacy refusal reached operation producer %d time(s)", legacyRequests)
		}

		native := NewNativeActuator(c)
		native.Reader, native.JournalNamespace = c, "operator"
		native.SetServingSecurity(security)
		result, enactErr := native.Actuate(ctx, request)
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
		if response, err := userClient.Get(serverURL + "/benign"); err != nil {
			t.Fatalf("benign request after restoration: %v", err)
		} else {
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("benign request status=%d", response.StatusCode)
			}
		}
		stack.mu.Lock()
		capabilityRequests, createRequests := stack.capabilityRequests, stack.createRequests
		statusRequests, reopenRequests := stack.statusRequests, stack.reopenRequests
		stack.mu.Unlock()
		// Two capability reads: the preparation read and the final exact
		// recheck immediately before the routing mutation (b6d7c614). Neither
		// is a create; exactly one operation is posted.
		if capabilityRequests != 2 || createRequests != 1 || statusRequests != 2 || reopenRequests != 1 {
			t.Fatalf("operation producer calls capability/create/status/reopen=%d/%d/%d/%d", capabilityRequests, createRequests, statusRequests, reopenRequests)
		}
		var receipts corev1.ConfigMapList
		if err := c.List(ctx, &receipts, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil || len(receipts.Items) != 0 {
			t.Fatalf("completed lifecycle receipt count=%d err=%v", len(receipts.Items), err)
		}
	})

	t.Run("restart-restores-without-replaying-http-abort", func(t *testing.T) {
		const address = "10.23.0.10"
		pol, pod, svc, slice := createM040APIObjects(t, ctx, c, "m040-recovery", "infer", address, 1)
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
