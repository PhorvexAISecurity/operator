package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type scriptedDrainV11 struct {
	mockVLLM
	t             *testing.T
	capability    drainV11CapabilityResponse
	status        drainV11StatusResponse
	createStatus  func(drainV11CreateRequest) drainV11StatusResponse
	statusCalls   int
	createCalls   int
	reopenCalls   int
	reopenStatus  drainV11StatusResponse
	reopenErr     error
	cancelCalls   int
	cancelStatus  drainV11StatusResponse
	cancelErr     error
	lastCancel    drainV11IntentRequest
	lastCreate    drainV11CreateRequest
	statusOnQuery func(string, string, string) drainV11StatusResponse
}

func journalDecodeReceipt(t *testing.T, receipt operationReceipt) operationReceipt {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded operationReceipt
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func preparedDrainV11Fixture() *drainV11Receipt {
	return &drainV11Receipt{
		OperationID:               strings.Repeat("1", 32),
		OperationGeneration:       "1",
		Attempt:                   1,
		ExpectedIncarnation:       strings.Repeat("2", 64),
		LedgerID:                  strings.Repeat("3", 32),
		ProxyBootID:               strings.Repeat("4", 32),
		EngineBootID:              strings.Repeat("5", 32),
		Deadline:                  "2026-09-20T20:00:00.000000Z",
		CancelNotBefore:           "2026-09-20T19:59:50.000000Z",
		CancellationGraceDeadline: "2026-09-20T20:00:30.000000Z",
		Owner: drainV11Owner{Tenant: "tenant", NamespaceUID: "namespace-uid", PolicyUID: "policy-uid",
			PodUID: "pod-uid", ServiceUID: "service-uid"},
		TargetNamespace:  "ns",
		TargetName:       "model",
		CapabilitySHA256: strings.Repeat("6", 64),
		ProxySource:      "proxy-source",
		EngineSource:     "engine-source",
		OperatorBinding:  strings.Repeat("7", 64),
	}
}

func TestDrainV11StatusRoutePreservesObservationQuery(t *testing.T) {
	got := (servingEndpoint{podIP: "127.0.0.1", port: 8000}).routeURL(
		"/v1/drain/operations/7/00112233445566778899aabbccddeeff?observation_nonce=ffeeddccbbaa99887766554433221100")
	want := "http://127.0.0.1:8000/v1/drain/operations/7/00112233445566778899aabbccddeeff?observation_nonce=ffeeddccbbaa99887766554433221100"
	if got != want {
		t.Fatalf("status query was not preserved as a query: got %q want %q", got, want)
	}
}

func TestOperationReceiptVersionsPartitionDrainV11FieldsAndPhases(t *testing.T) {
	old := aiPod("ns", "old", map[string]string{labelSwapGroup: "g", labelRole: roleLeader})
	next := aiPod("ns", "next", map[string]string{labelSwapGroup: "g", labelRole: roleShadow})
	pool := warmPoolIntent{RSName: "rs", RSUID: "rsuid", RSGeneration: 1, Desired: 2,
		RSTemplateHash: "template", RSSelectorHash: "selector", ServiceName: "svc", ServiceUID: "service-uid",
		ServiceSelectorHash: "service-selector", Members: []string{string(old.UID), string(next.UID)}}
	warmV2 := m066ValidV2Receipt(old, next, pool)
	warmV6 := warmV2
	warmV6.Version = warmSecureReceiptVersion
	warmV6.ServingBindingSHA256 = strings.Repeat("8", 64)
	warmV6.ServingServiceAccount = "default"
	warmV10 := warmV2
	warmV10.Version = warmDrainReceiptVersion
	warmV10.TargetLabels = copyLabels(old.Labels)
	warmV10.EndpointConfigSHA256 = strings.Repeat("9", 64)
	warmV10.NewEndpointConfigSHA256 = strings.Repeat("a", 64)
	warmV10.WarmSelectedUIDs = []string{string(old.UID)}
	warmV10.AdmittedFloor = 1
	warmV10.ServingLegacy = true
	warmV10.ServingServiceAccount = "default"

	pod, service, _, _ := requestDrainFixture(t, "true")
	requestV3 := testDrainReceipt(pod, service, "withdrawn")
	requestV7 := requestV3
	requestV7.Version = requestDrainSecureReceiptVersion
	requestV7.ServingBindingSHA256 = strings.Repeat("b", 64)
	requestV7.ServingServiceAccount = "default"

	legacy := []struct {
		name    string
		receipt operationReceipt
	}{
		{"warm-v2", warmV2},
		{"warm-v6", warmV6},
		{"warm-v10", warmV10},
		{"request-v3", requestV3},
		{"request-v7", requestV7},
	}
	for _, tc := range legacy {
		t.Run(tc.name+"-positive", func(t *testing.T) {
			if decoded := journalDecodeReceipt(t, tc.receipt); !decoded.valid() {
				t.Fatal("valid legacy receipt was rejected after JSON decode")
			}
		})
		for _, phase := range []string{"drain-dispatching-v11", "drain-cancel-dispatching-v11", "backend-reopened-v11"} {
			t.Run(tc.name+"-rejects-"+phase, func(t *testing.T) {
				forged := tc.receipt
				forged.Phase = phase
				if decoded := journalDecodeReceipt(t, forged); decoded.valid() {
					t.Fatalf("legacy receipt accepted v11 phase %q", phase)
				}
			})
		}
		t.Run(tc.name+"-rejects-v11-field", func(t *testing.T) {
			forged := tc.receipt
			forged.DrainV11 = preparedDrainV11Fixture()
			if decoded := journalDecodeReceipt(t, forged); decoded.valid() {
				t.Fatal("legacy receipt accepted DrainV11 authority")
			}
		})
	}

	unrelated := operationReceipt{Version: 1, Kind: "quarantine", Phase: "prepared", PolicyNamespace: "ns",
		PolicyName: "policy", PolicyUID: "policy-uid", TargetName: "pod", TargetUID: "pod-uid",
		TargetLabels: map[string]string{"app": "model"}, NPName: "deny"}
	if !journalDecodeReceipt(t, unrelated).valid() {
		t.Fatal("valid unrelated legacy receipt was rejected")
	}
	unrelated.DrainV11 = preparedDrainV11Fixture()
	if journalDecodeReceipt(t, unrelated).valid() {
		t.Fatal("unrelated legacy receipt accepted DrainV11 authority")
	}

	warmV11 := warmV10
	warmV11.Version = operationDrainReceiptVersion
	warmV11.DrainV11 = preparedDrainV11Fixture()
	requestV11 := requestV3
	requestV11.Version = operationDrainReceiptVersion
	requestV11.ServingLegacy = true
	requestV11.DrainV11 = preparedDrainV11Fixture()
	for name, receipt := range map[string]operationReceipt{"warm-v11": warmV11, "request-v11": requestV11} {
		t.Run(name+"-positive", func(t *testing.T) {
			if decoded := journalDecodeReceipt(t, receipt); !decoded.valid() {
				t.Fatal("valid v11 prepared receipt was rejected after JSON decode")
			}
		})
	}
}

func (s *scriptedDrainV11) DrainV11Capability(context.Context, servingEndpoint) (drainV11CapabilityResponse, error) {
	return s.capability, nil
}

func (s *scriptedDrainV11) DrainV11Create(_ context.Context, _ servingEndpoint, request drainV11CreateRequest) (drainV11StatusResponse, error) {
	s.createCalls++
	s.lastCreate = request
	return s.createStatus(request), nil
}

func (s *scriptedDrainV11) DrainV11Status(_ context.Context, _ servingEndpoint, generation, operationID, nonce string) (drainV11StatusResponse, error) {
	s.statusCalls++
	status := s.status
	if s.statusOnQuery != nil {
		status = s.statusOnQuery(generation, operationID, nonce)
	}
	status.QueryNonce = &nonce
	resignDrainV11Status(s.t, &status)
	return status, nil
}

func (s *scriptedDrainV11) DrainV11Cancel(_ context.Context, _ servingEndpoint, _ string, _ string, request drainV11IntentRequest) (drainV11StatusResponse, error) {
	s.cancelCalls++
	s.lastCancel = request
	if s.cancelErr != nil {
		return drainV11StatusResponse{}, s.cancelErr
	}
	if s.cancelStatus.Schema == "" {
		return drainV11StatusResponse{}, errors.New("unexpected cancel")
	}
	return s.cancelStatus, nil
}

func (s *scriptedDrainV11) DrainV11Reopen(context.Context, servingEndpoint, string, string, drainV11IntentRequest) (drainV11StatusResponse, error) {
	s.reopenCalls++
	if s.reopenErr != nil {
		return drainV11StatusResponse{}, s.reopenErr
	}
	if s.reopenStatus.Schema == "" {
		return drainV11StatusResponse{}, errors.New("unexpected reopen")
	}
	return s.reopenStatus, nil
}

func drainV11TestPod(containerSuffix string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "model", Namespace: "tenant", UID: types.UID("pod-uid"),
		ResourceVersion: "7", Annotations: map[string]string{annoDrainProxySource: "proxy-source", annoDrainEngineSource: "engine-source"}},
		Status: corev1.PodStatus{PodIP: "127.0.0.1",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "vllm", ContainerID: "containerd://vllm-" + containerSuffix},
				{Name: "guardrail", ContainerID: "containerd://guardrail-" + containerSuffix},
			}}}
}

func drainV11ConfirmedReceipt(t *testing.T, pod *corev1.Pod, capabilitySHA, incarnation string) (*drainV11Receipt, drainV11StatusResponse) {
	t.Helper()
	owner := drainV11Owner{Tenant: "tenant", NamespaceUID: "namespace-uid", PolicyUID: "policy-uid", PodUID: string(pod.UID), ServiceUID: "service-uid"}
	status := testDrainV11Status(t, owner, nil)
	status.BackendIncarnationDigest = incarnation
	status.EngineBootID = strings.Repeat("3", 32)
	resignDrainV11Status(t, &status)
	binding, err := drainV11OperatorBinding(pod, capabilitySHA, incarnation)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &drainV11Receipt{OperationID: status.OperationID, OperationGeneration: status.OperationGeneration,
		Attempt: 1, ExpectedIncarnation: incarnation, LedgerID: strings.Repeat("7", 32),
		ProxyBootID: strings.Repeat("8", 32), EngineBootID: status.EngineBootID, Deadline: status.Deadline,
		CancelNotBefore: "2026-09-20T19:59:50.000000Z", CancellationGraceDeadline: status.CancellationGraceDeadline,
		TransitionReason: "none", CancelBoundaryRevision: "0",
		Owner: owner, TargetNamespace: pod.Namespace, TargetName: pod.Name, CapabilitySHA256: capabilitySHA,
		ProxySource: "proxy-source", EngineSource: "engine-source", OperatorBinding: binding, CreateRequests: 1}
	if err := bindDrainV11Status(receipt, status, nil); err != nil || !receipt.confirmed() {
		t.Fatalf("confirmed receipt fixture: %#v, %v", receipt, err)
	}
	return receipt, status
}

func testDrainV11Status(t *testing.T, owner drainV11Owner, nonce *string) drainV11StatusResponse {
	t.Helper()
	ownerDigest, err := drainV11OwnerDigest(owner)
	if err != nil {
		t.Fatal(err)
	}
	zero := drainV11Queues{Waiting: []string{}, Running: []string{}, Swapped: []string{}, Cached: []string{}}
	status := drainV11StatusResponse{
		Schema: drainV11Schema, OperationID: strings.Repeat("1", 32), OperationGeneration: "1",
		Attempt: 1, OwnerDigest: ownerDigest, BackendIncarnationDigest: strings.Repeat("2", 64),
		Revision: "3", State: "QUIESCENT", Admission: "CLOSED", AdmissionGeneration: "1",
		EngineBootID:         strings.Repeat("3", 32),
		VirtualEngineIDs:     []int{0},
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
		Deadline: "2026-09-20T20:00:00Z", CancellationGraceDeadline: "2026-09-20T20:00:30.000000Z",
		TransitionReason: "none", CancelBoundaryRevision: "0",
		LastTransition: "2026-09-20T19:00:00Z", QueryNonce: nonce,
	}
	resignDrainV11Status(t, &status)
	return status
}

func TestDrainV11CachedMetadataMayOverlapOneSchedulerQueue(t *testing.T) {
	pod := drainV11TestPod("overlap")
	receipt, status := drainV11ConfirmedReceipt(t, pod, strings.Repeat("a", 64), strings.Repeat("b", 64))
	// The patched engine independently includes scheduled requests in cached
	// metadata while output is in flight. Its terminal map uses unique IDs.
	status.EngineSnapshot["0"] = drainV11Queues{
		Waiting: []string{}, Running: []string{"request-a"}, Swapped: []string{}, Cached: []string{"request-a"},
	}
	status.TerminalDispositions = map[string]string{"request-a": "completed-before-abort"}
	status.Revision = "4"
	resignDrainV11Status(t, &status)
	if err := bindDrainV11Status(receipt, status, nil); err != nil {
		t.Fatalf("producer-valid cached/scheduler overlap rejected: %v", err)
	}
	if !receipt.confirmed() || receipt.SnapshotRunning != 1 || receipt.SnapshotCached != 1 ||
		receipt.SnapshotOverlap != 1 || receipt.CompletedBeforeAbort != 1 || receipt.Aborted != 0 ||
		len(receipt.SnapshotDigests) != 1 {
		t.Fatalf("overlap changed unique disposition or durable quiescence proof: %#v", receipt)
	}
	tampered := *receipt
	tampered.SnapshotOverlap = 0
	if tampered.confirmed() {
		t.Fatal("receipt with omitted overlap remained confirmed")
	}
	for name, mutate := range map[string]func(*drainV11StatusResponse){
		"two scheduler queues": func(s *drainV11StatusResponse) {
			s.EngineSnapshot["0"] = drainV11Queues{Waiting: []string{"request-a"}, Running: []string{"request-a"}, Swapped: []string{}, Cached: []string{}}
		},
		"duplicate cached metadata": func(s *drainV11StatusResponse) {
			s.EngineSnapshot["0"] = drainV11Queues{Waiting: []string{}, Running: []string{}, Swapped: []string{}, Cached: []string{"request-a", "request-a"}}
		},
		"missing unique disposition": func(s *drainV11StatusResponse) {
			s.TerminalDispositions = map[string]string{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := status
			mutate(&candidate)
			resignDrainV11Status(t, &candidate)
			if err := validateDrainV11Status(candidate, candidate.OperationID, candidate.OperationGeneration, nil); err == nil {
				t.Fatal("invalid snapshot accepted with a self-consistent digest")
			}
		})
	}
}

func TestDrainV11HTTPClientRetainsRawCapabilityHashAndExactMediaType(t *testing.T) {
	body := `{"schema":"phorvex.drain.v1","capability":"operation-bound-quiescence-v1","pod_uid":"pod-uid","ledger_id":"11111111111111111111111111111111","proxy_boot_id":"22222222222222222222222222222222","engine_boot_id":"33333333333333333333333333333333","incarnation_digest":"4444444444444444444444444444444444444444444444444444444444444444","proxy_source":"proxy-source","engine_source":"engine-source","engine_mode":"v0-frontend-multiprocessing","virtual_engine_ids":[0],"generation_high_water":"0","next_operation_generation":"1","admission":"OPEN"}`
	contentType := "application/json; charset=utf-8"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/drain/capability" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	ep := servingEndpoint{scheme: "http", podIP: host, port: port, drainPath: "/v1/drain", client: server.Client()}
	result, err := (&httpVLLM{}).DrainV11Capability(t.Context(), ep)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(body))
	if result.RawSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("raw capability hash = %s", result.RawSHA256)
	}
	contentType = "text/plain"
	if _, err := (&httpVLLM{}).DrainV11Capability(t.Context(), ep); err == nil || !strings.Contains(err.Error(), "not application/json") {
		t.Fatalf("wrong media type accepted: %v", err)
	}
}

func TestDrainV11HTTPClientCancelBindsIntentAndClosedState(t *testing.T) {
	owner := drainV11Owner{Tenant: "tenant", NamespaceUID: "namespace", PolicyUID: "policy", PodUID: "pod", ServiceUID: "service"}
	status := testDrainV11Status(t, owner, nil)
	status.State, status.Admission = "CANCEL_REQUESTED", "CLOSED"
	status.TransitionReason, status.CancelBoundaryRevision = "operator-requested", "2"
	status.Observations = status.Observations[:1]
	resignDrainV11Status(t, &status)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/drain/operations/1/"+status.OperationID+"/cancel" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var intent drainV11IntentRequest
		if err := json.NewDecoder(r.Body).Decode(&intent); err != nil {
			t.Errorf("decode cancel intent: %v", err)
		}
		if intent.OwnerDigest != status.OwnerDigest || intent.ExpectedIncarnationDigest != status.BackendIncarnationDigest || intent.ExpectedRevision != "3" {
			t.Errorf("cancel intent changed: %#v", intent)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	}))
	defer server.Close()
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	ep := servingEndpoint{scheme: "http", podIP: host, port: port, drainPath: "/v1/drain", client: server.Client()}
	intent := drainV11IntentRequest{OwnerDigest: status.OwnerDigest,
		ExpectedIncarnationDigest: status.BackendIncarnationDigest, ExpectedRevision: "3"}
	got, err := (&httpVLLM{}).DrainV11Cancel(t.Context(), ep, "1", status.OperationID, intent)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "CANCEL_REQUESTED" || got.Admission != "CLOSED" {
		t.Fatalf("cancel response = %#v", got)
	}
}

func TestDrainV11ReceiptAttemptAndSupersessionAreExact(t *testing.T) {
	receipt := &drainV11Receipt{OperationID: strings.Repeat("1", 32), OperationGeneration: "2", Attempt: 2,
		Supersedes:          &drainV11Supersedes{OperationGeneration: "1", OperationID: strings.Repeat("2", 32), Revision: "3"},
		ExpectedIncarnation: strings.Repeat("3", 64), LedgerID: strings.Repeat("4", 32),
		ProxyBootID: strings.Repeat("5", 32), EngineBootID: strings.Repeat("6", 32),
		Deadline: "2026-09-20T20:00:00Z", CancelNotBefore: "2026-09-20T19:59:50.000000Z",
		CancellationGraceDeadline: "2026-09-20T20:00:30.000000Z", TransitionReason: "none", CancelBoundaryRevision: "0",
		Owner:           drainV11Owner{Tenant: "t", NamespaceUID: "n", PolicyUID: "p", PodUID: "u", ServiceUID: "s"},
		TargetNamespace: "n", TargetName: "pod", CapabilitySHA256: strings.Repeat("7", 64),
		ProxySource: "proxy", EngineSource: "engine", OperatorBinding: strings.Repeat("8", 64), CreateRequests: 1}
	if !receipt.prepared() {
		t.Fatal("valid attempt-2 supersession receipt refused")
	}
	create := drainV11CreateFromReceipt(receipt)
	if create.Attempt != 2 || create.Supersedes == nil || !reflect.DeepEqual(create.Supersedes, receipt.Supersedes) {
		t.Fatalf("supersession create changed: %#v", create)
	}
	for name, mutate := range map[string]func(*drainV11Receipt){
		"attempt1 supersedes": func(r *drainV11Receipt) { r.Attempt = 1 },
		"attempt2 absent":     func(r *drainV11Receipt) { r.Supersedes = nil },
		"leading zero":        func(r *drainV11Receipt) { r.Supersedes.OperationGeneration = "01" },
		"too many creates":    func(r *drainV11Receipt) { r.CreateRequests = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneDrainV11Receipt(receipt)
			mutate(candidate)
			if candidate.prepared() {
				t.Fatal("malformed supersession receipt accepted")
			}
		})
	}
}

func TestDrainV11StatusAcceptsBoundAttemptTwoAndCreateRejectsChangedAttempt(t *testing.T) {
	owner := drainV11Owner{Tenant: "tenant", NamespaceUID: "namespace", PolicyUID: "policy", PodUID: "pod", ServiceUID: "service"}
	status := testDrainV11Status(t, owner, nil)
	status.Attempt = 2
	resignDrainV11Status(t, &status)
	if err := validateDrainV11Status(status, status.OperationID, status.OperationGeneration, nil); err != nil {
		t.Fatalf("attempt-2 status refused: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	}))
	defer server.Close()
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	ep := servingEndpoint{scheme: "http", podIP: host, port: port, drainPath: "/v1/drain", client: server.Client()}
	request := drainV11CreateRequest{OperationID: status.OperationID,
		OperationGeneration: status.OperationGeneration, Attempt: 1}
	if _, err := (&httpVLLM{}).DrainV11Create(t.Context(), ep, request); err == nil ||
		!strings.Contains(err.Error(), "changed the operation attempt") {
		t.Fatalf("changed create attempt accepted: %v", err)
	}
}

func TestDrainV11StatusRejectsSelfConsistentDifferentAdmissionGeneration(t *testing.T) {
	owner := drainV11Owner{Tenant: "tenant", NamespaceUID: "namespace", PolicyUID: "policy", PodUID: "pod", ServiceUID: "service"}
	status := testDrainV11Status(t, owner, nil)
	status.AdmissionGeneration = "2"
	resignDrainV11Status(t, &status)
	if err := validateDrainV11Status(status, status.OperationID, status.OperationGeneration, nil); err == nil ||
		!strings.Contains(err.Error(), "admission generation changed operation identity") {
		t.Fatalf("self-consistent different admission generation accepted: %v", err)
	}
}

func TestRecoverDrainV11PersistsExactStaleSupersessionBeforeSecondCreate(t *testing.T) {
	oldPod := drainV11TestPod("old")
	newPod := drainV11TestPod("new")
	oldCapabilitySHA, oldIncarnation := strings.Repeat("a", 64), strings.Repeat("b", 64)
	newCapabilitySHA, newIncarnation := strings.Repeat("c", 64), strings.Repeat("d", 64)
	receipt, priorStatus := drainV11ConfirmedReceipt(t, oldPod, oldCapabilitySHA, oldIncarnation)
	staleStatus := priorStatus
	staleStatus.State, staleStatus.Admission = "STALE", "CLOSED"
	resignDrainV11Status(t, &staleStatus)
	backend := &scriptedDrainV11{t: t, status: staleStatus,
		capability: drainV11CapabilityResponse{Schema: drainV11Schema, Capability: drainV11Capability,
			PodUID: string(newPod.UID), LedgerID: receipt.LedgerID, ProxyBootID: strings.Repeat("e", 32),
			EngineBootID: strings.Repeat("f", 32), IncarnationDigest: newIncarnation,
			ProxySource: "proxy-source", EngineSource: "engine-source", EngineMode: "v0-frontend-multiprocessing",
			VirtualEngineIDs: []int{0}, GenerationHighWater: "1", NextOperationGeneration: "2",
			Admission: "CLOSED", RawSHA256: newCapabilitySHA}}
	backend.createStatus = func(request drainV11CreateRequest) drainV11StatusResponse {
		status := testDrainV11Status(t, request.Owner, nil)
		status.OperationID, status.OperationGeneration, status.Attempt = request.OperationID, request.OperationGeneration, request.Attempt
		status.BackendIncarnationDigest, status.EngineBootID = request.ExpectedIncarnationDigest, backend.capability.EngineBootID
		status.Deadline, status.AdmissionGeneration = request.Deadline, request.OperationGeneration
		deadline, err := time.Parse(time.RFC3339Nano, request.Deadline)
		if err != nil {
			t.Fatal(err)
		}
		status.CancellationGraceDeadline = drainV11Time(deadline.Add(drainV11CancelGrace))
		resignDrainV11Status(t, &status)
		return status
	}
	reader := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(newPod).Build()
	operation := &operationReceipt{Version: operationDrainReceiptVersion, Kind: "warm-swap",
		Phase: "drain-dispatching-v11", DrainAttempts: 1, DrainV11: receipt}
	persisted := 0
	err := recoverDrainV11(t.Context(), EnactCtx{Reader: reader, VLLM: backend},
		servingEndpoint{}, operation, func() error {
			persisted++
			if backend.createCalls != 0 || operation.Phase != "drain-dispatching-v11" ||
				operation.DrainV11.Attempt != 2 || operation.DrainV11.CreateRequests != 1 ||
				operation.DrainV11.Supersedes == nil || operation.DrainV11.Supersedes.OperationID != receipt.OperationID ||
				operation.DrainV11.Supersedes.OperationGeneration != receipt.OperationGeneration ||
				operation.DrainV11.Supersedes.Revision != staleStatus.Revision {
				t.Fatalf("supersession was not durably complete before create: %#v", operation.DrainV11)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if persisted != 1 || backend.statusCalls != 1 || backend.createCalls != 1 ||
		operation.DrainV11.Attempt != 2 || !operation.DrainV11.confirmed() {
		t.Fatalf("stale recovery counts/result: persisted=%d status=%d create=%d receipt=%#v",
			persisted, backend.statusCalls, backend.createCalls, operation.DrainV11)
	}
	if backend.lastCreate.Supersedes == nil || *backend.lastCreate.Supersedes != *operation.DrainV11.Supersedes {
		t.Fatalf("create lost exact supersedes tuple: %#v", backend.lastCreate)
	}
}

func TestReopenDrainV11ReportsInternalStaleWithoutPosting(t *testing.T) {
	pod := drainV11TestPod("stable-kubernetes")
	capabilitySHA, incarnation := strings.Repeat("a", 64), strings.Repeat("b", 64)
	receipt, stale := drainV11ConfirmedReceipt(t, pod, capabilitySHA, incarnation)
	receipt.ReopenRequests = 1
	stale.State, stale.Admission = "STALE", "CLOSED"
	resignDrainV11Status(t, &stale)
	backend := &scriptedDrainV11{t: t, status: stale}
	reader := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod).Build()
	err := reopenDrainV11(t.Context(), EnactCtx{Reader: reader, VLLM: backend}, servingEndpoint{}, receipt)
	if !errors.Is(err, errDrainV11Stale) || backend.statusCalls != 1 || backend.reopenCalls != 0 {
		t.Fatalf("internal restart was not surfaced before reopen: err=%v status=%d reopen=%d", err, backend.statusCalls, backend.reopenCalls)
	}
}

func TestReopenDrainV11RetainsExactOpenedEvidenceForNewAndLostResponses(t *testing.T) {
	for _, lostResponse := range []bool{false, true} {
		t.Run(map[bool]string{false: "post-response", true: "lost-response-get"}[lostResponse], func(t *testing.T) {
			pod, receipt, _, cancelled := drainV11CancellationFixture(t)
			receipt.CancelRequests = 1
			if err := bindDrainV11Status(receipt, cancelled, nil); err != nil || !receipt.cancelled() {
				t.Fatalf("cancelled fixture: receipt=%#v err=%v", receipt, err)
			}
			receipt.ReopenRequests = 1
			opened := cancelled
			opened.State, opened.Admission, opened.Revision = "OPENED", "OPEN", "6"
			resignDrainV11Status(t, &opened)
			backend := &scriptedDrainV11{t: t, status: cancelled, reopenStatus: opened}
			if lostResponse {
				backend.status = opened
				backend.reopenStatus = drainV11StatusResponse{}
			}
			reader := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod).Build()
			if err := reopenDrainV11(t.Context(), EnactCtx{Reader: reader, VLLM: backend}, servingEndpoint{}, receipt); err != nil {
				t.Fatal(err)
			}
			wantPosts := 1
			if lostResponse {
				wantPosts = 0
			}
			if backend.statusCalls != 1 || backend.reopenCalls != wantPosts || receipt.State != "OPENED" ||
				receipt.Revision != "6" || !validDrainV11Hex(receipt.ReceiptSHA256, sha256.Size) ||
				(!lostResponse && receipt.ReceiptSHA256 != opened.ReceiptSHA256) || !receipt.reopenedAfterCancellation() {
				t.Fatalf("opened evidence not retained: status=%d reopen=%d receipt=%#v", backend.statusCalls, backend.reopenCalls, receipt)
			}
		})
	}
}

func drainV11CancellationFixture(t *testing.T) (*corev1.Pod, *drainV11Receipt, drainV11StatusResponse, drainV11StatusResponse) {
	t.Helper()
	pod := drainV11TestPod("cancel")
	owner := drainV11Owner{Tenant: "tenant", NamespaceUID: "namespace", PolicyUID: "policy", PodUID: string(pod.UID), ServiceUID: "service"}
	requesting := testDrainV11Status(t, owner, nil)
	deadline := time.Now().UTC().Add(time.Minute)
	requesting.Deadline = drainV11Time(deadline)
	requesting.CancellationGraceDeadline = drainV11Time(deadline.Add(drainV11CancelGrace))
	requesting.State, requesting.Revision = "CANCEL_REQUESTED", "4"
	requesting.TransitionReason, requesting.CancelBoundaryRevision = "operator-requested", "3"
	requesting.Observations = requesting.Observations[:1]
	resignDrainV11Status(t, &requesting)
	cancelled := requesting
	cancelled.State, cancelled.Revision = "CANCELLED", "5"
	cancelled.Observations = testDrainV11Status(t, owner, nil).Observations
	resignDrainV11Status(t, &cancelled)
	binding, err := drainV11OperatorBinding(pod, strings.Repeat("c", 64), requesting.BackendIncarnationDigest)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &drainV11Receipt{OperationID: requesting.OperationID, OperationGeneration: requesting.OperationGeneration,
		Attempt: 1, ExpectedIncarnation: requesting.BackendIncarnationDigest, LedgerID: strings.Repeat("7", 32),
		ProxyBootID: strings.Repeat("8", 32), EngineBootID: requesting.EngineBootID,
		Deadline: requesting.Deadline, CancelNotBefore: drainV11Time(deadline.Add(-10 * time.Second)),
		CancellationGraceDeadline: requesting.CancellationGraceDeadline, TransitionReason: "none", CancelBoundaryRevision: "0",
		Owner: owner, TargetNamespace: pod.Namespace, TargetName: pod.Name, CapabilitySHA256: strings.Repeat("c", 64),
		ProxySource: "proxy-source", EngineSource: "engine-source", OperatorBinding: binding,
		Revision: "3", State: "DRAINING", OwnerDigest: requesting.OwnerDigest,
		BackendIncarnation: requesting.BackendIncarnationDigest, AdmissionGeneration: requesting.AdmissionGeneration,
		LastTransition: requesting.LastTransition, CreateRequests: 1}
	return pod, receipt, requesting, cancelled
}

func TestRecoverDrainV11CancellationPersistsBeforeOneSendAndGETOnlyCompletes(t *testing.T) {
	pod, receipt, requesting, cancelled := drainV11CancellationFixture(t)
	backend := &scriptedDrainV11{t: t, cancelStatus: requesting, status: cancelled}
	reader := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod).Build()
	operation := &operationReceipt{Version: operationDrainReceiptVersion, Kind: "warm-swap",
		Phase: "drain-dispatching-v11", DrainAttempts: 1, DrainV11: receipt}
	persisted := 0
	err := recoverDrainV11Cancellation(t.Context(), EnactCtx{Reader: reader, VLLM: backend}, servingEndpoint{}, operation, func() error {
		persisted++
		if persisted == 1 && (backend.cancelCalls != 0 || operation.Phase != "drain-cancel-dispatching-v11" || operation.DrainV11.CancelRequests != 1) {
			t.Fatalf("cancel was not durably claimed before send: %#v", operation)
		}
		return nil
	})
	if !errors.Is(err, errDrainV11Cancelled) || backend.cancelCalls != 1 || backend.statusCalls != 1 ||
		operation.Phase != "drain-cancelled-v11" || !operation.DrainV11.cancelled() || persisted < 3 {
		t.Fatalf("cancel recovery = err %v, cancel %d, status %d, persisted %d, receipt %#v",
			err, backend.cancelCalls, backend.statusCalls, persisted, operation.DrainV11)
	}
}

func TestRecoverDrainV11CancellationJournalFailureSendsNothing(t *testing.T) {
	pod, receipt, requesting, _ := drainV11CancellationFixture(t)
	backend := &scriptedDrainV11{t: t, cancelStatus: requesting}
	reader := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod).Build()
	operation := &operationReceipt{Version: operationDrainReceiptVersion, Kind: "request-drain",
		Phase: "drain-dispatching-v11", DrainAttempts: 1, DrainV11: receipt}
	err := recoverDrainV11Cancellation(t.Context(), EnactCtx{Reader: reader, VLLM: backend}, servingEndpoint{}, operation,
		func() error { return errors.New("journal unavailable") })
	if err == nil || backend.cancelCalls != 0 || operation.Phase != "drain-cancel-dispatching-v11" {
		t.Fatalf("journal failure sent cancel: err=%v calls=%d operation=%#v", err, backend.cancelCalls, operation)
	}
}

func TestRecoverDrainV11CancellationLostResponseUsesGETWithoutReplay(t *testing.T) {
	pod, receipt, _, cancelled := drainV11CancellationFixture(t)
	backend := &scriptedDrainV11{t: t, cancelErr: errors.New("lost response"), status: cancelled}
	reader := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod).Build()
	operation := &operationReceipt{Version: operationDrainReceiptVersion, Kind: "request-drain",
		Phase: "drain-dispatching-v11", DrainAttempts: 1, DrainV11: receipt}
	persist := func() error { return nil }
	first := recoverDrainV11Cancellation(t.Context(), EnactCtx{Reader: reader, VLLM: backend}, servingEndpoint{}, operation, persist)
	if first == nil || backend.cancelCalls != 1 || operation.Phase != "drain-cancel-dispatching-v11" {
		t.Fatalf("lost cancel response was not retained: %v %#v", first, operation)
	}
	backend.cancelErr = nil
	second := recoverDrainV11Cancellation(t.Context(), EnactCtx{Reader: reader, VLLM: backend}, servingEndpoint{}, operation, persist)
	if !errors.Is(second, errDrainV11Cancelled) || backend.cancelCalls != 1 || backend.statusCalls != 1 {
		t.Fatalf("cancel was replayed or GET recovery failed: %v cancel=%d status=%d", second, backend.cancelCalls, backend.statusCalls)
	}
}

func TestRecoverDrainV11PropagatesValidatedCancellationBeforeIntentCAS(t *testing.T) {
	for _, alreadyCancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel-requested", true: "cancelled"}[alreadyCancelled], func(t *testing.T) {
			pod, receipt, requesting, cancelled := drainV11CancellationFixture(t)
			// Model a persisted create intent whose first backend response was lost.
			// No unvalidated backend fields may be invented before the exact GET.
			receipt.OwnerDigest, receipt.BackendIncarnation = "", ""
			receipt.Revision, receipt.State, receipt.ReceiptSHA256 = "", "", ""
			receipt.AdmissionGeneration, receipt.LastTransition = "", ""
			receipt.TransitionReason, receipt.CancelBoundaryRevision = "none", "0"
			receipt.ObservationNonces = nil
			receipt.ObservationSequences = nil
			receipt.ObservationHashes = nil
			backend := &scriptedDrainV11{t: t}
			if alreadyCancelled {
				backend.status = cancelled
			} else {
				backend.statusOnQuery = func(_, _, _ string) drainV11StatusResponse {
					if backend.statusCalls == 1 {
						return requesting
					}
					return cancelled
				}
			}
			reader := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod).Build()
			operation := &operationReceipt{Version: operationDrainReceiptVersion, Kind: "request-drain",
				Phase: "drain-dispatching-v11", DrainAttempts: 1, DrainV11: receipt}
			persisted := 0
			err := recoverDrainV11(t.Context(), EnactCtx{Reader: reader, VLLM: backend}, servingEndpoint{}, operation,
				func() error { persisted++; return nil })
			wantState, wantRevision := "CANCEL_REQUESTED", "4"
			if alreadyCancelled {
				wantState, wantRevision = "CANCELLED", "5"
			}
			if !errors.Is(err, errDrainV11CancellationRequired) || persisted != 0 ||
				operation.DrainV11.State != wantState || operation.DrainV11.Revision != wantRevision ||
				operation.DrainV11.OwnerDigest != requesting.OwnerDigest {
				t.Fatalf("validated cancellation was not propagated: err=%v persisted=%d receipt=%#v", err, persisted, operation.DrainV11)
			}
			if cancelErr := recoverDrainV11Cancellation(t.Context(), EnactCtx{Reader: reader, VLLM: backend}, servingEndpoint{}, operation,
				func() error { persisted++; return nil }); !errors.Is(cancelErr, errDrainV11Cancelled) {
				t.Fatalf("propagated cancellation did not complete: %v", cancelErr)
			}
			wantStatus := 1
			if !alreadyCancelled {
				wantStatus = 2
			}
			if backend.cancelCalls != 0 || backend.statusCalls != wantStatus || operation.Phase != "drain-cancelled-v11" {
				t.Fatalf("validated cancellation replayed POST or lost phase: cancel=%d status=%d operation=%#v", backend.cancelCalls, backend.statusCalls, operation)
			}
		})
	}
}

func resignDrainV11Status(t *testing.T, status *drainV11StatusResponse) {
	t.Helper()
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
	if err != nil {
		t.Fatal(err)
	}
}

func TestDrainV11CanonicalJSONMatchesPythonContract(t *testing.T) {
	value := map[string]string{"a": "<tag>&\u2028\u2029\x01", "b": `literal\u2028`}
	got, err := drainV11CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("7b2261223a223c7461673e26e280a8e280a95c7530303031222c2262223a226c69746572616c5c5c7532303238227d")
	if string(got) != string(want) {
		t.Fatalf("canonical bytes mismatch\n got %x\nwant %x", got, want)
	}
	digest, err := drainV11Digest("phorvex-test-v1", value)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "8110fa35f0f6250d8b1b6421e8d959b0259f13ba8d25c90ac5d254e6618b1189" {
		t.Fatalf("cross-language digest = %s", digest)
	}
	owner := map[string]string{"namespace_uid": "ns<>&\u2028", "pod_uid": "pod", "policy_uid": "p\u2029", "service_uid": "svc", "tenant": "租户"}
	digest, err = drainV11Digest("phorvex-test-v1", owner)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "844becbce0b5b7190eb6eb091b29923b07148e486ebaddab80a8ba970f95cefe" {
		t.Fatalf("owner-shaped cross-language digest = %s", digest)
	}
}

func TestDrainV11OperatorBindingPinsSourcesContainersAndReadiness(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "model", Namespace: "tenant",
		UID: types.UID("pod-uid"), Annotations: map[string]string{
			annoDrainProxySource: "proxy-source", annoDrainEngineSource: "engine-source"}},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "vllm", ContainerID: "containerd://vllm", RestartCount: 0},
				{Name: "guardrail", ContainerID: "containerd://guardrail", RestartCount: 0},
			}}}
	if err := drainV11SourceBinding(pod, "proxy-source", "engine-source"); err != nil {
		t.Fatal(err)
	}
	want, err := drainV11OperatorBinding(pod, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil || !validDrainV11Hex(want, 32) {
		t.Fatalf("binding = %q, %v", want, err)
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"source":    func(p *corev1.Pod) { p.Annotations[annoDrainEngineSource] = "changed" },
		"restart":   func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"container": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID = "containerd://replacement" },
		"readiness": func(p *corev1.Pod) { p.Status.Conditions[0].Status = corev1.ConditionFalse },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := pod.DeepCopy()
			mutate(candidate)
			if name == "source" {
				if err := drainV11SourceBinding(candidate, "proxy-source", "engine-source"); err == nil {
					t.Fatal("source drift accepted")
				}
				return
			}
			got, err := drainV11OperatorBinding(candidate, strings.Repeat("a", 64), strings.Repeat("b", 64))
			if err == nil && got == want {
				t.Fatal("runtime identity drift retained the binding")
			}
		})
	}
}

func TestDrainV11RecoveredContainerRestartBindsCurrentIncarnation(t *testing.T) {
	pod := drainV11TestPod("recovered")
	pod.Status.ContainerStatuses[1].RestartCount = 1 // Guardrail restarted before this operation.
	capabilitySHA, incarnation := strings.Repeat("a", 64), strings.Repeat("b", 64)
	binding, err := drainV11OperatorBinding(pod, capabilitySHA, incarnation)
	if err != nil || !validDrainV11Hex(binding, 32) {
		t.Fatalf("stable recovered participant binding = %q, %v", binding, err)
	}
	receipt := &drainV11Receipt{
		TargetNamespace: pod.Namespace, TargetName: pod.Name,
		Owner:            drainV11Owner{PodUID: string(pod.UID)},
		CapabilitySHA256: capabilitySHA, ExpectedIncarnation: incarnation,
		ProxySource: "proxy-source", EngineSource: "engine-source", OperatorBinding: binding,
	}
	authority := func(candidate *corev1.Pod) error {
		reader := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(candidate).Build()
		return drainV11Authority(t.Context(), EnactCtx{Reader: reader}, receipt)
	}
	if err := authority(pod); err != nil {
		t.Fatalf("unchanged current incarnation rejected: %v", err)
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"later restart":        func(p *corev1.Pod) { p.Status.ContainerStatuses[1].RestartCount++ },
		"new container ID":     func(p *corev1.Pod) { p.Status.ContainerStatuses[1].ContainerID = "containerd://replacement" },
		"missing container ID": func(p *corev1.Pod) { p.Status.ContainerStatuses[1].ContainerID = "" },
		"negative restart":     func(p *corev1.Pod) { p.Status.ContainerStatuses[1].RestartCount = -1 },
		"not Ready":            func(p *corev1.Pod) { p.Status.Conditions[0].Status = corev1.ConditionFalse },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := pod.DeepCopy()
			mutate(candidate)
			if err := authority(candidate); err == nil {
				t.Fatal("changed or unavailable participant retained protected authority")
			}
		})
	}
}

func TestBindDrainV11StatusRejectsSelfConsistentMalformedProofWithoutMutation(t *testing.T) {
	nonce := strings.Repeat("6", 32)
	owner := drainV11Owner{Tenant: "tenant", NamespaceUID: "namespace", PolicyUID: "policy", PodUID: "pod", ServiceUID: "service"}
	valid := testDrainV11Status(t, owner, &nonce)
	base := &drainV11Receipt{OperationID: valid.OperationID, OperationGeneration: valid.OperationGeneration, Attempt: 1,
		ExpectedIncarnation: valid.BackendIncarnationDigest, LedgerID: strings.Repeat("7", 32),
		ProxyBootID: strings.Repeat("8", 32), EngineBootID: valid.EngineBootID,
		Deadline: valid.Deadline, CancelNotBefore: "2026-09-20T19:59:50.000000Z",
		CancellationGraceDeadline: valid.CancellationGraceDeadline, TransitionReason: "none", CancelBoundaryRevision: "0",
		Owner: owner, TargetNamespace: "tenant", TargetName: "model",
		CapabilitySHA256: strings.Repeat("c", 64), ProxySource: "proxy-source",
		EngineSource: "engine-source", OperatorBinding: strings.Repeat("d", 64)}
	accepted := *base
	if err := bindDrainV11Status(&accepted, valid, &nonce); err != nil {
		t.Fatalf("valid proof: %v", err)
	}
	if !accepted.confirmed() || accepted.Aborted != 1 {
		t.Fatalf("valid proof not retained: %#v", accepted)
	}
	for name, mutate := range map[string]func(*drainV11Receipt){
		"observation hash":  func(r *drainV11Receipt) { r.ObservationHashes[1] = "bad" },
		"observation order": func(r *drainV11Receipt) { r.ObservationSequences[1] = r.ObservationSequences[0] },
		"snapshot total":    func(r *drainV11Receipt) { r.SnapshotCached++ },
		"capability hash":   func(r *drainV11Receipt) { r.CapabilitySHA256 = "bad" },
		"operator binding":  func(r *drainV11Receipt) { r.OperatorBinding = "bad" },
	} {
		t.Run("durable "+name, func(t *testing.T) {
			candidate := accepted
			candidate.ObservationNonces = append([]string(nil), accepted.ObservationNonces...)
			candidate.ObservationSequences = append([]string(nil), accepted.ObservationSequences...)
			candidate.ObservationHashes = append([]string(nil), accepted.ObservationHashes...)
			mutate(&candidate)
			if candidate.confirmed() {
				t.Fatal("tampered durable proof remained confirmed")
			}
		})
	}

	cases := map[string]func(*drainV11StatusResponse){
		"owner digest":             func(s *drainV11StatusResponse) { s.OwnerDigest = strings.Repeat("f", 64) },
		"attempt":                  func(s *drainV11StatusResponse) { s.Attempt = 2 },
		"deadline":                 func(s *drainV11StatusResponse) { s.Deadline = "2026-09-20T20:00:01Z" },
		"query nonce":              func(s *drainV11StatusResponse) { other := strings.Repeat("9", 32); s.QueryNonce = &other },
		"virtual engines":          func(s *drainV11StatusResponse) { s.VirtualEngineIDs = []int{0, 1} },
		"reused observation nonce": func(s *drainV11StatusResponse) { s.Observations[1].Nonce = s.Observations[0].Nonce },
		"nonzero observation": func(s *drainV11StatusResponse) {
			s.Observations[1].Queues["0"] = drainV11Queues{Waiting: []string{"late"}}
		},
		"missing disposition": func(s *drainV11StatusResponse) { s.TerminalDispositions = map[string]string{} },
		"incomplete proxy snapshot": func(s *drainV11StatusResponse) {
			s.ProxySnapshot = map[string]json.RawMessage{"before_engine_begin": json.RawMessage(`{}`)}
		},
		"revision regression": func(s *drainV11StatusResponse) { s.Revision = "2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := testDrainV11Status(t, owner, &nonce)
			mutate(&candidate)
			resignDrainV11Status(t, &candidate)
			receipt := *base
			if name == "revision regression" {
				receipt.Revision = "3"
			}
			before := receipt
			if err := bindDrainV11Status(&receipt, candidate, &nonce); err == nil {
				t.Fatal("malformed proof accepted")
			}
			if !reflect.DeepEqual(receipt, before) {
				t.Fatalf("receipt mutated on refusal: %#v", receipt)
			}
		})
	}
}
