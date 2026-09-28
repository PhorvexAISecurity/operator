package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Use the real HTTP decoder and request-bound refusal producer. The runtime
// counterpart exercises the real FastAPI+Coordinator producer through 64 drains.
type capacityHTTPBackend struct {
	mockVLLM
	http                   *httpVLLM
	ep                     servingEndpoint
	cap                    drainV11CapabilityResponse
	body, contentType      string
	code, creates, queries int
	onCreate               func()
	lostResponse           bool
}

func capacityBackend(t *testing.T, pod *corev1.Pod) *capacityHTTPBackend {
	t.Helper()
	b := &capacityHTTPBackend{http: &httpVLLM{}, body: `{"error":"ledger_capacity"}`, contentType: "application/json", code: 503}
	b.cap, _ = (&mockVLLM{}).DrainV11Capability(context.Background(), servingEndpoint{})
	b.cap.PodUID = string(pod.UID)
	b.cap.GenerationHighWater, b.cap.NextOperationGeneration = "64", "65"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer capacity-test-token" {
			t.Errorf("authenticated endpoint token not bound")
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", b.contentType)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/drain/capability":
			_ = json.NewEncoder(w).Encode(b.cap)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/drain/operations":
			b.creates++
			if b.onCreate != nil {
				b.onCreate()
			}
			if b.lostResponse {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
				return
			}
			w.WriteHeader(b.code)
			_, _ = w.Write([]byte(b.body))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/drain/operations/"):
			b.queries++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":"unknown_operation"}`))
		default:
			t.Errorf("unexpected effect request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(server.Close)
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	b.ep = servingEndpoint{scheme: "http", podIP: host, port: port, drainPath: "/v1/drain", token: "capacity-test-token", client: server.Client()}
	return b
}

func (b *capacityHTTPBackend) DrainV11Capability(ctx context.Context, _ servingEndpoint) (drainV11CapabilityResponse, error) {
	return b.http.DrainV11Capability(ctx, b.ep)
}
func (b *capacityHTTPBackend) DrainV11Create(ctx context.Context, _ servingEndpoint, request drainV11CreateRequest) (drainV11StatusResponse, error) {
	return b.http.DrainV11Create(ctx, b.ep, request)
}
func (b *capacityHTTPBackend) DrainV11Status(ctx context.Context, _ servingEndpoint, generation, id, nonce string) (drainV11StatusResponse, error) {
	return b.http.DrainV11Status(ctx, b.ep, generation, id, nonce)
}

func drainCapacityReceipts(t *testing.T, c client.Client) []corev1.ConfigMap {
	t.Helper()
	var list corev1.ConfigMapList
	if err := c.List(context.Background(), &list, client.InNamespace("operator"), client.MatchingLabels{journalLabel: "v1"}); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

func TestDrainV11CapacityPreflightRefusesBeforeRouteWithdrawal(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	backend := capacityBackend(t, pod)
	backend.cap.NextOperationGeneration = ""
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, backend), requestDrainReq(pod))
	current := getDrainPod(t, controller)
	if err == nil || !IsNoEffectRefusal(err) || result.Emitted || backend.creates != 0 ||
		current.Labels[labelServing] != "true" || current.Labels[labelDrainEpoch] != "" || len(drainCapacityReceipts(t, controller)) != 0 {
		t.Fatalf("full ledger changed routing: result=%+v pod=%v creates=%d err=%v", result, current.Labels, backend.creates, err)
	}
}

func TestDrainV11CapacityRefusalRestoresRouteWithoutAbortProof(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	backend := capacityBackend(t, pod)
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, backend), requestDrainReq(pod))
	current := getDrainPod(t, controller)
	if err == nil || !result.Emitted || result.DrainOperation != nil || backend.creates != 1 || backend.queries != 0 ||
		current.Labels[labelServing] != "true" || current.Labels[labelDrainEpoch] == "" || len(drainCapacityReceipts(t, controller)) != 0 ||
		!strings.Contains(result.Note, "no backend drain or abort") || !strings.Contains(result.Note, "endpoint membership restored") {
		t.Fatalf("capacity restoration claimed defense or stranded route: result=%+v pod=%v creates=%d queries=%d err=%v", result, current.Labels, backend.creates, backend.queries, err)
	}
}

type capacityProofAckClient struct {
	client.Client
	accept, failed bool
}

func (c *capacityProofAckClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if cm, ok := obj.(*corev1.ConfigMap); ok && !c.failed && strings.Contains(cm.Data["receipt"], `"phase":"drain-rejected-v11"`) {
		c.failed = true
		if c.accept {
			if err := c.Client.Update(ctx, obj, opts...); err != nil {
				return err
			}
		}
		return errors.New("create rejection proof CAS acknowledgment lost")
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestDrainV11CapacityRejectionProofAckLossRequiresDurableRestartProof(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(strconv.FormatBool(accepted), func(t *testing.T) {
			pod, _, _, controller := requestDrainFixture(t, "true")
			backend := capacityBackend(t, pod)
			fault := &capacityProofAckClient{Client: controller, accept: accepted}
			result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(fault, backend), requestDrainReq(pod))
			if err == nil || result.DrainOperation != nil || getDrainPod(t, controller).Labels[labelServing] != "drained" || !fault.failed {
				t.Fatalf("lost proof acknowledgment speculatively restored: %+v %v", result, err)
			}
			journal := drainCapacityReceipts(t, controller)
			if len(journal) != 1 {
				t.Fatalf("lost proof journal absent: %v", journal)
			}
			native := &NativeActuator{Client: controller, Reader: controller, JournalNamespace: "operator", RecoveryVLLM: backend}
			events, recoverErr := native.RecoverOperations(context.Background(), false)
			if recoverErr != nil || len(events) != 1 || backend.creates != 1 {
				t.Fatalf("recovery replayed create: %v %v", events, recoverErr)
			}
			current := getDrainPod(t, controller)
			if accepted {
				if current.Labels[labelServing] != "true" || events[0].Outcome != "confirmed" || !strings.Contains(events[0].Effect, "no backend drain or abort") || len(drainCapacityReceipts(t, controller)) != 0 {
					t.Fatalf("durable rejection did not restore safely: %v %v", current.Labels, events)
				}
			} else if current.Labels[labelServing] != "drained" || events[0].Outcome == "confirmed" || len(drainCapacityReceipts(t, controller)) != 1 {
				t.Fatalf("404 invented missing rejection proof: %v %v", current.Labels, events)
			}
		})
	}
}

func TestDrainV11CapacityHTTPRejectsUnboundOrAmbiguousErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body, media string
		code              int
	}{
		{"unavailable", `{"error":"drain_unavailable"}`, "application/json", 503},
		{"missing", `{}`, "application/json", 503},
		{"duplicate", `{"error":"ledger_capacity","error":"ledger_capacity"}`, "application/json", 503},
		{"unknown", `{"error":"ledger_capacity","extra":true}`, "application/json", 503},
		{"trailing", `{"error":"ledger_capacity"}{}`, "application/json", 503},
		{"malformed", `{"error":`, "application/json", 503},
		{"null", `{"error":null}`, "application/json", 503},
		{"oversized", `{"error":"ledger_capacity","padding":"` + strings.Repeat("a", drainV11MaxBody) + `"}`, "application/json", 503},
		{"media", `{"error":"ledger_capacity"}`, "text/plain", 503},
		{"status", `{"error":"ledger_capacity"}`, "application/json", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, _, _, _ := requestDrainFixture(t, "true")
			backend := capacityBackend(t, pod)
			backend.body, backend.contentType, backend.code = tc.body, tc.media, tc.code
			_, err := backend.DrainV11Create(context.Background(), servingEndpoint{}, drainV11CreateFromReceipt(preparedDrainV11Fixture()))
			var rejected *drainV11CreateRejectedError
			if err == nil || errors.As(err, &rejected) {
				t.Fatalf("ambiguous response authorized restore: %v", err)
			}
		})
	}
}

func TestDrainV11CapacityLostResponseAndNonCapacity503RemainProtected(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(strconv.FormatBool(lost), func(t *testing.T) {
			pod, _, _, controller := requestDrainFixture(t, "true")
			backend := capacityBackend(t, pod)
			backend.lostResponse = lost
			if !lost {
				backend.body = `{"error":"drain_unavailable"}`
			}
			result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, backend), requestDrainReq(pod))
			if err == nil || result.DrainOperation != nil || getDrainPod(t, controller).Labels[labelServing] != "drained" || len(drainCapacityReceipts(t, controller)) != 1 {
				t.Fatalf("ambiguous create restored: %+v %v", result, err)
			}
			native := &NativeActuator{Client: controller, Reader: controller, JournalNamespace: "operator", RecoveryVLLM: backend}
			_, _ = native.RecoverOperations(context.Background(), false)
			if backend.creates != 1 || getDrainPod(t, controller).Labels[labelServing] != "drained" || len(drainCapacityReceipts(t, controller)) != 1 {
				t.Fatal("unknown GET triggered replay or route restore")
			}
		})
	}
}

func TestDrainV11CapacityRejectionCannotRestoreChangedAuthority(t *testing.T) {
	for _, change := range []string{"generation", "incarnation", "proxy-boot", "engine-boot", "ledger", "source", "capability-pod", "closed", "service", "epoch", "pod-ip", "replacement"} {
		t.Run(change, func(t *testing.T) {
			pod, service, _, controller := requestDrainFixture(t, "true")
			backend := capacityBackend(t, pod)
			wantServing := "drained"
			backend.onCreate = func() {
				switch change {
				case "generation":
					backend.cap.GenerationHighWater, backend.cap.NextOperationGeneration = "65", "66"
				case "incarnation":
					backend.cap.IncarnationDigest = strings.Repeat("f", 64)
				case "proxy-boot":
					backend.cap.ProxyBootID = strings.Repeat("f", 32)
				case "engine-boot":
					backend.cap.EngineBootID = strings.Repeat("f", 32)
				case "ledger":
					backend.cap.LedgerID = strings.Repeat("f", 32)
				case "source":
					backend.cap.ProxySource = "other-source"
				case "capability-pod":
					backend.cap.PodUID = "other-pod"
				case "closed":
					backend.cap.Admission, backend.cap.NextOperationGeneration = "CLOSED", ""
				case "service":
					current := &corev1.Service{}
					if err := controller.Get(context.Background(), client.ObjectKeyFromObject(service), current); err != nil {
						t.Fatal(err)
					}
					current.UID = types.UID("replacement-service")
					if err := controller.Update(context.Background(), current); err != nil {
						t.Fatal(err)
					}
				default:
					current := getDrainPod(t, controller)
					if change == "epoch" {
						current.Labels[labelDrainEpoch] = "another-operation"
					}
					if change == "pod-ip" {
						current.Status.PodIP = "192.0.2.200"
					}
					if change == "replacement" {
						current.UID = types.UID("replacement-pod")
						current.Labels[labelServing] = "standby"
						wantServing = "standby"
					}
					if change == "pod-ip" {
						if err := controller.Status().Update(context.Background(), current); err != nil {
							t.Fatal(err)
						}
					} else if err := controller.Update(context.Background(), current); err != nil {
						t.Fatal(err)
					}
				}
			}
			result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, backend), requestDrainReq(pod))
			if err == nil || result.DrainOperation != nil || getDrainPod(t, controller).Labels[labelServing] != wantServing || len(drainCapacityReceipts(t, controller)) != 1 || backend.creates != 1 {
				t.Fatalf("changed %s authority restored: result=%+v pod=%v err=%v", change, result, getDrainPod(t, controller).Labels, err)
			}
		})
	}
}

func TestDrainV11CapacityRejectionReceiptCannotChangeRequestOrPhase(t *testing.T) {
	r := preparedDrainV11Fixture()
	r.CreateRequests = 1
	requestSHA, err := drainV11Digest("phorvex-drain-create-v1", drainV11CreateFromReceipt(r))
	if err != nil {
		t.Fatal(err)
	}
	r.CreateRejection = &drainV11CreateRejection{HTTPStatus: 503, Code: "ledger_capacity", RequestSHA256: requestSHA, ResponseSHA256: strings.Repeat("a", 64), CapabilitySHA256: strings.Repeat("b", 64), GenerationHighWater: "0"}
	if !r.rejected() || !r.prepared() {
		t.Fatal("valid rejection proof refused")
	}
	r.OperationID = strings.Repeat("f", 32)
	if r.rejected() || r.prepared() {
		t.Fatal("rejection proof accepted a different request")
	}
	r.OperationID = strings.Repeat("1", 32)
	r.State = "QUIESCENT"
	if r.prepared() || r.confirmed() {
		t.Fatal("create rejection became abort proof")
	}
}

func TestDrainV11CapacityDurableRecoveryRechecksCurrentAuthority(t *testing.T) {
	for _, change := range []string{"generation", "incarnation", "closed", "policy-uid", "policy-generation-disabled", "endpoint", "container", "epoch"} {
		t.Run(change, func(t *testing.T) {
			pod, _, _, controller := requestDrainFixture(t, "true")
			backend := capacityBackend(t, pod)
			if change == "container" {
				current := getDrainPod(t, controller)
				current.Annotations[annoDrainProxySource], current.Annotations[annoDrainEngineSource] = backend.cap.ProxySource, backend.cap.EngineSource
				if err := controller.Update(context.Background(), current); err != nil {
					t.Fatal(err)
				}
				current.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "guardrail", ContainerID: "containerd://proxy"}, {Name: "vllm", ContainerID: "containerd://engine"}}
				current.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
				if err := controller.Status().Update(context.Background(), current); err != nil {
					t.Fatal(err)
				}
			}
			fault := &capacityProofAckClient{Client: controller, accept: true}
			_, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(fault, backend), requestDrainReq(pod))
			if err == nil || getDrainPod(t, controller).Labels[labelServing] != "drained" {
				t.Fatal("durable restart fixture not withdrawn")
			}
			switch change {
			case "generation":
				backend.cap.GenerationHighWater, backend.cap.NextOperationGeneration = "65", "66"
			case "incarnation":
				backend.cap.IncarnationDigest = strings.Repeat("e", 64)
			case "closed":
				backend.cap.Admission, backend.cap.NextOperationGeneration = "CLOSED", ""
			case "policy-uid", "policy-generation-disabled":
				pol := &v1alpha1.PhorvexPolicy{}
				if err := controller.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "policy"}, pol); err != nil {
					t.Fatal(err)
				}
				if change == "policy-uid" {
					pol.UID = types.UID("replacement-policy")
				} else {
					pol.Generation++
					pol.Spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionQuarantine}
				}
				if err := controller.Update(context.Background(), pol); err != nil {
					t.Fatal(err)
				}
			default:
				current := getDrainPod(t, controller)
				if change == "endpoint" {
					current.Annotations[annoServingPort] = "8081"
				}
				if change == "epoch" {
					current.Labels[labelDrainEpoch] = "other-operation"
				}
				if change == "container" {
					current.Status.ContainerStatuses[0].RestartCount++
				}
				if change == "container" {
					if err := controller.Status().Update(context.Background(), current); err != nil {
						t.Fatal(err)
					}
				} else if err := controller.Update(context.Background(), current); err != nil {
					t.Fatal(err)
				}
			}
			native := &NativeActuator{Client: controller, Reader: controller, JournalNamespace: "operator", RecoveryVLLM: backend}
			events, err := native.RecoverOperations(context.Background(), false)
			if err != nil || len(events) != 1 || events[0].Outcome == "confirmed" || getDrainPod(t, controller).Labels[labelServing] != "drained" || len(drainCapacityReceipts(t, controller)) != 1 || backend.creates != 1 {
				t.Fatalf("durable %s drift restored or replayed: %v %v", change, events, err)
			}
		})
	}
}

func TestDrainV11CapacityPostRestoreDriftRetainsProofWithoutCompletion(t *testing.T) {
	pod, _, _, controller := requestDrainFixture(t, "true")
	backend := capacityBackend(t, pod)
	controller.patchErr = func(current *corev1.Pod) error {
		if current.Labels[labelServing] == "true" && current.Labels[labelDrainEpoch] != "" {
			backend.cap.Admission, backend.cap.NextOperationGeneration = "CLOSED", ""
		}
		return nil
	}
	result, err := requestDrainHandler{}.Enact(context.Background(), requestDrainEC(controller, backend), requestDrainReq(pod))
	if err == nil || result.DrainOperation != nil || len(drainCapacityReceipts(t, controller)) != 1 || !strings.Contains(result.Note, "before restoration confirmation") {
		t.Fatalf("backend change after label CAS received terminal credit: %+v %v", result, err)
	}
	journal := drainCapacityReceipts(t, controller)[0]
	if !strings.Contains(journal.Data["receipt"], `"phase":"drain-rejected-v11"`) {
		t.Fatal("post-CAS drift lost protected rejection phase")
	}
}
