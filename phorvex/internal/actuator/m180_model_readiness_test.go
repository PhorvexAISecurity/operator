package actuator

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type m180HTTPRecorder struct {
	mu     sync.Mutex
	calls  []string
	bodies map[string]string
	codes  map[string]int
}

func (r *m180HTTPRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.calls = append(r.calls, req.Method+" "+req.URL.Path)
	body := r.bodies[req.URL.Path]
	code := r.codes[req.URL.Path]
	r.mu.Unlock()
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

func (r *m180HTTPRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func m180Endpoint(t *testing.T, server *httptest.Server, healthPath, modelsPath string) servingEndpoint {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return servingEndpoint{podIP: host, port: port, healthPath: healthPath, modelsPath: modelsPath}
}

func TestM180ModelReadyRequiresValidatedNonemptyInventory(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		modelCode int
		wantReady bool
		wantErr   bool
	}{
		{name: "empty authoritative inventory", body: `{"data":[]}`},
		{name: "nonempty inventory", body: `{"data":[{"id":"base-model"}]}`, wantReady: true},
		{name: "malformed", body: `{"data":[`, wantErr: true},
		{name: "missing data", body: `{}`, wantErr: true},
		{name: "null data", body: `{"data":null}`, wantErr: true},
		{name: "missing entry id", body: `{"data":[{}]}`, wantErr: true},
		{name: "empty entry id", body: `{"data":[{"id":""}]}`, wantErr: true},
		{name: "non-string entry id", body: `{"data":[{"id":7}]}`, wantErr: true},
		{name: "duplicate id", body: `{"data":[{"id":"a"},{"id":"a"}]}`, wantErr: true},
		{name: "duplicate field", body: `{"data":[],"data":[]}`, wantErr: true},
		{name: "data alias", body: `{"Data":[]}`, wantErr: true},
		{name: "id alias", body: `{"data":[{"ID":"a"}]}`, wantErr: true},
		{name: "trailing value", body: `{"data":[]} {}`, wantErr: true},
		{name: "oversized", body: strings.Repeat("x", servingResponseMaxBytes+1), wantErr: true},
		{name: "models non-200", body: `{"data":[{"id":"base-model"}]}`, modelCode: http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &m180HTTPRecorder{
				bodies: map[string]string{"/health": `{}`, "/models": tc.body},
				codes:  map[string]int{"/models": tc.modelCode},
			}
			server := httptest.NewServer(recorder)
			defer server.Close()
			ready, err := (&httpVLLM{hc: server.Client()}).ModelReady(t.Context(), m180Endpoint(t, server, "/health", "/models"))
			if ready != tc.wantReady || (err != nil) != tc.wantErr {
				t.Fatalf("readiness=%t err=%v, want readiness=%t error=%t", ready, err, tc.wantReady, tc.wantErr)
			}
			calls := recorder.snapshot()
			if strings.Join(calls, ",") != "GET /health,GET /models" {
				t.Fatalf("serving requests=%v, want exactly health then models GET", calls)
			}
			for _, call := range calls {
				if strings.HasPrefix(call, http.MethodPost+" ") {
					t.Fatalf("readiness sent a mutation request: %v", calls)
				}
			}
		})
	}
}

func TestM180ModelReadyHealthAndContextBoundRequests(t *testing.T) {
	t.Run("health refusal stops before inventory", func(t *testing.T) {
		recorder := &m180HTTPRecorder{bodies: map[string]string{"/health": `{}`, "/models": `{"data":[{"id":"model"}]}`}, codes: map[string]int{"/health": http.StatusServiceUnavailable}}
		server := httptest.NewServer(recorder)
		defer server.Close()
		ready, err := (&httpVLLM{hc: server.Client()}).ModelReady(t.Context(), m180Endpoint(t, server, "/health", "/models"))
		if ready || err != nil || strings.Join(recorder.snapshot(), ",") != "GET /health" {
			t.Fatalf("health refusal: ready=%t err=%v calls=%v", ready, err, recorder.snapshot())
		}
	})

	t.Run("canceled before health", func(t *testing.T) {
		recorder := &m180HTTPRecorder{bodies: map[string]string{}}
		server := httptest.NewServer(recorder)
		defer server.Close()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		ready, err := (&httpVLLM{hc: server.Client()}).ModelReady(ctx, m180Endpoint(t, server, "/health", "/models"))
		if ready || !errors.Is(err, context.Canceled) || len(recorder.snapshot()) != 0 {
			t.Fatalf("pre-cancel: ready=%t err=%v calls=%v", ready, err, recorder.snapshot())
		}
	})

	t.Run("canceled between health and inventory", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		transport := &m078CancelAfterHealthTransport{cancel: cancel}
		ready, err := (&httpVLLM{hc: &http.Client{Transport: transport}}).ModelReady(ctx, servingEndpoint{podIP: "127.0.0.1", port: 8000})
		if ready || !errors.Is(err, context.Canceled) || transport.calls != 1 {
			t.Fatalf("mid-readiness cancellation: ready=%t err=%v calls=%d", ready, err, transport.calls)
		}
	})
}

func TestM180AdapterLoadedPreservesAuthoritativeEmptyAbsence(t *testing.T) {
	recorder := &m180HTTPRecorder{bodies: map[string]string{"/models": `{"data":[]}`}, codes: map[string]int{}}
	server := httptest.NewServer(recorder)
	defer server.Close()
	ep := m180Endpoint(t, server, "/health", "/models")
	loaded, err := (&httpVLLM{hc: server.Client()}).AdapterLoaded(t.Context(), ep, "adapter-a")
	if err != nil || loaded || strings.Join(recorder.snapshot(), ",") != "GET /models" {
		t.Fatalf("empty adapter inventory: loaded=%t err=%v calls=%v", loaded, err, recorder.snapshot())
	}
}

func TestM180WarmCandidatesSkipEmptyInventoryWithoutMutation(t *testing.T) {
	recorder := &m180HTTPRecorder{bodies: map[string]string{
		"/health-oldest": `{}`, "/models-oldest": `{"data":[]}`,
		"/health-younger": `{}`, "/models-younger": `{"data":[{"id":"model"}]}`,
	}, codes: map[string]int{}}
	server := httptest.NewServer(recorder)
	defer server.Close()
	ep := m180Endpoint(t, server, "/health", "/models")
	oldest := m078Candidate("oldest", "uid-oldest", ep.podIP, 100)
	younger := m078Candidate("younger", "uid-younger", ep.podIP, 200)
	for p, paths := range map[*corev1.Pod][2]string{
		&oldest:  {"/health-oldest", "/models-oldest"},
		&younger: {"/health-younger", "/models-younger"},
	} {
		p.Annotations[annoServingPort] = strconv.Itoa(ep.port)
		p.Annotations[annoHealthPath] = paths[0]
		p.Annotations[annoModelsPath] = paths[1]
	}
	beforeOldest := oldest.DeepCopy()
	picked, pending, err := m078Pick(t.Context(), &m078InventoryReader{items: []corev1.Pod{younger, oldest}}, &httpVLLM{hc: server.Client()})
	if err != nil || pending || picked == nil || picked.UID != younger.UID {
		t.Fatalf("candidate selection: picked=%v pending=%t err=%v", picked, pending, err)
	}
	if oldest.Labels[labelRole] != beforeOldest.Labels[labelRole] || oldest.ResourceVersion != beforeOldest.ResourceVersion {
		t.Fatalf("empty oldest candidate was mutated: before=%+v after=%+v", beforeOldest, oldest)
	}
	wantCalls := "GET /health-oldest,GET /models-oldest,GET /health-younger,GET /models-younger"
	if calls := recorder.snapshot(); strings.Join(calls, ",") != wantCalls {
		t.Fatalf("candidate readiness requests=%v want=%s", calls, wantCalls)
	}
}

func TestM180AllEmptyInventoriesRefuseWithoutMutationOrReceipt(t *testing.T) {
	recorder := &m180HTTPRecorder{bodies: map[string]string{
		"/health-a": `{}`, "/models-a": `{"data":[]}`,
		"/health-b": `{}`, "/models-b": `{"data":[]}`,
	}, codes: map[string]int{}}
	server := httptest.NewServer(recorder)
	defer server.Close()
	ep := m180Endpoint(t, server, "/health", "/models")
	leader := aiPod("ns", "leader", map[string]string{labelSwapGroup: "group", labelRole: roleLeader})
	leader.CreationTimestamp = metav1.NewTime(time.Unix(50, 0))
	a := m078Candidate("shadow-a", "uid-shadow-a", ep.podIP, 100)
	b := m078Candidate("shadow-b", "uid-shadow-b", ep.podIP, 200)
	for p, suffix := range map[*corev1.Pod]string{&a: "a", &b: "b"} {
		p.Annotations[annoServingPort] = strconv.Itoa(ep.port)
		p.Annotations[annoHealthPath] = "/health-" + suffix
		p.Annotations[annoModelsPath] = "/models-" + suffix
	}
	c := fakeC(leader, &a, &b)
	_, err := warmSwapHandler{}.Enact(t.Context(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", VLLM: &httpVLLM{hc: server.Client()}}, boundReq(leader, model.ActionWarmSwap))
	if err == nil || !strings.Contains(err.Error(), "no Ready model-loaded shadow") {
		t.Fatalf("all-empty inventory was not refused: %v", err)
	}
	for _, before := range []*corev1.Pod{leader, &a, &b} {
		var after corev1.Pod
		if getErr := c.Get(t.Context(), client.ObjectKeyFromObject(before), &after); getErr != nil {
			t.Fatalf("refusal removed %s: %v", before.Name, getErr)
		}
		if after.Labels[labelRole] != before.Labels[labelRole] {
			t.Fatalf("refusal mutated %s role: got=%q want=%q", before.Name, after.Labels[labelRole], before.Labels[labelRole])
		}
	}
	var receipts corev1.ConfigMapList
	if listErr := c.List(t.Context(), &receipts, client.InNamespace("operator")); listErr != nil || len(receipts.Items) != 0 {
		t.Fatalf("all-empty refusal persisted a receipt: count=%d err=%v", len(receipts.Items), listErr)
	}
	if calls := recorder.snapshot(); len(calls) != 4 {
		t.Fatalf("all-empty readiness calls=%v, want exactly four GETs", calls)
	}
	for _, call := range recorder.snapshot() {
		if strings.HasPrefix(call, http.MethodPost+" ") {
			t.Fatalf("all-empty refusal sent a mutation request: %v", recorder.snapshot())
		}
	}
}
