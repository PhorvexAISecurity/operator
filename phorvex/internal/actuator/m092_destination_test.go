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
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

func m092PodForServer(t *testing.T, rawURL string) *corev1.Pod {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "infer", UID: "pod-uid", ResourceVersion: "1",
			Annotations: map[string]string{annoServingPort: portText},
		},
		Status: corev1.PodStatus{PodIP: host},
	}
}

func TestM092AllServingRoutesAreValidatedBeforeAnyRequest(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()

	routes := []string{annoResetPath, annoHealthPath, annoModelsPath, annoUnloadPath, annoLoadPath, annoDrainPath, annoGuardrailPath, annoKVInvalidate}
	for _, annotation := range routes {
		t.Run(annotation, func(t *testing.T) {
			pod := m092PodForServer(t, server.URL)
			pod.Annotations[annotation] = "@alternate.invalid/escape"
			ep := endpointForPod(pod)
			before := requests.Load()
			err := newHTTPVLLM().ResetPrefixCache(context.Background(), ep)
			if !errors.Is(err, errServingConfiguration) {
				t.Fatalf("malformed %s was not a configuration error: %v", annotation, err)
			}
			if got := requests.Load(); got != before {
				t.Fatalf("malformed %s reached HTTP: requests %d -> %d", annotation, before, got)
			}
		})
	}
}

func TestM092EveryPublicServingMethodChecksCompleteEndpoint(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	pod := m092PodForServer(t, server.URL)
	pod.Annotations[annoKVInvalidate] = "/v1/%2fescape"
	ep := endpointForPod(pod)

	methods := map[string]func() error{
		"model-ready": func() error { _, err := newHTTPVLLM().ModelReady(context.Background(), ep); return err },
		"reset":       func() error { return newHTTPVLLM().ResetPrefixCache(context.Background(), ep) },
		"unload":      func() error { return newHTTPVLLM().UnloadAdapter(context.Background(), ep, "adapter") },
		"inventory": func() error {
			_, err := newHTTPVLLM().AdapterLoaded(context.Background(), ep, "adapter")
			return err
		},
		"load":  func() error { return newHTTPVLLM().LoadAdapter(context.Background(), ep, "adapter", "/models/adapter") },
		"drain": func() error { _, err := newHTTPVLLM().DrainRequests(context.Background(), ep); return err },
		"guard": func() error {
			return (httpGuardrail{v: newHTTPVLLM()}).ApplyVariant(context.Background(), ep, "v2")
		},
		"kv-invalidate": func() error {
			return (httpKVTransfer{v: newHTTPVLLM()}).InvalidateLocal(context.Background(), ep)
		},
	}
	for name, call := range methods {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, errServingConfiguration) {
				t.Fatalf("complete endpoint was not rejected: %v", err)
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("malformed unused route allowed %d HTTP request(s)", requests.Load())
	}
}

func TestM092ModelReadyRejectsMalformedSecondRouteBeforeHealth(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	pod := m092PodForServer(t, server.URL)
	pod.Annotations[annoHealthPath] = "/health"
	pod.Annotations[annoModelsPath] = "//alternate.invalid/models"

	ready, err := newHTTPVLLM().ModelReady(context.Background(), endpointForPod(pod))
	if ready || !errors.Is(err, errServingConfiguration) || requests.Load() != 0 {
		t.Fatalf("second-route error was not prior to health: ready=%t requests=%d err=%v", ready, requests.Load(), err)
	}
}

func TestM092ValidDefaultAndOverrideRoutesReachOnlySelectedPod(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/models"):
			_, _ = w.Write([]byte(`{"data":[{"id":"adapter"}]}`))
		case strings.HasSuffix(r.URL.Path, "/drain"):
			_, _ = w.Write([]byte(`{"aborted":1}`))
		case strings.HasSuffix(r.URL.Path, "/health"):
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/reset"):
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	for _, tc := range []struct {
		name   string
		prefix string
	}{
		{name: "defaults"},
		{name: "overrides", prefix: "/custom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := m092PodForServer(t, server.URL)
			if tc.prefix != "" {
				pod.Annotations[annoResetPath] = tc.prefix + "/reset"
				pod.Annotations[annoHealthPath] = tc.prefix + "/health"
				pod.Annotations[annoModelsPath] = tc.prefix + "/models"
				pod.Annotations[annoUnloadPath] = tc.prefix + "/unload"
				pod.Annotations[annoLoadPath] = tc.prefix + "/load"
				pod.Annotations[annoDrainPath] = tc.prefix + "/drain"
				pod.Annotations[annoGuardrailPath] = tc.prefix + "/guard"
				pod.Annotations[annoKVInvalidate] = tc.prefix + "/kv"
			}
			ep, err := validatedEndpointForPod(pod)
			if err != nil {
				t.Fatal(err)
			}
			v := newHTTPVLLM()
			ready, err := v.ModelReady(context.Background(), ep)
			if err != nil || !ready {
				t.Fatalf("ModelReady ready=%t err=%v", ready, err)
			}
			if err := v.ResetPrefixCache(context.Background(), ep); err != nil {
				t.Fatal(err)
			}
			if err := v.UnloadAdapter(context.Background(), ep, "adapter"); err != nil {
				t.Fatal(err)
			}
			loaded, err := v.AdapterLoaded(context.Background(), ep, "adapter")
			if err != nil || !loaded {
				t.Fatalf("AdapterLoaded loaded=%t err=%v", loaded, err)
			}
			if err := v.LoadAdapter(context.Background(), ep, "adapter", "/models/adapter"); err != nil {
				t.Fatal(err)
			}
			aborted, err := v.DrainRequests(context.Background(), ep)
			if err != nil || aborted != 1 {
				t.Fatalf("DrainRequests aborted=%d err=%v", aborted, err)
			}
			if err := (httpGuardrail{v: v}).ApplyVariant(context.Background(), ep, "v2"); err != nil {
				t.Fatal(err)
			}
			if err := (httpKVTransfer{v: v}).InvalidateLocal(context.Background(), ep); err != nil {
				t.Fatal(err)
			}
		})
	}

	mu.Lock()
	defer mu.Unlock()
	for path, want := range map[string]int{
		defaultHealthPath: 1, defaultModelsPath: 2, defaultResetPath: 1,
		defaultUnloadPath: 1, defaultLoadPath: 1, defaultDrainPath: 1,
		defaultGuardPath: 1, defaultKVInvPath: 1,
		"/custom/health": 1, "/custom/models": 2, "/custom/reset": 1,
		"/custom/unload": 1, "/custom/load": 1, "/custom/drain": 1,
		"/custom/guard": 1, "/custom/kv": 1,
	} {
		if hits[path] != want {
			t.Errorf("path %s hits=%d want=%d (all=%v)", path, hits[path], want, hits)
		}
	}
}

func TestM092ServingRouteSyntaxAndEndpointAuthority(t *testing.T) {
	invalidPaths := []string{"", "relative", "//authority/path", "@authority/path", "/with?query", "/with#fragment", "/back\\slash", "/a/../b", "/a//b", "/%2e%2e/escape", "/line\nbreak", " /space"}
	for _, raw := range invalidPaths {
		t.Run(strconv.Quote(raw), func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{annoResetPath: raw}}, Status: corev1.PodStatus{PodIP: "127.0.0.1"}}
			if _, err := validatedEndpointForPod(pod); !errors.Is(err, errServingConfiguration) {
				t.Fatalf("invalid route %q accepted: %v", raw, err)
			}
		})
	}

	for _, tc := range []struct {
		name, ip, port, wantBase string
	}{
		{name: "IPv4", ip: "127.0.0.1", port: " 8080 ", wantBase: "http://127.0.0.1:8080"},
		{name: "IPv6", ip: "2001:db8::1", port: "8443", wantBase: "http://[2001:db8::1]:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{annoServingPort: tc.port, annoHealthPath: "/ready/live"}}, Status: corev1.PodStatus{PodIP: tc.ip}}
			ep, err := validatedEndpointForPod(pod)
			if err != nil || ep.base() != tc.wantBase || ep.healthPath != "/ready/live" {
				t.Fatalf("validated endpoint=%+v err=%v", ep, err)
			}
		})
	}

	for _, tc := range []struct{ name, ip, port string }{
		{name: "hostname", ip: "pod.ns.svc", port: "8000"},
		{name: "IP whitespace", ip: " 127.0.0.1", port: "8000"},
		{name: "empty explicit port", ip: "127.0.0.1", port: ""},
		{name: "zero port", ip: "127.0.0.1", port: "0"},
		{name: "large port", ip: "127.0.0.1", port: "65536"},
		{name: "nonnumeric port", ip: "127.0.0.1", port: "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{annoServingPort: tc.port}}, Status: corev1.PodStatus{PodIP: tc.ip}}
			if _, err := validatedEndpointForPod(pod); !errors.Is(err, errServingConfiguration) {
				t.Fatalf("invalid endpoint accepted: %v", err)
			}
		})
	}

	unscheduled := &corev1.Pod{}
	ep, err := validatedEndpointForPod(unscheduled)
	if err != nil || ep.reachable() {
		t.Fatalf("missing Pod IP must remain unavailable, not malformed: ep=%+v err=%v", ep, err)
	}
}

func TestM092ProxyAndRedirectCannotReceiveServingBearer(t *testing.T) {
	const token = "synthetic-m092-token"
	var selected, alternate, proxied atomic.Int64
	alternateServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		alternate.Add(1)
	}))
	defer alternateServer.Close()
	proxyServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		proxied.Add(1)
	}))
	defer proxyServer.Close()
	selectedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selected.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("selected receiver authorization=%q", got)
		}
		w.Header().Set("Location", alternateServer.URL+"/escape")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer selectedServer.Close()
	pod := m092PodForServer(t, selectedServer.URL)
	pod.Annotations[annoServingTok] = token

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	defer transport.CloseIdleConnections()
	err = (&httpVLLM{hc: &http.Client{Transport: transport}}).ResetPrefixCache(context.Background(), endpointForPod(pod))
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect response was not returned at the selected destination: %v", err)
	}
	if selected.Load() != 1 || alternate.Load() != 0 || proxied.Load() != 0 {
		t.Fatalf("destination containment selected=%d alternate=%d proxy=%d", selected.Load(), alternate.Load(), proxied.Load())
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("serving error exposed bearer token: %v", err)
	}
}

func TestM092ExtendedHandlerRejectsMalformedUnusedRouteBeforeEffects(t *testing.T) {
	pod := guardrailPod("ns", "guard", "v1", "v2")
	pod.Status.PodIP = "127.0.0.1"
	pod.Annotations[annoKVInvalidate] = "//alternate.invalid/unused"
	kube := fakeC(pod)
	recorder := &recordingGuardrail{}
	result, err := (guardrailRotateHandler{}).Enact(context.Background(), EnactCtx{Client: kube, Guardrail: recorder}, Request{Namespace: pod.Namespace, Pod: pod.Name, Action: model.ActionGuardrailRotate})
	if err == nil || !IsNoEffectRefusal(err) || result.Emitted || len(recorder.variants) != 0 {
		t.Fatalf("malformed complete endpoint reached extended effect: result=%+v variants=%v err=%v", result, recorder.variants, err)
	}
	current := &corev1.Pod{}
	if err := kube.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
		t.Fatal(err)
	}
	if current.Annotations[annoGuardrailVariant] != "v1" || current.Annotations[annoGuardrailSnap] != "" || current.Labels["phorvex.ai/guardrail-epoch"] != "" {
		t.Fatalf("malformed complete endpoint wrote guardrail state: annotations=%v labels=%v", current.Annotations, current.Labels)
	}
}

func TestM075RawKVHandlerRequiresExactDeclaredServingTarget(t *testing.T) {
	var requests atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != defaultKVInvPath {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()
	receiverURL, _ := url.Parse(receiver.URL)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort("127.0.0.1", strconv.Itoa(defaultServePort)) {
			return nil, errors.New("unexpected default serving destination " + address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, receiverURL.Host)
	}
	defer transport.CloseIdleConnections()
	kv := httpKVTransfer{v: &httpVLLM{hc: &http.Client{Transport: transport}}}

	negative := []struct {
		name   string
		mutate func(*corev1.Pod)
		uid    string
	}{
		{name: "ordinary Pod"},
		{name: "generic app", mutate: func(p *corev1.Pod) { p.Labels["app"] = "web" }},
		{name: "GPU only", mutate: func(p *corev1.Pod) {
			p.Spec.Containers = []corev1.Container{{Name: "worker", Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("1")}}}}
		}},
		{name: "whitespace model", mutate: func(p *corev1.Pod) { p.Annotations["phorvex.ai/model-id"] = " \t " }},
		{name: "invalid explicit port", mutate: func(p *corev1.Pod) {
			p.Annotations["phorvex.ai/model-id"] = "cpu-model"
			p.Annotations[annoServingPort] = "0"
		}},
		{name: "invalid Pod IP", mutate: func(p *corev1.Pod) {
			p.Annotations["phorvex.ai/model-id"] = "cpu-model"
			p.Status.PodIP = "pod.ns.svc"
		}},
		{name: "target UID mismatch", mutate: func(p *corev1.Pod) { p.Annotations["phorvex.ai/model-id"] = "cpu-model" }, uid: "replacement"},
	}
	for _, tc := range negative {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "infer", UID: "pod-uid", ResourceVersion: "1", Labels: map[string]string{}, Annotations: map[string]string{}}, Status: corev1.PodStatus{PodIP: "127.0.0.1"}}
			if tc.mutate != nil {
				tc.mutate(pod)
			}
			uid := tc.uid
			if uid == "" {
				uid = string(pod.UID)
			}
			kube := fakeC(pod)
			before := requests.Load()
			result, err := (kvMigrateInvalidateHandler{}).Enact(context.Background(), EnactCtx{Client: kube, Reader: kube, KVXfer: kv}, Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: uid, Action: model.ActionKVMigrateInvalidate})
			if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || requests.Load() != before {
				t.Fatalf("undeclared or mismatched Pod was not refused: result=%+v requests=%d->%d err=%v", result, before, requests.Load(), err)
			}
			current := &corev1.Pod{}
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
				t.Fatal(err)
			}
			if current.Annotations[annoKVEpoch] != "" {
				t.Fatalf("refused Pod acquired KV epoch %q", current.Annotations[annoKVEpoch])
			}
		})
	}
}

func TestM075RawKVHandlersUseAuthoritativePodBeforeHTTP(t *testing.T) {
	var requests atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()

	for _, authority := range []string{"same-name replacement", "declaration removed"} {
		for _, action := range []model.Action{model.ActionKVReset, model.ActionKVMigrateInvalidate} {
			t.Run(authority+"/"+string(action), func(t *testing.T) {
				cached := m092PodForServer(t, receiver.URL)
				cached.Annotations["phorvex.ai/model-id"] = "cached-model"
				current := cached.DeepCopy()
				current.ResourceVersion = "2"
				switch authority {
				case "same-name replacement":
					current.UID = "replacement-uid"
				case "declaration removed":
					delete(current.Annotations, "phorvex.ai/model-id")
					delete(current.Annotations, annoServingPort)
				}
				writer := fakeC(cached)
				reader := fakeC(current)
				req := Request{Namespace: cached.Namespace, Pod: cached.Name, TargetUID: string(cached.UID), Action: action}
				before := requests.Load()
				var result HandlerResult
				var err error
				if action == model.ActionKVReset {
					result, err = (kvResetHandler{}).Enact(context.Background(), EnactCtx{Client: writer, Reader: reader, VLLM: newHTTPVLLM()}, req)
				} else {
					result, err = (kvMigrateInvalidateHandler{}).Enact(context.Background(), EnactCtx{Client: writer, Reader: reader, KVXfer: httpKVTransfer{v: newHTTPVLLM()}}, req)
				}
				if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || requests.Load() != before {
					t.Fatalf("stale cached authority crossed boundary: result=%+v requests=%d->%d err=%v", result, before, requests.Load(), err)
				}
				stored := &corev1.Pod{}
				if err := writer.Get(context.Background(), client.ObjectKeyFromObject(cached), stored); err != nil {
					t.Fatal(err)
				}
				if stored.Annotations[annoKVResetEpoch] != "" || stored.Annotations[annoKVEpoch] != "" {
					t.Fatalf("stale cached target acquired epoch: %v", stored.Annotations)
				}
			})
		}
	}
}

func TestM075RawKVHandlerPreservesDeclaredCPUAndPortServingTargets(t *testing.T) {
	var requests atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != defaultKVInvPath {
			t.Errorf("path=%q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()
	for _, declaration := range []string{"model", "port"} {
		t.Run(declaration, func(t *testing.T) {
			pod := m092PodForServer(t, receiver.URL)
			v := newHTTPVLLM()
			if declaration == "model" {
				pod.Annotations["phorvex.ai/model-id"] = "cpu-model"
				delete(pod.Annotations, annoServingPort)
				u, _ := url.Parse(receiver.URL)
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.Proxy = nil
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					if address != net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(defaultServePort)) {
						return nil, errors.New("unexpected default serving destination " + address)
					}
					return (&net.Dialer{}).DialContext(ctx, network, u.Host)
				}
				defer transport.CloseIdleConnections()
				v = &httpVLLM{hc: &http.Client{Transport: transport}}
			} else {
				delete(pod.Annotations, "phorvex.ai/model-id")
			}
			kube := fakeC(pod)
			before := requests.Load()
			result, err := (kvMigrateInvalidateHandler{}).Enact(context.Background(), EnactCtx{Client: kube, Reader: kube, KVXfer: httpKVTransfer{v: v}}, boundReq(pod, model.ActionKVMigrateInvalidate))
			if err != nil || !result.Emitted || requests.Load() != before+1 {
				t.Fatalf("declared target failed: result=%+v requests=%d->%d err=%v", result, before, requests.Load(), err)
			}
			current := &corev1.Pod{}
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
				t.Fatal(err)
			}
			if current.Annotations[annoKVEpoch] == "" {
				t.Fatal("confirmed local invalidation did not write KV epoch")
			}
		})
	}
}
