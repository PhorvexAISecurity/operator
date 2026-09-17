package actuator

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type m077RoundTripper func(*http.Request) (*http.Response, error)

func (f m077RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func m077Endpoint(t *testing.T, rawURL string) servingEndpoint {
	t.Helper()
	hostPort := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return servingEndpoint{podIP: host, port: port, resetPath: "/", healthPath: "/", modelsPath: "/", unloadPath: "/", drainPath: "/"}
}

func m077ClosedEndpoint(t *testing.T) servingEndpoint {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ep := m077Endpoint(t, "http://"+listener.Addr().String())
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return ep
}

func TestM077AcceptedRequestTimeoutIsUnknownForBothHTTPMethods(t *testing.T) {
	for _, kind := range []string{"do", "postJSON"} {
		t.Run(kind, func(t *testing.T) {
			var accepted atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				accepted.Add(1)
				time.Sleep(100 * time.Millisecond)
			}))
			defer server.Close()
			v := &httpVLLM{hc: &http.Client{Timeout: 10 * time.Millisecond}}
			var err error
			if kind == "do" {
				_, _, err = v.do(context.Background(), http.MethodPost, server.URL, "")
			} else {
				_, _, err = v.postJSON(context.Background(), server.URL, "", map[string]string{"operation": "test"})
			}
			if accepted.Load() != 1 || err == nil || !errors.Is(err, errServingOutcomeUnknown) || errors.Is(err, errStackUnreachable) {
				t.Fatalf("accepted request classification: accepted=%d err=%v", accepted.Load(), err)
			}
		})
	}
}

func TestM077CompleteChunkedResponseIsPreservedForBothHTTPMethods(t *testing.T) {
	var accepted atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		accepted.Add(1)
		_, _ = io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "last")
	}))
	defer server.Close()
	v := &httpVLLM{hc: server.Client()}
	for _, kind := range []string{"do", "postJSON"} {
		var code int
		var body string
		var err error
		if kind == "do" {
			code, body, err = v.do(context.Background(), http.MethodPost, server.URL, "")
		} else {
			code, body, err = v.postJSON(context.Background(), server.URL, "", map[string]string{"operation": "test"})
		}
		if err != nil || code != http.StatusOK || body != "firstlast" {
			t.Fatalf("%s complete response: code=%d body=%q err=%v", kind, code, body, err)
		}
	}
	if accepted.Load() != 2 {
		t.Fatalf("requests=%d, want one per method", accepted.Load())
	}
}

func TestM077TruncatedResponseAfterAcceptedRequestIsUnknown(t *testing.T) {
	for _, kind := range []string{"do", "postJSON"} {
		t.Run(kind, func(t *testing.T) {
			var accepted atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				accepted.Add(1)
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					t.Error("response writer cannot hijack")
					return
				}
				conn, out, err := hijacker.Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = out.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
				_ = out.Flush()
				_ = conn.Close()
			}))
			defer server.Close()
			v := &httpVLLM{hc: server.Client()}
			var err error
			if kind == "do" {
				_, _, err = v.do(context.Background(), http.MethodPost, server.URL, "")
			} else {
				_, _, err = v.postJSON(context.Background(), server.URL, "", map[string]string{"operation": "test"})
			}
			if accepted.Load() != 1 || err == nil || !errors.Is(err, errServingOutcomeUnknown) || !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, errStackUnreachable) {
				t.Fatalf("truncated response classification: accepted=%d err=%v", accepted.Load(), err)
			}
		})
	}
}

func TestM077RedirectIsNotFollowedAfterAcceptedPOST(t *testing.T) {
	closed := m077ClosedEndpoint(t)
	location := fmt.Sprintf("http://%s:%d/second", closed.podIP, closed.port)
	var accepted atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		accepted.Add(1)
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	v := &httpVLLM{hc: server.Client()}
	for _, kind := range []string{"do", "postJSON"} {
		var code int
		var err error
		if kind == "do" {
			code, _, err = v.do(context.Background(), http.MethodPost, server.URL, "")
		} else {
			code, _, err = v.postJSON(context.Background(), server.URL, "", map[string]string{"operation": "test"})
		}
		if err != nil || code != http.StatusTemporaryRedirect {
			t.Fatalf("%s redirect result: code=%d err=%v", kind, code, err)
		}
	}
	if accepted.Load() != 2 {
		t.Fatalf("redirected POST repeated or omitted: accepted=%d", accepted.Load())
	}
}

func TestM077OnlyTypedTrustworthyDialFailuresAreUnreachable(t *testing.T) {
	closed := m077ClosedEndpoint(t)
	closedURL := fmt.Sprintf("http://%s:%d/", closed.podIP, closed.port)
	v := newHTTPVLLM()
	for _, kind := range []string{"do", "postJSON"} {
		var err error
		if kind == "do" {
			_, _, err = v.do(context.Background(), http.MethodPost, closedURL, "")
		} else {
			_, _, err = v.postJSON(context.Background(), closedURL, "", map[string]string{"operation": "test"})
		}
		if !errors.Is(err, errStackUnreachable) || !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("%s closed-port classification: %v", kind, err)
		}
	}

	dnsCause := &net.DNSError{Err: "no such host", Name: "missing.invalid", IsNotFound: true}
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, dnsCause
	}}
	defer transport.CloseIdleConnections()
	_, _, err := (&httpVLLM{hc: &http.Client{Transport: transport}}).do(context.Background(), http.MethodGet, "http://missing.invalid/", "")
	var gotDNS *net.DNSError
	if !errors.Is(err, errStackUnreachable) || !errors.As(err, &gotDNS) || gotDNS != dnsCause {
		t.Fatalf("typed DNS cause was not preserved as definite unavailable: %v", err)
	}
}

func TestM077OpaqueAndCustomTransportErrorsRemainUnknown(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: syscall.ECONNREFUSED.Error()}}
	opaque := errors.New("opaque custom transport failure containing refused and timeout")
	for name, cause := range map[string]error{"typed dial from opaque transport": refused, "text only": opaque} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: m077RoundTripper(func(*http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("custom wrapper: %w", cause)
			})}
			_, _, err := (&httpVLLM{hc: client}).postJSON(context.Background(), "http://127.0.0.1/", "", map[string]bool{"test": true})
			if err == nil || !errors.Is(err, errServingOutcomeUnknown) || errors.Is(err, errStackUnreachable) || !errors.Is(err, cause) {
				t.Fatalf("custom transport classification: %v", err)
			}
		})
	}
}

func TestM077CanceledMalformedMarshalAndTLSFailuresKeepCauses(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := newHTTPVLLM().do(canceled, http.MethodPost, "http://127.0.0.1:1/", "")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, errServingOutcomeUnknown) || errors.Is(err, errStackUnreachable) {
		t.Fatalf("canceled request classification: %v", err)
	}

	_, _, malformed := newHTTPVLLM().do(context.Background(), http.MethodPost, "://bad-url", "")
	if malformed == nil || errors.Is(malformed, errStackUnreachable) {
		t.Fatalf("malformed request was hidden: %v", malformed)
	}

	_, _, marshalErr := newHTTPVLLM().postJSON(context.Background(), "http://127.0.0.1/", "", make(chan int))
	var unsupported *json.UnsupportedTypeError
	if !errors.As(marshalErr, &unsupported) || errors.Is(marshalErr, errStackUnreachable) {
		t.Fatalf("marshal cause was lost: %v", marshalErr)
	}

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	_, _, tlsErr := (&httpVLLM{hc: &http.Client{Timeout: time.Second}}).do(context.Background(), http.MethodGet, tlsServer.URL, "")
	var unknownAuthority x509.UnknownAuthorityError
	if tlsErr == nil || !errors.Is(tlsErr, errServingOutcomeUnknown) || errors.Is(tlsErr, errStackUnreachable) || !errors.As(tlsErr, &unknownAuthority) {
		t.Fatalf("TLS cause was lost or treated as definitely unavailable: %v", tlsErr)
	}
}

func TestM077UnknownMutationCannotStampEpochOrUseNoEffectFallback(t *testing.T) {
	var accepted atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		accepted.Add(1)
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	ep := m077Endpoint(t, server.URL)
	pod := aiPod("ns", "infer", map[string]string{})
	pod.Status.PodIP = ep.podIP
	pod.Annotations[annoServingPort] = strconv.Itoa(ep.port)
	pod.Annotations[annoResetPath] = "/"
	c := fakeC(pod)
	result, err := (kvResetHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: &httpVLLM{hc: &http.Client{Timeout: 10 * time.Millisecond}}}, boundReq(pod, model.ActionKVReset))
	if accepted.Load() != 1 || err == nil || result.Emitted || result.MutationKind != "partial" || !strings.Contains(result.Note, "outcome unknown") || errors.Is(err, errStackUnreachable) || IsNoEffectRefusal(err) {
		t.Fatalf("unknown mutation became success/fallback: accepted=%d result=%+v err=%v", accepted.Load(), result, err)
	}
	current := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
		t.Fatal(err)
	}
	if current.Annotations[annoKVResetEpoch] != "" {
		t.Fatal("unknown reset outcome stamped a success epoch")
	}
}

func TestM077RedirectedMutationCannotStampEpochOrRepeatPOST(t *testing.T) {
	closed := m077ClosedEndpoint(t)
	location := fmt.Sprintf("http://%s:%d/repeated", closed.podIP, closed.port)
	const responseMarker = "private-serving-response-marker"
	var accepted atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		accepted.Add(1)
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, responseMarker)
	}))
	defer server.Close()
	ep := m077Endpoint(t, server.URL)
	pod := aiPod("ns", "infer", map[string]string{})
	pod.Status.PodIP = ep.podIP
	pod.Annotations[annoServingPort] = strconv.Itoa(ep.port)
	pod.Annotations[annoResetPath] = "/"
	c := fakeC(pod)
	result, err := (kvResetHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: &httpVLLM{hc: server.Client()}}, boundReq(pod, model.ActionKVReset))
	if accepted.Load() != 1 || err == nil || result.Emitted || result.MutationKind != "partial" || !strings.Contains(result.Note, "outcome unknown") || errors.Is(err, errStackUnreachable) || IsNoEffectRefusal(err) || !strings.Contains(err.Error(), "HTTP 307") || !strings.Contains(err.Error(), responseMarker) {
		t.Fatalf("redirected mutation became success/fallback: accepted=%d result=%+v err=%v", accepted.Load(), result, err)
	}
	if strings.Contains(result.Note, responseMarker) || strings.Contains(result.Note, location) {
		t.Fatalf("retained result Note exposed response or endpoint details: %q", result.Note)
	}
	current := &corev1.Pod{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), current); err != nil {
		t.Fatal(err)
	}
	if current.Annotations[annoKVResetEpoch] != "" {
		t.Fatal("redirected reset outcome stamped a success epoch")
	}
}

func TestM077OtherReceiptlessServingMutationsRetainUnknownOutcome(t *testing.T) {
	var accepted atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		accepted.Add(1)
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	ep := m077Endpoint(t, server.URL)
	hc := &http.Client{Timeout: 10 * time.Millisecond}

	guardPod := guardrailPod("ns", "guard", "v1", "v2")
	guardPod.Status.PodIP = ep.podIP
	guardPod.Annotations[annoServingPort] = strconv.Itoa(ep.port)
	guardPod.Annotations[annoGuardrailPath] = "/"
	guardClient := fakeC(guardPod)
	guardResult, guardErr := (guardrailRotateHandler{}).Enact(context.Background(), EnactCtx{
		Client: guardClient, Guardrail: httpGuardrail{v: &httpVLLM{hc: hc}},
	}, Request{Namespace: guardPod.Namespace, Pod: guardPod.Name, Action: model.ActionGuardrailRotate})
	if guardErr == nil || !errors.Is(guardErr, errServingOutcomeUnknown) || guardResult.Emitted || guardResult.MutationKind != "partial" || !strings.Contains(guardResult.Note, "outcome unknown") {
		t.Fatalf("guardrail unknown outcome was erased: result=%+v err=%v", guardResult, guardErr)
	}
	currentGuard := &corev1.Pod{}
	if err := guardClient.Get(context.Background(), client.ObjectKeyFromObject(guardPod), currentGuard); err != nil {
		t.Fatal(err)
	}
	if currentGuard.Annotations[annoGuardrailVariant] != "v1" || currentGuard.Annotations[annoGuardrailSnap] != "" || currentGuard.Labels["phorvex.ai/guardrail-epoch"] != "" {
		t.Fatalf("guardrail unknown outcome wrote success state: annotations=%v labels=%v", currentGuard.Annotations, currentGuard.Labels)
	}

	kvPod := aiPod("ns", "infer-kv", map[string]string{"app": "infer"})
	kvPod.Status.PodIP = ep.podIP
	kvPod.Annotations[annoServingPort] = strconv.Itoa(ep.port)
	kvPod.Annotations[annoKVInvalidate] = "/"
	kvClient := fakeC(kvPod)
	kvResult, kvErr := (kvMigrateInvalidateHandler{}).Enact(context.Background(), EnactCtx{
		Client: kvClient, KVXfer: httpKVTransfer{v: &httpVLLM{hc: hc}},
	}, Request{Namespace: kvPod.Namespace, Pod: kvPod.Name, Action: model.ActionKVMigrateInvalidate})
	if kvErr == nil || !errors.Is(kvErr, errServingOutcomeUnknown) || kvResult.Emitted || kvResult.MutationKind != "partial" || !strings.Contains(kvResult.Note, "outcome unknown") {
		t.Fatalf("local KV unknown outcome was erased: result=%+v err=%v", kvResult, kvErr)
	}
	currentKV := &corev1.Pod{}
	if err := kvClient.Get(context.Background(), client.ObjectKeyFromObject(kvPod), currentKV); err != nil {
		t.Fatal(err)
	}
	if currentKV.Annotations[annoKVEpoch] != "" {
		t.Fatal("local KV unknown outcome wrote a success epoch")
	}
	if accepted.Load() != 2 {
		t.Fatalf("accepted serving mutations=%d, want 2", accepted.Load())
	}
}

func TestM077ObservationAndDrainFallbackRequireDefiniteUnavailable(t *testing.T) {
	closed := m077ClosedEndpoint(t)
	pod := aiPod("ns", "shadow", map[string]string{labelModelLoaded: "true"})
	pod.Status.PodIP = closed.podIP
	pod.Annotations[annoServingPort] = strconv.Itoa(closed.port)
	ready, pending := shadowModelReady(context.Background(), EnactCtx{VLLM: newHTTPVLLM()}, pod)
	if !ready || !pending {
		t.Fatalf("definite unavailable lost compatibility fallback: ready=%t pending=%t", ready, pending)
	}
	if aborted, drainPending, err := drainInflight(context.Background(), EnactCtx{VLLM: newHTTPVLLM()}, pod); err != nil || aborted != 0 || !drainPending {
		t.Fatalf("definite unavailable drain fallback: aborted=%d pending=%t err=%v", aborted, drainPending, err)
	}

	var accepted atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		accepted.Add(1)
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	ep := m077Endpoint(t, server.URL)
	pod.Status.PodIP = ep.podIP
	pod.Annotations[annoServingPort] = strconv.Itoa(ep.port)
	pod.Annotations[annoHealthPath] = "/"
	pod.Annotations[annoDrainPath] = "/"
	unknownClient := &httpVLLM{hc: &http.Client{Timeout: 10 * time.Millisecond}}
	ready, pending = shadowModelReady(context.Background(), EnactCtx{VLLM: unknownClient}, pod)
	if ready || pending {
		t.Fatalf("unknown health observation authorized fallback: ready=%t pending=%t", ready, pending)
	}
	if aborted, drainPending, err := drainInflight(context.Background(), EnactCtx{VLLM: unknownClient}, pod); err == nil || aborted != 0 || drainPending || !errors.Is(err, errServingOutcomeUnknown) {
		t.Fatalf("unknown drain authorized fallback: aborted=%d pending=%t err=%v", aborted, drainPending, err)
	}
	if accepted.Load() != 2 {
		t.Fatalf("expected one accepted health and drain request, got %d", accepted.Load())
	}
}

func TestM077ModelInventoryFailureAfterHealthResponseCannotFallback(t *testing.T) {
	var health atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		health.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ep := m077Endpoint(t, server.URL)

	// Exercise ModelReady with a client whose first dial reaches health and whose
	// second dial is refused. The complete operation has proven stack reachability.
	var dials atomic.Int64
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if dials.Add(1) == 1 {
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}}
	defer transport.CloseIdleConnections()
	ready, err := (&httpVLLM{hc: &http.Client{Transport: transport}}).ModelReady(context.Background(), servingEndpoint{
		podIP: ep.podIP, port: ep.port, healthPath: "/health", modelsPath: "/models",
	})
	if ready || err == nil || !errors.Is(err, errServingOutcomeUnknown) || errors.Is(err, errStackUnreachable) || !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("models failure after health response authorized fallback: ready=%t err=%v", ready, err)
	}
	if health.Load() != 1 || dials.Load() != 2 {
		t.Fatalf("attempt history health=%d dials=%d", health.Load(), dials.Load())
	}
}
