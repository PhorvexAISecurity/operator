package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

func TestM074ParseDisaggKVPeers(t *testing.T) {
	tooMany := strings.Repeat("peer.example:80,", 32) + "last.example:80"
	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{
		{name: "absent"},
		{name: "whitespace only", raw: " \t\n"},
		{name: "DNS IPv4 IPv6 and dedupe", raw: " EXAMPLE.COM.:080,10.0.0.2:8000,[2001:0db8::1]:00443,example.com:80 ", want: []string{"example.com:80", "10.0.0.2:8000", "[2001:db8::1]:443"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDisaggKVPeers(tc.raw)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parse = %v, %v; want %v", got, err, tc.want)
			}
		})
	}

	invalid := map[string]string{
		"empty element":          "a.example:80,,b.example:80",
		"mixed validity":         "a.example:80,bad",
		"zero port":              "a.example:0",
		"large port":             "a.example:65536",
		"signed port":            "a.example:+80",
		"URL":                    "https://a.example:80",
		"credentials":            "user@a.example:80",
		"path":                   "a.example:80/x",
		"query":                  "a.example:80?q=x",
		"fragment":               "a.example:80#x",
		"embedded whitespace":    "a .example:80",
		"control character":      "a.example:\x0080",
		"unspecified IPv4":       "0.0.0.0:80",
		"unspecified IPv6":       "[::]:80",
		"malformed IPv4":         "999.1.1.1:80",
		"bracketless IPv6":       "2001:db8::1:80",
		"bracketed DNS":          "[decode.example]:8000",
		"bracketed IPv4":         "[127.0.0.1]:8000",
		"IPv6 zone":              "[fe80::1%eth0]:80",
		"bad DNS label":          "-bad.example:80",
		"underscore DNS":         "bad_name.example:80",
		"entry count overflow":   tooMany,
		"declaration byte limit": strings.Repeat("a", 4097),
	}
	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			if got, err := parseDisaggKVPeers(raw); err == nil {
				t.Fatalf("invalid declaration parsed as %v", got)
			}
		})
	}
}

type m074KVRecorder struct {
	calls  *[]string
	peers  []string
	invErr error
	migErr error
}

func (r *m074KVRecorder) InvalidateLocal(context.Context, servingEndpoint) error {
	*r.calls = append(*r.calls, "local")
	return r.invErr
}

func (r *m074KVRecorder) MigrateRemote(_ context.Context, _ servingEndpoint, peers []string) error {
	*r.calls = append(*r.calls, "remote")
	r.peers = append([]string(nil), peers...)
	return r.migErr
}

type m074UpdateRecorder struct {
	client.Client
	calls *[]string
	err   error
}

func (r m074UpdateRecorder) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	*r.calls = append(*r.calls, "epoch")
	if r.err != nil {
		return r.err
	}
	return r.Client.Update(ctx, obj, opts...)
}

func m074KVFixture(t *testing.T, peers string, localErr, remoteErr, updateErr error) (HandlerResult, error, []string, []string, client.Client) {
	t.Helper()
	pod := aiPod("ns", "infer", map[string]string{"app": "infer"})
	pod.Annotations["phorvex.ai/model-id"] = "fixture-model"
	pod.Annotations[annoDisaggPeers] = peers
	base := fakeC(pod)
	calls := []string{}
	recorder := &m074KVRecorder{calls: &calls, invErr: localErr, migErr: remoteErr}
	c := m074UpdateRecorder{Client: base, calls: &calls, err: updateErr}
	hr, err := kvMigrateInvalidateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: base, KVXfer: recorder}, boundReq(pod, model.ActionKVMigrateInvalidate))
	return hr, err, calls, recorder.peers, base
}

func TestM074InvalidPeerDeclarationRefusesBeforeEffects(t *testing.T) {
	hr, err, calls, _, base := m074KVFixture(t, "decode.example:8000,bad", nil, nil, nil)
	if err == nil || hr.Emitted || len(calls) != 0 {
		t.Fatalf("invalid declaration reached an effect: result=%+v err=%v calls=%v", hr, err, calls)
	}
	var pod corev1.Pod
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &pod); err != nil {
		t.Fatal(err)
	}
	if pod.Annotations[annoKVEpoch] != "" {
		t.Fatalf("invalid declaration wrote epoch %q", pod.Annotations[annoKVEpoch])
	}
}

func TestM074KVEffectOrderingAndTruthfulResults(t *testing.T) {
	deferred := errors.New("remote connector deferred [PENDING-GPU-VALIDATION]")
	for _, tc := range []struct {
		name                   string
		peers                  string
		localErr, remoteErr    error
		updateErr              error
		wantCalls, wantPeers   []string
		wantErr, wantEmitted   bool
		wantKind, wantNote     string
		wantEpoch, wantTouched bool
	}{
		{name: "no peers", peers: " \t", wantCalls: []string{"local", "epoch"}, wantEmitted: true, wantKind: "forward-only", wantNote: "not attempted", wantEpoch: true, wantTouched: true},
		{name: "remote confirmed", peers: "DECODE.EXAMPLE.:080,10.0.0.2:8000", wantCalls: []string{"local", "remote", "epoch"}, wantPeers: []string{"decode.example:80", "10.0.0.2:8000"}, wantEmitted: true, wantKind: "forward-only", wantNote: "connector confirmed", wantEpoch: true, wantTouched: true},
		{name: "remote deferred", peers: "decode.example:8000", remoteErr: deferred, wantCalls: []string{"local", "remote", "epoch"}, wantPeers: []string{"decode.example:8000"}, wantErr: true, wantEmitted: true, wantKind: "partial", wantNote: "outcome unconfirmed", wantEpoch: true, wantTouched: true},
		{name: "remote failure", peers: "decode.example:8000", remoteErr: errors.New("HTTP 500"), wantCalls: []string{"local", "remote", "epoch"}, wantPeers: []string{"decode.example:8000"}, wantErr: true, wantEmitted: true, wantKind: "partial", wantNote: "outcome unconfirmed", wantEpoch: true, wantTouched: true},
		{name: "local unreachable", peers: "decode.example:8000", localErr: errStackUnreachable, wantCalls: []string{"local"}, wantKind: "none", wantNote: "no local or cross-worker", wantEpoch: false},
		{name: "local failure", peers: "decode.example:8000", localErr: errors.New("HTTP 500"), wantCalls: []string{"local"}, wantErr: true, wantKind: "partial", wantNote: "outcome unknown", wantEpoch: false},
		{name: "epoch failure after remote success", peers: "decode.example:8000", updateErr: errors.New("write failed"), wantCalls: []string{"local", "remote", "epoch"}, wantPeers: []string{"decode.example:8000"}, wantErr: true, wantEmitted: true, wantKind: "partial", wantNote: "local effect occurred", wantEpoch: false},
		{name: "remote and epoch failure", peers: "decode.example:8000", remoteErr: deferred, updateErr: errors.New("write failed"), wantCalls: []string{"local", "remote", "epoch"}, wantPeers: []string{"decode.example:8000"}, wantErr: true, wantEmitted: true, wantKind: "partial", wantNote: "local effect occurred", wantEpoch: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hr, err, calls, peers, base := m074KVFixture(t, tc.peers, tc.localErr, tc.remoteErr, tc.updateErr)
			if !reflect.DeepEqual(calls, tc.wantCalls) || !reflect.DeepEqual(peers, tc.wantPeers) {
				t.Fatalf("calls=%v peers=%v; want %v %v", calls, peers, tc.wantCalls, tc.wantPeers)
			}
			if (err != nil) != tc.wantErr || hr.Emitted != tc.wantEmitted || hr.MutationKind != tc.wantKind || (tc.wantNote != "" && !strings.Contains(hr.Note, tc.wantNote)) {
				t.Fatalf("result=%+v err=%v", hr, err)
			}
			if (len(hr.ObjectsTouched) > 0) != tc.wantTouched {
				t.Fatalf("objects touched=%v, want present=%v", hr.ObjectsTouched, tc.wantTouched)
			}
			var pod corev1.Pod
			if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "infer"}, &pod); err != nil {
				t.Fatal(err)
			}
			if (pod.Annotations[annoKVEpoch] != "") != tc.wantEpoch {
				t.Fatalf("epoch=%q, want present=%v", pod.Annotations[annoKVEpoch], tc.wantEpoch)
			}
		})
	}
}

func TestM074HTTPKVTransferLocalProducer(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost || r.URL.Path != "/fixture/kv-invalidate" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]bool
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body["local"] {
			t.Errorf("unexpected local invalidation body %v, %v", body, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	ep := servingEndpoint{podIP: host, port: port}.withRoutes("", "", "", "", "/fixture/kv-invalidate")
	if err := (httpKVTransfer{v: newHTTPVLLM()}).InvalidateLocal(context.Background(), ep); err != nil {
		t.Fatalf("local HTTP producer: %v", err)
	}
	if !called {
		t.Fatal("local HTTP producer did not reach the fixture")
	}
}
