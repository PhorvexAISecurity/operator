package scenarios

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

func TestNATSResponseServiceAnswerRequiresStableEndpointMembership(t *testing.T) {
	before := natsResponseCurrentControl{ServiceIP: "10.0.0.1", EndpointSliceUID: "slice-uid", Members: map[types.UID]bool{"source-uid": true, "peer-uid": true}}
	after := natsResponseCurrentControl{ServiceIP: "10.0.0.1", EndpointSliceUID: "slice-uid", Members: map[types.UID]bool{"peer-uid": true}}
	receipt := natsResponseServiceReceipt{AddressKind: "SERVICE", Status: "HTTP_200", PodUID: "source-uid"}
	if err := natsResponseBindServiceReceipt(&receipt, before, after); err == nil {
		t.Fatal("source HTTP response retained availability credit after exact source endpoint left Service")
	}
	receipt.PodUID = "peer-uid"
	if err := natsResponseBindServiceReceipt(&receipt, before, after); err != nil || receipt.EndpointSliceUID != "slice-uid" || len(receipt.EndpointMemberUIDs) != 1 || receipt.EndpointMemberUIDs[0] != "peer-uid" {
		t.Fatalf("stable original peer endpoint refused: %v", err)
	}
	after.Members = map[types.UID]bool{"replacement-uid": true}
	if err := natsResponseBindServiceReceipt(&receipt, before, after); err == nil {
		t.Fatal("same-name replacement endpoint accepted")
	}
}

func TestNATSResponseHTTPRequiresExactPeerAndServer(t *testing.T) {
	const nonce = "0123456789abcdef01234567"
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" || r.Method != http.MethodGet {
			t.Error("wrong health route")
		}
		uid := "source-uid"
		if calls.Add(1) > 1 {
			uid = "peer-uid"
		}
		_, _ = fmt.Fprintf(w, `{"nonce":%q,"podUID":%q,"serverID":"NATS-A"}`, nonce, uid)
	}))
	defer srv.Close()
	address := strings.TrimPrefix(srv.URL, "http://")
	ip, portRaw, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portRaw)
	got, err := natsResponseProbeHealthPort(t.Context(), "SERVICE", ip, port, nonce, "service-uid", "peer-uid", "source-uid", map[string]bool{"NATS-A": true})
	if err != nil || got.Status != "HTTP_200" || got.PodUID != "source-uid" || calls.Load() != 1 {
		t.Fatalf("Service did not preserve actual original source response: %+v %v calls=%d", got, err, calls.Load())
	}
	peerResult, err := natsResponseProbeHealthPort(t.Context(), "PEER_DIRECT", ip, port, nonce, "service-uid", "peer-uid", "", map[string]bool{"NATS-A": true})
	if err != nil || peerResult.PodUID != "peer-uid" {
		t.Fatalf("separate original peer direct health absent: %+v %v", peerResult, err)
	}
	if _, err := natsResponseProbeHealthPort(t.Context(), "PEER_DIRECT", ip, port, nonce, "service-uid", "wrong-peer", "", map[string]bool{"NATS-A": true}); err == nil {
		t.Fatal("wrong direct peer identity accepted")
	}
	if _, err := natsResponseProbeHealthPort(t.Context(), "PEER_DIRECT", ip, port, nonce, "service-uid", "peer-uid", "", map[string]bool{"FOREIGN": true}); err == nil {
		t.Fatal("wrong broker process identity accepted")
	}
}

func TestNATSResponseHTTP503AndRedirectRemainUnknown(t *testing.T) {
	const nonce = "0123456789abcdef01234567"
	for name, status := range map[string]int{"unready": http.StatusServiceUnavailable, "redirect": http.StatusFound} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "http://example.invalid/")
				w.WriteHeader(status)
			}))
			defer srv.Close()
			ip, portRaw, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			port, _ := strconv.Atoi(portRaw)
			got, err := natsResponseProbeHealthPort(context.Background(), "PEER_DIRECT", ip, port, nonce, "service-uid", "peer-uid", "", map[string]bool{"NATS-A": true})
			if err == nil || got.Status != "UNKNOWN" || got.PodUID != "" {
				t.Fatalf("non-200 became service availability: %+v %v", got, err)
			}
		})
	}
}
