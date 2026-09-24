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
	proof := func(uid types.UID) natsResponseServiceMember {
		return natsResponseServiceMember{PodUID: uid, PodName: string(uid), PodIP: "192.0.2.8", OwnerKind: "ReplicaSet",
			OwnerUID: "rs-uid", ContainerID: "containerd://" + string(uid), ImageID: "image@sha256:owned", Ready: true}
	}
	before := natsResponseCurrentControl{ServiceIP: "10.0.0.1", EndpointSliceUID: "slice-uid",
		Members:       map[types.UID]bool{"source-uid": true, "peer-uid": true},
		MemberDetails: map[types.UID]natsResponseServiceMember{"source-uid": proof("source-uid"), "peer-uid": proof("peer-uid")}}
	after := natsResponseCurrentControl{ServiceIP: "10.0.0.1", EndpointSliceUID: "slice-uid",
		Members: map[types.UID]bool{"peer-uid": true}, MemberDetails: map[types.UID]natsResponseServiceMember{"peer-uid": proof("peer-uid")}}
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
	before.Members, after.Members = map[types.UID]bool{"peer-uid": true, "replacement-uid": true}, map[types.UID]bool{"peer-uid": true, "replacement-uid": true}
	before.MemberDetails["replacement-uid"], after.MemberDetails["replacement-uid"] = proof("replacement-uid"), proof("replacement-uid")
	receipt.PodUID = "replacement-uid"
	if err := natsResponseBindServiceReceipt(&receipt, before, after); err != nil || len(receipt.EndpointMembers) != 2 {
		t.Fatalf("attested replacement Service answer refused: %+v %v", receipt, err)
	}
	after.MemberDetails["replacement-uid"] = natsResponseServiceMember{PodUID: "replacement-uid", OwnerKind: "ReplicaSet", OwnerUID: "other-rs"}
	if err := natsResponseBindServiceReceipt(&receipt, before, after); err == nil {
		t.Fatal("changed replacement process accepted between snapshots")
	}
}

func TestNATSResponseServiceProbeAdmitsOnlyCurrentReplacementUID(t *testing.T) {
	const nonce = "0123456789abcdef01234567"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"nonce":%q,"podUID":"replacement-uid","serverID":"NATS-A"}`, nonce)
	}))
	defer srv.Close()
	ip, rawPort, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(rawPort)
	allowed := map[types.UID]bool{"peer-uid": true, "replacement-uid": true}
	good, err := natsResponseProbeHealthPortMembers(t.Context(), "SERVICE", ip, port, nonce, "service-uid", "peer-uid", allowed, map[string]bool{"NATS-A": true})
	if err != nil || good.PodUID != "replacement-uid" {
		t.Fatalf("current replacement Service answer refused: %+v %v", good, err)
	}
	if _, err := natsResponseProbeHealthPortMembers(t.Context(), "SERVICE", ip, port, nonce, "service-uid", "peer-uid",
		map[types.UID]bool{"peer-uid": true}, map[string]bool{"NATS-A": true}); err == nil {
		t.Fatal("unadmitted replacement Service response accepted")
	}
	if _, err := natsResponseProbeHealthPortMembers(t.Context(), "PEER_DIRECT", ip, port, nonce, "service-uid", "peer-uid",
		allowed, map[string]bool{"NATS-A": true}); err == nil {
		t.Fatal("replacement substituted for exact legitimate peer")
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
