package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// This is an independent, finite HTTP probe of the consumer's broker-backed
// health endpoint. A 503, timeout, unexpected route, or wrong Pod identity is
// UNKNOWN; none is treated as evidence that packet containment succeeded.
func natsResponseProbeHealth(ctx context.Context, addressKind, ip, nonce string, serviceUID, expectedPodUID, otherOriginalUID types.UID, serverIDs map[string]bool) (natsResponseServiceReceipt, error) {
	return natsResponseProbeHealthPort(ctx, addressKind, ip, 8080, nonce, serviceUID, expectedPodUID, otherOriginalUID, serverIDs)
}

func natsResponseProbeHealthMembers(ctx context.Context, addressKind, ip, nonce string, serviceUID, expectedPodUID types.UID,
	allowedServiceMembers map[types.UID]bool, serverIDs map[string]bool) (natsResponseServiceReceipt, error) {
	return natsResponseProbeHealthPortMembers(ctx, addressKind, ip, 8080, nonce, serviceUID, expectedPodUID, allowedServiceMembers, serverIDs)
}

// The Service may route any exact current, API-attested serving member,
// including one admitted ReplicaSet replacement after quarantine. The direct
// original-peer probe supplies the independent legitimate availability control.
func natsResponseBindServiceReceipt(receipt *natsResponseServiceReceipt, before, after natsResponseCurrentControl) error {
	if receipt == nil {
		return errors.New("NATS response Service HTTP receipt absent")
	}
	if receipt.AddressKind != "SERVICE" || receipt.Status != "HTTP_200" || receipt.PodUID == "" ||
		!before.Members[receipt.PodUID] || !after.Members[receipt.PodUID] ||
		before.ServiceIP == "" || before.ServiceIP != after.ServiceIP ||
		before.EndpointSliceUID == "" || before.EndpointSliceUID != after.EndpointSliceUID {
		return errors.New("NATS response Service HTTP answer lacks stable current EndpointSlice membership")
	}
	receipt.EndpointSliceUID = after.EndpointSliceUID
	receipt.EndpointMemberUIDs = nil
	receipt.EndpointMembers = nil
	for uid := range after.Members {
		proof := after.MemberDetails[uid]
		if !before.Members[uid] || !reflect.DeepEqual(before.MemberDetails[uid], proof) ||
			proof.PodUID != uid || proof.PodName == "" || proof.PodIP == "" || proof.OwnerKind == "" ||
			proof.OwnerUID == "" || proof.ContainerID == "" || proof.ImageID == "" || !proof.Ready || proof.RestartCount != 0 {
			return errors.New("NATS response Service membership or member process changed during HTTP probe")
		}
		receipt.EndpointMemberUIDs = append(receipt.EndpointMemberUIDs, uid)
		receipt.EndpointMembers = append(receipt.EndpointMembers, proof)
	}
	sort.Slice(receipt.EndpointMemberUIDs, func(i, j int) bool { return receipt.EndpointMemberUIDs[i] < receipt.EndpointMemberUIDs[j] })
	sort.Slice(receipt.EndpointMembers, func(i, j int) bool { return receipt.EndpointMembers[i].PodUID < receipt.EndpointMembers[j].PodUID })
	return nil
}

func natsResponseProbeHealthPort(ctx context.Context, addressKind, ip string, port int, nonce string, serviceUID, expectedPodUID, otherOriginalUID types.UID, serverIDs map[string]bool) (natsResponseServiceReceipt, error) {
	allowed := map[types.UID]bool{expectedPodUID: true}
	if addressKind == "SERVICE" && otherOriginalUID != "" {
		allowed[otherOriginalUID] = true
	}
	return natsResponseProbeHealthPortMembers(ctx, addressKind, ip, port, nonce, serviceUID, expectedPodUID, allowed, serverIDs)
}

func natsResponseProbeHealthPortMembers(ctx context.Context, addressKind, ip string, port int, nonce string,
	serviceUID, expectedPodUID types.UID, allowedServiceMembers map[types.UID]bool, serverIDs map[string]bool) (natsResponseServiceReceipt, error) {
	receipt := natsResponseServiceReceipt{AddressKind: addressKind, ServiceUID: serviceUID,
		Status: "UNKNOWN", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if (addressKind != "SERVICE" && addressKind != "PEER_DIRECT") || net.ParseIP(ip) == nil ||
		port < 1 || port > 65535 || !natsResponseNonce.MatchString(nonce) || serviceUID == "" || expectedPodUID == "" ||
		len(serverIDs) == 0 || (addressKind == "SERVICE" && len(allowedServiceMembers) == 0) {
		return receipt, errors.New("NATS response health target authority incomplete")
	}
	address := net.JoinHostPort(ip, fmt.Sprint(port))
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: func(c context.Context, network, requested string) (net.Conn, error) {
			if network != "tcp" || requested != address {
				return nil, errors.New("NATS response HTTP dial left exact consumer address")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(c, network, address)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for attempt := 0; attempt < 5; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/ready", nil)
		if err != nil {
			return receipt, err
		}
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 257))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || len(body) > 256 {
				return receipt, errors.New("NATS response health body unavailable or oversized")
			}
			if response.StatusCode == http.StatusOK {
				if err := strictNATSResponseObject(body, map[string]bool{"nonce": true, "podUID": true, "serverID": true}); err != nil {
					return receipt, err
				}
				var got struct {
					Nonce    string `json:"nonce"`
					PodUID   string `json:"podUID"`
					ServerID string `json:"serverID"`
				}
				if json.Unmarshal(body, &got) != nil || got.Nonce != nonce || !serverIDs[got.ServerID] {
					return receipt, errors.New("NATS response HTTP health answered from wrong Pod or broker")
				}
				if (addressKind == "PEER_DIRECT" && got.PodUID != string(expectedPodUID)) ||
					(addressKind == "SERVICE" && !allowedServiceMembers[types.UID(got.PodUID)]) {
					return receipt, errors.New("NATS response HTTP health answered from wrong Pod")
				}
				receipt.PodUID, receipt.ServerID, receipt.Status = types.UID(got.PodUID), got.ServerID, "HTTP_200"
				receipt.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
				return receipt, nil
			}
			if response.StatusCode != http.StatusServiceUnavailable {
				return receipt, fmt.Errorf("NATS response health returned unsupported HTTP %d", response.StatusCode)
			}
		}
		select {
		case <-ctx.Done():
			return receipt, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return receipt, errors.New("NATS response exact healthy consumer not observed")
}
