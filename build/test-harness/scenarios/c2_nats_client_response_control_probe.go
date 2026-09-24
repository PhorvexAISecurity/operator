package scenarios

import (
	"context"
	"errors"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// The Service request and peer-direct request use separate sockets and
// independent API snapshots. A source answer from the Service is allowed only
// while that original UID remains a current serving endpoint; it never stands
// in for the peer-direct legitimate workload control.
func natsResponseProbeControls(ctx context.Context, env *core.Env, fixture natsResponseFixture,
	policySpec map[string]any, route natsRouteIdentity, requireSourceReady bool) (natsResponseServiceReceipt, natsResponseServiceReceipt, error) {
	service := natsResponseServiceReceipt{AddressKind: "SERVICE", ServiceUID: fixture.ServiceUID, Status: "UNKNOWN"}
	peer := natsResponseServiceReceipt{AddressKind: "PEER_DIRECT", ServiceUID: fixture.ServiceUID, Status: "UNKNOWN"}
	before, err := natsResponseCurrentControls(ctx, env, fixture, policySpec, requireSourceReady)
	if err != nil {
		return service, peer, err
	}
	if err := requireNATSRoute(ctx, env, route); err != nil {
		return service, peer, err
	}
	allowed := make(map[string]bool, len(route.Brokers))
	for _, broker := range route.Brokers {
		allowed[broker.ServerID] = true
	}
	service, err = natsResponseProbeHealth(ctx, "SERVICE", before.ServiceIP,
		env.Config.NATSExposureFixture.Nonce, fixture.ServiceUID, fixture.Peer.UID, fixture.Client.UID, allowed)
	if err != nil {
		return service, peer, err
	}
	middle, err := natsResponseCurrentControls(ctx, env, fixture, policySpec, requireSourceReady)
	if err != nil {
		return service, peer, err
	}
	if err := natsResponseBindServiceReceipt(&service, before, middle); err != nil {
		return service, peer, err
	}
	peer, err = natsResponseProbeHealth(ctx, "PEER_DIRECT", fixture.Peer.IP,
		env.Config.NATSExposureFixture.Nonce, fixture.ServiceUID, fixture.Peer.UID, "", allowed)
	if err != nil {
		return service, peer, err
	}
	after, err := natsResponseCurrentControls(ctx, env, fixture, policySpec, requireSourceReady)
	if err != nil {
		return service, peer, err
	}
	if err := natsResponseBindServiceReceipt(&service, middle, after); err != nil {
		return service, peer, err
	}
	if !middle.Members[fixture.Peer.UID] || !after.Members[fixture.Peer.UID] ||
		peer.PodUID != fixture.Peer.UID || peer.Status != "HTTP_200" ||
		service.ServiceUID != fixture.ServiceUID || peer.ServiceUID != fixture.ServiceUID {
		return service, peer, errors.New("NATS response legitimate peer or Service identity not independently available")
	}
	if err := requireNATSRoute(ctx, env, route); err != nil {
		return service, peer, err
	}
	return service, peer, nil
}
