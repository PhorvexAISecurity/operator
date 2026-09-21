package jetstreamprobe

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
)

type realClusterMember struct {
	name      string
	storeDir  string
	routePort int
	opts      *server.Options
	srv       *server.Server
}

type realThreeMemberCluster struct {
	members []*realClusterMember
}

func startRealThreeMemberCluster(t *testing.T) *realThreeMemberCluster {
	t.Helper()
	const clusterName = "post25-js-durability"
	routePorts := []int{reserveLocalPort(t), reserveLocalPort(t), reserveLocalPort(t)}
	cluster := &realThreeMemberCluster{}
	for i := range 3 {
		routes := make([]*url.URL, 0, 2)
		for j, port := range routePorts {
			if i == j {
				continue
			}
			route, err := url.Parse(fmt.Sprintf("nats-route://127.0.0.1:%d", port))
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, route)
		}
		member := &realClusterMember{
			name:      fmt.Sprintf("fixture-nats-%d", i),
			storeDir:  filepath.Join(t.TempDir(), "jetstream"),
			routePort: routePorts[i],
		}
		member.opts = &server.Options{
			ServerName:         member.name,
			Host:               "127.0.0.1",
			Port:               -1,
			NoLog:              true,
			NoSigs:             true,
			JetStream:          true,
			JetStreamMaxMemory: 32 << 20,
			JetStreamMaxStore:  64 << 20,
			StoreDir:           member.storeDir,
			Cluster: server.ClusterOpts{
				Name:           clusterName,
				Host:           "127.0.0.1",
				Port:           member.routePort,
				ConnectRetries: 10,
				PoolSize:       1,
			},
			Routes: routes,
		}
		startRealClusterMember(t, member)
		cluster.members = append(cluster.members, member)
	}
	waitForExactRoutes(t, cluster, 4, 10*time.Second)
	waitForJetStreamMetaLeader(t, cluster, 10*time.Second)
	t.Cleanup(func() { cluster.shutdown() })
	return cluster
}

func waitForJetStreamMetaLeader(t *testing.T, cluster *realThreeMemberCluster, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		leaders := 0
		leaderPeers := 0
		for _, member := range cluster.members {
			if member.srv != nil && member.srv.JetStreamIsLeader() {
				leaders++
				leaderPeers = len(member.srv.JetStreamClusterPeers())
			}
		}
		if leaders == 1 && leaderPeers == len(cluster.members) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("JetStream metadata leader did not converge")
}

func reserveLocalPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func startRealClusterMember(t *testing.T, member *realClusterMember) {
	t.Helper()
	opts := *member.opts
	opts.Routes = append([]*url.URL(nil), member.opts.Routes...)
	srv, err := server.NewServer(&opts)
	if err != nil {
		t.Fatalf("create %s: %v", member.name, err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		srv.Shutdown()
		t.Fatalf("%s did not become ready", member.name)
	}
	member.srv = srv
}

func waitForExactRoutes(t *testing.T, cluster *realThreeMemberCluster, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ready := true
		for _, member := range cluster.members {
			if member.srv == nil || member.srv.NumRoutes() != want {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	counts := make([]string, 0, len(cluster.members))
	for _, member := range cluster.members {
		count := -1
		if member.srv != nil {
			count = member.srv.NumRoutes()
		}
		counts = append(counts, fmt.Sprintf("%s=%d", member.name, count))
	}
	t.Fatalf("route convergence failed: %s", strings.Join(counts, ","))
}

func (c *realThreeMemberCluster) clientURLs() string {
	urls := make([]string, 0, len(c.members))
	for _, member := range c.members {
		urls = append(urls, member.srv.ClientURL())
	}
	return strings.Join(urls, ",")
}

func (c *realThreeMemberCluster) serverIDs() []string {
	ids := make([]string, 0, len(c.members))
	for _, member := range c.members {
		ids = append(ids, member.srv.ID())
	}
	sort.Strings(ids)
	return ids
}

func (c *realThreeMemberCluster) restart(t *testing.T, index int) (string, string) {
	t.Helper()
	member := c.members[index]
	oldID := member.srv.ID()
	member.srv.Shutdown()
	member.srv.WaitForShutdown()
	member.srv = nil
	startRealClusterMember(t, member)
	waitForExactRoutes(t, c, 4, 10*time.Second)
	waitForJetStreamMetaLeader(t, c, 10*time.Second)
	newID := member.srv.ID()
	if newID == oldID {
		t.Fatalf("restarted %s retained process server ID %s", member.name, oldID)
	}
	return oldID, newID
}

func (c *realThreeMemberCluster) shutdown() {
	for _, member := range c.members {
		if member.srv != nil {
			member.srv.Shutdown()
		}
	}
	for _, member := range c.members {
		if member.srv != nil {
			member.srv.WaitForShutdown()
			member.srv = nil
		}
	}
}

func TestRealThreeMemberClusterPreservesAcknowledgedMessageAcrossMemberRestart(t *testing.T) {
	cluster := startRealThreeMemberCluster(t)
	cfg := testConfig(cluster.clientURLs())
	cfg.Replicas = 3
	cfg.RequestTimeout = 3 * time.Second
	cfg.RequestTimeout = 3 * time.Second
	cfg.FetchTimeout = 400 * time.Millisecond
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	before, err := probe.WaitCurrentReplicas(t.Context(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Stream.Members) != 3 || len(before.Consumer.Members) != 3 {
		t.Fatalf("baseline replication=%+v", before)
	}
	idsBefore := cluster.serverIDs()
	if len(idsBefore) != 3 || idsBefore[0] == idsBefore[1] || idsBefore[1] == idsBefore[2] {
		t.Fatalf("server IDs are not exact and distinct: %v", idsBefore)
	}

	messageA := Message{ID: "restart-a", Payload: []byte("nonce-bound-restart-payload-a")}
	ackA, err := probe.Publish(t.Context(), messageA, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.ConsumeAndAck(t.Context(), messageA, ackA.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := probe.RequireNoSameConsumerRedelivery(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := probe.GetStored(t.Context(), messageA, ackA.Sequence); err != nil {
		t.Fatal(err)
	}

	connectedID := probe.nc.ConnectedServerId()
	restartIndex := -1
	for i, member := range cluster.members {
		if member.srv.ID() != connectedID && member.name != before.Stream.Leader {
			restartIndex = i
			break
		}
	}
	if restartIndex < 0 {
		for i, member := range cluster.members {
			if member.srv.ID() != connectedID {
				restartIndex = i
				break
			}
		}
	}
	if restartIndex < 0 {
		t.Fatal("no non-client member available for restart")
	}
	oldID, newID := cluster.restart(t, restartIndex)
	if oldID == "" || newID == "" || oldID == newID {
		t.Fatalf("restart IDs old=%q new=%q", oldID, newID)
	}
	after, err := probe.WaitCurrentReplicas(t.Context(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if before.Stream.Cluster != after.Stream.Cluster || before.Stream.Replicas != after.Stream.Replicas {
		t.Fatalf("stream cluster identity changed: before=%+v after=%+v", before.Stream, after.Stream)
	}
	if _, err := probe.GetStored(t.Context(), messageA, ackA.Sequence); err != nil {
		t.Fatalf("message A not stored after member restart: %v", err)
	}

	messageB := Message{ID: "restart-b", Payload: []byte("nonce-bound-restart-payload-b")}
	ackB, err := probe.Publish(t.Context(), messageB, false, ackA.Sequence+1)
	if err != nil {
		t.Fatal(err)
	}
	deliveryB, err := probe.ConsumeAndAck(t.Context(), messageB, ackB.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if deliveryB.StreamSequence != ackB.Sequence || deliveryB.Deliveries != 1 {
		t.Fatalf("message B delivery=%+v ack=%+v", deliveryB, ackB)
	}
	if err := probe.RequireNoSameConsumerRedelivery(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var state StateReceipt
	for time.Now().Before(deadline) {
		state, err = probe.State(t.Context())
		if err == nil && state.Messages == 2 && state.FirstSequence == ackA.Sequence && state.LastSequence == ackB.Sequence && state.AckFloor >= ackB.Sequence && state.AckPending == 0 && state.ConsumerRedelivered == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("post-restart state did not converge: state=%+v err=%v", state, err)
}

func TestWaitCurrentReplicasDoesNotTreatCancellationAsConvergence(t *testing.T) {
	cluster := startRealThreeMemberCluster(t)
	cfg := testConfig(cluster.clientURLs())
	cfg.Replicas = 3
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	if _, err := probe.WaitCurrentReplicas(t.Context(), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := probe.WaitCurrentReplicas(ctx, time.Second); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("canceled replica gate passed: %v", err)
	}
}
