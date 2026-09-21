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
	cfg.FetchTimeout = 400 * time.Millisecond
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	idsBefore := cluster.serverIDs()
	if len(idsBefore) != 3 || idsBefore[0] == idsBefore[1] || idsBefore[1] == idsBefore[2] {
		t.Fatalf("server IDs are not exact and distinct: %v", idsBefore)
	}
	connectedID := probe.nc.ConnectedServerId()
	restartIndex := -1
	for i, member := range cluster.members {
		if member.srv.ID() != connectedID {
			restartIndex = i
			break
		}
	}
	if restartIndex < 0 {
		t.Fatal("no non-client member available for restart")
	}
	member := cluster.members[restartIndex]
	storeHash := hash([]byte(member.storeDir))
	messageA := Message{ID: "restart-a", Payload: []byte("nonce-bound-restart-payload-a")}
	messageB := Message{ID: "restart-b", Payload: []byte("nonce-bound-restart-payload-b")}
	receipt, err := probe.RunRestartOracle(t.Context(), messageA, messageB, func(context.Context) (RestartBoundaryReceipt, error) {
		started := time.Now()
		oldID, newID := cluster.restart(t, restartIndex)
		return RestartBoundaryReceipt{Member: member.name, ActionAttempted: true, ActionSent: true, ActionCompleted: true, ElapsedNanos: time.Since(started).Nanoseconds(), OldProcessID: oldID, NewProcessID: newID, WorkloadUIDBefore: member.name, WorkloadUIDAfter: member.name, VolumeUIDBefore: storeHash, VolumeUIDAfter: storeHash, StorePathHashBefore: storeHash, StorePathHashAfter: storeHash}, nil
	}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.Baseline.Stream.Members) != 3 || len(receipt.Baseline.Consumer.Members) != 3 || len(receipt.Recovered.Stream.Members) != 3 || len(receipt.Recovered.Consumer.Members) != 3 {
		t.Fatalf("replication receipt=%+v", receipt)
	}
	if receipt.MessageB.Sequence != receipt.MessageA.Sequence+1 || receipt.StoredBefore != receipt.StoredAfter || receipt.FinalState.Messages != 2 || receipt.FinalState.AckFloor < receipt.MessageB.Sequence {
		t.Fatalf("restart oracle receipt=%+v", receipt)
	}
}

func TestRealThreeMemberClusterRetainsAcknowledgedPartialReceiptOnInvalidRestart(t *testing.T) {
	cluster := startRealThreeMemberCluster(t)
	cfg := testConfig(cluster.clientURLs())
	cfg.Replicas = 3
	cfg.RequestTimeout = 3 * time.Second
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	member := cluster.members[2]
	serverID := member.srv.ID()
	receipt, err := probe.RunRestartOracle(t.Context(), Message{ID: "partial-a", Payload: []byte("partial-payload-a")}, Message{ID: "partial-b", Payload: []byte("partial-payload-b")}, func(context.Context) (RestartBoundaryReceipt, error) {
		return RestartBoundaryReceipt{Member: member.name, ActionAttempted: true, ActionSent: true, ActionCompleted: true, ElapsedNanos: 1, OldProcessID: serverID, NewProcessID: serverID, WorkloadUIDBefore: member.name, WorkloadUIDAfter: member.name, VolumeUIDBefore: member.storeDir, VolumeUIDAfter: member.storeDir, StorePathHashBefore: hash([]byte(member.storeDir)), StorePathHashAfter: hash([]byte(member.storeDir))}, nil
	}, 10*time.Second)
	if err == nil || !strings.Contains(err.Error(), "retained the old process identity") {
		t.Fatalf("invalid actual-producer restart passed: %v", err)
	}
	if receipt.MessageA.Sequence == 0 || receipt.DeliveryA.StreamSequence != receipt.MessageA.Sequence || receipt.StoredBefore.StreamSequence != receipt.MessageA.Sequence || !receipt.Restart.ActionSent || receipt.MessageB.Sequence != 0 || receipt.FinalState.Messages != 0 {
		t.Fatalf("partial receipt did not faithfully retain completed producer stages: %+v", receipt)
	}
}

func TestRealThreeMemberClusterNoActionProtocolIsSeparate(t *testing.T) {
	cluster := startRealThreeMemberCluster(t)
	cfg := testConfig(cluster.clientURLs())
	cfg.Replicas = 3
	cfg.RequestTimeout = 3 * time.Second
	probe, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	receipt, err := probe.RunNoActionOracle(t.Context(), Message{ID: "control-a", Payload: []byte("control-payload-a")}, Message{ID: "control-b", Payload: []byte("control-payload-b")}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.MessageB.Sequence != receipt.MessageA.Sequence+1 || receipt.StoredA.StreamSequence != receipt.MessageA.Sequence || receipt.FinalState.Messages != 2 || receipt.FinalState.ConsumerRedelivered != 0 {
		t.Fatalf("no-action receipt=%+v", receipt)
	}
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

func TestRestartBoundaryRequiresChangedProcessAndStableStorageIdentity(t *testing.T) {
	valid := RestartBoundaryReceipt{Member: "nats-2", ActionAttempted: true, ActionSent: true, ActionCompleted: true, ElapsedNanos: 1, OldProcessID: "old", NewProcessID: "new", WorkloadUIDBefore: "pod", WorkloadUIDAfter: "pod", VolumeUIDBefore: "pvc", VolumeUIDAfter: "pvc", StorePathHashBefore: "store", StorePathHashAfter: "store"}
	if err := validateRestartBoundary(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RestartBoundaryReceipt){
		"same process":   func(r *RestartBoundaryReceipt) { r.NewProcessID = r.OldProcessID },
		"changed pod":    func(r *RestartBoundaryReceipt) { r.WorkloadUIDAfter = "replacement" },
		"changed volume": func(r *RestartBoundaryReceipt) { r.VolumeUIDAfter = "foreign" },
		"changed store":  func(r *RestartBoundaryReceipt) { r.StorePathHashAfter = "foreign" },
		"missing member": func(r *RestartBoundaryReceipt) { r.Member = "" },
		"action unsent":  func(r *RestartBoundaryReceipt) { r.ActionSent = false },
		"no attempt":     func(r *RestartBoundaryReceipt) { r.ActionAttempted = false },
	} {
		t.Run(name, func(t *testing.T) {
			receipt := valid
			mutate(&receipt)
			if err := validateRestartBoundary(receipt); err == nil {
				t.Fatalf("invalid restart boundary accepted: %+v", receipt)
			}
		})
	}
}

func TestExactClusterMembershipDoesNotAcceptSameSizedReplacement(t *testing.T) {
	left := ClusterReceipt{Members: []ReplicaMemberReceipt{{Name: "nats-0"}, {Name: "nats-1"}, {Name: "nats-2"}}}
	if !sameClusterMembers(left, left) || !clusterHasMember(left, "nats-1") || clusterHasMember(left, "foreign") {
		t.Fatal("exact member controls rejected their own baseline")
	}
	replaced := ClusterReceipt{Members: []ReplicaMemberReceipt{{Name: "nats-0"}, {Name: "nats-1"}, {Name: "nats-3"}}}
	if sameClusterMembers(left, replaced) {
		t.Fatal("same-sized replacement member set was accepted")
	}
}
