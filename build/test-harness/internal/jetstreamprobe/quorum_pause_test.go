package jetstreamprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const quorumHelperEnv = "PHORVEX_NATS_QUORUM_HELPER"

type quorumHelperConfig struct {
	Name, StoreDir, ReadyFile string
	ClientPort, RoutePort     int
	RoutePorts                []int
}

func TestNATSQuorumServerProcess(t *testing.T) {
	raw := os.Getenv(quorumHelperEnv)
	if raw == "" {
		return
	}
	var cfg quorumHelperConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	routes := make([]*url.URL, 0, len(cfg.RoutePorts)-1)
	for _, port := range cfg.RoutePorts {
		if port == cfg.RoutePort {
			continue
		}
		route, err := url.Parse(fmt.Sprintf("nats-route://127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		routes = append(routes, route)
	}
	opts := &server.Options{ServerName: cfg.Name, Host: "127.0.0.1", Port: cfg.ClientPort, NoLog: true, NoSigs: true, JetStream: true, JetStreamMaxMemory: 32 << 20, JetStreamMaxStore: 64 << 20, StoreDir: cfg.StoreDir, Cluster: server.ClusterOpts{Name: "post25-js-quorum", Host: "127.0.0.1", Port: cfg.RoutePort, ConnectRetries: 20, PoolSize: 1}, Routes: routes}
	srv, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("helper server did not become ready")
	}
	if err := os.WriteFile(cfg.ReadyFile, []byte(srv.ID()), 0600); err != nil {
		t.Fatal(err)
	}
	select {}
}

type quorumProcessMember struct {
	name, storeDir, serverID string
	clientPort               int
	cmd                      *exec.Cmd
	startTicks               uint64
}

func startQuorumProcessCluster(t *testing.T) []*quorumProcessMember {
	t.Helper()
	routePorts := []int{reserveLocalPort(t), reserveLocalPort(t), reserveLocalPort(t)}
	clientPorts := []int{reserveLocalPort(t), reserveLocalPort(t), reserveLocalPort(t)}
	members := make([]*quorumProcessMember, 0, 3)
	for i := range 3 {
		dir := t.TempDir()
		ready := filepath.Join(dir, "ready")
		cfg := quorumHelperConfig{Name: fmt.Sprintf("fixture-nats-%d", i), StoreDir: filepath.Join(dir, "jetstream"), ReadyFile: ready, ClientPort: clientPorts[i], RoutePort: routePorts[i], RoutePorts: routePorts}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestNATSQuorumServerProcess$")
		cmd.Env = append(os.Environ(), quorumHelperEnv+"="+string(raw))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		member := &quorumProcessMember{name: cfg.Name, storeDir: cfg.StoreDir, clientPort: cfg.ClientPort, cmd: cmd}
		members = append(members, member)
		t.Cleanup(func() {
			_ = cmd.Process.Signal(syscall.SIGCONT)
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			value, readErr := os.ReadFile(ready)
			if readErr == nil && len(value) > 0 {
				member.serverID = string(value)
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if member.serverID == "" {
			t.Fatal("NATS helper did not publish its real server ID")
		}
		member.startTicks = processStartTicks(t, cmd.Process.Pid)
	}
	time.Sleep(750 * time.Millisecond)
	return members
}

func processStartTicks(t *testing.T, pid int) uint64 {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndex(string(raw), ")")
	fields := strings.Fields(string(raw)[end+1:])
	if end < 0 || len(fields) < 20 {
		t.Fatalf("invalid proc stat for pid %d", pid)
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || value == 0 {
		t.Fatalf("invalid process start ticks for pid %d: %v", pid, err)
	}
	return value
}

func TestQuorumPublicationsDisableSDKNoResponderRetries(t *testing.T) {
	srv := startServer(t)
	cfg := testConfig(srv.ClientURL())
	responder, err := nats.Connect(cfg.URL, nats.MaxReconnects(0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(responder.Close)
	client, err := nats.Connect(cfg.URL, nats.MaxReconnects(0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	js, err := jetstream.New(client)
	if err != nil {
		t.Fatal(err)
	}
	probe := &Probe{cfg: cfg, nc: client, js: js}
	var requests atomic.Int32
	sub, err := responder.Subscribe(cfg.Subject, func(request *nats.Msg) {
		requests.Add(1)
		reply := &nats.Msg{Subject: request.Reply, Header: nats.Header{}}
		reply.Header.Set("Status", "503")
		reply.Header.Set("Description", "No Responders")
		_ = responder.PublishMsg(reply)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := responder.Flush(); err != nil {
		t.Fatal(err)
	}

	x := Message{ID: "one-send-x", Payload: []byte("one-send-payload-x")}
	attempt := probe.publishAttempt(t.Context(), x)
	if attempt.AttemptCount != 1 || attempt.Acknowledged || attempt.ErrorClass != "no-responders" || requests.Load() != 1 {
		t.Fatalf("one-send X receipt=%+v wire requests=%d", attempt, requests.Load())
	}
	if _, err := probe.publishReconcile(t.Context(), x, 1); !errors.Is(err, jetstream.ErrNoStreamResponse) {
		t.Fatalf("one-send reconciliation error=%v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("two logical operations emitted %d wire publications, want exactly 2", got)
	}
}

func TestRealThreeProcessClusterReconcilesAmbiguousPublicationAfterQuorumPause(t *testing.T) {
	members := startQuorumProcessCluster(t)
	cfg := testConfig(fmt.Sprintf("nats://127.0.0.1:%d", members[0].clientPort))
	cfg.Replicas = 3
	cfg.ConnectTimeout = 2 * time.Second
	cfg.RequestTimeout = 600 * time.Millisecond
	cfg.FetchTimeout = 250 * time.Millisecond
	cfg.DuplicateWindow = 5 * time.Second
	var probe *Probe
	var err error
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		probe, err = Open(t.Context(), cfg)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	if got := probe.ConnectedServerID(); got != members[0].serverID {
		t.Fatalf("client server=%s want=%s", got, members[0].serverID)
	}

	a := Message{ID: "quorum-a", Payload: []byte("quorum-payload-a")}
	x := Message{ID: "quorum-x", Payload: []byte("quorum-payload-x")}
	y := Message{ID: "quorum-y", Payload: []byte("quorum-payload-y")}
	receipt, err := probe.RunQuorumOracle(t.Context(), a, x, y, func(ctx context.Context, observe QuorumObservation) (boundary QuorumPauseReceipt, observation QuorumObservationReceipt, resultErr error) {
		boundary.ConnectedMember = members[0].name
		boundary.MaximumPauseNanos = int64(2 * time.Second)
		for _, member := range members[1:] {
			entry := PausedMemberReceipt{Member: member.name, ServerIDBefore: member.serverID, PID: member.cmd.Process.Pid, PIDStartTimeTicks: member.startTicks, Generation: 1, WorkloadUIDBefore: member.name, VolumeUIDBefore: member.storeDir, StorePathHashBefore: hash([]byte(member.storeDir)), ResumeArmedBeforePause: true, PauseAttempted: true, PauseSent: true}
			if err := member.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
				return boundary, observation, err
			}
			entry.PauseConfirmed = true
			entry.PausedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
			boundary.Members = append(boundary.Members, entry)
		}
		autoResume := time.AfterFunc(2*time.Second, func() {
			for _, member := range members[1:] {
				_ = member.cmd.Process.Signal(syscall.SIGCONT)
			}
		})
		observation, resultErr = observe(ctx)
		for i, member := range members[1:] {
			boundary.Members[i].StillPausedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
			_ = member.cmd.Process.Signal(syscall.SIGCONT)
			boundary.Members[i].ResumeRequested = true
			boundary.Members[i].ResumeConfirmed = true
			boundary.Members[i].ServerIDAfter = member.serverID
			boundary.Members[i].WorkloadUIDAfter = member.name
			boundary.Members[i].VolumeUIDAfter = member.storeDir
			boundary.Members[i].StorePathHashAfter = hash([]byte(member.storeDir))
			boundary.Members[i].ResumedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
		}
		autoResume.Stop()
		pauseStart, _ := time.Parse(time.RFC3339Nano, boundary.Members[1].PausedAtUTC)
		pauseEnd, _ := time.Parse(time.RFC3339Nano, boundary.Members[0].StillPausedAtUTC)
		boundary.ObservedPauseNanos = pauseEnd.Sub(pauseStart).Nanoseconds()
		return boundary, observation, resultErr
	}, 12*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.DuringPause.Publish.AttemptCount != 1 || receipt.DuringPause.Publish.ErrorClass != "timeout-unknown" || !receipt.DuringPause.Ping.Reachable {
		t.Fatalf("quorum observation=%+v", receipt.DuringPause)
	}
	if receipt.ReconciledX.Sequence != receipt.MessageA.Sequence+1 || receipt.MessageY.Sequence != receipt.ReconciledX.Sequence+1 || receipt.StoredX.MessageID != x.ID || receipt.FinalState.Messages != 3 {
		t.Fatalf("quorum receipt=%+v", receipt)
	}
}

func TestQuorumPauseBoundaryRejectsPartialAndWrongProcessAuthority(t *testing.T) {
	baseline := ReplicationReceipt{Stream: ClusterReceipt{Members: []ReplicaMemberReceipt{{Name: "fixture-nats-0"}, {Name: "fixture-nats-1"}, {Name: "fixture-nats-2"}}}, Consumer: ClusterReceipt{Members: []ReplicaMemberReceipt{{Name: "fixture-nats-0"}, {Name: "fixture-nats-1"}, {Name: "fixture-nats-2"}}}}
	base := time.Now().UTC()
	member := func(name string) PausedMemberReceipt {
		return PausedMemberReceipt{Member: name, ServerIDBefore: name + "-id", ServerIDAfter: name + "-id", PID: 10, PIDStartTimeTicks: 20, Generation: 1, WorkloadUIDBefore: name, WorkloadUIDAfter: name, VolumeUIDBefore: name + "-vol", VolumeUIDAfter: name + "-vol", StorePathHashBefore: name + "-store", StorePathHashAfter: name + "-store", ResumeArmedBeforePause: true, PauseAttempted: true, PauseSent: true, PauseConfirmed: true, PausedAtUTC: base.Format(time.RFC3339Nano), StillPausedAtUTC: base.Add(2 * time.Second).Format(time.RFC3339Nano), ResumeRequested: true, ResumeConfirmed: true, ResumedAtUTC: base.Add(3 * time.Second).Format(time.RFC3339Nano)}
	}
	valid := QuorumPauseReceipt{ConnectedMember: "fixture-nats-0", Members: []PausedMemberReceipt{member("fixture-nats-1"), member("fixture-nats-2")}, MaximumPauseNanos: int64(10 * time.Second), ObservedPauseNanos: int64(2 * time.Second), ObservationStartedAtUTC: base.Add(500 * time.Millisecond).Format(time.RFC3339Nano), ObservationFinishedAtUTC: base.Add(time.Second).Format(time.RFC3339Nano), ObservationCalls: 1}
	if err := validateQuorumPauseBoundary(valid, baseline); err != nil {
		t.Fatal(err)
	}
	partial := valid
	partial.Members = partial.Members[:1]
	if err := validateQuorumPauseBoundary(partial, baseline); err == nil {
		t.Fatal("partial pause passed")
	}
	wrongStart := valid
	wrongStart.Members = append([]PausedMemberReceipt(nil), valid.Members...)
	wrongStart.Members[0].PIDStartTimeTicks = 0
	if err := validateQuorumPauseBoundary(wrongStart, baseline); err == nil {
		t.Fatal("missing PID start time passed")
	}
	missingRequestedResume := valid
	missingRequestedResume.Members = append([]PausedMemberReceipt(nil), valid.Members...)
	missingRequestedResume.Members[0].ResumeRequested = false
	if err := validateQuorumPauseBoundary(missingRequestedResume, baseline); err == nil {
		t.Fatal("automatic-only resume passed the positive boundary")
	}
	earlyStopProof := valid
	earlyStopProof.Members = append([]PausedMemberReceipt(nil), valid.Members...)
	earlyStopProof.Members[0].StillPausedAtUTC = base.Add(750 * time.Millisecond).Format(time.RFC3339Nano)
	if err := validateQuorumPauseBoundary(earlyStopProof, baseline); err == nil {
		t.Fatal("stop proof ending before the observation passed")
	}
}

func TestDuplicateWindowUsesEarliestAttemptAndReservesReconcileTimeout(t *testing.T) {
	now := time.Now()
	if !canFinishWithinDuplicateWindow(now, now.Add(-time.Second), 5*time.Second, 2*time.Second) {
		t.Fatal("bounded reconciliation inside the original publication window was refused")
	}
	for name, started := range map[string]time.Time{
		"future attempt":       now.Add(time.Nanosecond),
		"expired attempt":      now.Add(-5 * time.Second),
		"insufficient reserve": now.Add(-3 * time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			if canFinishWithinDuplicateWindow(now, started, 5*time.Second, 2*time.Second) {
				t.Fatal("unsafe same-ID reconciliation window accepted")
			}
		})
	}
	if canFinishWithinDuplicateWindow(now, now, 5*time.Second, 0) {
		t.Fatal("zero reconciliation reserve accepted")
	}
}

func TestQuorumObservationCancellationRemainsUnknown(t *testing.T) {
	srv := startServer(t)
	probe, err := Open(t.Context(), testConfig(srv.ClientURL()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probe.Close)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	receipt := probe.publishAttempt(ctx, Message{ID: "canceled-x", Payload: []byte("canceled-payload")})
	if receipt.AttemptCount != 1 || receipt.Acknowledged || receipt.Ack != nil || receipt.ErrorClass != "canceled-unknown" || receipt.StartedAtUTC == "" || receipt.FinishedAtUTC == "" {
		t.Fatalf("canceled actual-client publication receipt=%+v", receipt)
	}
	state, err := probe.State(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.Messages != 0 {
		t.Fatalf("pre-canceled actual-client publication changed stream state: %+v", state)
	}
}
