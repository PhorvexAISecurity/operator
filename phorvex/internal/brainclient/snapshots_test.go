package brainclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/brainclient"
	"github.com/phorvex/phorvex/internal/brainpb"
	"github.com/phorvex/phorvex/internal/brainsvc"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/mathlab"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func serveSnapshotRPC(t *testing.T, service brainpb.BrainServiceServer, timeout time.Duration) (*brainclient.Client, brainpb.BrainServiceClient) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(wire.MaxMessageBytes), grpc.MaxSendMsgSize(wire.MaxMessageBytes))
	brainpb.RegisterBrainServiceServer(srv, service)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///brain-snapshots", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := brainclient.New(ctx, conn, brainclient.Options{Config: testConfig, CallTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return client, brainpb.NewBrainServiceClient(conn)
}

func TestRemoteSnapshotRelayUsesRealRecorderStoreAndAuditRoute(t *testing.T) {
	recon.Registry.SetDefault("ucw-recon")
	engine := decision.NewCoverageEngine()
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	engine.Now = func() time.Time { return now }
	store, err := mathlab.OpenStore(t.TempDir(), 64<<20, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go store.Run(ctx)
	recorder, err := mathlab.NewRecorder(mathlab.Config{Policies: []string{"vllm/vllm-defense"}, GPUEnvelopeMax: cost.GPUEnvelopeMax(),
		ProducerIdentity: &mathlab.CaptureIdentity{GitSHA: strings.Repeat("b", 40), BrainImage: "brain:stage@sha256:" + strings.Repeat("2", 64)}}, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := serveSnapshotRPC(t, brainsvc.NewServer(brainsvc.NewLocal(engine, recorder), testConfig.SHA256(), brainsvc.WithSnapshotSource(store)), 5*time.Second)
	if client.SnapshotSource() == nil {
		t.Fatal("actual brain store not advertised")
	}
	pol := fixturePolicy()
	// Use the manager's real spec-to-policy resolution. The generic wire-parity
	// fixture's manually assigned default label weight is not a policy API value.
	spec := v1alpha1.PhorvexPolicySpec{AssetValue: v1alpha1.AssetValueSpec{FromLabels: map[string]v1alpha1.LabelValueWeights{"data-class": {"restricted": "1"}}}}
	pol.AssetWeights = spec.AssetLabelWeights()
	log := &gateLog{}
	decisions, recording, err := client.Decide(brainapi.DecideRequest{Views: fleet(), Policy: pol, Gate: log.gate(), Capture: &brainapi.Capture{Spec: spec, CapturedAt: now}})
	if err != nil {
		t.Fatal(err)
	}
	recording.Finalize(decisions)
	recording.Close()
	client.Flush()
	deadline := time.Now().Add(5 * time.Second)
	for len(store.List(mathlab.ListFilter{})) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(store.List(mathlab.ListFilter{})) != 1 {
		t.Fatal("actual recording was not persisted")
	}
	_ = log.take()
	before, err := json.Marshal(engine.ExportOwnerState(pol.Owner()))
	if err != nil {
		t.Fatal(err)
	}
	// This is exactly the source assigned by the remote-manager branch to its
	// existing audit listener; existing TLS and Console scope checks sit outside it.
	httpServer := httptest.NewServer(audittransport.ServerConfig{MathLab: client.SnapshotSource()}.Handler())
	defer httpServer.Close()
	resp, err := http.Get(httpServer.URL + "/v1/math-lab/snapshots?namespace=vllm&policy=vllm-defense&policyUID=pol-uid&limit=1")
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Schema  string               `json:"schema"`
		Entries []mathlab.StoreEntry `json:"entries"`
	}
	err = json.NewDecoder(resp.Body).Decode(&index)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || index.Schema != "math-lab.snapshot-index.v1" || len(index.Entries) != 1 {
		t.Fatalf("index=%+v status=%d err=%v", index, resp.StatusCode, err)
	}
	digest := index.Entries[0].Digest
	resp, err = http.Get(httpServer.URL + "/v1/math-lab/snapshots/" + digest)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || mathlab.Digest(raw) != digest || resp.Header.Get("X-Snapshot-Digest") != digest {
		t.Fatalf("read status=%d err=%v", resp.StatusCode, err)
	}
	want, err := store.Read(digest)
	if err != nil || !bytes.Equal(want, raw) {
		t.Fatal("relay changed immutable snapshot bytes", err)
	}
	snapshot, err := mathlab.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Header.GitSHA != strings.Repeat("b", 40) || snapshot.Header.BrainImage != "brain:stage@sha256:"+strings.Repeat("2", 64) || snapshot.Inputs.Policy.GitSHA != pol.GitSHA {
		t.Fatal("actual brain producer identity was replaced by manager identity")
	}
	result, err := mathlab.Replay(snapshot, mathlab.ReplayOptions{Arms: []mathlab.Arm{{ID: "baseline"}}})
	if err != nil || len(result) != 1 {
		t.Fatalf("relayed real snapshot replay: count=%d %v", len(result), err)
	}
	if result[0].Baseline == nil || !result[0].Baseline.Reproduced {
		t.Fatalf("relayed real snapshot not exactly replayable: %+v", result[0].Baseline)
	}
	after, _ := json.Marshal(engine.ExportOwnerState(pol.Owner()))
	if !bytes.Equal(before, after) || len(log.take()) != 0 {
		t.Fatal("snapshot reads changed live state or called decision gates")
	}
	filtered, err := client.IndexJSON(audittransport.MathLabSnapshotQuery{Namespace: "other", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(filtered, &index); err != nil || len(index.Entries) != 0 {
		t.Fatal("namespace filter lost", err)
	}
}

type snapshotProbe struct {
	data, index []byte
	reads       int
}

func (p *snapshotProbe) Read(string) ([]byte, error) {
	p.reads++
	if p.data == nil {
		return nil, os.ErrNotExist
	}
	return p.data, nil
}
func (p *snapshotProbe) IndexJSON(audittransport.MathLabSnapshotQuery) ([]byte, error) {
	p.reads++
	if p.index != nil {
		return p.index, nil
	}
	return []byte(`{"schema":"math-lab.snapshot-index.v1","entries":[]}`), nil
}

func TestSnapshotRelayDefaultsAndMalformedRequestsFailClosed(t *testing.T) {
	local := brainsvc.NewLocal(decision.NewCoverageEngine(), nil)
	client, rpc := serveSnapshotRPC(t, brainsvc.NewServer(local, testConfig.SHA256()), time.Second)
	if client.SnapshotSource() == nil {
		t.Fatal("remote read-only relay missing")
	}
	if _, err := client.IndexJSON(audittransport.MathLabSnapshotQuery{}); status.Code(err) != codes.Unavailable {
		t.Fatal("disabled index must fail closed", err)
	}
	if _, err := rpc.ListSnapshots(context.Background(), &brainpb.ListSnapshotsRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
	probe := &snapshotProbe{}
	client, rpc = serveSnapshotRPC(t, brainsvc.NewServer(local, testConfig.SHA256(), brainsvc.WithSnapshotSource(probe)), time.Second)
	for _, req := range []*brainpb.ListSnapshotsRequest{{Limit: 5001}, {Namespace: strings.Repeat("x", 254)}, {Since: "yesterday"}, {Since: "2026-10-31T00:00:00Z", Until: "2026-10-30T00:00:00Z"}} {
		if _, err := rpc.ListSnapshots(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid query accepted: %v", err)
		}
	}
	if _, err := client.Read("../../etc/passwd"); err == nil {
		t.Fatal("path accepted as digest")
	}
	stream, err := rpc.ReadSnapshot(context.Background(), &brainpb.ReadSnapshotRequest{Digest: "invalid"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.InvalidArgument || probe.reads != 0 {
		t.Fatalf("malformed request reached store: reads=%d err=%v", probe.reads, err)
	}
	if _, err := client.Read(strings.Repeat("0", 64)); status.Code(err) != codes.NotFound {
		t.Fatal(err)
	}
}

type oldSnapshotServer struct{ *brainsvc.Server }

func (s *oldSnapshotServer) ListSnapshots(context.Context, *brainpb.ListSnapshotsRequest) (*brainpb.ListSnapshotsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "old brain has no snapshot RPC")
}

func TestSnapshotRelayRecoversAcrossBrainRolloutWithoutManagerRestart(t *testing.T) {
	for _, old := range []bool{false, true} {
		t.Run(fmt.Sprintf("old-protocol-%v", old), func(t *testing.T) {
			local := brainsvc.NewLocal(decision.NewCoverageEngine(), nil)
			var service brainpb.BrainServiceServer = brainsvc.NewServer(local, testConfig.SHA256())
			wantCode := codes.Unavailable
			if old {
				service = &oldSnapshotServer{service.(*brainsvc.Server)}
				wantCode = codes.Unimplemented
			}
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := lis.Addr().String()
			server := grpc.NewServer()
			brainpb.RegisterBrainServiceServer(server, service)
			go func() { _ = server.Serve(lis) }()
			t.Cleanup(server.Stop)
			conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := brainclient.New(ctx, conn, brainclient.Options{Config: testConfig, CallTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			// Manager stores this source once before the old process is replaced.
			source := client.SnapshotSource()
			if source == nil {
				t.Fatal("startup capability froze the relay disabled")
			}
			if _, err := source.IndexJSON(audittransport.MathLabSnapshotQuery{}); status.Code(err) != wantCode {
				t.Fatalf("old/disabled process did not fail closed: %v", err)
			}
			server.Stop()
			lis, err = net.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			replacement := grpc.NewServer()
			brainpb.RegisterBrainServiceServer(replacement, brainsvc.NewServer(local, testConfig.SHA256(), brainsvc.WithSnapshotSource(&snapshotProbe{data: []byte("immutable")})))
			go func() { _ = replacement.Serve(lis) }()
			t.Cleanup(replacement.Stop)
			deadline := time.Now().Add(5 * time.Second)
			for {
				_, err = source.IndexJSON(audittransport.MathLabSnapshotQuery{})
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("same manager source did not recover: %v", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if raw, err := source.Read(mathlab.Digest([]byte("immutable"))); err != nil || string(raw) != "immutable" {
				t.Fatalf("replacement source read: %q %v", raw, err)
			}
		})
	}
}

func TestSnapshotRelayChunkingHashAndServerBounds(t *testing.T) {
	probe := &snapshotProbe{data: bytes.Repeat([]byte("x"), (2<<20)+23)}
	local := brainsvc.NewLocal(decision.NewCoverageEngine(), nil)
	client, rpc := serveSnapshotRPC(t, brainsvc.NewServer(local, testConfig.SHA256(), brainsvc.WithSnapshotSource(probe)), 5*time.Second)
	digest := mathlab.Digest(probe.data)
	raw, err := client.Read(digest)
	if err != nil || !bytes.Equal(raw, probe.data) {
		t.Fatal("chunked read failed", err)
	}
	stream, err := rpc.ReadSnapshot(context.Background(), &brainpb.ReadSnapshotRequest{Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	chunks := 0
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		chunks++
		if len(chunk.Data) > 1<<20 {
			t.Fatal("oversized chunk")
		}
	}
	if chunks != 3 {
		t.Fatalf("chunks=%d", chunks)
	}
	if _, err := client.Read(strings.Repeat("0", 64)); status.Code(err) != codes.DataLoss {
		t.Fatal("corrupt store bytes accepted", err)
	}
	probe.data = make([]byte, audittransport.MathLabMaxSnapshotBytes+1)
	if _, err := client.Read(digest); status.Code(err) != codes.ResourceExhausted {
		t.Fatal("oversized snapshot accepted", err)
	}
	probe.data = nil
	probe.index = bytes.Repeat([]byte(" "), audittransport.MathLabMaxIndexBytes+1)
	if _, err := client.IndexJSON(audittransport.MathLabSnapshotQuery{}); status.Code(err) != codes.ResourceExhausted {
		t.Fatal("oversized index accepted", err)
	}
	probe.index = []byte("not-json")
	if _, err := client.IndexJSON(audittransport.MathLabSnapshotQuery{}); status.Code(err) != codes.DataLoss {
		t.Fatal("invalid index accepted", err)
	}
}

type brokenSnapshotServer struct {
	*brainsvc.Server
	behavior string
}

func (s *brokenSnapshotServer) ReadSnapshot(_ *brainpb.ReadSnapshotRequest, stream brainpb.BrainService_ReadSnapshotServer) error {
	switch s.behavior {
	case "timeout":
		<-stream.Context().Done()
		return stream.Context().Err()
	case "oversized":
		return stream.Send(&brainpb.ReadSnapshotResponse{Data: make([]byte, (1<<20)+1)})
	default:
		return stream.Send(&brainpb.ReadSnapshotResponse{Data: []byte("tampered")})
	}
}
func TestSnapshotClientValidatesPeerChunksAndDeadline(t *testing.T) {
	for _, behavior := range []string{"timeout", "oversized", "tampered"} {
		t.Run(behavior, func(t *testing.T) {
			server := &brokenSnapshotServer{brainsvc.NewServer(brainsvc.NewLocal(decision.NewCoverageEngine(), nil), testConfig.SHA256(), brainsvc.WithSnapshotSource(&snapshotProbe{})), behavior}
			client, _ := serveSnapshotRPC(t, server, 20*time.Millisecond)
			_, err := client.Read(mathlab.Digest([]byte("expected")))
			if err == nil {
				t.Fatal("invalid peer stream accepted")
			}
			if behavior == "timeout" && status.Code(err) != codes.DeadlineExceeded {
				t.Fatal(fmt.Sprintf("deadline error=%v", err))
			}
		})
	}
}
