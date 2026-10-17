package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/phorvex/phorvex/cmd/internal/decisionconfig"
	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/brainclient"
	"github.com/phorvex/phorvex/internal/brainpb"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
)

func TestBrainServesTheContractUntilStopped(t *testing.T) {
	cfg := config{metricsAddr: "127.0.0.1:0", probeAddr: "127.0.0.1:0", engine: "p1",
		gpuEnvelopeMax: cost.DefaultGPUEnvelopeMax, flowClasses: "vllm", shutdownGrace: time.Second}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, lis, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	optimizer, err := decisionconfig.Apply(cfg.engine, cfg.gpuEnvelopeMax, cfg.flowClasses)
	if err != nil {
		t.Fatal(err)
	}
	decisionConfig, err := decisionconfig.Describe(optimizer, cfg.gpuEnvelopeMax, cfg.flowClasses)
	if err != nil {
		t.Fatal(err)
	}
	helloCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := brainclient.New(helloCtx, conn, brainclient.Options{Config: decisionConfig})
	if err != nil {
		t.Fatal(err)
	}
	if client.Name() != optimizer.Name() || !client.GatesCandidates() {
		t.Fatalf("brain reports %q gates=%v", client.Name(), client.GatesCandidates())
	}
	// An empty tick may be refused by the engine, never by the transport.
	_, rec, err := client.Decide(brainapi.DecideRequest{Policy: model.Policy{Tenant: "t"}})
	rec.Close()
	if err != nil && strings.HasPrefix(err.Error(), "brain service:") {
		t.Fatalf("evaluation did not reach the engine: %v", err)
	}
	health, err := healthpb.NewHealthClient(conn).Check(helloCtx, &healthpb.HealthCheckRequest{Service: brainpb.BrainService_ServiceDesc.ServiceName})
	if err != nil || health.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health = %v, %v", health, err)
	}

	other := decisionConfig
	other.GPUEnvelopeMax = 0.5
	if _, err := brainclient.New(helloCtx, conn, brainclient.Options{Config: other}); err == nil {
		t.Fatal("brain accepted a manager with another GPU envelope")
	}

	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("brain stopped with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("brain did not stop")
	}
}
