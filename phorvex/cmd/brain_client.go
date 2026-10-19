package main

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/phorvex/phorvex/cmd/internal/decisionconfig"
	"github.com/phorvex/phorvex/internal/brainclient"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/wire"
)

// connectBrain opens the brain service and completes its handshake: the brain
// refuses a manager built against another contract or configured differently.
func connectBrain(endpoint string, optimizer decision.Optimizer, gpuEnvelopeMax float64, flowClasses string,
	connectTimeout, callTimeout, decideTimeout time.Duration) (*brainclient.Client, *grpc.ClientConn, error) {
	config, err := decisionconfig.Describe(optimizer, gpuEnvelopeMax, flowClasses)
	if err != nil {
		return nil, nil, err
	}
	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(wire.MaxMessageBytes), grpc.MaxCallSendMsgSize(wire.MaxMessageBytes)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}))
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	client, err := brainclient.New(ctx, conn, brainclient.Options{
		Config: config, CallTimeout: callTimeout, DecideTimeout: decideTimeout, Log: ctrl.Log.WithName("brain-client"),
	})
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return client, conn, nil
}
