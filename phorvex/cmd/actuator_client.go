package main

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/actuatorclient"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/wire"
)

// connectActuator opens the actuator service over transport and completes its
// handshake: the actuator refuses a manager built against another contract or configured with
// another operator namespace, detector trust or endpoint lease authority.
func connectActuator(endpoint string, transport grpc.DialOption, config actuatorapi.Config, connectTimeout, callTimeout time.Duration) (*actuatorclient.Client, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(endpoint, append(metrics.GRPCDialOptions(),
		transport,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(wire.MaxMessageBytes), grpc.MaxCallSendMsgSize(wire.MaxMessageBytes)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}))...)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	client, err := actuatorclient.New(ctx, conn, actuatorclient.Options{Config: config, CallTimeout: callTimeout})
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return client, conn, nil
}
