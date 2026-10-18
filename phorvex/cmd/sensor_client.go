package main

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/phorvex/phorvex/internal/sensorapi"
	"github.com/phorvex/phorvex/internal/sensorclient"
	"github.com/phorvex/phorvex/internal/wire"
)

// connectSensor opens the sensor service and completes its handshake: the sensor
// refuses a manager built against another contract or configured with other trust.
func connectSensor(endpoint string, config sensorapi.Config, connectTimeout, callTimeout time.Duration) (*sensorclient.Client, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(wire.MaxMessageBytes), grpc.MaxCallSendMsgSize(wire.MaxMessageBytes)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}))
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	client, err := sensorclient.New(ctx, conn, sensorclient.Options{Config: config, CallTimeout: callTimeout})
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return client, conn, nil
}
