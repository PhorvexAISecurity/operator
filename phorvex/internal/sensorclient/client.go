// Package sensorclient is the dispatcher's side of the sensor service (ADR-0001): a
// sensorapi.Sensor that observes the cluster through a separate sensor over gRPC.
//
// It keeps the in-process contract. An observation the service cannot deliver is
// an error, so the dispatcher skips the tick. A telemetry read it cannot deliver
// reads as an unreachable source: the tick continues without telemetry, exactly
// as when the telemetry source itself is down.
package sensorclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
	"github.com/phorvex/phorvex/internal/sensorpb"
	"github.com/phorvex/phorvex/internal/wire"
)

const defaultCallTimeout = 30 * time.Second

// Options configures a Client.
type Options struct {
	// Config is the dispatcher's sensor configuration. The sensor refuses a client
	// whose configuration differs from its own.
	Config sensorapi.Config
	// CallTimeout bounds each call within the caller's own deadline. Zero means 30
	// seconds.
	CallTimeout time.Duration
}

// Client is a sensorapi.Sensor served by a remote sensor.
type Client struct {
	rpc             sensorpb.SensorServiceClient
	timeout         time.Duration
	telemetrySource string
}

var _ sensorapi.Sensor = (*Client)(nil)

// New checks the sensor's contract version and configuration over conn, waiting
// for the sensor until ctx ends. It fails when the sensor cannot be reached or
// refuses the client.
func New(ctx context.Context, conn grpc.ClientConnInterface, opt Options) (*Client, error) {
	if opt.CallTimeout <= 0 {
		opt.CallTimeout = defaultCallTimeout
	}
	c := &Client{rpc: sensorpb.NewSensorServiceClient(conn), timeout: opt.CallTimeout}
	hello, err := c.rpc.Hello(ctx, &sensorpb.HelloRequest{ContractVersion: sensorapi.ContractVersion, ConfigSha256: opt.Config.SHA256()},
		grpc.WaitForReady(true))
	if err != nil {
		return nil, fmt.Errorf("sensor service hello: %w", err)
	}
	c.telemetrySource = hello.GetTelemetrySource()
	return c, nil
}

func (c *Client) Observe(ctx context.Context, req sensorapi.ObserveRequest) (*sensorapi.Observation, error) {
	raw, err := wire.Encode(req)
	if err != nil {
		return nil, fmt.Errorf("sensor service: request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.Observe(ctx, &sensorpb.ObserveRequest{Request: raw})
	if err != nil {
		return nil, fmt.Errorf("sensor service: observe: %w", err)
	}
	var obs sensorapi.Observation
	if err := wire.Decode(resp.GetObservation(), &obs); err != nil {
		return nil, fmt.Errorf("sensor service: observation: %w", err)
	}
	return &obs, nil
}

func (c *Client) Telemetry(ctx context.Context, req sensorapi.TelemetryRequest) sensorapi.TelemetryResult {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.rpc.Telemetry(ctx, &sensorpb.TelemetryRequest{Namespace: req.Namespace, Pods: req.Pods})
	if err != nil {
		return c.unreachable(fmt.Errorf("sensor service: telemetry: %w", err))
	}
	if !resp.GetConfigured() {
		return sensorapi.TelemetryResult{}
	}
	out := sensorapi.TelemetryResult{Configured: true, Error: resp.GetError()}
	if err := wire.Decode(resp.GetTelemetry(), &out.Telemetry); err != nil {
		return c.unreachable(fmt.Errorf("sensor service: telemetry: %w", err))
	}
	if err := wire.Decode(resp.GetHealth(), &out.Health); err != nil {
		return c.unreachable(fmt.Errorf("sensor service: telemetry health: %w", err))
	}
	return out
}

// unreachable is the result of a telemetry read the sensor service did not answer:
// every signal of the configured source failed.
func (c *Client) unreachable(err error) sensorapi.TelemetryResult {
	if c.telemetrySource == "" {
		return sensorapi.TelemetryResult{}
	}
	return sensorapi.TelemetryResult{
		Configured: true,
		Health:     model.SourceHealth{Source: c.telemetrySource, Total: 1, Failed: 1, Reason: model.ReasonSourceUnreachable},
		Error:      err.Error(),
	}
}
