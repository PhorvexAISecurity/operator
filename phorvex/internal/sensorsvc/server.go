package sensorsvc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/phorvex/phorvex/internal/sensorapi"
	"github.com/phorvex/phorvex/internal/sensorpb"
	"github.com/phorvex/phorvex/internal/wire"
)

// Server serves a sensorapi.Sensor over gRPC (sensorpb.SensorService).
type Server struct {
	sensorpb.UnimplementedSensorServiceServer

	sensor          sensorapi.Sensor
	configSHA256    string
	telemetrySource string
}

var _ sensorpb.SensorServiceServer = (*Server)(nil)

// NewServer serves sensor. configSHA256 is this process's sensorapi.Config hash; a
// client presenting another is refused. telemetrySource names the telemetry
// source, empty when none is configured.
func NewServer(sensor sensorapi.Sensor, configSHA256, telemetrySource string) *Server {
	return &Server{sensor: sensor, configSHA256: configSHA256, telemetrySource: telemetrySource}
}

func (s *Server) Hello(_ context.Context, req *sensorpb.HelloRequest) (*sensorpb.HelloResponse, error) {
	if req.GetContractVersion() != sensorapi.ContractVersion {
		return nil, status.Errorf(codes.FailedPrecondition, "sensor contract version %d, client %d", sensorapi.ContractVersion, req.GetContractVersion())
	}
	if req.GetConfigSha256() != s.configSHA256 {
		return nil, status.Errorf(codes.FailedPrecondition, "sensor configuration differs: sensor %s, client %s", s.configSHA256, req.GetConfigSha256())
	}
	return &sensorpb.HelloResponse{ContractVersion: sensorapi.ContractVersion, ConfigSha256: s.configSHA256, TelemetrySource: s.telemetrySource}, nil
}

func (s *Server) Observe(ctx context.Context, req *sensorpb.ObserveRequest) (*sensorpb.ObserveResponse, error) {
	var observe sensorapi.ObserveRequest
	if err := wire.Decode(req.GetRequest(), &observe); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "request: %v", err)
	}
	obs, err := s.sensor.Observe(ctx, observe)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	raw, err := wire.Encode(obs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "observation: %v", err)
	}
	return &sensorpb.ObserveResponse{Observation: raw}, nil
}

func (s *Server) Telemetry(ctx context.Context, req *sensorpb.TelemetryRequest) (*sensorpb.TelemetryResponse, error) {
	read := s.sensor.Telemetry(ctx, sensorapi.TelemetryRequest{Namespace: req.GetNamespace(), Pods: req.GetPods()})
	out := &sensorpb.TelemetryResponse{Configured: read.Configured, Error: read.Error}
	if !read.Configured {
		return out, nil
	}
	var err error
	if out.Telemetry, err = wire.Encode(read.Telemetry); err != nil {
		return nil, status.Errorf(codes.Internal, "telemetry: %v", err)
	}
	if out.Health, err = wire.Encode(read.Health); err != nil {
		return nil, status.Errorf(codes.Internal, "health: %v", err)
	}
	return out, nil
}

// TelemetrySource names l's telemetry source, empty when none is configured.
func (l *Local) TelemetrySource() string {
	if l.Metrics == nil {
		return ""
	}
	return l.Metrics.Name()
}
