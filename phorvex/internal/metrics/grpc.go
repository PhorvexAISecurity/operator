package metrics

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// The services' gRPC calls (ADR-0001), counted and timed on both ends. The labels are
// the contract's own closed vocabulary: its service, its method and the status code.
var (
	grpcServerHandled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_grpc_server_handled_total",
		Help: "gRPC calls this process answered, by contract service, method and status code.",
	}, []string{"grpc_service", "grpc_method", "grpc_code"})
	grpcServerSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "phorvex_grpc_server_handling_seconds",
		Help:    "Time this process took to answer a gRPC call, by contract service and method. A stream is timed until it ends.",
		Buckets: grpcBuckets,
	}, []string{"grpc_service", "grpc_method"})
	grpcClientHandled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_grpc_client_handled_total",
		Help: "gRPC calls this process made to another service, by contract service, method and status code.",
	}, []string{"grpc_service", "grpc_method", "grpc_code"})
	grpcClientSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "phorvex_grpc_client_handling_seconds",
		Help:    "Time a gRPC call to another service took, by contract service and method. A stream is timed until it ends.",
		Buckets: grpcBuckets,
	}, []string{"grpc_service", "grpc_method"})
)

// From a cached read to a whole decide stream within a tick.
var grpcBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

func init() {
	crmetrics.Registry.MustRegister(grpcServerHandled, grpcServerSeconds, grpcClientHandled, grpcClientSeconds)
}

// GRPCServerOptions measure every call a service's gRPC server answers.
func GRPCServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			start := time.Now()
			resp, err := handler(ctx, req)
			observeGRPC(grpcServerHandled, grpcServerSeconds, info.FullMethod, start, err)
			return resp, err
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			start := time.Now()
			err := handler(srv, ss)
			observeGRPC(grpcServerHandled, grpcServerSeconds, info.FullMethod, start, err)
			return err
		}),
	}
}

// GRPCDialOptions measure every call a client makes to another service. A stream is
// counted when it is opened and timed until its first error or end.
func GRPCDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			start := time.Now()
			err := invoker(ctx, method, req, reply, cc, opts...)
			observeGRPC(grpcClientHandled, grpcClientSeconds, method, start, err)
			return err
		}),
		grpc.WithChainStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			start := time.Now()
			stream, err := streamer(ctx, desc, cc, method, opts...)
			if err != nil {
				observeGRPC(grpcClientHandled, grpcClientSeconds, method, start, err)
				return nil, err
			}
			return &measuredStream{ClientStream: stream, method: method, start: start}, nil
		}),
	}
}

// measuredStream records a client stream once, when it first reports an error; a
// stream that ends normally reports io.EOF, which is its OK.
type measuredStream struct {
	grpc.ClientStream
	method string
	start  time.Time
	done   bool
}

func (s *measuredStream) RecvMsg(m any) error {
	err := s.ClientStream.RecvMsg(m)
	if err != nil && !s.done {
		s.done = true
		if errors.Is(err, io.EOF) {
			observeGRPC(grpcClientHandled, grpcClientSeconds, s.method, s.start, nil)
		} else {
			observeGRPC(grpcClientHandled, grpcClientSeconds, s.method, s.start, err)
		}
	}
	return err
}

func observeGRPC(handled *prometheus.CounterVec, seconds *prometheus.HistogramVec, fullMethod string, start time.Time, err error) {
	service, method := splitMethod(fullMethod)
	handled.WithLabelValues(service, method, status.Code(err).String()).Inc()
	seconds.WithLabelValues(service, method).Observe(time.Since(start).Seconds())
}

// splitMethod turns "/phorvex.brain.v1.BrainService/Decide" into its service and method.
func splitMethod(full string) (string, string) {
	service, method, ok := strings.Cut(strings.TrimPrefix(full, "/"), "/")
	if !ok {
		return "unknown", "unknown"
	}
	return service, method
}
