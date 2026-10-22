package metrics

import (
	"context"
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCCallsAreMeasuredOnBothEnds(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	server := grpc.NewServer(GRPCServerOptions()...)
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("phorvex.test.v1.Probe", healthpb.HealthCheckResponse_SERVING)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet", append(GRPCDialOptions(),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := healthpb.NewHealthClient(conn)

	const service, method = "grpc.health.v1.Health", "Check"
	before := map[string]float64{}
	for _, code := range []string{"OK", "NotFound"} {
		before["server"+code] = value(t, grpcServerHandled.WithLabelValues(service, method, code))
		before["client"+code] = value(t, grpcClientHandled.WithLabelValues(service, method, code))
	}
	if _, err := client.Check(t.Context(), &healthpb.HealthCheckRequest{Service: "phorvex.test.v1.Probe"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Check(t.Context(), &healthpb.HealthCheckRequest{Service: "absent"}); status.Code(err) != codes.NotFound {
		t.Fatalf("an unknown service answered %v", err)
	}
	for _, code := range []string{"OK", "NotFound"} {
		for end, counter := range map[string]float64{
			"server": value(t, grpcServerHandled.WithLabelValues(service, method, code)),
			"client": value(t, grpcClientHandled.WithLabelValues(service, method, code)),
		} {
			if counter-before[end+code] != 1 {
				t.Errorf("%s counted %v %s calls, want 1", end, counter-before[end+code], code)
			}
		}
	}
	var timed dto.Metric
	if err := grpcServerSeconds.WithLabelValues(service, method).(prometheus.Metric).Write(&timed); err != nil || timed.GetHistogram().GetSampleCount() < 2 {
		t.Errorf("server calls were not timed: %v", err)
	}
}

func value(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func TestSplitMethod(t *testing.T) {
	for full, want := range map[string][2]string{
		"/phorvex.brain.v1.BrainService/Decide": {"phorvex.brain.v1.BrainService", "Decide"},
		"malformed":                             {"unknown", "unknown"},
	} {
		if service, method := splitMethod(full); service != want[0] || method != want[1] {
			t.Errorf("splitMethod(%q) = %q, %q", full, service, method)
		}
	}
}
