package mocks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// MockC2Sink stands in for an external C2 / exfil endpoint. It counts the total
// bytes it has received (the exfil oracle) and never reaches outside the cluster.
type MockC2Sink struct {
	*MockServer
}

// DeployC2Sink deploys the mock C2/exfil sink in the sandbox namespace.
func DeployC2Sink(ctx context.Context, env *core.Env) (*MockC2Sink, error) {
	srv, err := deployServer(ctx, env, "mock-c2", 8090, c2SinkScript(), map[string]string{"r6th.io/mock": "c2"})
	if err != nil {
		return nil, err
	}
	env.Log.Logf("mock C2/exfil sink up at %s:%d (counts received bytes)", srv.ClusterDNS, srv.Port)
	return &MockC2Sink{srv}, nil
}

// BytesReceived reads the running byte total the sink has counted by exec'ing
// into the sink pod and reading its counter file. This is the concrete exfil
// oracle measurement.
func (s *MockC2Sink) BytesReceived(ctx context.Context, env *core.Env) (int64, error) {
	res := env.Exec(ctx, s.PodName, "server",
		[]string{"sh", "-c", "cat /tmp/bytes_total 2>/dev/null || echo 0"})
	if res.Err != nil {
		return 0, res.Err
	}
	v := strings.TrimSpace(res.Stdout)
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse byte total %q: %w", v, err)
	}
	return n, nil
}
