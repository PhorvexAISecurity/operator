package trustconfig

import (
	"flag"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/ingest"
)

func TestRegisterAndNormalize(t *testing.T) {
	var trust Trust
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	trust.Register(fs)
	if err := fs.Parse([]string{"--trusted-detectors=vllm/b, vllm/a,,vllm/a", "--endpoint-lease-approved-source-sha256=src",
		"--endpoint-lease-approved-proxy-image=proxy", "--endpoint-lease-approved-engine-image=engine"}); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(trust.Detectors().List(), ","), strings.Join(ingest.NewTrustedDetectors([]string{"vllm/a", "vllm/b"}).List(), ","); got != want {
		t.Fatalf("detectors = %s, want %s", got, want)
	}
	if trust.EndpointLeaseApprovedSource != "src" || trust.EndpointLeaseApprovedProxyImage != "proxy" || trust.EndpointLeaseApprovedEngineImage != "engine" {
		t.Fatalf("lease authority = %+v", trust)
	}
}
