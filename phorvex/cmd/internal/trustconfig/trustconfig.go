// Package trustconfig holds the trust more than one service reads: the detector
// identities whose SecurityEvents are evidence, and the reviewed endpoint lease
// authority. The sensor projects evidence with them, the actuator re-checks
// adapter evidence and enforces lease revocation with them, and the dispatcher
// fences on the lease authority (ADR-0001). Each binary registers these flags once.
package trustconfig

import (
	"flag"
	"os"
	"strings"

	"github.com/phorvex/phorvex/internal/eventtrust"
)

// Trust is the shared trust configuration.
type Trust struct {
	TrustedDetectors                 string
	EndpointLeaseApprovedSource      string
	EndpointLeaseApprovedProxyImage  string
	EndpointLeaseApprovedEngineImage string
}

// Register defines the flags on fs.
func (t *Trust) Register(fs *flag.FlagSet) {
	fs.StringVar(&t.TrustedDetectors, "trusted-detectors", os.Getenv("PHORVEX_TRUSTED_DETECTORS"), "Comma-separated allowlist of detector identities whose SecurityEvents may become belief evidence (M-94), e.g. \"vllm/detector-kv-canary,vllm/detector-adapter-inv\". Matched against the admission-stamped authenticated creator, never against the self-declared spec.rule.source. Empty = no external detector is trusted (fail-closed).")
	fs.StringVar(&t.EndpointLeaseApprovedSource, "endpoint-lease-approved-source-sha256", os.Getenv("PHORVEX_ENDPOINT_LEASE_APPROVED_SOURCE_SHA256"), "Reviewed endpoint lease proxy source SHA-256; empty disables lease-revoke.")
	fs.StringVar(&t.EndpointLeaseApprovedProxyImage, "endpoint-lease-approved-proxy-image", os.Getenv("PHORVEX_ENDPOINT_LEASE_APPROVED_PROXY_IMAGE"), "Reviewed immutable endpoint lease proxy repo@sha256; empty disables lease-revoke.")
	fs.StringVar(&t.EndpointLeaseApprovedEngineImage, "endpoint-lease-approved-engine-image", os.Getenv("PHORVEX_ENDPOINT_LEASE_APPROVED_ENGINE_IMAGE"), "Reviewed immutable endpoint lease engine repo@sha256; empty disables lease-revoke.")
}

// Detectors is the trusted detector allowlist, normalized.
func (t Trust) Detectors() eventtrust.TrustedDetectors {
	return eventtrust.NewTrustedDetectors(strings.Split(t.TrustedDetectors, ","))
}
