// Command verification-loop verifies one credential-admission defense in a private
// API server and local HTTP runtime. It does not access an existing cluster.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/verificationloop"
)

func main() {
	var o verificationloop.Options
	flag.StringVar(&o.RepoRoot, "repo-root", "..", "Operator repository root")
	flag.StringVar(&o.OutputDir, "out", "", "New evidence directory (required)")
	flag.StringVar(&o.Python, "python", "python3", "Python interpreter with httpx and uvicorn")
	flag.StringVar(&o.Assets, "assets", os.Getenv("KUBEBUILDER_ASSETS"), "Private envtest API-server/etcd binary directory")
	flag.StringVar(&o.GitSHA, "git-sha", buildinfo.Current().GitSHA, "Source revision recorded in evidence")
	flag.DurationVar(&o.Timeout, "timeout", 3*time.Minute, "Whole run timeout")
	flag.DurationVar(&o.HoldDuration, "hold", 2*time.Second, "Actual wall-clock denial hold interval")
	flag.DurationVar(&o.HoldInterval, "hold-interval", 250*time.Millisecond, "Interval between hold probes")
	flag.DurationVar(&o.MaxLegitimateLatency, "max-legitimate-latency", 2*time.Second, "Local legitimate probe latency ceiling")
	flag.BoolVar(&o.SkipDispatch, "skip-dispatch", false, "Negative control: verify attack remains landed when native dispatch is withheld (exits nonzero)")
	flag.StringVar(&o.Arm, "arm", "", "Security Gain validation branch after the decision: intervention (default path), baseline, selected, cf-rotate, cf-endpoint-rotate or cf-endpoint-lease-revoke")
	flag.StringVar(&o.Scenario, "scenario", "", "Stolen attacker capability: lease (default), token (Pod-bound API bearer) or combined; token and combined run two replicas and study arms only")
	flag.BoolVar(&o.UnavailableAuthority, "unavailable-authority", false, "Negative control: remove private policy before effect probes; a 503 outage must fail (exits nonzero)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, err := verificationloop.Run(ctx, o)
	if report != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"verdict": report.Verdict, "scope": report.Scope, "out": o.OutputDir, "error": report.Error})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "verification-loop:", err)
		os.Exit(1)
	}
}
