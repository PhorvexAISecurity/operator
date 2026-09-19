package scaleprobe

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func validReport() Report {
	samples := make([]Sample, 20)
	for i := range samples {
		policies := make(map[string]float64, 8)
		for policy := 0; policy < 8; policy++ {
			policies[fmt.Sprintf("tenant-%d", policy)] = 0.01
		}
		samples[i] = Sample{Index: i, Outcome: "finished-full-snapshot", DurationSec: 0.5, PolicySeconds: policies, HeapBytes: 1, RSSBytes: 1, StatusWrites: 8}
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		Environment:   Environment{GitSHA: "source", Executable: "m137.test", ExecutableSHA256: strings.Repeat("a", 64), GoVersion: "go1.26.1", KubernetesAssets: "k8s-1.34", CPUCount: 2, GOMAXPROCS: 2, MemoryTotalBytes: 8 << 30, HarnessPID: 1, APIProcessPID: 2, EtcdProcessPID: 3, APIProcessRSSBytes: 1, EtcdProcessRSSBytes: 1},
		Fixture: Fixture{
			Case: "valid", Backend: "native", CacheReader: "controller-runtime-cache", ReceiptReader: "direct-api",
			OwnerReader: "direct-api", TransportCoverage: "all harness clients counted; control-plane internals excluded", Optimizer: "production p1", TelemetrySource: "honest absent", Calibration: "production enabled", Readiness: "manually seeded consistently", SelectorMode: "partitioned", Deployments: 4, ReplicaSets: 4, Pods: 1000, Namespaces: 4, Policies: 8, PoliciesPerNS: 2, PodsPerPolicy: 125,
			Nodes: 2, ServiceAccounts: 4, Services: 4, PDBs: 4, NetworkPolicies: 4, Roles: 4, RoleBindings: 4, ClusterRoles: 1, ClusterBindings: 1, SecurityEvents: 2, Receipts: 1, BrakeConfigMaps: 4,
			RequestedAttempts: 20, WarmupTicks: 2, TickTimeoutMS: 30000, TickIntervalMS: 20000, SampleCadence: "forced-due-back-to-back", AuditByteLimit: 2 << 20, AuditRetained: 1, MetricsSink: "bounded labels", TrustFixture: "synthetic",
		},
		Samples: samples,
		Controls: []Control{{Purpose: "deadline-exclusion-and-no-cadence", Sample: Sample{
			Index: 20, Outcome: "deadline", DurationSec: 0.01, PolicySeconds: map[string]float64{}, RSSBytes: 1, Error: "deadline exceeded",
		}}},
		StartupHTTP:     map[string]int64{"cache|WATCH|pods|-": 1},
		SampleHTTP:      map[string]int64{"direct|LIST|securityevents|-": 20, "direct|GET|replicasets|-": 80, "direct|GET|deployments|-": 80, "manager|PUT|phorvexpolicies|status": 160},
		ConvergenceHTTP: map[string]int64{"convergence|GET|phorvexpolicies|-": 160},
		ControlHTTP:     map[string]int64{"direct|LIST|securityevents|-": 1},
		RESTConfigs:     map[string]RESTConfig{"fixture": {Server: "https://127.0.0.1", QPS: 5, Burst: 10, Timeout: "0s", RateLimiter: "client-go-token-bucket-effective-qps-burst", UserAgent: "test"}, "cache": {Server: "https://127.0.0.1", QPS: 5, Burst: 10, Timeout: "0s", RateLimiter: "client-go-token-bucket-effective-qps-burst", UserAgent: "test"}, "manager": {Server: "https://127.0.0.1", QPS: 5, Burst: 10, Timeout: "0s", RateLimiter: "client-go-token-bucket-effective-qps-burst", UserAgent: "test"}, "direct": {Server: "https://127.0.0.1", QPS: 5, Burst: 10, Timeout: "0s", RateLimiter: "client-go-token-bucket-effective-qps-burst", UserAgent: "test"}, "convergence": {Server: "https://127.0.0.1", QPS: 5, Burst: 10, Timeout: "0s", RateLimiter: "client-go-token-bucket-effective-qps-burst", UserAgent: "test"}},
		Memory:          Memory{Scope: "sampled post-tick harness-process", HarnessBaseline: 1, HarnessPeak: 2, HarnessFinal: 2, HarnessSlopeBytes: 1, HeapBaseline: 1, HeapPeak: 2, HeapFinal: 2, HeapSlopeBytes: 1, APIBaseline: 1, APIPeak: 1, APIFinal: 1, EtcdBaseline: 1, EtcdPeak: 1, EtcdFinal: 1},
		Correctness:     Correctness{CacheConverged: true, ProtectedObjectCount: 1000, GraphEdgesPresent: true, RBACPresent: true, TrustedEventPresent: true, ReceiptPresent: true, DecisionRecords: 1, SelectedFeasibleRecords: 1, CurrentOwnerEligible: true, ControllerStatusPreserved: true, NoFalseCadence: true},
		NFRVerdict:      "PASS", NFRDetail: "all successful full ticks below the predeclared one-second target",
		Limitations: []string{"isolated local source-shaped fixture, not live behavior", "intended hardware, cadence, lifetime and maximum fleet remain unverified"},
	}
	report.Summary = Summarize(report.Samples, 1)
	return report
}

func TestM137ScaleReportAcceptsExplicitMeasuredFailure(t *testing.T) {
	report := validReport()
	report.Samples[0].DurationSec = 2
	report.Summary = Summarize(report.Samples, 1)
	report.NFRVerdict = "FAIL"
	report.NFRDetail = "one successful full tick breached the fixed target; observed bottleneck and traffic counts retained"
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestM137ScaleReportAcceptsRetainedWorkloadDeadlineAsFailure(t *testing.T) {
	report := validReport()
	report.Samples[0] = Sample{Index: 0, Outcome: "deadline", DurationSec: 30, PolicySeconds: map[string]float64{}, HeapBytes: 1, RSSBytes: 1, Error: "deadline exceeded"}
	report.SampleHTTP["manager|PUT|phorvexpolicies|status"] -= 8
	report.ConvergenceHTTP["convergence|GET|phorvexpolicies|-"] -= 8
	report.Summary = Summarize(report.Samples, 1)
	report.NFRVerdict = "FAIL"
	report.NFRDetail = "one fixed-budget workload attempt reached its deadline and was retained outside successful-only percentiles"
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestM137ScaleReportAcceptsFixedBudgetWithNoSuccessfulAttemptsAsFailure(t *testing.T) {
	report := validReport()
	for i := range report.Samples {
		report.Samples[i] = Sample{Index: i, Outcome: "deadline", DurationSec: 30, PolicySeconds: map[string]float64{}, HeapBytes: 1, RSSBytes: 1, Error: "deadline exceeded"}
	}
	report.StartupHTTP["direct|GET|replicasets|-"] = 1
	report.StartupHTTP["direct|GET|deployments|-"] = 1
	report.SampleHTTP = map[string]int64{}
	report.ConvergenceHTTP = map[string]int64{}
	report.Summary = Summarize(report.Samples, 1)
	report.NFRVerdict = "FAIL"
	report.NFRDetail = "all 20 fixed-budget workload attempts reached the deadline; successful-only percentiles are empty"
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestM137ScaleReportValidation(t *testing.T) {
	valid := validReport()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "missing-source", mutate: func(r *Report) { r.Environment.GitSHA = "" }},
		{name: "malformed-executable-sha", mutate: func(r *Report) { r.Environment.ExecutableSHA256 = "not-a-sha256" }},
		{name: "missing-api-memory", mutate: func(r *Report) { r.Environment.APIProcessRSSBytes = 0 }},
		{name: "missing-harness-final", mutate: func(r *Report) { r.Memory.HarnessFinal = 0 }},
		{name: "missing-heap-baseline", mutate: func(r *Report) { r.Memory.HeapBaseline = 0 }},
		{name: "missing-harness-slope", mutate: func(r *Report) { r.Memory.HarnessSlopeBytes = 0 }},
		{name: "missing-heap-slope", mutate: func(r *Report) { r.Memory.HeapSlopeBytes = 0 }},
		{name: "too-few-samples", mutate: func(r *Report) { r.Samples = r.Samples[:19]; r.Summary = Summarize(r.Samples, 1) }},
		{name: "incomplete-unclassified", mutate: func(r *Report) { r.Samples[0].Outcome = "deadline"; r.Summary = Summarize(r.Samples, 1) }},
		{name: "incorrect-summary", mutate: func(r *Report) { r.Summary.P95Seconds = 9 }},
		{name: "missing-correctness", mutate: func(r *Report) { r.Correctness.ReceiptPresent = false }},
		{name: "missing-sink-binding", mutate: func(r *Report) { r.Fixture.MetricsSink = "" }},
		{name: "inconsistent-fixture-count", mutate: func(r *Report) { r.Fixture.PoliciesPerNS++ }},
		{name: "missing-live-debt", mutate: func(r *Report) { r.Limitations = nil }},
		{name: "missing-authoritative-traffic", mutate: func(r *Report) { delete(r.SampleHTTP, "direct|LIST|securityevents|-") }},
		{name: "missing-effective-rest-limit", mutate: func(r *Report) {
			r.RESTConfigs["direct"] = RESTConfig{Server: "https://127.0.0.1", Timeout: "0s", RateLimiter: "none", UserAgent: "test"}
		}},
		{name: "negative-policy-duration", mutate: func(r *Report) { r.Samples[0].PolicySeconds["tenant-0"] = -1; r.Summary = Summarize(r.Samples, 1) }},
		{name: "nonfinite-policy-duration", mutate: func(r *Report) {
			r.Samples[0].PolicySeconds["tenant-0"] = math.NaN()
			r.Summary = Summarize(r.Samples, 1)
		}},
		{name: "inconsistent-status-writes", mutate: func(r *Report) { r.Samples[0].StatusWrites-- }},
		{name: "negative-http-count", mutate: func(r *Report) { r.SampleHTTP["direct|LIST|securityevents|-"] = -1 }},
		{name: "false-pass-verdict", mutate: func(r *Report) { r.Samples[0].DurationSec = 2; r.Summary = Summarize(r.Samples, 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := validReport()
			tc.mutate(&report)
			if err := report.Validate(); err == nil {
				t.Fatal("malformed report accepted")
			}
		})
	}
}

func TestM137ScaleReportDecodeRejectsUnknownFields(t *testing.T) {
	if _, err := Decode(strings.NewReader(`{"schemaVersion":"phorvex.m137.scale.v1","unknown":true}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestM137ScaleReportDecodeRejectsTrailingJSON(t *testing.T) {
	if _, err := Decode(strings.NewReader(`{} {}`)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
