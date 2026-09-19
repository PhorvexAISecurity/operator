package scaleprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

const SchemaVersion = "phorvex.m137.scale.v1"

type Environment struct {
	GitSHA              string `json:"gitSHA"`
	Executable          string `json:"executable"`
	ExecutableSHA256    string `json:"executableSHA256"`
	GoVersion           string `json:"goVersion"`
	KubernetesAssets    string `json:"kubernetesAssets"`
	CPUCount            int    `json:"cpuCount"`
	GOMAXPROCS          int    `json:"goMaxProcs"`
	MemoryTotalBytes    int64  `json:"memoryTotalBytes"`
	MemoryLimitBytes    int64  `json:"memoryLimitBytes"`
	HarnessPID          int    `json:"harnessPID"`
	APIProcessPID       int    `json:"apiProcessPID,omitempty"`
	EtcdProcessPID      int    `json:"etcdProcessPID,omitempty"`
	APIProcessRSSBytes  int64  `json:"apiProcessRSSBytes,omitempty"`
	EtcdProcessRSSBytes int64  `json:"etcdProcessRSSBytes,omitempty"`
}

type RESTConfig struct {
	Server      string  `json:"server"`
	QPS         float32 `json:"qps"`
	Burst       int     `json:"burst"`
	Timeout     string  `json:"timeout"`
	RateLimiter string  `json:"rateLimiter"`
	UserAgent   string  `json:"userAgent"`
}

type Fixture struct {
	Case              string `json:"case"`
	Backend           string `json:"backend"`
	CacheReader       string `json:"cacheReader"`
	ReceiptReader     string `json:"receiptReader"`
	OwnerReader       string `json:"ownerReader"`
	TransportCoverage string `json:"transportCoverage"`
	Optimizer         string `json:"optimizer"`
	TelemetrySource   string `json:"telemetrySource"`
	Calibration       string `json:"calibration"`
	Readiness         string `json:"readiness"`
	SelectorMode      string `json:"selectorMode"`
	Deployments       int    `json:"deployments"`
	ReplicaSets       int    `json:"replicaSets"`
	Pods              int    `json:"pods"`
	Namespaces        int    `json:"namespaces"`
	ServiceAccounts   int    `json:"serviceAccounts"`
	Policies          int    `json:"policies"`
	PoliciesPerNS     int    `json:"policiesPerNamespace"`
	PodsPerPolicy     int    `json:"podsPerPolicy"`
	Nodes             int    `json:"nodes"`
	Services          int    `json:"services"`
	PDBs              int    `json:"pdbs"`
	NetworkPolicies   int    `json:"networkPolicies"`
	Roles             int    `json:"roles"`
	RoleBindings      int    `json:"roleBindings"`
	ClusterRoles      int    `json:"clusterRoles"`
	ClusterBindings   int    `json:"clusterRoleBindings"`
	SecurityEvents    int    `json:"securityEvents"`
	Receipts          int    `json:"receipts"`
	BrakeConfigMaps   int    `json:"brakeConfigMaps"`
	WarmupTicks       int    `json:"warmupTicks"`
	RequestedAttempts int    `json:"requestedAttempts"`
	TickTimeoutMS     int64  `json:"tickTimeoutMs"`
	TickIntervalMS    int64  `json:"tickIntervalMs"`
	SampleCadence     string `json:"sampleCadence"`
	AuditByteLimit    int    `json:"auditByteLimit"`
	AuditRetained     int    `json:"auditRetainedBytes"`
	AuditDropped      int    `json:"auditDroppedBytes"`
	MetricsSink       string `json:"metricsSink"`
	TrustFixture      string `json:"trustFixture"`
}

type Sample struct {
	Index         int                `json:"index"`
	Outcome       string             `json:"outcome"`
	DurationSec   float64            `json:"durationSeconds"`
	PolicySeconds map[string]float64 `json:"policyDurationSeconds"`
	HeapBytes     uint64             `json:"heapBytes"`
	RSSBytes      int64              `json:"rssBytes"`
	StatusWrites  int64              `json:"statusWrites"`
	Error         string             `json:"error,omitempty"`
}

type Control struct {
	Purpose string `json:"purpose"`
	Sample  Sample `json:"sample"`
}

type Memory struct {
	Scope             string  `json:"scope"`
	HarnessBaseline   int64   `json:"harnessBaselineRSSBytes"`
	HarnessPeak       int64   `json:"harnessPeakRSSBytes"`
	HarnessFinal      int64   `json:"harnessFinalRSSBytes"`
	HarnessSlopeBytes float64 `json:"harnessRSSSlopeBytesPerTick"`
	HeapBaseline      uint64  `json:"heapBaselineBytes"`
	HeapPeak          uint64  `json:"heapPeakBytes"`
	HeapFinal         uint64  `json:"heapFinalBytes"`
	HeapSlopeBytes    float64 `json:"heapSlopeBytesPerTick"`
	GCCount           uint32  `json:"gcCount"`
	APIBaseline       int64   `json:"apiServerBaselineRSSBytes"`
	APIPeak           int64   `json:"apiServerPeakRSSBytes"`
	APIFinal          int64   `json:"apiServerFinalRSSBytes"`
	EtcdBaseline      int64   `json:"etcdBaselineRSSBytes"`
	EtcdPeak          int64   `json:"etcdPeakRSSBytes"`
	EtcdFinal         int64   `json:"etcdFinalRSSBytes"`
}

type Correctness struct {
	CacheConverged            bool `json:"cacheConverged"`
	ProtectedObjectCount      int  `json:"protectedObjectCount"`
	GraphEdgesPresent         bool `json:"graphEdgesPresent"`
	RBACPresent               bool `json:"rbacPresent"`
	TrustedEventPresent       bool `json:"trustedEventPresent"`
	ReceiptPresent            bool `json:"receiptPresent"`
	DecisionRecords           int  `json:"decisionRecords"`
	SelectedFeasibleRecords   int  `json:"selectedFeasibleRecords"`
	CurrentOwnerEligible      bool `json:"currentOwnerEligible"`
	ControllerStatusPreserved bool `json:"controllerStatusPreserved"`
	NoFalseCadence            bool `json:"noFalseCadenceOnDeadline"`
}

type Summary struct {
	Successful         int     `json:"successful"`
	Incomplete         int     `json:"incomplete"`
	P50Seconds         float64 `json:"p50Seconds"`
	P95Seconds         float64 `json:"p95Seconds"`
	P99Seconds         float64 `json:"p99Seconds"`
	MaxSeconds         float64 `json:"maxSeconds"`
	ResidualP95Seconds float64 `json:"managerResidualP95Seconds"`
	PolicyP95Seconds   float64 `json:"measuredPolicyPortionP95Seconds"`
	ObservedDominant   string  `json:"observedDominantComponent"`
	BreachCount        int     `json:"breachCount"`
	TargetSec          float64 `json:"targetSeconds"`
}

type Report struct {
	SchemaVersion string                `json:"schemaVersion"`
	Environment   Environment           `json:"environment"`
	Fixture       Fixture               `json:"fixture"`
	Samples       []Sample              `json:"samples"`
	Controls      []Control             `json:"controls"`
	StartupHTTP   map[string]int64      `json:"startupHTTP"`
	SampleHTTP    map[string]int64      `json:"sampleHTTP"`
	ControlHTTP   map[string]int64      `json:"controlHTTP"`
	RESTConfigs   map[string]RESTConfig `json:"restConfigs"`
	Memory        Memory                `json:"memory"`
	Correctness   Correctness           `json:"correctness"`
	Summary       Summary               `json:"summary"`
	NFRVerdict    string                `json:"nfrVerdict"`
	NFRDetail     string                `json:"nfrDetail"`
	Limitations   []string              `json:"limitations"`
	ProbeErrors   []string              `json:"probeErrors,omitempty"`
}

func Summarize(samples []Sample, targetSeconds float64) Summary {
	values := make([]float64, 0, len(samples))
	residualValues := make([]float64, 0, len(samples))
	policyValues := make([]float64, 0, len(samples))
	incomplete := 0
	breaches := 0
	for _, sample := range samples {
		if sample.Outcome != "finished-full-snapshot" {
			incomplete++
			continue
		}
		values = append(values, sample.DurationSec)
		policy := 0.0
		for _, duration := range sample.PolicySeconds {
			policy += duration
		}
		residual := math.Max(sample.DurationSec-policy, 0)
		residualValues = append(residualValues, residual)
		policyValues = append(policyValues, policy)
		if sample.DurationSec >= targetSeconds {
			breaches++
		}
	}
	sort.Float64s(values)
	sort.Float64s(residualValues)
	sort.Float64s(policyValues)
	summary := Summary{
		Successful: len(values), Incomplete: incomplete, TargetSec: targetSeconds,
		P50Seconds: percentile(values, 0.50), P95Seconds: percentile(values, 0.95),
		P99Seconds: percentile(values, 0.99), MaxSeconds: percentile(values, 1),
		ResidualP95Seconds: percentile(residualValues, 0.95), PolicyP95Seconds: percentile(policyValues, 0.95),
		BreachCount: breaches,
	}
	if summary.ResidualP95Seconds >= summary.PolicyP95Seconds {
		summary.ObservedDominant = "manager-residual"
	} else {
		summary.ObservedDominant = "measured-policy-portion"
	}
	return summary
}

func percentile(sorted []float64, fraction float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(math.Ceil(fraction*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func Decode(r io.Reader) (Report, error) {
	var report Report
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return Report{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Report{}, errors.New("report must contain exactly one JSON value")
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

func (r Report) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion=%q, want %q", r.SchemaVersion, SchemaVersion)
	}
	if r.Environment.GitSHA == "" || r.Environment.Executable == "" || r.Environment.ExecutableSHA256 == "" || r.Environment.GoVersion == "" || r.Environment.KubernetesAssets == "" || r.Environment.CPUCount <= 0 || r.Environment.GOMAXPROCS <= 0 {
		return errors.New("source, toolchain, assets and CPU binding are required")
	}
	if decoded, err := hex.DecodeString(r.Environment.ExecutableSHA256); err != nil || len(decoded) != sha256.Size {
		return errors.New("executableSHA256 must be a complete SHA-256 digest")
	}
	if r.Environment.MemoryTotalBytes <= 0 || r.Environment.HarnessPID <= 0 || r.Environment.APIProcessPID <= 0 || r.Environment.EtcdProcessPID <= 0 || r.Environment.APIProcessRSSBytes <= 0 || r.Environment.EtcdProcessRSSBytes <= 0 {
		return errors.New("host, harness, API server and etcd process evidence are required")
	}
	if r.Fixture.Case == "" || r.Fixture.Backend == "" || r.Fixture.CacheReader == "" || r.Fixture.ReceiptReader == "" || r.Fixture.OwnerReader == "" || r.Fixture.TransportCoverage == "" || r.Fixture.Optimizer == "" || r.Fixture.TelemetrySource == "" || r.Fixture.Calibration == "" || r.Fixture.Readiness == "" {
		return errors.New("case and reader/backend configuration are required")
	}
	if r.Fixture.Deployments <= 0 || r.Fixture.ReplicaSets <= 0 || r.Fixture.Pods <= 0 || r.Fixture.Namespaces <= 0 || r.Fixture.Policies <= 0 || r.Fixture.PoliciesPerNS <= 0 || r.Fixture.PodsPerPolicy <= 0 || r.Fixture.RequestedAttempts < 20 || r.Fixture.WarmupTicks <= 0 || r.Fixture.TickTimeoutMS <= 0 || r.Fixture.TickIntervalMS <= 0 || r.Fixture.SampleCadence == "" {
		return errors.New("object counts, warmup and at least 20 requested samples are required")
	}
	if r.Fixture.Deployments != r.Fixture.Namespaces || r.Fixture.ReplicaSets != r.Fixture.Namespaces || r.Fixture.ServiceAccounts != r.Fixture.Namespaces || r.Fixture.Services != r.Fixture.Namespaces || r.Fixture.PDBs != r.Fixture.Namespaces || r.Fixture.NetworkPolicies != r.Fixture.Namespaces || r.Fixture.Roles != r.Fixture.Namespaces || r.Fixture.RoleBindings != r.Fixture.Namespaces || r.Fixture.BrakeConfigMaps != r.Fixture.Namespaces || r.Fixture.Policies%r.Fixture.Namespaces != 0 || r.Fixture.PoliciesPerNS != r.Fixture.Policies/r.Fixture.Namespaces {
		return errors.New("fixture object and per-namespace counts are inconsistent")
	}
	switch r.Fixture.SelectorMode {
	case "partitioned":
		if r.Fixture.Pods%r.Fixture.Policies != 0 || r.Fixture.PodsPerPolicy != r.Fixture.Pods/r.Fixture.Policies {
			return errors.New("partitioned selector pod count is inconsistent")
		}
	case "overlapping":
		if r.Fixture.Pods%r.Fixture.Namespaces != 0 || r.Fixture.PodsPerPolicy != r.Fixture.Pods/r.Fixture.Namespaces {
			return errors.New("overlapping selector pod count is inconsistent")
		}
	default:
		return fmt.Errorf("selectorMode=%q is not a measured fixture mode", r.Fixture.SelectorMode)
	}
	if r.Fixture.Nodes <= 0 || r.Fixture.Services <= 0 || r.Fixture.PDBs <= 0 || r.Fixture.NetworkPolicies <= 0 || r.Fixture.Roles <= 0 || r.Fixture.RoleBindings <= 0 || r.Fixture.ClusterRoles <= 0 || r.Fixture.ClusterBindings <= 0 || r.Fixture.SecurityEvents <= 0 || r.Fixture.Receipts <= 0 || r.Fixture.BrakeConfigMaps <= 0 {
		return errors.New("complete controller, topology, RBAC, event, receipt and brake object counts are required")
	}
	if r.Fixture.AuditByteLimit <= 0 || r.Fixture.AuditRetained <= 0 || r.Fixture.AuditDropped < 0 || r.Fixture.MetricsSink == "" || r.Fixture.TrustFixture == "" {
		return errors.New("bounded audit/metrics sinks and trust fixture declaration are required")
	}
	if len(r.Samples) != r.Fixture.RequestedAttempts {
		return fmt.Errorf("workload attempts=%d, want fixed predeclared budget %d", len(r.Samples), r.Fixture.RequestedAttempts)
	}
	finished := 0
	statusWrites := int64(0)
	indices := make(map[int]struct{}, len(r.Samples))
	for i, sample := range r.Samples {
		if sample.Index < 0 || sample.DurationSec < 0 || math.IsNaN(sample.DurationSec) || math.IsInf(sample.DurationSec, 0) || sample.Outcome == "" || sample.HeapBytes == 0 || sample.RSSBytes <= 0 || sample.StatusWrites < 0 || sample.StatusWrites > int64(r.Fixture.Policies) {
			return fmt.Errorf("sample %d is incomplete", i)
		}
		if sample.Index != i {
			return fmt.Errorf("sample index=%d at position %d, want fixed attempt order", sample.Index, i)
		}
		for tenant, duration := range sample.PolicySeconds {
			if tenant == "" || duration < 0 || math.IsNaN(duration) || math.IsInf(duration, 0) {
				return fmt.Errorf("sample %d has invalid policy duration for %q", i, tenant)
			}
		}
		statusWrites += sample.StatusWrites
		if _, duplicate := indices[sample.Index]; duplicate {
			return fmt.Errorf("sample index %d is duplicated", sample.Index)
		}
		indices[sample.Index] = struct{}{}
		if sample.Outcome == "finished-full-snapshot" {
			finished++
			if sample.Error != "" || len(sample.PolicySeconds) != r.Fixture.Policies || sample.StatusWrites != int64(r.Fixture.Policies) {
				return fmt.Errorf("sample %d lacks complete successful per-policy, memory or status-write evidence", i)
			}
		} else {
			switch sample.Outcome {
			case "no-snapshot", "snapshot-failed", "deadline", "canceled":
			default:
				return fmt.Errorf("sample %d has unknown outcome %q", i, sample.Outcome)
			}
			if sample.Error == "" {
				return fmt.Errorf("sample %d is incomplete without an error classification", i)
			}
		}
	}
	wantSummary := Summarize(r.Samples, r.Summary.TargetSec)
	if r.Summary != wantSummary {
		return errors.New("summary does not match retained samples")
	}
	if r.Summary.TargetSec != 1 {
		return fmt.Errorf("targetSeconds=%v, want the predeclared one-second target", r.Summary.TargetSec)
	}
	if r.Fixture.Pods == 1000 {
		want := "PASS"
		if r.Summary.BreachCount > 0 || r.Summary.Incomplete > 0 {
			want = "FAIL"
		}
		if r.NFRVerdict != want || r.NFRDetail == "" {
			return fmt.Errorf("1000-pod NFR verdict=%q detail=%q, want %s with explicit detail", r.NFRVerdict, r.NFRDetail, want)
		}
	} else {
		want := "OBSERVATION"
		if r.Summary.Incomplete > 0 {
			want = "INCOMPLETE"
		}
		if r.NFRVerdict != want || r.NFRDetail == "" {
			return fmt.Errorf("non-1000-pod verdict=%q, want %s with explicit detail", r.NFRVerdict, want)
		}
	}
	deadlineControl := false
	for _, control := range r.Controls {
		if control.Purpose == "deadline-exclusion-and-no-cadence" && control.Sample.Index == r.Fixture.RequestedAttempts && control.Sample.Outcome == "deadline" && control.Sample.Error != "" && control.Sample.DurationSec >= 0 && !math.IsNaN(control.Sample.DurationSec) && !math.IsInf(control.Sample.DurationSec, 0) && len(control.Sample.PolicySeconds) == 0 && control.Sample.StatusWrites == 0 {
			deadlineControl = true
		}
	}
	if !deadlineControl {
		return errors.New("separate deliberate deadline exclusion/no-cadence control is required")
	}
	if len(r.StartupHTTP) == 0 || r.SampleHTTP == nil || r.ControlHTTP == nil {
		return errors.New("startup, sampled and control HTTP counters are required")
	}
	for scope, counts := range map[string]map[string]int64{"startup": r.StartupHTTP, "sample": r.SampleHTTP, "control": r.ControlHTTP} {
		for key, value := range counts {
			if key == "" || value < 0 {
				return fmt.Errorf("%s HTTP count %q=%d is invalid", scope, key, value)
			}
		}
	}
	for _, origin := range []string{"fixture", "cache", "manager", "direct"} {
		config, ok := r.RESTConfigs[origin]
		if !ok || config.Server == "" || config.Timeout == "" || config.RateLimiter == "" || config.UserAgent == "" || config.QPS <= 0 || config.Burst <= 0 {
			return fmt.Errorf("counted REST origin %q lacks complete QPS/burst/timeout/rate-limiter binding", origin)
		}
	}
	if httpCount(r.StartupHTTP, "cache|WATCH|") == 0 {
		return errors.New("startup cache watch traffic is missing")
	}
	for key, value := range r.SampleHTTP {
		if strings.HasPrefix(key, "cache|LIST|") && value != 0 {
			return fmt.Errorf("sampled cache inventory LIST recurred: %s=%d", key, value)
		}
	}
	if httpCount(r.SampleHTTP, "direct|LIST|securityevents|") < int64(finished) {
		return errors.New("sampled direct SecurityEvent authority reads are missing")
	}
	if httpCount(r.ControlHTTP, "direct|LIST|securityevents|") == 0 {
		return errors.New("deadline control did not reach the post-snapshot producer boundary")
	}
	if httpCount(r.ControlHTTP, "manager|PUT|phorvexpolicies|status")+httpCount(r.ControlHTTP, "manager|PATCH|phorvexpolicies|status") != 0 {
		return errors.New("deadline control incorrectly wrote policy status")
	}
	if httpCount(r.SampleHTTP, "manager|PUT|phorvexpolicies|status")+httpCount(r.SampleHTTP, "manager|PATCH|phorvexpolicies|status") != statusWrites {
		return errors.New("sampled policy status traffic does not equal retained per-attempt writes")
	}
	if strings.Contains(r.Fixture.Backend, "native") && (httpCount(r.StartupHTTP, "direct|GET|replicasets|")+httpCount(r.SampleHTTP, "direct|GET|replicasets|") == 0 || httpCount(r.StartupHTTP, "direct|GET|deployments|")+httpCount(r.SampleHTTP, "direct|GET|deployments|") == 0) {
		return errors.New("native owner reads are missing from startup and sampled traffic")
	}
	if len(r.Limitations) < 2 {
		return errors.New("local scope and live capacity limitations are required")
	}
	if len(r.ProbeErrors) > 0 {
		return fmt.Errorf("probe correctness errors were retained: %v", r.ProbeErrors)
	}
	if r.Memory.Scope == "" || r.Memory.HarnessBaseline <= 0 || r.Memory.HarnessPeak <= 0 || r.Memory.APIBaseline <= 0 || r.Memory.APIPeak <= 0 || r.Memory.APIFinal <= 0 || r.Memory.EtcdBaseline <= 0 || r.Memory.EtcdPeak <= 0 || r.Memory.EtcdFinal <= 0 {
		return errors.New("process-scoped memory evidence is required")
	}
	c := r.Correctness
	if !c.CacheConverged || c.ProtectedObjectCount != r.Fixture.Pods || !c.GraphEdgesPresent || !c.RBACPresent || !c.TrustedEventPresent || !c.ReceiptPresent || c.DecisionRecords <= 0 || c.SelectedFeasibleRecords <= 0 || !c.CurrentOwnerEligible || !c.ControllerStatusPreserved || !c.NoFalseCadence {
		return errors.New("correctness controls did not all pass")
	}
	return nil
}

func httpCount(counts map[string]int64, prefix string) int64 {
	var total int64
	for key, value := range counts {
		if strings.HasPrefix(key, prefix) {
			total += value
		}
	}
	return total
}
