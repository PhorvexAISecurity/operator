/*
 * Phorvex cost-validation live probe (PHORVEXSEC-35).
 *
 * This binary is deliberately a benchmark tool, not part of the operator. It invokes
 * the real P1 cost model and NativeActuator, but refuses every namespace outside the
 * disposable phorvex-cost-validate-* prefix before constructing an actuator request.
 */
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	namespacePrefix = "phorvex-cost-validate-"
	schemaVersion   = "phorvex.cost-validation-observation.v1"
)

type nullableFloat struct {
	Value float64
	Valid bool
}

func (n nullableFloat) MarshalJSON() ([]byte, error) {
	if !n.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(n.Value)
}

type metricSnapshot struct {
	P99MS                 nullableFloat `json:"p99_ms"`
	TokensPerSecond       nullableFloat `json:"tokens_per_sec"`
	RequestRate           nullableFloat `json:"request_rate"`
	ActiveConnections     nullableFloat `json:"active_connections"`
	GPUUtil               nullableFloat `json:"gpu_util"`
	VRAMPressure          nullableFloat `json:"vram_pressure"`
	KVRebuildSeconds      nullableFloat `json:"kv_rebuild_sec"`
	GPUAllocationDelaySec nullableFloat `json:"gpu_allocation_delay_sec"`
	GPURecomputeBurden    nullableFloat `json:"gpu_recompute_burden"`
	StateVersion          string        `json:"state_version"`
	KVEpoch               string        `json:"kv_epoch"`
}

func (m *metricSnapshot) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	decodeFloat := func(key string) nullableFloat {
		v, ok := raw[key]
		if !ok || string(v) == "null" {
			return nullableFloat{}
		}
		var f float64
		if json.Unmarshal(v, &f) != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nullableFloat{}
		}
		return nullableFloat{Value: f, Valid: true}
	}
	m.P99MS = decodeFloat("p99_ms")
	m.TokensPerSecond = decodeFloat("tokens_per_sec")
	m.RequestRate = decodeFloat("request_rate")
	m.ActiveConnections = decodeFloat("active_connections")
	m.GPUUtil = decodeFloat("gpu_util")
	m.VRAMPressure = decodeFloat("vram_pressure")
	m.KVRebuildSeconds = decodeFloat("kv_rebuild_sec")
	m.GPUAllocationDelaySec = decodeFloat("gpu_allocation_delay_sec")
	m.GPURecomputeBurden = decodeFloat("gpu_recompute_burden")
	_ = json.Unmarshal(raw["state_version"], &m.StateVersion)
	_ = json.Unmarshal(raw["kv_epoch"], &m.KVEpoch)
	return nil
}

type observation struct {
	SchemaVersion string    `json:"schema_version"`
	CapturedAt    time.Time `json:"captured_at"`
	Cluster       string    `json:"cluster"`
	Revision      string    `json:"benchmark_revision"`

	ScenarioID   string `json:"scenario_id"`
	Seed         int    `json:"seed"`
	TickID       string `json:"tick_id"`
	WorkloadID   string `json:"workload_id"`
	WorkloadType string `json:"workload_type"`
	LoadProfile  string `json:"load_profile"`

	Namespace string `json:"namespace"`
	PodBefore string `json:"pod_before"`
	UIDBefore string `json:"uid_before"`
	PodAfter  string `json:"pod_after"`
	UIDAfter  string `json:"uid_after"`

	Action               string  `json:"action"`
	ActionFamily         string  `json:"action_family"`
	ImplementationStatus string  `json:"implementation_status"`
	CandidateGenerated   bool    `json:"candidate_generated"`
	CostModelAvailable   bool    `json:"cost_model_available"`
	FeasibilityStatus    string  `json:"feasibility_status"`
	CHi                  float64 `json:"chi"`

	CNorm              float64       `json:"c_norm"`
	CFlow              float64       `json:"c_flow"`
	CState             float64       `json:"c_state"`
	CGPU               nullableFloat `json:"c_gpu"`
	CAvailability      float64       `json:"c_availability"`
	C0Cost             float64       `json:"c0_cost"`
	Lambda             float64       `json:"lambda"`
	SecurityValue      float64       `json:"security_value"`
	PredictedObjective float64       `json:"predicted_objective"`

	ReadyBefore        int           `json:"ready_before"`
	ReadyAfter         int           `json:"ready_after"`
	MinReadyObserved   int           `json:"min_ready_observed"`
	DesiredReplicas    int           `json:"desired_replicas"`
	P99BeforeMS        nullableFloat `json:"p99_before_ms"`
	P99AfterMS         nullableFloat `json:"p99_after_ms"`
	TokensBefore       nullableFloat `json:"tokens_before_per_sec"`
	TokensAfter        nullableFloat `json:"tokens_after_per_sec"`
	TimeToReadySec     nullableFloat `json:"time_to_ready_sec"`
	ConnectionDrainSec nullableFloat `json:"connection_drain_sec"`
	StateOrKVLoss      nullableFloat `json:"state_or_kv_loss"`
	GPUUtilBefore      nullableFloat `json:"gpu_util_before"`
	GPUUtilAfter       nullableFloat `json:"gpu_util_after"`
	VRAMPressure       nullableFloat `json:"vram_pressure"`
	KVRebuildSec       nullableFloat `json:"kv_rebuild_sec"`
	GPUAllocationDelay nullableFloat `json:"gpu_allocation_delay_sec"`
	GPUBurden          nullableFloat `json:"gpu_burden"`
	AvailabilityLoss   float64       `json:"availability_loss"`
	SLOViolation       bool          `json:"slo_violation"`
	CostObserved       nullableFloat `json:"cost_observed"`
	ObservedLabelTerms int           `json:"observed_label_terms"`

	Actuator       string   `json:"actuator"`
	Emitted        bool     `json:"emitted"`
	Handler        string   `json:"handler"`
	MutationKind   string   `json:"mutation_kind"`
	ObjectsTouched []string `json:"objects_touched"`
	ActuationError string   `json:"actuation_error"`
	Missing        []string `json:"missing_measurements"`
}

type options struct {
	Namespace       string
	Pod             string
	Selector        string
	Action          string
	ScenarioID      string
	Seed            int
	TickID          string
	WorkloadID      string
	WorkloadType    string
	LoadProfile     string
	Phase           string
	Cluster         string
	Revision        string
	MetricsURL      string
	Output          string
	Implementation  string
	Feasibility     string
	Candidate       bool
	Stateful        bool
	RAG             bool
	GPU             bool
	DesiredReplicas int
	Lambda          float64
	SecurityValue   float64
	NormWeight      float64
	FlowWeight      float64
	SLOP99MS        float64
	Timeout         time.Duration
	PostWindow      time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.Namespace, "namespace", "", "disposable namespace (must begin phorvex-cost-validate-)")
	flag.StringVar(&o.Pod, "pod", "", "target pod name")
	flag.StringVar(&o.Selector, "selector", "", "label selector for workload replicas")
	flag.StringVar(&o.Action, "action", "", "action under test, including noop")
	flag.StringVar(&o.ScenarioID, "scenario-id", "", "scenario identifier")
	flag.IntVar(&o.Seed, "seed", 0, "scenario seed")
	flag.StringVar(&o.TickID, "tick-id", "", "candidate decision group")
	flag.StringVar(&o.WorkloadID, "workload-id", "", "workload identifier")
	flag.StringVar(&o.WorkloadType, "workload-type", "stateless", "stateless|stateful|gpu|rag")
	flag.StringVar(&o.LoadProfile, "load-profile", "low", "low|high|slo-hot|connections")
	flag.StringVar(&o.Phase, "phase", "Warm", "ColdStarting|Warm|Idle|Draining|Unknown")
	flag.StringVar(&o.Cluster, "cluster", "", "cluster provenance")
	flag.StringVar(&o.Revision, "revision", "", "benchmark git revision")
	flag.StringVar(&o.MetricsURL, "metrics-url", "", "optional JSON workload snapshot endpoint")
	flag.StringVar(&o.Output, "output", "-", "JSONL output path or -")
	flag.StringVar(&o.Implementation, "implementation-status", "implemented", "implementation classification")
	flag.StringVar(&o.Feasibility, "feasibility", "feasible", "pre-actuation feasibility classification")
	flag.BoolVar(&o.Candidate, "candidate-generated", true, "whether the engine can generate this candidate")
	flag.BoolVar(&o.Stateful, "stateful", false, "workload carries durable state")
	flag.BoolVar(&o.RAG, "rag", false, "workload carries RAG/KV state")
	flag.BoolVar(&o.GPU, "gpu", false, "workload is GPU-backed")
	flag.IntVar(&o.DesiredReplicas, "desired-replicas", 0, "expected workload replicas (0 derives from observed ready replicas)")
	flag.Float64Var(&o.Lambda, "lambda", 1, "optimizer cost shadow price")
	flag.Float64Var(&o.SecurityValue, "security-value", 1, "candidate security/coverage value")
	flag.Float64Var(&o.NormWeight, "norm-weight", 0.4, "current C0 norm weight")
	flag.Float64Var(&o.FlowWeight, "flow-weight", 0.6, "current C0 flow weight")
	flag.Float64Var(&o.SLOP99MS, "slo-p99-ms", 0, "p99 SLO threshold; 0 means unspecified")
	flag.DurationVar(&o.Timeout, "timeout", 10*time.Minute, "maximum recovery wait")
	flag.DurationVar(&o.PostWindow, "post-window", 5*time.Second, "settling window before post snapshot")
	flag.Parse()

	if err := run(context.Background(), o); err != nil {
		fmt.Fprintln(os.Stderr, "costprobe:", err)
		os.Exit(1)
	}
}

func validateNamespace(ns string) error {
	if !strings.HasPrefix(ns, namespacePrefix) || len(ns) <= len(namespacePrefix) {
		return fmt.Errorf("refusing namespace %q: benchmark mutations are restricted to %s*", ns, namespacePrefix)
	}
	return nil
}

func run(parent context.Context, o options) error {
	if err := validateNamespace(o.Namespace); err != nil {
		return err
	}
	if o.Pod == "" || o.Selector == "" || o.Action == "" || o.ScenarioID == "" || o.TickID == "" {
		return errors.New("namespace, pod, selector, action, scenario-id, and tick-id are required")
	}
	action := model.Action(o.Action)
	if !knownAction(action) {
		return fmt.Errorf("unknown action %q", action)
	}

	cfg, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("kube config: %w", err)
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	kube, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("kube client: %w", err)
	}

	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	var target corev1.Pod
	if err := kube.Get(ctx, client.ObjectKey{Namespace: o.Namespace, Name: o.Pod}, &target); err != nil {
		return fmt.Errorf("target pod: %w", err)
	}
	readyBefore, podsBefore, err := readyPods(ctx, kube, o.Namespace, o.Selector)
	if err != nil {
		return err
	}
	desired := o.DesiredReplicas
	if desired <= 0 {
		desired = readyBefore
		if desired <= 0 {
			desired = len(podsBefore)
		}
		if desired <= 0 {
			desired = 1
		}
	}
	preActionUIDs := make(map[string]bool, len(podsBefore))
	for i := range podsBefore {
		preActionUIDs[string(podsBefore[i].UID)] = true
	}

	before, beforeErr := fetchMetrics(ctx, o.MetricsURL)
	view := workloadView(target, o, before, readyBefore, desired)
	pol := model.Policy{NormSparsity: o.NormWeight, FlowDisruption: o.FlowWeight}
	p1 := cost.NewP1Cost()
	components := p1.Components(view, model.Move{Action: action}, pol)
	chi := p1.CHi(view, model.Move{Action: action}, pol)

	obs := observation{
		SchemaVersion: schemaVersion, CapturedAt: time.Now().UTC(), Cluster: o.Cluster, Revision: o.Revision,
		ScenarioID: o.ScenarioID, Seed: o.Seed, TickID: o.TickID, WorkloadID: defaultString(o.WorkloadID, o.ScenarioID),
		WorkloadType: o.WorkloadType, LoadProfile: o.LoadProfile,
		Namespace: o.Namespace, PodBefore: target.Name, UIDBefore: string(target.UID),
		Action: string(action), ActionFamily: actionFamily(action), ImplementationStatus: o.Implementation,
		CandidateGenerated: o.Candidate, CostModelAvailable: true, FeasibilityStatus: o.Feasibility,
		CHi: chi, CNorm: components.Norm, CFlow: components.Flow, CState: stateFeature(action, o),
		CGPU: gpuFeature(action, o, before), CAvailability: availabilityFeature(action, readyBefore),
		C0Cost: components.Total, Lambda: o.Lambda, SecurityValue: o.SecurityValue,
		PredictedObjective: o.SecurityValue - o.Lambda*components.Total,
		ReadyBefore:        readyBefore, DesiredReplicas: desired,
		P99BeforeMS: before.P99MS, TokensBefore: before.TokensPerSecond,
		GPUUtilBefore: before.GPUUtil, VRAMPressure: before.VRAMPressure,
		Actuator: "native", MinReadyObserved: readyBefore,
	}
	if beforeErr != nil {
		obs.Missing = append(obs.Missing, "pre_metrics:"+compactError(beforeErr))
	}

	start := time.Now()
	if action == model.ActionNoop {
		obs.Emitted = false
		obs.Handler = "noop/control"
		obs.MutationKind = "control"
	} else if o.Feasibility != "feasible" {
		obs.ActuationError = "not executed: feasibility=" + o.Feasibility
	} else {
		native := actuator.NewNativeActuator(kube)
		native.StrictTenantNamespace = true
		if err := native.EnsurePolicy(ctx, actuator.TenantTarget{Tenant: "cost-validation", Namespace: o.Namespace}); err != nil {
			return err
		}
		res, actErr := native.Actuate(ctx, actuator.Request{
			Tenant: "cost-validation", Namespace: o.Namespace, Pod: o.Pod, Action: action,
			Reason: "PHORVEXSEC-35 isolated cost validation", Score: 1,
		})
		obs.Emitted = res.Emitted
		obs.Handler = res.Handler
		obs.MutationKind = res.MutationKind
		obs.ObjectsTouched = res.ObjectsTouched
		if actErr != nil {
			obs.ActuationError = actErr.Error()
		}
	}

	minReady := readyBefore
	var afterPod corev1.Pod
	var targetDeparted nullableFloat
	for {
		ready, pods, listErr := readyPods(ctx, kube, o.Namespace, o.Selector)
		if listErr != nil {
			return listErr
		}
		if ready < minReady {
			minReady = ready
		}
		if !targetDeparted.Valid && !containsUID(pods, string(target.UID)) {
			targetDeparted = nullableFloat{Value: time.Since(start).Seconds(), Valid: true}
		}
		if action == model.ActionRotate {
			afterPod = newReplica(pods, preActionUIDs)
		} else if len(pods) > 0 {
			afterPod = pods[0]
		}
		if action == model.ActionNoop || obs.ActuationError != "" || (ready >= desired && afterPod.Name != "") {
			break
		}
		select {
		case <-ctx.Done():
			obs.ActuationError = strings.TrimSpace(obs.ActuationError + "; recovery timeout: " + ctx.Err().Error())
			break
		case <-time.After(500 * time.Millisecond):
		}
		if ctx.Err() != nil {
			break
		}
	}
	readyDelay := time.Since(start).Seconds()
	if action == model.ActionNoop {
		readyDelay = 0
	}
	obs.TimeToReadySec = nullableFloat{Value: readyDelay, Valid: obs.ActuationError == ""}
	obs.MinReadyObserved = minReady
	obs.ReadyAfter, _, _ = readyPods(context.Background(), kube, o.Namespace, o.Selector)
	obs.PodAfter = afterPod.Name
	obs.UIDAfter = string(afterPod.UID)
	obs.AvailabilityLoss = clamp01(float64(readyBefore-minReady) / float64(maxInt(desired, 1)))

	if o.PostWindow > 0 {
		select {
		case <-time.After(o.PostWindow):
		case <-ctx.Done():
		}
	}
	after, afterErr := fetchMetrics(context.Background(), o.MetricsURL)
	obs.P99AfterMS = after.P99MS
	obs.TokensAfter = after.TokensPerSecond
	obs.GPUUtilAfter = after.GPUUtil
	obs.KVRebuildSec = after.KVRebuildSeconds
	obs.GPUAllocationDelay = after.GPUAllocationDelaySec
	if after.VRAMPressure.Valid {
		obs.VRAMPressure = after.VRAMPressure
	}
	if afterErr != nil {
		obs.Missing = append(obs.Missing, "post_metrics:"+compactError(afterErr))
	}
	if action == model.ActionNoop {
		obs.ConnectionDrainSec = nullableFloat{Value: 0, Valid: true}
	} else if targetDeparted.Valid {
		// For replacement/isolation moves this is the real Kubernetes drain boundary:
		// the target UID has been deleted or detached from the workload selector.
		obs.ConnectionDrainSec = targetDeparted
	} else if before.ActiveConnections.Valid && before.ActiveConnections.Value <= 0 {
		obs.ConnectionDrainSec = nullableFloat{Value: 0, Valid: true}
	} else if before.ActiveConnections.Valid && after.ActiveConnections.Valid && after.ActiveConnections.Value <= 0 {
		obs.ConnectionDrainSec = nullableFloat{Value: time.Since(start).Seconds(), Valid: true}
	} else {
		obs.Missing = append(obs.Missing, "connection_drain_time")
	}
	if o.Stateful || o.RAG {
		beforeState := before.StateVersion + "\x00" + before.KVEpoch
		afterState := after.StateVersion + "\x00" + after.KVEpoch
		if beforeState != "\x00" && afterState != "\x00" {
			loss := 0.0
			if beforeState != afterState {
				loss = 1
			}
			obs.StateOrKVLoss = nullableFloat{Value: loss, Valid: true}
		} else {
			obs.Missing = append(obs.Missing, "state_or_kv_loss")
		}
	} else {
		obs.StateOrKVLoss = nullableFloat{Value: 0, Valid: true}
	}
	obs.GPUBurden = observedGPUBurden(before, after)
	if (o.GPU || o.RAG) && !obs.GPUBurden.Valid {
		obs.Missing = append(obs.Missing, "gpu_burden")
	}
	obs.SLOViolation = obs.ReadyAfter < desired || (o.SLOP99MS > 0 && after.P99MS.Valid && after.P99MS.Value > o.SLOP99MS)
	obs.CostObserved, obs.ObservedLabelTerms = observedCost(obs)
	if !obs.CostObserved.Valid {
		obs.Missing = append(obs.Missing, "cost_observed")
	}
	sort.Strings(obs.Missing)
	return writeObservation(o.Output, obs)
}

func workloadView(pod corev1.Pod, o options, metrics metricSnapshot, ready, desired int) *model.WorkloadView {
	phase := model.WorkloadPhase(o.Phase)
	if phase == "" {
		phase = model.PhaseUnknown
	}
	t := model.Telemetry{}
	if metrics.P99MS.Valid || metrics.TokensPerSecond.Valid || metrics.RequestRate.Valid || metrics.ActiveConnections.Valid || metrics.GPUUtil.Valid {
		t.Present = true
		t.P99Ms = metrics.P99MS.Value
		t.TokensPerSec = metrics.TokensPerSecond.Value
		t.ReqRate = metrics.RequestRate.Value
		t.ConnCount = metrics.ActiveConnections.Value
		t.GPUUtil = metrics.GPUUtil.Value
	}
	return &model.WorkloadView{
		Pod: model.Pod{
			Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID), Labels: pod.Labels,
			Ready: podReady(pod), DesiredReplicas: desired, ReadyReplicas: ready,
			HasGPU: o.GPU, Stateful: o.Stateful,
		},
		Telemetry: t, Phase: phase,
	}
}

func readyPods(ctx context.Context, kube client.Client, namespace, selector string) (int, []corev1.Pod, error) {
	parsed, err := metav1.ParseToLabelSelector(selector)
	if err != nil {
		return 0, nil, fmt.Errorf("selector: %w", err)
	}
	sel, err := metav1.LabelSelectorAsSelector(parsed)
	if err != nil {
		return 0, nil, err
	}
	var list corev1.PodList
	if err := kube.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return 0, nil, err
	}
	ready := 0
	for i := range list.Items {
		if podReady(list.Items[i]) {
			ready++
		}
	}
	return ready, list.Items, nil
}

func podReady(p corev1.Pod) bool {
	if p.DeletionTimestamp != nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func newReplica(pods []corev1.Pod, preActionUIDs map[string]bool) corev1.Pod {
	for i := range pods {
		if !preActionUIDs[string(pods[i].UID)] {
			return pods[i]
		}
	}
	return corev1.Pod{}
}

func containsUID(pods []corev1.Pod, uid string) bool {
	for i := range pods {
		if string(pods[i].UID) == uid {
			return true
		}
	}
	return false
}

func fetchMetrics(ctx context.Context, url string) (metricSnapshot, error) {
	if url == "" {
		return metricSnapshot{}, errors.New("metrics URL not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return metricSnapshot{}, err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return metricSnapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return metricSnapshot{}, fmt.Errorf("metrics HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out metricSnapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return metricSnapshot{}, err
	}
	return out, nil
}

func knownAction(action model.Action) bool {
	if action == model.ActionNoop || action == model.ActionDisable {
		return true
	}
	for _, candidate := range model.MutatingActions {
		if action == candidate {
			return true
		}
	}
	return false
}

func actionFamily(action model.Action) string {
	switch action {
	case model.ActionNoop:
		return "control"
	case model.ActionRotate, model.ActionWarmSwap, model.ActionMIGRebind, model.ActionModelShardReplace:
		return "replacement"
	case model.ActionQuarantine, model.ActionRouteRotate, model.ActionEndpointRotate, model.ActionRequestDrain:
		return "traffic-isolation"
	case model.ActionKVReset, model.ActionKVMigrateInvalidate:
		return "state-invalidation"
	case model.ActionIdentityRotate:
		return "identity"
	case model.ActionDebugger, model.ActionCustomInject:
		return "injection"
	case model.ActionAdapterRotate:
		return "adapter"
	case model.ActionGuardrailRotate:
		return "guardrail"
	case model.ActionDisable:
		return "declared"
	default:
		return "other"
	}
}

func stateFeature(action model.Action, o options) float64 {
	if !o.Stateful && !o.RAG {
		return 0
	}
	switch action {
	case model.ActionRotate, model.ActionWarmSwap, model.ActionMIGRebind, model.ActionKVReset,
		model.ActionModelShardReplace, model.ActionKVMigrateInvalidate:
		return 1
	default:
		return 0
	}
}

func gpuFeature(action model.Action, o options, metrics metricSnapshot) nullableFloat {
	if !o.GPU {
		return nullableFloat{Value: 0, Valid: true}
	}
	switch action {
	case model.ActionRotate, model.ActionWarmSwap, model.ActionMIGRebind, model.ActionKVReset,
		model.ActionModelShardReplace, model.ActionAdapterRotate, model.ActionKVMigrateInvalidate:
		if metrics.GPUUtil.Valid || metrics.VRAMPressure.Valid {
			return nullableFloat{Value: math.Max(metrics.GPUUtil.Value, metrics.VRAMPressure.Value), Valid: true}
		}
		return nullableFloat{}
	default:
		return nullableFloat{Value: 0, Valid: true}
	}
}

func availabilityFeature(action model.Action, ready int) float64 {
	switch action {
	case model.ActionRotate, model.ActionQuarantine, model.ActionDisable, model.ActionMIGRebind, model.ActionRequestDrain:
		return 1 / float64(maxInt(ready, 1))
	default:
		return 0
	}
}

func observedGPUBurden(before, after metricSnapshot) nullableFloat {
	vals := []float64{}
	if after.GPURecomputeBurden.Valid {
		vals = append(vals, clamp01(after.GPURecomputeBurden.Value))
	}
	if after.GPUAllocationDelaySec.Valid {
		vals = append(vals, clamp01(after.GPUAllocationDelaySec.Value/400.0))
	}
	if before.GPUUtil.Valid && after.GPUUtil.Valid && before.GPUUtil.Value > 0 {
		vals = append(vals, clamp01((before.GPUUtil.Value-after.GPUUtil.Value)/before.GPUUtil.Value))
	}
	if len(vals) == 0 {
		return nullableFloat{}
	}
	return nullableFloat{Value: mean(vals), Valid: true}
}

func observedCost(o observation) (nullableFloat, int) {
	terms := []float64{o.AvailabilityLoss}
	if o.P99BeforeMS.Valid && o.P99AfterMS.Valid {
		terms = append(terms, normalizedIncrease(o.P99BeforeMS.Value, o.P99AfterMS.Value))
	}
	if o.TokensBefore.Valid && o.TokensAfter.Valid {
		terms = append(terms, normalizedDrop(o.TokensBefore.Value, o.TokensAfter.Value))
	}
	if o.TimeToReadySec.Valid {
		terms = append(terms, clamp01(o.TimeToReadySec.Value/400.0))
	}
	if o.StateOrKVLoss.Valid {
		terms = append(terms, clamp01(o.StateOrKVLoss.Value))
	}
	if o.GPUBurden.Valid {
		terms = append(terms, clamp01(o.GPUBurden.Value))
	}
	if len(terms) == 0 {
		return nullableFloat{}, 0
	}
	return nullableFloat{Value: mean(terms), Valid: true}, len(terms)
}

func normalizedIncrease(before, after float64) float64 {
	return clamp01((after - before) / math.Max(math.Abs(before), 1))
}

func normalizedDrop(before, after float64) float64 {
	return clamp01((before - after) / math.Max(math.Abs(before), 1e-9))
}

func clamp01(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func mean(v []float64) float64 {
	total := 0.0
	for _, x := range v {
		total += x
	}
	return total / float64(len(v))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func compactError(err error) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(strings.TrimSpace(err.Error()), "\n", " ")
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func writeObservation(path string, obs observation) error {
	data, err := json.Marshal(obs)
	if err != nil {
		return err
	}
	if path == "-" {
		_, err = fmt.Fprintln(os.Stdout, string(data))
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, string(data))
	return err
}
