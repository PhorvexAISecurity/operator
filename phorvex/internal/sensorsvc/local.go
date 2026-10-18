// Package sensorsvc serves the sensorapi contract from the cluster and its
// telemetry. Local runs in the caller's process; the sensor service's gRPC server
// serves the same adapter, so both paths share one implementation.
package sensorsvc

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/graph"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/sensorapi"
)

// Local observes the cluster through Kubernetes readers and a telemetry source.
type Local struct {
	// Client is the cached client the inventories are listed from.
	Client client.Client
	// OwnershipReader is the uncached reader for rotation-owner and warm-pool
	// evidence, read only when a request asks for owners.
	OwnershipReader client.Reader
	// BoundaryReader is the uncached reader for SecurityEvents, Phoenix receipts and
	// the live object bindings. Nil leaves receipts unobserved.
	BoundaryReader client.Reader
	// PromURL feeds the GPU half of the physics witness (DCGM via Prometheus);
	// empty leaves it absent. PCIeClasses is its PCIe capacity fallback.
	PromURL     string
	PCIeClasses ingest.PCIeClassTable
	// Metrics is the telemetry source; nil means none is configured.
	Metrics ingest.MetricsSource
}

var _ sensorapi.Sensor = (*Local)(nil)

func (l *Local) Observe(ctx context.Context, req sensorapi.ObserveRequest) (*sensorapi.Observation, error) {
	scopes, err := parseScopes(req.Scopes)
	if err != nil {
		return nil, err
	}
	var ownerReader client.Reader
	if req.ResolveOwners {
		ownerReader = l.OwnershipReader
	}
	snap, err := ingest.CollectSnapshotForRotationTargetsWithReceiptReader(ctx, l.Client, req.Now, GenericAssetValue,
		ownerReader, l.BoundaryReader, func(p *corev1.Pod) bool { return scopes.selects(p.Namespace, p.Labels) })
	if err != nil {
		return nil, err
	}
	// The GPU half is best effort: an unreachable DCGM feed leaves the neutral witness.
	var gpuErr error
	if l.PromURL != "" {
		gpuErr = ingest.PopulateGPUWitness(ctx, snap, l.PromURL, l.PCIeClasses)
	}
	obs, err := FromSnapshot(snap, req.Scopes)
	if err == nil && gpuErr != nil {
		obs.GPUWitnessError = gpuErr.Error()
	}
	return obs, err
}

func (l *Local) Telemetry(ctx context.Context, req sensorapi.TelemetryRequest) sensorapi.TelemetryResult {
	if l.Metrics == nil {
		return sensorapi.TelemetryResult{}
	}
	telemetry, err := l.Metrics.PodMetrics(ctx, req.Namespace, req.Pods)
	out := sensorapi.TelemetryResult{Configured: true, Telemetry: telemetry, Health: model.SourceHealth{Source: l.Metrics.Name()}}
	if hr, ok := l.Metrics.(ingest.HealthReporter); ok {
		out.Health = hr.LastHealth()
	} else if err != nil {
		out.Health = model.SourceHealth{Source: l.Metrics.Name(), Total: 1, Failed: 1}
	}
	if err != nil {
		out.Error = err.Error()
	}
	return out
}

// FromSnapshot derives the observation of a collected snapshot: the physics
// witnesses of every Pod, and the graph and event context of each Pod a scope
// selects. It reads nothing from the cluster.
func FromSnapshot(snap *ingest.Snapshot, scopes []sensorapi.Scope) (*sensorapi.Observation, error) {
	parsed, err := parseScopes(scopes)
	if err != nil {
		return nil, err
	}
	platformName, physics := platform.Derive(snap)
	obs := &sensorapi.Observation{
		Now: snap.Now, Pods: snap.Pods, Nodes: snap.Nodes, Services: snap.Services,
		NamespaceLabels: snap.NamespaceLabels, NamespaceDryRun: snap.NamespaceDryRun,
		Events: snap.Events, EventByPod: snap.EventByPod, EvidenceEvents: ingest.EvidenceEvents(snap.Events),
		PhoenixReceipts:                 snap.PhoenixReceipts,
		PodInventoryComplete:            snap.PodInventoryComplete,
		PolicyInventoryComplete:         snap.PolicyInventoryComplete,
		EventInventoryComplete:          snap.EventInventoryComplete,
		PhoenixReceiptInventoryComplete: snap.PhoenixReceiptInventoryComplete,
		Context:                         map[string]sensorapi.PodContext{},
		Physics:                         physics,
		Platform:                        platformName,
	}
	obs.PolicyMembership, obs.PolicySelectorsValid = policyMembership(snap)
	infected := infectedSet(snap.EventByPod)
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if parsed.selects(p.Namespace, p.Labels) {
			obs.Context[p.Namespace+"/"+p.Name] = podContext(snap, p, infected)
		}
	}
	return obs, nil
}

// GenericAssetValue is the tenant-INDEPENDENT pod value used to weight the shared
// blast-radius graph (per-tenant label weights are applied later in the context
// provider). It values mounted secrets and stateful pods, with a small baseline.
func GenericAssetValue(p *model.Pod) float64 {
	v := 0.1 + 0.8*float64(len(p.MountedSecrets))
	if p.Stateful {
		v += 0.3
	}
	return v
}

func podContext(snap *ingest.Snapshot, p *model.Pod, infected map[string]bool) sensorapi.PodContext {
	g := snap.Graph
	if g == nil {
		g = &graph.Graph{}
	}
	events := append([]model.SecurityEventInfo{}, snap.EventByPod[p.Namespace+"/"+p.Name]...)
	nbKeys := g.Neighbors(p.Namespace, p.Name)
	neighbors := make([]model.NeighborRef, 0, len(nbKeys))
	for _, nb := range nbKeys {
		for _, ne := range snap.EventByPod[nb] {
			ne.TargetsPod = false
			events = append(events, ne)
		}
		val := 0.0
		if np, ok := snap.PodByKey[nb]; ok {
			val = GenericAssetValue(np)
		}
		neighbors = append(neighbors, model.NeighborRef{Key: nb, Value: val})
	}
	return sensorapi.PodContext{
		BlastRadius:       g.BlastRadius(p.Namespace, p.Name),
		NeighborCount:     g.NeighborCount(p.Namespace, p.Name),
		Neighbors:         neighbors,
		Events:            events,
		InfectionFrontier: infectionFrontier(nbKeys, infected),
	}
}

// infectedSet (P-CONTEXT live-beta Tier-1) reconstructs the per-tick infected set:
// pods with a high/critical TargetsPod event (an exploit+ foothold). It is a lossy
// LOWER bound (under-counts — the safe direction, never inflates cover). Empty => no
// frontier lift => byte-identical to the pre-P-CONTEXT decision.
func infectedSet(eventByPod map[string][]model.SecurityEventInfo) map[string]bool {
	inf := map[string]bool{}
	for key, evs := range eventByPod {
		for i := range evs {
			// A copied Pod-bound bearer may be usable off-Pod. It identifies an
			// exact source for credential response, but does not establish an
			// exploit foothold on that Pod or its graph neighbors.
			if evs[i].Type == model.AttackVectorPodBoundAPIAuth {
				continue
			}
			if isHighSeverity(evs[i].ThreatLevel) {
				inf[key] = true
				break
			}
		}
	}
	return inf
}

func isHighSeverity(tl string) bool {
	switch tl {
	case "high", "High", "HIGH", "critical", "Critical", "CRITICAL":
		return true
	}
	return false
}

// infectionFrontier returns 1 + kappa (kappa=0.5) when any graph-neighbor is in the
// infected set, else 1.0 (honest-absent).
func infectionFrontier(nbKeys []string, infected map[string]bool) float64 {
	for _, nb := range nbKeys {
		if infected[nb] {
			return 1.5
		}
	}
	return 1.0
}

// policyMembership lists, per Pod, the tenants of the policies selecting it. It
// is false when a policy selector does not parse.
func policyMembership(snap *ingest.Snapshot) (map[string][]string, bool) {
	membership, valid := map[string][]string{}, true
	for _, p := range snap.Policies {
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.Selector)
		if err != nil {
			valid = false
			continue
		}
		for _, pod := range snap.Pods {
			if pod.Namespace == p.Namespace && sel.Matches(labels.Set(pod.Labels)) {
				key := pod.Namespace + "/" + pod.Name
				membership[key] = append(membership[key], p.EffectiveTenant())
			}
		}
	}
	return membership, valid
}

type parsedScope struct {
	namespace string
	selector  labels.Selector
}

type scopeSet []parsedScope

func parseScopes(scopes []sensorapi.Scope) (scopeSet, error) {
	out := make(scopeSet, 0, len(scopes))
	for _, s := range scopes {
		sel, err := labels.Parse(s.Selector)
		if err != nil {
			return nil, fmt.Errorf("scope %s selector %q: %w", s.Namespace, s.Selector, err)
		}
		out = append(out, parsedScope{namespace: s.Namespace, selector: sel})
	}
	return out, nil
}

func (s scopeSet) selects(namespace string, podLabels map[string]string) bool {
	for _, scope := range s {
		if namespace == scope.namespace && scope.selector.Matches(labels.Set(podLabels)) {
			return true
		}
	}
	return false
}
