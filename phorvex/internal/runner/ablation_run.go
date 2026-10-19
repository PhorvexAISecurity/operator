/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package runner

import (
	"context"
	"fmt"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"time"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
	"github.com/phorvex/phorvex/internal/sensorsvc"
)

// ContextRow is one pod's live kill-chain context (P-CONTEXT proof).
type ContextRow struct {
	Pod                   string
	Stage                 string
	AIClassified          bool
	PHold                 float64
	PreemptMargin         float64
	ProjectedNextStageSec float64
	InfectionFrontier     float64
}

// ContextScan ingests the live cluster (with discovered physics) and runs the
// kill-chain Assess per pod — surfacing the AI-stage classification + the predictive
// horizon (PreemptMargin / ProjectedNextStageSec = the moved-before-next-stage metric).
func (m *Manager) ContextScan(ctx context.Context, namespace string, sel labels.Selector) ([]ContextRow, error) {
	views, _, err := m.buildAblationViews(ctx, namespace, sel)
	if err != nil {
		return nil, err
	}
	km := killchain.NewModel()
	pol := ablationPolicy(namespace, 2)
	rows := make([]ContextRow, 0, len(views))
	for _, v := range views {
		exp := 0.0
		if d, ok := v.ExposureByVariable[model.VarPodIdentity]; ok {
			exp = d.Seconds()
		}
		a := km.Assess(v, pol, exp, pol.ProactiveFloor.Seconds())
		rows = append(rows, ContextRow{
			Pod: v.Pod.Namespace + "/" + v.Pod.Name, Stage: a.StageName, AIClassified: a.AIClassified,
			PHold: a.PHold, PreemptMargin: a.PreemptMargin, ProjectedNextStageSec: a.ProjectedNextStageSec,
			InfectionFrontier: v.InfectionFrontier,
		})
	}
	return rows, nil
}

// buildAblationViews ingests the real cluster and builds WorkloadViews (the SAME way the
// tick loop does — read-only, fresh clock) WITH the discovered view.Physics stamped from
// the live platform scan. Shared by the per-dollar ablation and the scarcity A/B.
func (m *Manager) buildAblationViews(ctx context.Context, namespace string, sel labels.Selector) ([]*model.WorkloadView, string, error) {
	now := time.Now()
	// A read-only sensor over the cached client alone: no owner, receipt or binding reads.
	sensor := &sensorsvc.Local{Client: m.Client, PromURL: m.PromURL, PCIeClasses: m.PCIeClasses}
	obs, err := sensor.Observe(ctx, sensorapi.ObserveRequest{Now: now,
		Scopes: []sensorapi.Scope{{Namespace: namespace, Selector: selectorString(sel)}}})
	if err != nil {
		return nil, "", err
	}
	// The ablation builds a fresh observation, so the GPU witness must come from the
	// configured live DCGM feed. Otherwise --scan can print a real GPU witness while its
	// subsequent scarcity A/B silently runs GPU-neutral.
	if obs.GPUWitnessError != "" {
		return nil, "", fmt.Errorf("GPU/DCGM witness ingest: %s", obs.GPUWitnessError)
	}
	platformName := obs.Platform
	clock := exposure.NewClock()
	// [M-140] The offline ablation has no API object, so it uses the name-kind owner
	// fallback — the same key ablationPolicy(namespace, ...).Owner() produces.
	owner := model.OwnerKey(model.OwnerKindName, namespace)
	var views []*model.WorkloadView
	for i := range obs.Pods {
		p := &obs.Pods[i]
		if p.Namespace != namespace {
			continue
		}
		if sel != nil && !sel.Matches(labels.Set(p.Labels)) {
			continue
		}
		clock.Observe(exposure.Observation{
			Owner: owner, Namespace: p.Namespace, Pod: p.Name, StartedAt: p.StartedAt,
			Fingerprints: map[string]string{model.VarPodIdentity: p.UID},
		}, now)
		exp := clock.Since(owner, p.Namespace, p.Name, now)
		podContext := observedContext(obs, p)
		ph, ok := obs.Physics[p.Namespace+"/"+p.Name]
		if !ok {
			ph = model.NeutralPhysics()
		}
		phase, phaseReason := model.ClassifyPhase(*p, model.Telemetry{})
		views = append(views, &model.WorkloadView{
			Pod:                *p,
			Phase:              phase,
			PhaseReason:        phaseReason,
			BlastRadius:        podContext.BlastRadius,
			NeighborCount:      podContext.NeighborCount,
			Neighbors:          podContext.Neighbors,
			Events:             podContext.Events,
			ExposureByVariable: exp,
			Physics:            ph,
			InfectionFrontier:  podContext.InfectionFrontier,
		})
	}
	return views, platformName, nil
}

// Ablate runs the STEP-3 IP ablation LIVE (P1 coverage optimizer vs random per-dollar)
// over the real cluster with discovered physics stamped.
func (m *Manager) Ablate(ctx context.Context, namespace string, sel labels.Selector, seeds []int64, budget int) (decision.AblationResult, error) {
	views, _, err := m.buildAblationViews(ctx, namespace, sel)
	if err != nil {
		return decision.AblationResult{}, err
	}
	eng := decision.NewCoverageEngine()
	return eng.Ablate(views, ablationPolicy(namespace, budget), seeds), nil
}

// AblateScarcity runs the P-PHYSICS separately-ablated A/B LIVE: standard-recon (no
// discovered dispersion) vs ucw-recon (discovered) over the SAME real fleet, so any
// ratio delta is attributable to discovery. On a uniform cluster (kind) this is an
// exact tie; only measured dispersion lifts it.
func (m *Manager) AblateScarcity(ctx context.Context, namespace string, sel labels.Selector, seeds []int64, budget int) (decision.ScarcityAblation, string, error) {
	views, platformName, err := m.buildAblationViews(ctx, namespace, sel)
	if err != nil {
		return decision.ScarcityAblation{}, "", err
	}
	return decision.AblateScarcity(views, ablationPolicy(namespace, budget), seeds), platformName, nil
}

func ablationPolicy(namespace string, budget int) model.Policy {
	if budget <= 0 {
		budget = 2
	}
	return model.Policy{
		Tenant: namespace, Namespace: namespace, Mode: "dryRun", DryRun: true,
		Lambda: 0.6, NormSparsity: 0.4, FlowDisruption: 0.6, WeightSecrets: 0.8, BlastRadiusFromGraph: true,
		MaxMovesPerTick: budget, TickInterval: 20 * time.Second, AntiOverRotationWindow: 10 * time.Second,
		ProactiveFloor: 30 * time.Second, MinAvailableReplicas: 1, EventDriven: true,
		ExposurePressureCap: v1alpha1.DefaultExposurePressureCap,
		EnabledActions:      map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true},
	}
}
