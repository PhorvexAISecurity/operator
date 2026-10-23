/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package runner

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
)

// AblationViews observes the cluster through sensor and builds WorkloadViews (the SAME
// way the tick loop does — read-only, fresh clock) WITH the discovered view.Physics
// stamped from the live platform scan. The one-shot context scan, per-dollar ablation and
// scarcity A/B score them (internal/inprocess).
func AblationViews(ctx context.Context, sensor sensorapi.Sensor, namespace string, sel labels.Selector) ([]*model.WorkloadView, string, error) {
	now := time.Now()
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
