package inprocess

import (
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
	"github.com/phorvex/phorvex/internal/sensorsvc"
)

// The one-shot ablations score views runner.AblationViews builds from a live
// observation, with the in-process brain. They move to the brain service with the
// ablations themselves (ADR-0001).

// ReadOnlySensor observes through the cached client alone: no owner, receipt or
// binding reads, as the one-shot ablations need.
func (s *Services) ReadOnlySensor(c client.Client, promURL string) sensorapi.Sensor {
	return &sensorsvc.Local{Client: c, PromURL: promURL, PCIeClasses: s.PCIeClasses}
}

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

// ContextScan runs the kill-chain Assess per pod — surfacing the AI-stage
// classification + the predictive horizon (PreemptMargin / ProjectedNextStageSec = the
// moved-before-next-stage metric).
func ContextScan(views []*model.WorkloadView, namespace string) []ContextRow {
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
	return rows
}

// Ablate runs the STEP-3 IP ablation (P1 coverage optimizer vs random per-dollar) over
// the views, which carry the discovered physics.
func Ablate(views []*model.WorkloadView, namespace string, seeds []int64, budget int) decision.AblationResult {
	return decision.NewCoverageEngine().Ablate(views, ablationPolicy(namespace, budget), seeds)
}

// AblateScarcity runs the P-PHYSICS separately-ablated A/B: standard-recon (no
// discovered dispersion) vs ucw-recon (discovered) over the SAME fleet, so any ratio
// delta is attributable to discovery. On a uniform cluster (kind) this is an exact tie;
// only measured dispersion lifts it.
func AblateScarcity(views []*model.WorkloadView, namespace string, seeds []int64, budget int) decision.ScarcityAblation {
	return decision.AblateScarcity(views, ablationPolicy(namespace, budget), seeds)
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
