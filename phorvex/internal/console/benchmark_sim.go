/*
 * Phorvex Console — OPTIMIZER BENCH: run the REAL decision engine (p1-coverage) against a fixed
 * scenario across a sweep of optimizer configs, IN-PROCESS (no cluster, no live attack), and report
 * each config's real decision vs two reference baselines: R6 blind-timer and attack-landed.
 *
 * Everything is the engine's genuine output — this uses ONLY the exported decision API
 * (NewCoverageEngine / Decide / Ablate), the same in-process path the apply-fix safety gate uses.
 * Nothing is synthetic: where a parameter does not change the p1 decision, the benchmark shows that
 * honestly (identical results), and each parameter is labeled by its real role in the engine.
 *
 * POST /api/benchmark-sim  {scenario, configs:[...]}  ->  per-config real decisions + baselines.
 */

package console

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

// benchConfig is one optimizer configuration the user wants to evaluate.
type benchConfig struct {
	Label                string   `json:"label"`
	MaxMovesPerTick      int      `json:"maxMovesPerTick"`      // B — the greedy budget (DIRECT p1 effect)
	NormSparsity         float64  `json:"normSparsity"`        // cost-ceiling term (DIRECT p1 effect)
	FlowDisruption       float64  `json:"flowDisruption"`      // cost-ceiling term (DIRECT p1 effect)
	WeightSecrets        float64  `json:"weightSecrets"`       // asset-value lift for secrets (DIRECT p1 effect)
	MinAvailableReplicas int      `json:"minAvailableReplicas"` // quorum floor / feasibility (DIRECT p1 effect)
	ProactiveFloorSec    float64  `json:"proactiveFloorSec"`   // proactive hygiene floor + prov() (DIRECT p1 effect)
	ReactiveOnly         bool     `json:"reactiveOnly"`        // calm-until-attacked gate (DIRECT p1 effect)
	EnabledActions       []string `json:"enabledActions"`      // action vocabulary (DIRECT p1 effect); empty => rotate+quarantine
	Lambda               float64  `json:"lambda"`              // budget weight — used by p0-greedy; p1 SOLVES λ online (cadence/pricing note)
	TickIntervalSec      float64  `json:"tickIntervalSec"`     // evaluation cadence (does NOT change a single decision)
	AntiOverRotationSec  float64  `json:"antiOverRotationSec"` // re-actuation suppression window (cadence, not a single decision)
}

type benchMove struct {
	Pod           string  `json:"pod"`
	Stateful      bool    `json:"stateful"`
	Attacked      bool    `json:"attacked"`
	Action        string  `json:"action"`
	Selected      bool    `json:"selected"`
	Feasible      bool    `json:"feasible"`
	InfeasibleWhy string  `json:"infeasibleWhy"`
	Cost          float64 `json:"cost"`
	Coverage      float64 `json:"coverage"`
	CoveredFacts  int     `json:"coveredFacts"`
	PerDollar     float64 `json:"perDollar"`
	Stage         string  `json:"stage"`
	PHold         float64 `json:"pHold"`
	AssetValue    float64 `json:"assetValue"`
	BlindCost     float64 `json:"blindCost"` // what R6's blind rotate would cost on THIS pod
	R6Would       string  `json:"r6Would"`   // R6 counterfactual (always rotate)
}

type benchConfigResult struct {
	Label   string      `json:"label"`
	Config  benchConfig `json:"config"`
	Moves   []benchMove `json:"moves"`

	// Phorvex(config) — real engine aggregates
	MovesSelected   int     `json:"movesSelected"`
	TotalCoverage   float64 `json:"totalCoverage"`
	TotalCost       float64 `json:"totalCost"`
	PerDollar       float64 `json:"perDollar"`     // totalCoverage / totalCost (targeting efficiency)
	AblationRatio   float64 `json:"ablationRatio"` // recon-per-$ vs equal-budget random (>1 = better than random)
	StatefulRotated bool    `json:"statefulRotated"` // no-harm violation (should stay false)

	// greedy-vs-exact optimality (from the engine's own OptimalityOut): on the shipped asset-disjoint
	// facts the objective is modular so greedy is PROVABLY optimal (ratio 1.000). A gap can only appear
	// if a recon profile shares a fact across pods (submodular) — see the hub-spoke unit test.
	OptimalityRatio float64 `json:"optimalityRatio"` // greedy / exact objective (1.000 = greedy is exact)
	OptimalityGap   float64 `json:"optimalityGap"`   // exact - greedy objective (0 = no gap)
	CoversDisjoint  bool    `json:"coversDisjoint"`  // true = modular facts => greedy provably optimal
	ExactSkipped    bool    `json:"exactSkipped"`    // fleet exceeded the brute-force cap (ratio not computed)
	SwapRatio       float64 `json:"swapRatio"`       // greedy+swaps / exact (1.000 = the local search reaches the optimum)

	// derived cadence (arithmetic from the cadence params — NOT a single-decision output)
	PhorvexMovesPerHour float64 `json:"phorvexMovesPerHour"`

	// TEMPORAL: a real multi-tick simulation over the horizon (this is where tickInterval +
	// antiOverRotationWindow actually manifest). nil if the horizon is 0.
	Temporal *benchTemporal `json:"temporal,omitempty"`
}

// benchTemporal is a real over-time simulation: the engine is stepped once per tick across the horizon
// with the exposure clock advanced (and reset on an identity-changing move, per VarPodIdentity's
// definition), so the anti-over-rotation feasibility law and the online dual-λ evolution both engage.
type benchTemporal struct {
	HorizonSec       float64              `json:"horizonSec"`
	TickSec          float64              `json:"tickSec"`
	Ticks            int                  `json:"ticks"`
	PhorvexMoves     int                  `json:"phorvexMoves"`
	PhorvexCost      float64              `json:"phorvexCost"`
	PhorvexByAction  map[string]int       `json:"phorvexByAction"`
	R6IntervalSec    float64              `json:"r6IntervalSec"`
	R6Moves          int                  `json:"r6Moves"`
	R6Cost           float64              `json:"r6Cost"`
	R6StatefulKills  int                  `json:"r6StatefulKills"` // destructive blind rotations of a stateful pod
	SavingsVsR6      float64              `json:"savingsVsR6"`
	Series           []benchTemporalPoint `json:"series"`
}

type benchTemporalPoint struct {
	Sec        float64 `json:"sec"`
	PhorvexCum float64 `json:"phorvexCum"`
	R6Cum      float64 `json:"r6Cum"`
	Moves      int     `json:"moves"`
}

// benchResult is the whole benchmark: the config-independent baselines + one entry per config.
type benchResult struct {
	Scenario   string              `json:"scenario"`
	ScenarioLabel string           `json:"scenarioLabel"`
	Engine     string              `json:"engine"`
	Pods       int                 `json:"pods"`
	Stateful   int                 `json:"stateful"`
	Attacked   int                 `json:"attacked"`

	// reference baselines (config-independent)
	AttackLandedRisk    float64 `json:"attackLandedRisk"`    // Σ AssetValue left fully exposed (no defense)
	R6BlindCost         float64 `json:"r6BlindCost"`         // Σ BlindCost — blind rotate of EVERY pod, one cycle
	R6DestroysStateful  int     `json:"r6DestroysStateful"`  // # stateful pods a blind rotate would delete (data loss)
	R6BlindMovesPerHour float64 `json:"r6BlindMovesPerHour"` // blind cadence over the fleet (15s default timer)

	// temporal window (echoed so the UI can label the over-time series)
	HorizonSec    float64 `json:"horizonSec"`
	R6IntervalSec float64 `json:"r6IntervalSec"`
	ComputeMs     int64   `json:"computeMs"` // wall-clock the whole sweep took (the benchmark's own runtime)

	// live optimizer probe: greedy vs greedy+swaps vs brute-force exact on the shared hub-spoke stress
	// case (greedy 0.845 -> swaps 1.000) and the disjoint control (both 1.000) — the regression target closed.
	OptimizerProbe decision.OptimizerProbe `json:"optimizerProbe"`

	Configs []benchConfigResult `json:"configs"`
	Note    string              `json:"note"`
}

func (s *Server) benchmarkSim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		Scenario      string        `json:"scenario"`
		Configs       []benchConfig `json:"configs"`
		HorizonSec    float64       `json:"horizonSec"`    // temporal window (0 => skip temporal)
		R6IntervalSec float64       `json:"r6IntervalSec"` // blind-timer cadence (default 15s)
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	started := time.Now()
	if req.R6IntervalSec <= 0 {
		req.R6IntervalSec = 15
	}

	views, label := benchScenario(req.Scenario)
	if len(views) == 0 {
		writeJSON(w, 400, map[string]string{"error": "unknown scenario: " + req.Scenario})
		return
	}
	statefulOf := map[string]bool{}
	attackedOf := map[string]bool{}
	nStateful, nAttacked := 0, 0
	for _, v := range views {
		statefulOf[v.Pod.Name] = v.Pod.Stateful
		att := v.Pod.SuspectAdapter != "" || len(v.Events) > 0
		attackedOf[v.Pod.Name] = att
		if v.Pod.Stateful {
			nStateful++
		}
		if att {
			nAttacked++
		}
	}

	out := benchResult{
		Scenario: req.Scenario, ScenarioLabel: label, Engine: "p1-coverage",
		Pods: len(views), Stateful: nStateful, Attacked: nAttacked,
		R6BlindMovesPerHour: float64(len(views)) * (3600.0 / 15.0), // blind 15s timer rotates every pod
		Note: "Every number is the real p1-coverage engine's output, run in-process on a fixed scenario (no live attack). " +
			"maxMovesPerTick, cost weights, proactiveFloor, reactiveOnly, weightSecrets, minAvailableReplicas and the action set " +
			"shape the decision directly. λ is a solved online dual shadow-price on p1 (seeded 0.6) — the static λ knob drives the " +
			"p0-greedy engine, so sweeping it here does not change a single p1 decision. tickInterval and antiOverRotationWindow are " +
			"cadence controls (they bound how OFTEN a move can fire, not WHAT is decided) — their effect appears in the TEMPORAL " +
			"series, where the engine is stepped once per tick over the horizon (the anti-over-rotation feasibility law and the " +
			"online dual-λ both engage, and the exposure clock resets on an identity rotation). Baselines: attack-landed = full asset " +
			"value left exposed; R6 blind-timer = cost of rotating every pod on a fixed schedule (which DELETES stateful state each cycle).",
	}

	// Reference baselines (config-independent): read AssetValue + BlindCost from a neutral run.
	basePol := benchPolicy(benchConfig{MaxMovesPerTick: 1, NormSparsity: 0.4, FlowDisruption: 0.6, WeightSecrets: 0.8, MinAvailableReplicas: 2, ProactiveFloorSec: 900})
	for _, d := range decision.NewCoverageEngine().Decide(views, basePol) {
		out.AttackLandedRisk += d.AssetValue
		out.R6BlindCost += d.BlindCost
	}
	out.R6DestroysStateful = nStateful

	seeds := make([]int64, 20)
	for i := range seeds {
		seeds[i] = int64(i + 1)
	}

	for _, cfg := range req.Configs {
		pol := benchPolicy(cfg)
		decs := decision.NewCoverageEngine().Decide(views, pol)
		abl := decision.NewCoverageEngine().Ablate(views, pol, seeds)

		cr := benchConfigResult{
			Label: cfg.Label, Config: cfg, AblationRatio: round4c(abl.Ratio),
			OptimalityRatio: round4c(abl.OptimalityRatio), OptimalityGap: round4c(abl.OptimalityGap),
			CoversDisjoint: abl.CoversDisjoint, ExactSkipped: abl.ExactSkipped, SwapRatio: round4c(abl.SwapRatio),
		}
		for _, d := range decs {
			m := benchMove{
				Pod: d.Pod, Stateful: statefulOf[d.Pod], Attacked: attackedOf[d.Pod],
				Action: string(d.Action), Selected: d.Selected, Feasible: d.Feasible,
				InfeasibleWhy: d.InfeasibleWhy, Cost: round4c(d.Cost), Coverage: round4c(d.CoveredWeight),
				CoveredFacts: d.CoveredFacts, PerDollar: round4c(d.PerDollar), Stage: d.Stage,
				PHold: round4c(d.PHold), AssetValue: round4c(d.AssetValue),
				BlindCost: round4c(d.BlindCost), R6Would: string(d.R6Counterfactual),
			}
			cr.Moves = append(cr.Moves, m)
			if d.Selected && d.Action != model.ActionNoop {
				cr.MovesSelected++
				cr.TotalCoverage += d.CoveredWeight
				cr.TotalCost += d.Cost
				if d.Action == model.ActionRotate && statefulOf[d.Pod] {
					cr.StatefulRotated = true
				}
			}
		}
		cr.TotalCoverage = round4c(cr.TotalCoverage)
		cr.TotalCost = round4c(cr.TotalCost)
		if cr.TotalCost > 0 {
			cr.PerDollar = round4c(cr.TotalCoverage / cr.TotalCost)
		}
		cr.PhorvexMovesPerHour = phorvexCadence(cfg)
		if req.HorizonSec > 0 {
			cr.Temporal = simulateTemporal(req.Scenario, pol, req.HorizonSec, req.R6IntervalSec)
		}
		out.Configs = append(out.Configs, cr)
	}
	out.OptimizerProbe = decision.RunOptimizerProbe()
	out.HorizonSec = req.HorizonSec
	out.R6IntervalSec = req.R6IntervalSec
	out.ComputeMs = time.Since(started).Milliseconds()
	writeJSON(w, 200, out)
}

// simulateTemporal steps the REAL engine once per tick across the horizon. The exposure clock is
// advanced each tick and RESET on an identity-changing move (rotate/identity-rotate/warm-swap — the
// VarPodIdentity definition), so the anti-over-rotation feasibility law engages exactly as it does live,
// and the stateful online dual-λ evolves across ticks. R6 fires a blind rotate of EVERY pod every
// r6IntervalSec. Nothing is fabricated — every move + cost is the engine's own output over simulated time.
func simulateTemporal(name string, pol model.Policy, horizonSec, r6IntervalSec float64) *benchTemporal {
	views, _ := benchScenario(name) // fresh, isolated fleet (its exposure map is mutated below)
	if len(views) == 0 {
		return nil
	}
	tickSec := pol.TickInterval.Seconds()
	if tickSec <= 0 {
		tickSec = 10
	}
	if r6IntervalSec <= 0 {
		r6IntervalSec = 15
	}
	e := decision.NewCoverageEngine()
	base := time.Unix(1_700_000_000, 0) // fixed simulated epoch (deterministic; no wall-clock in the decision)
	var simClock time.Time
	e.Now = func() time.Time { return simClock }

	t := &benchTemporal{HorizonSec: horizonSec, TickSec: tickSec, R6IntervalSec: r6IntervalSec, PhorvexByAction: map[string]int{}}
	tickDur := time.Duration(tickSec * float64(time.Second))
	blindByPod := map[string]float64{}
	statefulByPod := map[string]bool{}
	for _, v := range views {
		statefulByPod[v.Pod.Name] = v.Pod.Stateful
	}

	total := int(horizonSec / tickSec)
	every := 1
	if total > 60 {
		every = total / 60 // cap the series at ~60 points
	}

	phorvexCum, r6Cum := 0.0, 0.0
	nextR6 := 0.0
	tick := 0
	for sec := 0.0; sec < horizonSec; sec += tickSec {
		simClock = base.Add(time.Duration(sec * float64(time.Second)))
		if tick > 0 {
			for _, v := range views {
				v.ExposureByVariable[model.VarPodIdentity] += tickDur
			}
		}
		for _, d := range e.Decide(views, pol) {
			if _, ok := blindByPod[d.Pod]; !ok {
				blindByPod[d.Pod] = d.BlindCost
			}
			if d.Selected && d.Action != model.ActionNoop {
				phorvexCum += d.Cost
				t.PhorvexMoves++
				t.PhorvexByAction[string(d.Action)]++
				if isIdentityMove(d.Action) {
					for _, v := range views {
						if v.Pod.Name == d.Pod {
							v.ExposureByVariable[model.VarPodIdentity] = 0 // new identity => clock resets (anti-rotation engages)
						}
					}
				}
			}
		}
		// R6 blind timer: rotate EVERY pod every r6IntervalSec, regardless of value/feasibility.
		for nextR6 <= sec {
			for _, v := range views {
				r6Cum += blindByPod[v.Pod.Name]
				t.R6Moves++
				if statefulByPod[v.Pod.Name] {
					t.R6StatefulKills++
				}
			}
			nextR6 += r6IntervalSec
		}
		if tick%every == 0 {
			t.Series = append(t.Series, benchTemporalPoint{Sec: round4c(sec), PhorvexCum: round4c(phorvexCum), R6Cum: round4c(r6Cum), Moves: t.PhorvexMoves})
		}
		tick++
	}
	t.Series = append(t.Series, benchTemporalPoint{Sec: round4c(horizonSec), PhorvexCum: round4c(phorvexCum), R6Cum: round4c(r6Cum), Moves: t.PhorvexMoves})
	t.Ticks = tick
	t.PhorvexCost = round4c(phorvexCum)
	t.R6Cost = round4c(r6Cum)
	t.SavingsVsR6 = round4c(r6Cum - phorvexCum)
	return t
}

// isIdentityMove reports whether an action rotates the pod's identity (resets the VarPodIdentity clock).
func isIdentityMove(a model.Action) bool {
	return a == model.ActionRotate || a == model.ActionIdentityRotate || a == model.ActionWarmSwap
}

// phorvexCadence is the DERIVED max actuation rate (moves/hour) the cadence knobs imply — pure
// arithmetic, not a single-tick engine output: at most B moves per tickInterval, and each asset can
// re-fire at most once per antiOverRotationWindow.
func phorvexCadence(cfg benchConfig) float64 {
	tick := cfg.TickIntervalSec
	if tick <= 0 {
		tick = 10
	}
	b := cfg.MaxMovesPerTick
	if b <= 0 {
		b = 1
	}
	perHour := float64(b) * (3600.0 / tick)
	if cfg.AntiOverRotationSec > 0 {
		// per-asset re-fire cap (a rough upper bound across the fleet is not asset-specific here;
		// we report the per-asset ceiling the window imposes).
		assetCap := 3600.0 / cfg.AntiOverRotationSec
		if assetCap < perHour {
			perHour = assetCap
		}
	}
	return round4c(perHour)
}

// benchPolicy resolves a benchConfig into the engine's model.Policy (mirrors runner.buildPolicy).
func benchPolicy(cfg benchConfig) model.Policy {
	b := cfg.MaxMovesPerTick
	if b <= 0 {
		b = 1
	}
	var enabled map[model.Action]bool
	if len(cfg.EnabledActions) > 0 {
		enabled = map[model.Action]bool{}
		for _, a := range cfg.EnabledActions {
			enabled[model.Action(a)] = true
		}
	} // nil => historical default (rotate + quarantine only)

	lambda := cfg.Lambda
	if lambda <= 0 {
		lambda = 0.6
	}
	dc := map[string]float64{"restricted": 1.0, "internal": 0.4, "public": 0.1}

	return model.Policy{
		Tenant:                 "bench",
		Namespace:              "bench",
		Mode:                   "active",
		DryRun:                 false,
		Lambda:                 lambda,
		NormSparsity:           cfg.NormSparsity,
		FlowDisruption:         cfg.FlowDisruption,
		WeightSecrets:          cfg.WeightSecrets,
		BlastRadiusFromGraph:   true,
		MaxMovesPerTick:        b,
		TickInterval:           secDur(cfg.TickIntervalSec, 10),
		AntiOverRotationWindow: secDur(cfg.AntiOverRotationSec, 60),
		ProactiveFloor:         secDur(cfg.ProactiveFloorSec, 900),
		MinAvailableReplicas:   cfg.MinAvailableReplicas,
		ReactiveOnly:           cfg.ReactiveOnly,
		EnabledActions:         enabled,
		AssetWeightFromLabels: func(labels map[string]string) float64 {
			if labels == nil {
				return 0.4
			}
			if w, ok := dc[labels["data-class"]]; ok {
				return w
			}
			return 0.4
		},
	}
}

func secDur(sec, def float64) time.Duration {
	if sec <= 0 {
		sec = def
	}
	return time.Duration(sec * float64(time.Second))
}

func round4c(x float64) float64 {
	if x < 0 {
		return -round4c(-x)
	}
	return float64(int64(x*10000+0.5)) / 10000
}

// --- fixed benchmark scenarios (fleets of WorkloadViews). Attacked pods carry a real detector Event
// (or a poisoned adapter) so reactiveOnly has something to react to; calm pods have none. ---

func benchScenario(name string) ([]*model.WorkloadView, string) {
	foothold := []model.SecurityEventInfo{{
		Type: "container-escape", ThreatLevel: "critical", Source: "ExternalDetector",
		Description: "foothold detected", AnomalyScore: 0.9, TargetsPod: true, Age: 30 * time.Second,
	}}
	pod := func(name string, secrets, stateful bool, dataClass string, expo time.Duration, ev []model.SecurityEventInfo) *model.WorkloadView {
		v := &model.WorkloadView{
			Pod: model.Pod{
				Namespace: "bench", Name: name, UID: "u-" + name,
				Labels: map[string]string{"data-class": dataClass},
				DesiredReplicas: 3, ReadyReplicas: 3, Ready: true, Stateful: stateful,
			},
			Phase:              model.PhaseWarm,
			BlastRadius:        0.6,
			Neighbors:          []model.NeighborRef{{Key: "bench/crown", Value: 5.0}},
			Events:             ev,
			ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: expo},
		}
		if secrets {
			v.Pod.MountedSecrets = []string{"creds"}
		}
		return v
	}

	switch name {
	case "nats-broker":
		return []*model.WorkloadView{
			pod("broker-0", true, true, "restricted", 1*time.Hour, foothold), // attacked stateful broker
			pod("broker-1", true, true, "restricted", 30*time.Minute, nil),
			pod("broker-2", true, true, "restricted", 30*time.Minute, nil),
		}, "NATS JetStream — 3 stateful brokers, broker-0 under a foothold"
	case "mixed-fleet":
		return []*model.WorkloadView{
			pod("crown1", true, false, "restricted", 3*time.Hour, nil),       // long-exposed secret (proactivity probe)
			pod("crown2", true, false, "restricted", 1*time.Hour, foothold),  // attacked crown
			pod("cheap1", false, false, "public", 2*time.Hour, nil),
			pod("cheap2", false, false, "internal", 90*time.Minute, nil),
			pod("stateful-db", true, true, "restricted", 3*time.Hour, nil),   // no-harm probe (never rotate)
		}, "Mixed fleet — crowns, cheap pods, a stateful DB; crown2 under a foothold"
	case "ai-gpu":
		p0 := pod("infer-0", true, false, "restricted", 1*time.Hour, nil)
		p0.Pod.HasGPU = true
		p0.Pod.SuspectAdapter = "evil-lora" // AI poison marker => attack-backed
		p0.Pod.ModelID = "qwen2.5"
		p1 := pod("infer-1", true, false, "restricted", 2*time.Hour, nil)
		p1.Pod.HasGPU = true
		p1.Pod.ModelID = "qwen2.5"
		return []*model.WorkloadView{p0, p1}, "AI/GPU — 2 inference pods, infer-0 carries a poisoned LoRA adapter"
	}
	return nil, ""
}
