/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package audit is the explainable decision log (PRD FR7 / FR6): every decision is
// recorded with its inputs (residual, context, belief, score), the chosen action and
// WHY, the R6 counterfactual (what the blind machinery would have done), and the
// dry-run flag. Records go to the structured logger AND, optionally, as JSON Lines to
// a writer (the demo/forensic artifact).
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/model"
)

// Record is the serialized form of one decision (stable JSON for the audit trail).
type Record struct {
	Kind             string    `json:"kind"`
	Time             time.Time `json:"time"`
	Tenant           string    `json:"tenant"`
	Namespace        string    `json:"namespace"`
	Pod              string    `json:"pod"`
	Node             string    `json:"node,omitempty"`
	Action           string    `json:"action"`
	Selected         bool      `json:"selected"`
	Feasible         bool      `json:"feasible"`
	InfeasibleWhy    string    `json:"infeasibleWhy,omitempty"`
	DryRun           bool      `json:"dryRun"`
	Actuated         bool      `json:"actuated"`
	Risk             float64   `json:"risk"`
	Cost             float64   `json:"cost"`
	Net              float64   `json:"net"`
	Residual         float64   `json:"residual"`
	ThreatPosture    float64   `json:"threatPosture"`
	Exposure         float64   `json:"exposure"`
	Belief           float64   `json:"belief"`
	AssetValue       float64   `json:"assetValue"`
	BlastRadius      float64   `json:"blastRadius"`
	SLOHeadroom      float64   `json:"sloHeadroom"`
	Phase            string    `json:"phase"`
	Reason             string `json:"reason"`
	R6Counterfactual   string `json:"r6Counterfactual"`
	CounterfactualNote string `json:"counterfactualNote,omitempty"`
	BlindCost          float64 `json:"blindCost"` // cost R6's blind timer incurs this cycle (always rotates) — for the cost comparison

	// P1 (coverage engine) fields — present only under the p1-coverage brain.
	Engine        string                  `json:"engine,omitempty"`
	PerDollar     float64                 `json:"perDollar,omitempty"`
	CoveredWeight float64                 `json:"coveredWeight,omitempty"`
	CoveredFacts  int                     `json:"coveredFacts,omitempty"`
	Stage         string                  `json:"stage,omitempty"`
	NextStage     string                  `json:"nextStage,omitempty"`
	StageHazard   float64                 `json:"stageHazard,omitempty"`
	PHold         float64                 `json:"pHold,omitempty"`
	Lambda        float64                 `json:"lambda,omitempty"`
	ProactiveRate float64                 `json:"proactiveRate,omitempty"`
	Attribution   []model.AttributionTerm `json:"attribution,omitempty"`

	// P-ACTUATOR native-actuator forensic fields — what the hands actually did, so a
	// kv-reset is distinguishable from a kill. Present only when the native actuator emitted.
	Handler        string   `json:"handler,omitempty"`
	ObjectsTouched []string `json:"objectsTouched,omitempty"`
	RollbackRef    string   `json:"rollbackRef,omitempty"`
	MutationKind   string   `json:"mutationKind,omitempty"`

	// P-DASHBOARD-2: the P-CONTEXT predictive horizon, serialized so the Live-Ops + Context
	// panels can stream the moved-before-next-stage story (IP-sensitive — owner-redacted).
	PreemptMargin         float64 `json:"preemptMargin,omitempty"`
	ProjectedNextStageSec float64 `json:"projectedNextStageSec,omitempty"`
	AIClassified          bool    `json:"aiClassified,omitempty"`
}

// Logger writes decision records.
type Logger struct {
	log     logr.Logger
	mu      sync.Mutex
	jsonOut io.Writer // optional JSON-Lines sink (the single shared / single-tenant sink)
	// [P-VCLUSTER O10] sinkFor, when set, routes each record to a PER-TENANT sink (by rec.Tenant) so a
	// noisy tenant's rotation cannot evict another tenant's audit history. nil => the single jsonOut
	// (byte-identical single-tenant path).
	sinkFor func(tenant string) io.Writer
	// OnlySelected, when true, logs only Selected (non-noop) decisions to the logger
	// to keep operator logs quiet; the JSON sink (if set) always gets every record.
	OnlySelected bool
}

// SetTenantSink installs a per-tenant JSON-Lines sink router (O10 audit isolation): each tenant's
// records go to its OWN writer, so one tenant's volume/rotation never evicts another's history. Pass
// nil to revert to the single shared sink.
func (l *Logger) SetTenantSink(router func(tenant string) io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sinkFor = router
}

// New constructs a Logger. jsonOut may be nil.
func New(log logr.Logger, jsonOut io.Writer) *Logger {
	return &Logger{log: log.WithName("audit"), jsonOut: jsonOut, OnlySelected: true}
}

// ToRecord converts a Decision to a Record.
func ToRecord(d model.Decision) Record {
	return Record{
		Kind:             "phorvex.decision",
		Time:             d.DecidedAt,
		Tenant:           d.Tenant,
		Namespace:        d.Namespace,
		Pod:              d.Pod,
		Node:             d.Node,
		Action:           string(d.Action),
		Selected:         d.Selected,
		Feasible:         d.Feasible,
		InfeasibleWhy:    d.InfeasibleWhy,
		DryRun:           d.DryRun,
		Actuated:         d.Actuated,
		Risk:             round4(d.Risk),
		Cost:             round4(d.Cost),
		Net:              round4(d.Net),
		Residual:         round4(d.Residual),
		ThreatPosture:    round4(d.ThreatPosture),
		Exposure:         round4(d.Exposure),
		Belief:           round4(d.Belief),
		AssetValue:       round4(d.AssetValue),
		BlastRadius:      round4(d.BlastRadius),
		SLOHeadroom:      round4(d.SLOHeadroom),
		Phase:            string(d.Phase),
		Reason:             d.Reason,
		R6Counterfactual:   string(d.R6Counterfactual),
		CounterfactualNote: d.CounterfactualNote,
		BlindCost:          round4(d.BlindCost),
		Engine:             d.Engine,
		PerDollar:        round4(d.PerDollar),
		CoveredWeight:    round4(d.CoveredWeight),
		CoveredFacts:     d.CoveredFacts,
		Stage:            d.Stage,
		NextStage:        d.NextStage,
		StageHazard:      round4(d.StageHazard),
		PHold:            round4(d.PHold),
		Lambda:           round4(d.Lambda),
		ProactiveRate:    round4(d.ProactiveRate),
		Attribution:      d.Attribution,
		Handler:          d.Handler,
		ObjectsTouched:   d.ObjectsTouched,
		RollbackRef:      d.RollbackRef,
		MutationKind:     d.MutationKind,
		PreemptMargin:         round4(d.PreemptMargin),
		ProjectedNextStageSec: round4(d.ProjectedNextStageSec),
		AIClassified:          d.AIClassified,
	}
}

// Record logs one decision.
func (l *Logger) Record(d model.Decision) {
	rec := ToRecord(d)
	l.mu.Lock()
	out := l.jsonOut
	if l.sinkFor != nil { // [P-VCLUSTER O10] route to the tenant's own sink (default-off => byte-identical)
		if w := l.sinkFor(rec.Tenant); w != nil {
			out = w
		}
	}
	if out != nil {
		if b, err := json.Marshal(rec); err == nil {
			_, _ = out.Write(append(b, '\n'))
		}
	}
	l.mu.Unlock()
	if l.OnlySelected && !d.Selected {
		return
	}
	l.log.Info("decision",
		"tenant", rec.Tenant, "pod", rec.Namespace+"/"+rec.Pod, "action", rec.Action,
		"selected", rec.Selected, "feasible", rec.Feasible, "dryRun", rec.DryRun,
		"engine", rec.Engine, "perDollar", rec.PerDollar, "coveredFacts", rec.CoveredFacts,
		"stage", rec.Stage, "nextStage", rec.NextStage, "hazard", rec.StageHazard,
		"pHold", rec.PHold, "lambda", rec.Lambda, "proactiveRate", rec.ProactiveRate,
		"cost", rec.Cost, "net", rec.Net, "asset", rec.AssetValue, "blast", rec.BlastRadius,
		"attribution", rec.Attribution,
		"r6Would", rec.R6Counterfactual, "r6Note", rec.CounterfactualNote,
		"why", rec.Reason, "infeasibleWhy", rec.InfeasibleWhy)
}

// TickSummary logs a per-tenant tick rollup.
func (l *Logger) TickSummary(tenant string, total, selected, infeasible int, dur time.Duration, mode string, killSwitch bool) {
	l.log.Info("tick",
		"tenant", tenant, "pods", total, "selected", selected, "infeasible", infeasible,
		"mode", mode, "killSwitch", killSwitch, "durationMs", dur.Milliseconds())
}

func round4(x float64) float64 {
	return float64(int64(x*10000+sign(x)*0.5)) / 10000
}

func sign(x float64) float64 {
	if x < 0 {
		return -1
	}
	return 1
}
