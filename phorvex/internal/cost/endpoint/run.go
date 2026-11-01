package endpoint

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Row struct {
	ID          string   `json:"candidate_id"`
	Action      string   `json:"action"`
	V           *float64 `json:"V"`
	J           *float64 `json:"J"`
	Cost        Cost     `json:"cost"`
	Admitted    bool     `json:"admitted"`
	Selected    bool     `json:"selected"`
	Containment bool     `json:"containment"`
	Refusals    []string `json:"refusals"`
}
type ArmResult struct {
	Arm      string  `json:"arm"`
	Executed bool    `json:"executed"`
	Pick     *string `json:"pick"`
	Noop     string  `json:"noop_reason,omitempty"`
	Rows     []Row   `json:"candidates"`
}
type TickResult struct {
	ID          string    `json:"tick_id"`
	At          float64   `json:"at"`
	WorkloadUID string    `json:"workload_uid"`
	PolicyUID   string    `json:"policy_uid"`
	State       string    `json:"state"`
	Budget      Budget    `json:"budget"`
	Lambda      Lambda    `json:"lambda"`
	V2          ArmResult `json:"v2"`
	V3          ArmResult `json:"v3"`
	Changed     *bool     `json:"changed"`
}
type Result struct {
	Schema         string             `json:"schema"`
	State          string             `json:"state"`
	Mode           string             `json:"mode"`
	Evidence       string             `json:"evidence"`
	SourceRevision string             `json:"source_revision"`
	Config         Config             `json:"config"`
	Ticks          []TickResult       `json:"ticks"`
	Comparable     int                `json:"comparable_ticks"`
	Changed        *int               `json:"changed_choices"`
	Noop           map[string]int     `json:"noop"`
	Forecast       map[string]float64 `json:"forecast_endpoint_seconds"`
	ActualCharges  any                `json:"counterfactual_actual_charges"`
	VerifiedFacts  any                `json:"counterfactual_verified_facts"`
	MissingReasons map[string]int     `json:"missing_reasons"`
	Limitations    []string           `json:"limitations"`
}

func Value(c Candidate) (*float64, string) {
	if !c.FactsKnown {
		return nil, "GROUNDED_FACTS_MISSING"
	}
	weights := map[string]float64{}
	for _, f := range c.Facts {
		if f.ID == "" || !finite(f.Weight) || f.Weight < 0 {
			return nil, "FACT_INVALID"
		}
		if w, ok := weights[f.ID]; ok && w != f.Weight {
			return nil, "FACT_WEIGHT_CONFLICT"
		}
		weights[f.ID] = f.Weight
	}
	keys := []string{}
	for key := range weights {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	v := 0.0
	for _, key := range keys {
		v += weights[key]
	}
	if !finite(v) {
		return nil, "FACT_VALUE_NONFINITE"
	}
	return ptr(v), ""
}

func score(t Tick, b Budget, lambda float64, cfg Config, arm string) ArmResult {
	out := ArmResult{Arm: arm, Executed: true, Rows: []Row{}}
	for _, c := range t.Candidates {
		v, reason := Value(c)
		row := Row{ID: c.ID, Action: c.Action, V: v, Containment: c.Containment, Refusals: append([]string{}, c.Gates...)}
		if !t.CandidateSetComplete {
			row.Refusals = append(row.Refusals, "CANDIDATE_SET_INCOMPLETE")
		}
		if !c.GatesKnown {
			row.Refusals = append(row.Refusals, "NON_COST_GATES_MISSING")
		}
		if reason != "" {
			row.Refusals = append(row.Refusals, reason)
		}
		row.Cost = Price(t, c, b, cfg)
		if row.Cost.Refusal != "" {
			row.Refusals = append(row.Refusals, row.Cost.Refusal)
		}
		if b.Refusal != "" {
			row.Refusals = append(row.Refusals, b.Refusal)
		}
		if b.Left != nil && row.Cost.Rho != nil && *row.Cost.Rho != 0 && *row.Cost.Rho > *b.Left {
			row.Refusals = append(row.Refusals, "BUDGET")
		}
		if !c.Containment {
			if !nonnegative(c.WorthThreshold) {
				row.Refusals = append(row.Refusals, "WORTH_THRESHOLD_MISSING")
			} else if v != nil && *v <= *c.WorthThreshold {
				row.Refusals = append(row.Refusals, "BELOW_V_WORTH_THRESHOLD")
			}
		}
		if v != nil && row.Cost.E != nil {
			j := *v
			if !c.Containment {
				j -= lambda * *row.Cost.E
			}
			if finite(j) {
				row.J = ptr(j)
			} else {
				row.Refusals = append(row.Refusals, "NONFINITE_J")
			}
		}
		row.Admitted = len(row.Refusals) == 0 && row.J != nil
		out.Rows = append(out.Rows, row)
	}
	// Deterministic pre-existing containment priority is supplied explicitly;
	// a failed mandatory action never becomes a licence to price containment.
	if t.MandatoryID != "" {
		for i := range out.Rows {
			if out.Rows[i].ID == t.MandatoryID && out.Rows[i].Containment && out.Rows[i].Admitted {
				out.Rows[i].Selected = true
				id := out.Rows[i].ID
				out.Pick = &id
				return out
			}
		}
		out.Noop = "NO_SAFE_CONTAINMENT_ACTION"
		return out
	}
	best := -1
	for i, r := range out.Rows {
		if r.Containment {
			out.Noop = "MANDATORY_PRIORITY_MISSING"
			return out
		}
		if !r.Admitted {
			continue
		}
		if best < 0 || better(r, out.Rows[best]) {
			best = i
		}
	}
	if best < 0 {
		out.Noop = "NO_FEASIBLE_CANDIDATE"
		return out
	}
	out.Rows[best].Selected = true
	id := out.Rows[best].ID
	out.Pick = &id
	return out
}
func better(a, b Row) bool {
	if *a.J != *b.J {
		return *a.J > *b.J
	}
	if *a.V != *b.V {
		return *a.V > *b.V
	}
	if *a.Cost.E != *b.Cost.E {
		return *a.Cost.E < *b.Cost.E
	}
	return a.ID < b.ID
}

// pricingNeeded distinguishes an unevaluated price from a known rejection.
// An established non-cost veto or the existing V<=theta rule already excludes
// the candidate independently of price. Unknown facts/gates/thresholds cannot
// establish that exclusion; Run records those missing inputs separately.
func pricingNeeded(c Candidate) bool {
	if c.GatesKnown && len(c.Gates) > 0 {
		return false
	}
	if !c.Containment && nonnegative(c.WorthThreshold) {
		if v, reason := Value(c); reason == "" && v != nil && *v <= *c.WorthThreshold {
			return false
		}
	}
	return true
}

func ValidateTrace(t Trace) error {
	if t.Schema != TraceSchema || (t.Evidence != "recorded" && t.Evidence != "synthetic") {
		return fmt.Errorf("unsupported endpoint trace schema/evidence")
	}
	if t.SourceRevision == "" || len(t.Ticks) == 0 || len(t.Ticks) > 5000 {
		return fmt.Errorf("source revision and 1..5000 ticks required")
	}
	if t.Evidence == "recorded" {
		if len(t.SourceRevision) != 40 {
			return fmt.Errorf("recorded source revision must be a full SHA")
		}
		for _, c := range t.SourceRevision {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return fmt.Errorf("invalid source revision")
			}
		}
	}
	seen, times := map[string]bool{}, map[string]bool{}
	total := 0
	for _, tick := range t.Ticks {
		if tick.ID == "" || seen[tick.ID] || tick.WorkloadUID == "" || tick.PolicyUID == "" || !finite(tick.At) || tick.At < 0 {
			return fmt.Errorf("duplicate/missing tick identity or invalid timestamp")
		}
		seen[tick.ID] = true
		timeKey := fmt.Sprintf("%s/%g", tick.PolicyUID, tick.At)
		if times[timeKey] {
			return fmt.Errorf("simultaneous policy ticks require one joined candidate set; do not split a policy tick across workloads")
		}
		times[timeKey] = true
		if len(tick.Candidates) > 256 {
			return fmt.Errorf("maximum 256 candidates per tick")
		}
		total += len(tick.Candidates)
		ids, pairs := map[string]bool{}, map[string]bool{}
		for _, c := range tick.Candidates {
			pair := c.PodUID + "\x00" + c.Action
			if c.ID == "" || c.PodUID == "" || c.Action == "" || ids[c.ID] || pairs[pair] {
				return fmt.Errorf("missing/duplicate candidate identity")
			}
			ids[c.ID] = true
			pairs[pair] = true
			if len(c.Facts) > 512 || len(c.Samples) > 2000 {
				return fmt.Errorf("candidate facts/history exceeds bounds")
			}
		}
		if tick.MandatoryID != "" && !ids[tick.MandatoryID] {
			return fmt.Errorf("mandatory candidate not present")
		}
		if tick.Ledger != nil {
			if len(tick.Ledger.Moves) > 10000 {
				return fmt.Errorf("ledger exceeds 10000 move observations")
			}
			for _, m := range tick.Ledger.Moves {
				if len(m.Intervals) > 1000 {
					return fmt.Errorf("move interval limit exceeded")
				}
			}
		}
	}
	if total > 100000 {
		return fmt.Errorf("candidate output limit exceeded")
	}
	return nil
}

func Run(trace Trace, cfg Config, store StateStore) (Result, error) {
	out := Result{Schema: ResultSchema, State: "BLOCKED", Mode: "PAIRED_GO_REFERENCE", Evidence: trace.Evidence, SourceRevision: trace.SourceRevision, Config: cfg, Ticks: []TickResult{}, Noop: map[string]int{"v2": 0, "v3": 0}, Forecast: map[string]float64{"v2": 0, "v3": 0}, MissingReasons: map[string]int{}, Limitations: []string{
		"Offline Go experiment on explicitly supplied candidate facts/gates and telemetry; not a deployed production V3 implementation.",
		"V2 and V3 use identical new endpoint costs, budget gates and candidates. Only optional ordering is priced in V3; B=1.",
		"No entropy, history picker, counterfactual spend feedback or priced-worth gate. Counterfactual actual costs and verified security effects are unknown.",
		"Class priors, rollback proxy, lambda constants and explicitly declared SLO defaults are study assumptions, not production approval.",
		"Candidate producers must establish real fact-to-action mapping, all non-cost safety gates, containment priority and historical telemetry. An uploaded fixture does not prove production provenance.",
		"An arm's executed flag means its scoring code ran. Only comparable ticks with complete required inputs contribute to changed choices, NOOP counts or forecast totals.",
	}}
	if err := cfg.Validate(); err != nil {
		return out, err
	}
	if err := ValidateTrace(trace); err != nil {
		return out, err
	}
	// Copy before sorting; every arm sees the exact same immutable recorded input.
	ticks := append([]Tick(nil), trace.Ticks...)
	sort.Slice(ticks, func(i, j int) bool {
		if ticks[i].At == ticks[j].At {
			return ticks[i].ID < ticks[j].ID
		}
		return ticks[i].At < ticks[j].At
	})
	controller := NewController(cfg, store)
	changed := 0
	for _, t := range ticks {
		b := Account(t, cfg)
		l := controller.Update(t, b)
		r := TickResult{ID: t.ID, At: t.At, WorkloadUID: t.WorkloadUID, PolicyUID: t.PolicyUID, State: "COMPLETE", Budget: b, Lambda: l}
		r.V2 = score(t, b, 0, cfg, "v2")
		r.V3 = score(t, b, l.Effective, cfg, "v3")
		missing := []string{}
		if !t.CandidateSetComplete {
			missing = append(missing, "CANDIDATE_SET_INCOMPLETE")
		}
		if b.Refusal != "" {
			missing = append(missing, b.Refusal)
		}
		if b.Spend == nil {
			missing = append(missing, l.Reason)
		}
		if l.Write != "COMMITTED" {
			missing = append(missing, l.Reason)
		}
		for i, c := range t.Candidates {
			if !c.GatesKnown {
				missing = append(missing, "NON_COST_GATES_MISSING")
			}
			if !c.FactsKnown {
				missing = append(missing, "GROUNDED_FACTS_MISSING")
			}
			if !c.Containment && !nonnegative(c.WorthThreshold) {
				missing = append(missing, "WORTH_THRESHOLD_MISSING")
			}
			if _, reason := Value(c); reason != "" {
				missing = append(missing, reason)
			}
			if pricingNeeded(c) {
				if c.K == nil {
					missing = append(missing, "ENDPOINT_MEMBERSHIP_MISSING")
				}
				if c.K != nil && *c.K > 0 && !c.HistoryKnown && (c.Action == "rotate" || c.Action == "request-drain" || c.Action == "quarantine") {
					missing = append(missing, "DURATION_HISTORY_MISSING")
				}
				// Price is identical in both arms. A missing/censored/invalid
				// bound is unavailable evidence, not a successful NOOP. A
				// known BUDGET refusal remains a valid comparable rejection.
				if reason := r.V2.Rows[i].Cost.Refusal; strings.HasPrefix(reason, "BOUND_MISSING:") {
					missing = append(missing, reason)
				}
			}
		}
		if len(missing) > 0 {
			r.State = "BLOCKED"
			unique := map[string]bool{}
			for _, reason := range missing {
				if reason != "" && !unique[reason] {
					out.MissingReasons[reason]++
					unique[reason] = true
				}
			}
		} else {
			out.Comparable++
			different := (r.V2.Pick == nil) != (r.V3.Pick == nil) || (r.V2.Pick != nil && r.V3.Pick != nil && *r.V2.Pick != *r.V3.Pick)
			r.Changed = &different
			if different {
				changed++
			}
			for _, arm := range []ArmResult{r.V2, r.V3} {
				if arm.Pick == nil {
					out.Noop[arm.Arm]++
				}
				for _, row := range arm.Rows {
					if row.Selected && row.Cost.E != nil {
						out.Forecast[arm.Arm] += *row.Cost.E
					}
				}
			}
		}
		out.Ticks = append(out.Ticks, r)
	}
	if out.Comparable > 0 {
		out.Changed = &changed
		out.State = "PARTIAL"
	} else {
		out.Noop = nil
		out.Forecast = nil
	}
	if out.Comparable == len(ticks) {
		out.State = "COMPLETE"
	}
	// Check all emitted diagnostics for JSON finiteness, including supplied input
	// values that were rejected. Never let a NaN turn a missing-data report into success.
	if _, err := json.Marshal(out); err != nil {
		return Result{}, fmt.Errorf("nonfinite result: %w", err)
	}
	return out, nil
}
