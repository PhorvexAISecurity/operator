package console

import (
	"strings"

	"github.com/phorvex/metricvalidity"
)

// runMetricRow is the common, permissive metric projection used by both the
// persisted run evidence reader and the live run stream. Keeping the validity
// inputs here prevents the two console views from assigning different meaning
// to the same harness row.
type runMetricRow struct {
	Scenario              string                   `json:"scenario"`
	Defender              string                   `json:"defender"`
	Trial                 int                      `json:"trial"`
	OracleAchieved        bool                     `json:"oracleAchieved"`
	DisruptionVsOracle    float64                  `json:"disruptionVsOracle"`
	AttackerDwellSeconds  float64                  `json:"attackerDwellSeconds"`
	TimeToActionSeconds   float64                  `json:"timeToActionSeconds"`
	DefensiveActions      int                      `json:"defensiveActions"`
	FalseDefensiveActions int                      `json:"falseDefensiveActions"`
	SecurityPerCost       float64                  `json:"securityPerCost"`
	EvidenceRetention     float64                  `json:"evidenceRetention"`
	Skipped               bool                     `json:"skipped"`
	SkipReason            string                   `json:"skipReason"`
	NegativeControl       bool                     `json:"negativeControl"`
	MTDEffect             string                   `json:"mtdEffect"`
	ObservedState         string                   `json:"observedState"`
	Commands              []string                 `json:"commands"`
	Validity              *metricvalidity.Validity `json:"validity"`
	ScenarioRealism       string                   `json:"scenarioRealism"`
	ScenarioBenignControl bool                     `json:"scenarioBenignControl"`
	ScenarioClaimLimits   string                   `json:"scenarioClaimLimits"`
	BenchmarkEvidence     map[string]string        `json:"benchmarkEvidence"`
	Schwartau             *runMetricSchwartau      `json:"schwartau"`
	Reuse                 *runMetricReuse          `json:"reuse"`
}

type runMetricSchwartau struct {
	ProtectionTimeSeconds float64 `json:"protectionTimeSeconds"`
	DetectionTimeSeconds  float64 `json:"detectionTimeSeconds"`
	ReactionTimeSeconds   float64 `json:"reactionTimeSeconds"`
}

type runMetricReuse struct {
	ReplaySuccessCount int `json:"replaySuccessCount"`
	ReplayAttempts     int `json:"replayAttempts"`
}

func (r runMetricRow) verdict() metricvalidity.Verdict {
	return metricvalidity.Evaluate(r.Validity, metricvalidity.Observations{
		Trial:                 r.Trial,
		Disruption:            r.DisruptionVsOracle,
		DefensiveActions:      r.DefensiveActions,
		FalseDefensiveActions: r.FalseDefensiveActions,
		TimeToActionSeconds:   r.TimeToActionSeconds,
		AttackerDwellSeconds:  r.AttackerDwellSeconds,
	})
}

type trialOutcome struct {
	Outcome           string   `json:"outcome"`
	OutcomeReason     string   `json:"outcomeReason"`
	ClaimClass        string   `json:"claimClass"`
	MeasurementStatus string   `json:"measurementStatus"`
	MeasurementPhase  string   `json:"measurementPhase"`
	ValidityReasons   []string `json:"validityReasons"`
}

const (
	outcomeTestFailed        = "test-failed"
	outcomeInconclusive      = "inconclusive"
	outcomeUnverified        = "unverified"
	outcomeFunctionalPass    = "functional-pass"
	outcomeFunctionalFail    = "functional-fail"
	outcomeSkipped           = "skipped"
	outcomeNegativeControl   = "negative-control"
	outcomeSecurityLanded    = "security-landed"
	outcomeSecurityDisrupted = "security-disrupted"
)

func (r runMetricRow) outcome() trialOutcome {
	v := r.verdict()
	out := trialOutcome{
		ClaimClass:        "security",
		MeasurementStatus: string(v.Status()),
		MeasurementPhase:  string(v.Claim.Phase),
		ValidityReasons:   v.Reasons(),
	}
	if r.ScenarioBenignControl {
		out.ClaimClass = "functional"
		if r.Scenario == limitedV1GuardrailCalibrationID {
			out.ClaimClass = "calibration"
		}
	}
	if r.NegativeControl || v.Kind() == metricvalidity.TrialNegativeControl {
		out.ClaimClass = "control"
	}
	if strings.TrimSpace(r.Scenario) == "" || strings.TrimSpace(r.Defender) == "" {
		return unverifiedOutcome(out, "metric row lacks scenario or defender identity")
	}

	// A missing contract is historical evidence, never a fresh result. An
	// unknown contract version/kind/status is also unreadable by this build.
	if v.Legacy || !v.Supported {
		out.Outcome = outcomeUnverified
		out.OutcomeReason = firstReason(v, "measurement-validity contract is absent or unsupported")
		return out
	}
	// Producer-declared invalidity is a test failure. It precedes the generic
	// contradiction bucket so the exact failed phase and producer reason remain
	// visible (for example, the vLLM drain attack-execute refusal).
	if v.Status() == metricvalidity.StatusInvalid {
		out.Outcome = outcomeTestFailed
		out.OutcomeReason = firstReason(v, "the test did not produce a valid measurement")
		return out
	}
	if v.Unverified {
		out.Outcome = outcomeUnverified
		out.OutcomeReason = firstReason(v, "the measurement claim is internally inconsistent")
		return out
	}
	// Corroborate the scenario metadata that the shared numeric contract does
	// not know about. Older rows may carry a valid numeric block while also
	// claiming that a benign control was scored as an attack; that history stays
	// visible but cannot be promoted to either a functional or security result.
	if r.ScenarioBenignControl && (v.Claim.Scored || v.Claim.Baseline.Required || v.Claim.Baseline.Usable) {
		return unverifiedOutcome(out, "benign-control metadata contradicts a scored attack comparison or required positive-control baseline")
	}
	if v.Scorable && r.ScenarioRealism != "executable-mechanism" {
		return unverifiedOutcome(out, "scored security comparison lacks executable-mechanism scenario realism")
	}
	if r.Skipped && v.Scorable {
		return unverifiedOutcome(out, "row is marked skipped while claiming a scored security comparison")
	}
	if !r.Skipped && v.Status() == metricvalidity.StatusSkipped {
		return unverifiedOutcome(out, "validity reports skipped but the metric row does not")
	}
	if v.Status() == metricvalidity.StatusSkipped {
		out.Outcome = outcomeSkipped
		out.OutcomeReason = firstReason(v, r.SkipReason)
		return out
	}
	if r.NegativeControl || v.Kind() == metricvalidity.TrialNegativeControl {
		out.Outcome = outcomeNegativeControl
		out.OutcomeReason = firstReason(v, "negative control; no attack outcome exists")
		return out
	}
	if r.ScenarioBenignControl {
		status, explicit, conflict := functionalOracleStatus(r.BenchmarkEvidence)
		if conflict {
			return unverifiedOutcome(out, "benchmark evidence contains conflicting oracleStatus and oracle.status values")
		}
		if r.ScenarioRealism != "executable-mechanism" || !v.OracleUsable || !v.Claim.Cleanup.Verified || !explicit || status != "complete" {
			out.Outcome = outcomeInconclusive
			switch {
			case r.ScenarioRealism != "executable-mechanism":
				out.OutcomeReason = "benign control lacks executable-mechanism scenario realism"
			case !explicit:
				out.OutcomeReason = "benign control has no explicit benchmark oracle status"
			case status != "complete":
				out.OutcomeReason = "benign control oracle is " + status
			case !v.Claim.Cleanup.Verified:
				out.OutcomeReason = "benign control cleanup absence was not verified"
			default:
				out.OutcomeReason = firstReason(v, "benign control oracle is not a usable observation")
			}
			return out
		}
		if r.OracleAchieved {
			out.Outcome = outcomeFunctionalPass
			out.OutcomeReason = "completed functional oracle achieved; security outcome is not applicable"
		} else {
			out.Outcome = outcomeFunctionalFail
			out.OutcomeReason = "completed functional oracle not achieved; security outcome is not applicable"
		}
		return out
	}
	if !v.Scorable {
		out.Outcome = outcomeInconclusive
		out.OutcomeReason = firstReason(v, v.UnscoredReason())
		return out
	}
	// A scored disruption comparison, rather than oracle=false by itself, is
	// required for a security disruption result.
	if r.DisruptionVsOracle >= 0.5 {
		out.Outcome = outcomeSecurityDisrupted
		out.OutcomeReason = "validated scored comparison measured disruption"
		return out
	}
	if r.OracleAchieved {
		out.Outcome = outcomeSecurityLanded
		out.OutcomeReason = "validated scored comparison observed the attack oracle with low disruption"
		return out
	}
	out.Outcome = outcomeInconclusive
	out.OutcomeReason = "scored row has low disruption but no achieved attack oracle"
	return out
}

func functionalOracleStatus(evidence map[string]string) (status string, present, conflict bool) {
	camel, hasCamel := evidence["oracleStatus"]
	dotted, hasDotted := evidence["oracle.status"]
	camel, dotted = strings.TrimSpace(camel), strings.TrimSpace(dotted)
	if hasCamel && hasDotted && camel != dotted {
		return "", true, true
	}
	if hasCamel {
		return camel, camel != "", false
	}
	if hasDotted {
		return dotted, dotted != "", false
	}
	return "", false, false
}

func unverifiedOutcome(out trialOutcome, reason string) trialOutcome {
	out.Outcome = outcomeUnverified
	out.OutcomeReason = reason
	out.ValidityReasons = append(out.ValidityReasons, "console projection: "+reason)
	return out
}

func firstReason(v metricvalidity.Verdict, fallback string) string {
	for _, reason := range v.Reasons() {
		if reason = strings.TrimSpace(reason); reason != "" {
			return reason
		}
	}
	if reason := strings.TrimSpace(v.UnscoredReason()); reason != "" {
		return reason
	}
	if fallback = strings.TrimSpace(fallback); fallback != "" {
		return fallback
	}
	return "measurement outcome is unavailable"
}
