// Package verificationloop runs one bounded, local behavioral verification case.
// It never connects to an existing Kubernetes cluster or alters the decision engine.
package verificationloop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/slo"
)

const Marker = "verification-loop-synthetic-downstream"

type Options struct {
	RepoRoot             string
	OutputDir            string
	Python               string
	Assets               string
	GitSHA               string
	Timeout              time.Duration
	HoldDuration         time.Duration
	HoldInterval         time.Duration
	MaxLegitimateLatency time.Duration
	SkipDispatch         bool // Explicit negative control: selection alone must never pass.
	UnavailableAuthority bool // Delete the private lease policy after dispatch to test outage honesty.
	// Arm selects a Security Gain validation branch after the brain's decision. "" and
	// "intervention" keep the reviewed defended path. "baseline" withholds every action;
	// "cf-rotate" and "cf-endpoint-rotate" dispatch that competing action instead of the
	// selected one. Study arms record probes without asserting an outcome.
	Arm string
}

// Study arms. Counterfactual actions run only in this private environment.
const (
	ArmIntervention     = "intervention"
	ArmBaseline         = "baseline"
	ArmCFRotate         = "cf-rotate"
	ArmCFEndpointRotate = "cf-endpoint-rotate"
)

func ValidArm(arm string) bool {
	switch arm {
	case "", ArmIntervention, ArmBaseline, ArmCFRotate, ArmCFEndpointRotate:
		return true
	}
	return false
}

type Probe struct {
	Name              string          `json:"name"`
	At                time.Time       `json:"at"`
	RequestStartedAt  time.Time       `json:"request_started_at"`
	RequestFinishedAt time.Time       `json:"request_finished_at"`
	Status            int             `json:"status"`
	LatencyMS         float64         `json:"latency_ms"`
	BodySHA256        string          `json:"body_sha256"`
	Body              json.RawMessage `json:"body"`
	RawBody           string          `json:"raw_body"`
	Nonce             string          `json:"nonce"`
	BeforeCalls       int             `json:"before_calls"`
	AfterCalls        int             `json:"after_calls"`
	Error             string          `json:"error,omitempty"`
}

type Stage struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type Report struct {
	Schema                      string            `json:"schema"`
	Scope                       string            `json:"scope"`
	Verdict                     string            `json:"verdict"`
	StartedAt                   time.Time         `json:"started_at"`
	FinishedAt                  time.Time         `json:"finished_at"`
	GitSHA                      string            `json:"git_sha"`
	GitSHAProvenance            string            `json:"git_sha_provenance"`
	ExecutableSHA256            string            `json:"executable_sha256"`
	FixtureFilesSHA256          map[string]string `json:"fixture_files_sha256"`
	ToolFilesSHA256             map[string]string `json:"tool_files_sha256"`
	DecisionClock               time.Time         `json:"decision_clock"`
	DispatchStartedAt           time.Time         `json:"dispatch_started_at"`
	DispatchFinishedAt          time.Time         `json:"dispatch_finished_at"`
	BaselineToConfirmedDenialMS float64           `json:"baseline_to_confirmed_denial_ms"`
	LegitimateSamples           int               `json:"legitimate_samples"`
	LegitimateMaxLatencyMS      float64           `json:"legitimate_max_latency_ms"`
	LegitimateDispatchOverlaps  int               `json:"legitimate_dispatch_overlaps"`
	SourceSHA256                string            `json:"source_sha256"`
	BrainFilesSHA256            map[string]string `json:"brain_files_sha256"`
	Stages                      []Stage           `json:"stages"`
	Probes                      []Probe           `json:"probes"`
	CleanDecisions              []model.Decision  `json:"clean_decisions"`
	StaleDecisions              []model.Decision  `json:"stale_decisions"`
	Decisions                   []model.Decision  `json:"decisions"`
	Dispatch                    *actuator.Result  `json:"dispatch,omitempty"`
	ReplayExact                 bool              `json:"replay_exact"`
	ShadowStateUnchanged        bool              `json:"shadow_state_unchanged"`
	HoldElapsedMS               float64           `json:"hold_elapsed_ms"`
	// Security Gain validation: the branch this episode ran, the competing action dispatched
	// instead of the selected one, and the brain's re-observation of the same pod after the
	// branch (which facts it still mints, and what it would now select).
	Arm                  string            `json:"arm,omitempty"`
	CounterfactualAction string            `json:"counterfactual_action,omitempty"`
	PostTarget           string            `json:"post_target,omitempty"`
	PostDecisionClock    time.Time         `json:"post_decision_clock,omitempty"`
	PostDecisions        []model.Decision  `json:"post_decisions,omitempty"`
	PostObservationError string            `json:"post_observation_error,omitempty"`
	FormalSLO            slo.Bound         `json:"formal_slo"`
	Artifacts            map[string]string `json:"artifacts"`
	Limitations          []string          `json:"limitations"`
	Error                string            `json:"error,omitempty"`
	CleanupErrors        []string          `json:"cleanup_errors,omitempty"`
}

func SHA256(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// ValidateProbe treats outage, backend refusal, and admission denial as different
// observations. The counter proves whether the protected downstream operation ran.
func ValidateProbe(p Probe, allowed bool, maxLatency time.Duration) error {
	if maxLatency <= 0 || math.IsNaN(p.LatencyMS) || math.IsInf(p.LatencyMS, 0) || p.LatencyMS < 0 || p.BeforeCalls < 0 || p.AfterCalls < 0 {
		return fmt.Errorf("%s: invalid latency limit, measurement or counter", p.Name)
	}
	if p.Error != "" {
		return fmt.Errorf("%s: %s", p.Name, p.Error)
	}
	var body map[string]any
	if err := json.Unmarshal(p.Body, &body); err != nil {
		return fmt.Errorf("%s: invalid JSON", p.Name)
	}
	if allowed {
		if p.Status != 200 || body["marker"] != Marker || body["nonce"] != p.Nonce || p.Nonce == "" || p.AfterCalls != p.BeforeCalls+1 || body["call_count"] != float64(p.AfterCalls) {
			return fmt.Errorf("%s: successful downstream operation not proved", p.Name)
		}
		if p.LatencyMS > float64(maxLatency)/float64(time.Millisecond) {
			return fmt.Errorf("%s: local legitimate latency limit exceeded", p.Name)
		}
	} else if p.Status != 401 || body["error"] != "unauthorized" || p.AfterCalls != p.BeforeCalls {
		return fmt.Errorf("%s: exact lease admission denial with zero downstream effect not proved", p.Name)
	}
	raw := []byte(p.Body)
	if p.RawBody != "" {
		var retained, parsed bytes.Buffer
		if json.Compact(&retained, []byte(p.RawBody)) != nil || json.Compact(&parsed, p.Body) != nil || !bytes.Equal(retained.Bytes(), parsed.Bytes()) {
			return fmt.Errorf("%s: parsed body differs from retained raw response", p.Name)
		}
		raw = []byte(p.RawBody)
	}
	if p.BodySHA256 != SHA256(raw) {
		return fmt.Errorf("%s: body digest differs", p.Name)
	}
	return nil
}
