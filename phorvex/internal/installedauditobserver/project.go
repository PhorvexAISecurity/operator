package installedauditobserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

type rawActionDisposition struct {
	Action        string `json:"action"`
	Status        string `json:"status"`
	ExclusionKind string `json:"exclusionKind"`
	Reason        string `json:"reason"`
	Scored        *bool  `json:"scored"`
}

var availabilityRefusalPattern = regexp.MustCompile(`^availability: ready=(0|[1-9][0-9]*)-1 < minAvailable=(0|[1-9][0-9]*)$`)

func projectAvailabilityRefusal(candidate rawActionDisposition) *AvailabilityRefusal {
	if candidate.Action != string(model.ActionRotate) || candidate.Status != model.ActionStatusInfeasible || candidate.ExclusionKind != model.ExclusionFeasibility {
		return nil
	}
	match := availabilityRefusalPattern.FindStringSubmatch(candidate.Reason)
	if match == nil {
		return nil
	}
	ready, readyErr := strconv.Atoi(match[1])
	minimum, minimumErr := strconv.Atoi(match[2])
	const removed = 1
	if readyErr != nil || minimumErr != nil || ready < removed || ready-removed >= minimum {
		return nil
	}
	return &AvailabilityRefusal{Ready: ready, Removed: removed, MinAvailable: minimum}
}

type rawTrace struct {
	SchemaVersion   string                 `json:"schemaVersion"`
	DecisionID      string                 `json:"decisionID"`
	TickID          string                 `json:"tickID"`
	Timestamp       string                 `json:"timestamp"`
	BrainImage      string                 `json:"brainImage"`
	GitSHA          string                 `json:"gitSHA"`
	PolicyNamespace string                 `json:"policyNamespace"`
	PolicyName      string                 `json:"policyName"`
	PolicyUID       string                 `json:"policyUID"`
	AssetNamespace  string                 `json:"assetNamespace"`
	AssetName       string                 `json:"assetName"`
	AssetUID        string                 `json:"assetUID"`
	SelectedAction  string                 `json:"selectedAction"`
	DryRun          *bool                  `json:"dryRun"`
	DispatchOutcome string                 `json:"dispatchOutcome"`
	ActionStatus    []rawActionDisposition `json:"actionStatus"`
}

type rawParameterSet struct {
	SchemaVersion       string `json:"schemaVersion"`
	ManifestID          string `json:"manifestId"`
	ManifestHash        string `json:"manifestHash"`
	PolicyOverridesID   string `json:"policyOverridesId"`
	PolicyOverridesHash string `json:"policyOverridesHash"`
}

type rawGraceful struct {
	PolicyNamespace             string `json:"policyNamespace"`
	PolicyName                  string `json:"policyName"`
	PolicyUID                   string `json:"policyUID"`
	PolicyGeneration            int64  `json:"policyGeneration"`
	PolicyGraceCapSeconds       int64  `json:"policyGraceCapSeconds"`
	WorkloadGraceSeconds        int64  `json:"workloadGraceSeconds"`
	WorkloadGraceExplicit       bool   `json:"workloadGraceExplicit"`
	EffectiveGracePeriodSeconds int64  `json:"effectiveGracePeriodSeconds"`
	PodUID                      string `json:"podUID"`
	PodResourceVersion          string `json:"podResourceVersion"`
	TerminationStatus           string `json:"terminationStatus"`
}

type rawRecord struct {
	SchemaVersion           string           `json:"schemaVersion"`
	Kind                    string           `json:"kind"`
	Time                    time.Time        `json:"time"`
	Namespace               string           `json:"namespace"`
	Pod                     string           `json:"pod"`
	Action                  string           `json:"action"`
	Selected                *bool            `json:"selected"`
	Feasible                *bool            `json:"feasible"`
	DryRun                  *bool            `json:"dryRun"`
	Actuated                *bool            `json:"actuated"`
	DispatchOutcome         string           `json:"dispatchOutcome"`
	Handler                 string           `json:"handler"`
	ObjectsTouched          []string         `json:"objectsTouched"`
	MutationKind            string           `json:"mutationKind"`
	GracefulTermination     *rawGraceful     `json:"gracefulTermination"`
	ParameterMaterialStatus string           `json:"parameterMaterialStatus"`
	ParameterSet            *rawParameterSet `json:"parameterSet"`
	DecisionTrace           *rawTrace        `json:"decisionTrace"`
}

// rejectDuplicateFields recursively rejects duplicate JSON object names. The
// standard decoder otherwise keeps the last value, which could make identity
// or dispatch evidence ambiguous.
func rejectDuplicateFields(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch delim := tok.(type) {
		case json.Delim:
			switch delim {
			case '{':
				seen := map[string]bool{}
				for dec.More() {
					nameToken, err := dec.Token()
					if err != nil {
						return err
					}
					name, ok := nameToken.(string)
					if !ok {
						return errors.New("JSON object name is not a string")
					}
					if seen[name] {
						return fmt.Errorf("duplicate JSON field %q", name)
					}
					seen[name] = true
					if err := walk(); err != nil {
						return err
					}
				}
				end, err := dec.Token()
				if err != nil || end != json.Delim('}') {
					return errors.New("unterminated JSON object")
				}
			case '[':
				for dec.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				end, err := dec.Token()
				if err != nil || end != json.Delim(']') {
					return errors.New("unterminated JSON array")
				}
			default:
				return errors.New("unexpected JSON delimiter")
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func imageDigest(value string) string {
	s := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(s[:])
}

func safeActionDisposition(schema, status, exclusion string, scored *bool) bool {
	switch status {
	case model.ActionStatusNotEnabled, model.ActionStatusNoCover, model.ActionStatusInfeasible,
		model.ActionStatusConformalSLO, model.ActionStatusPricedOut, model.ActionStatusBudgetExhausted,
		model.ActionStatusCandidate, model.ActionStatusSelected, model.ActionStatusNotEvaluated,
		model.ActionStatusNotInstallable, model.ActionStatusIneligible:
	default:
		return false
	}
	if exclusion == model.ExclusionResourceCapacity {
		return schema == model.DecisionTraceSchemaV7 && status == model.ActionStatusInfeasible && scored != nil && !*scored
	}
	switch exclusion {
	case model.ExclusionNone, model.ExclusionNotEnabled, model.ExclusionReconCover, model.ExclusionFeasibility,
		model.ExclusionCostNaN, model.ExclusionSLOGate, model.ExclusionReactiveOnly, model.ExclusionSelection,
		model.ExclusionNotInstallable, model.ExclusionNoRBAC, model.ExclusionCapability,
		model.ExclusionActionFailure, model.ExclusionOperatorOptOut:
		return true
	default:
		return false
	}
}

func project(raw []byte, ranges []SourceRange, cfg Config) (Receipt, bool, error) {
	if len(raw) == 0 || int64(len(raw)) > MaxRecordBytes {
		return Receipt{}, false, errors.New("audit row is empty or oversized")
	}
	if err := rejectDuplicateFields(raw); err != nil {
		return Receipt{}, false, fmt.Errorf("ambiguous audit row: %w", err)
	}
	var row rawRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&row); err != nil {
		return Receipt{}, false, fmt.Errorf("decode audit row: %w", err)
	}
	if row.Kind != "phorvex.decision" {
		return Receipt{}, false, nil
	}
	if row.SchemaVersion != audit.SchemaVersionCurrent {
		return Receipt{}, false, fmt.Errorf("unsupported audit schema %q", row.SchemaVersion)
	}
	if row.DecisionTrace == nil {
		inWindow := row.Time.IsZero() || (!row.Time.Before(cfg.NotBefore) && !row.Time.After(cfg.NotAfter))
		if inWindow && row.Namespace == cfg.TargetNamespace && row.Pod == cfg.TargetName {
			return Receipt{}, false, errors.New("target audit row lacks decision trace attribution")
		}
		return Receipt{}, false, nil
	}
	t := row.DecisionTrace
	when, err := time.Parse(time.RFC3339Nano, t.Timestamp)
	if err != nil || row.Time.IsZero() || !row.Time.Equal(when) {
		return Receipt{}, false, errors.New("decision timestamps are absent or contradictory")
	}
	if when.Before(cfg.NotBefore) || when.After(cfg.NotAfter) {
		return Receipt{}, false, nil
	}
	// A policy normally evaluates many Pods. Only the exact policy/target name
	// pair is a candidate observation; other rows remain unrelated.
	if t.PolicyNamespace != cfg.PolicyNamespace || t.PolicyName != cfg.PolicyName ||
		t.AssetNamespace != cfg.TargetNamespace || t.AssetName != cfg.TargetName {
		return Receipt{}, false, nil
	}
	if t.PolicyUID != cfg.PolicyUID || t.AssetUID != cfg.TargetUID || row.Namespace != cfg.TargetNamespace || row.Pod != cfg.TargetName {
		return Receipt{}, false, errors.New("matching policy/target name has a changed UID or top-level identity")
	}
	if t.SchemaVersion != cfg.ExpectedTraceSchema || t.BrainImage != cfg.ExpectedBrainImage || t.GitSHA != cfg.ExpectedGitSHA {
		return Receipt{}, false, errors.New("matching decision has a stale or unexpected source identity")
	}
	if t.DecisionID == "" || t.TickID == "" {
		return Receipt{}, false, errors.New("matching decision lacks decision or tick identity")
	}
	if row.Selected == nil || row.Feasible == nil || row.DryRun == nil || row.Actuated == nil || t.DryRun == nil {
		return Receipt{}, false, errors.New("matching decision lacks required boolean evidence")
	}
	if len(t.DecisionID) > MaxIdentityBytes || len(t.TickID) > MaxIdentityBytes {
		return Receipt{}, false, errors.New("matching decision identity exceeds its size bound")
	}
	if row.ParameterSet == nil || row.ParameterMaterialStatus != "retained" {
		return Receipt{}, false, errors.New("matching decision lacks retained parameter material")
	}
	p := row.ParameterSet
	if p.SchemaVersion != model.DecisionParameterSetV1 || p.ManifestID != cfg.ExpectedManifestID || p.ManifestHash != cfg.ExpectedManifestHash ||
		p.PolicyOverridesID != cfg.overridesID() || !digestPattern.MatchString(p.PolicyOverridesHash) ||
		(cfg.ExpectedOverridesHash != "" && p.PolicyOverridesHash != cfg.ExpectedOverridesHash) {
		return Receipt{}, false, errors.New("matching decision has the wrong parameter epoch")
	}
	if row.Action != t.SelectedAction || *row.DryRun != *t.DryRun {
		return Receipt{}, false, errors.New("top-level decision contradicts its trace")
	}
	if row.Action != string(model.ActionNoop) && row.Action != string(model.ActionRotate) {
		return Receipt{}, false, errors.New("installed observer action is outside its allowlist")
	}
	if row.Handler != "" && row.Handler != row.Action {
		return Receipt{}, false, errors.New("handler contradicts the selected action")
	}
	switch row.MutationKind {
	case "", "none", "reversible", "irreversible", "forward-only", "swap", "declared", "partial":
	default:
		return Receipt{}, false, errors.New("mutation kind is outside its allowlist")
	}
	traceOutcome := model.SafeDispatchOutcome(t.DispatchOutcome)
	rowOutcome := model.SafeDispatchOutcome(row.DispatchOutcome)
	if traceOutcome == "" || (row.DispatchOutcome != "" && rowOutcome != traceOutcome) {
		return Receipt{}, false, errors.New("dispatch outcome is absent, unknown, or contradictory")
	}
	if *row.Actuated != (traceOutcome == model.DispatchEmitted) {
		return Receipt{}, false, errors.New("actuated flag contradicts dispatch outcome")
	}
	if traceOutcome == model.DispatchEmitted && (row.Action != string(model.ActionRotate) || !*row.Selected || !*row.Feasible || *row.DryRun) {
		return Receipt{}, false, errors.New("emitted dispatch contradicts selection, feasibility, dry-run, or action")
	}
	if row.Action == string(model.ActionNoop) && traceOutcome != model.DispatchNotAttempted {
		return Receipt{}, false, errors.New("noop carries an attempted dispatch")
	}
	if len(row.ObjectsTouched) > MaxObjectsTouched {
		return Receipt{}, false, errors.New("objectsTouched exceeds its bound")
	}
	if len(row.ObjectsTouched) > 0 && !slices.Equal(row.ObjectsTouched, cfg.AllowedObjectsTouched) {
		return Receipt{}, false, errors.New("objectsTouched differs from the exact allowlist")
	}
	if len(row.ObjectsTouched) == 0 && traceOutcome == model.DispatchEmitted {
		return Receipt{}, false, errors.New("emitted dispatch lacks an exact touched object")
	}
	var disposition *ActionDisposition
	seenActions := map[string]bool{}
	if len(t.ActionStatus) > MaxActionStatuses {
		return Receipt{}, false, errors.New("action disposition exceeds its bound")
	}
	for _, candidate := range t.ActionStatus {
		if candidate.Action == "" || seenActions[candidate.Action] || !safeActionDisposition(t.SchemaVersion, candidate.Status, candidate.ExclusionKind, candidate.Scored) {
			return Receipt{}, false, errors.New("action disposition is empty or duplicated")
		}
		seenActions[candidate.Action] = true
		if candidate.Action == string(model.ActionRotate) {
			disposition = &ActionDisposition{Action: candidate.Action, Status: candidate.Status, ExclusionKind: candidate.ExclusionKind, AvailabilityRefusal: projectAvailabilityRefusal(candidate)}
		}
	}
	if t.SchemaVersion != model.DecisionTraceSchemaV2 && disposition == nil {
		return Receipt{}, false, errors.New("current trace lacks rotate disposition")
	}
	var graceful *GracefulTermination
	if row.GracefulTermination != nil {
		g := row.GracefulTermination
		if row.Action != string(model.ActionRotate) || traceOutcome != model.DispatchEmitted || !*row.Actuated || row.Handler != string(model.ActionRotate) ||
			g.PolicyNamespace != cfg.PolicyNamespace || g.PolicyName != cfg.PolicyName || g.PolicyUID != cfg.PolicyUID || g.PolicyGeneration != cfg.PolicyGeneration ||
			g.PodUID != cfg.TargetUID || g.PodResourceVersion == "" || g.TerminationStatus != "unconfirmed" ||
			cfg.ExpectedPodResourceVersion == "" || g.PodResourceVersion != cfg.ExpectedPodResourceVersion || cfg.ExpectedGraceSeconds == nil ||
			g.EffectiveGracePeriodSeconds != *cfg.ExpectedGraceSeconds || g.PolicyGraceCapSeconds < 1 ||
			g.EffectiveGracePeriodSeconds > g.PolicyGraceCapSeconds || g.WorkloadGraceSeconds < 0 ||
			(g.WorkloadGraceExplicit && g.EffectiveGracePeriodSeconds > g.WorkloadGraceSeconds) {
			return Receipt{}, false, errors.New("native rotate receipt does not match the exact policy, target, resourceVersion, grace, or dispatch")
		}
		graceful = &GracefulTermination{PolicyGeneration: g.PolicyGeneration, PolicyGraceCapSeconds: g.PolicyGraceCapSeconds,
			WorkloadGraceSeconds: g.WorkloadGraceSeconds, WorkloadGraceExplicit: g.WorkloadGraceExplicit,
			EffectiveGracePeriodSeconds: g.EffectiveGracePeriodSeconds, PodResourceVersion: g.PodResourceVersion,
			TerminationStatus: g.TerminationStatus}
	} else if traceOutcome == model.DispatchEmitted && row.Action == string(model.ActionRotate) {
		return Receipt{}, false, errors.New("emitted native rotate lacks graceful termination receipt")
	}
	sum := sha256.Sum256(raw)
	return Receipt{
		SchemaVersion: ReceiptSchema, DecisionTime: when, DecisionID: t.DecisionID, TickID: t.TickID,
		Policy:      PolicyIdentity{Namespace: cfg.PolicyNamespace, Name: cfg.PolicyName, UID: cfg.PolicyUID, Generation: cfg.PolicyGeneration},
		Target:      TargetIdentity{Namespace: cfg.TargetNamespace, Name: cfg.TargetName, UID: cfg.TargetUID},
		TraceSchema: t.SchemaVersion, BrainImageSHA256: imageDigest(t.BrainImage), GitSHA: t.GitSHA,
		ParameterEpoch: ParameterEpoch{SchemaVersion: p.SchemaVersion, ManifestID: p.ManifestID, ManifestHash: p.ManifestHash,
			PolicyOverridesID: p.PolicyOverridesID, PolicyOverridesHash: p.PolicyOverridesHash},
		Action: row.Action, Selected: *row.Selected, Feasible: *row.Feasible, DryRun: *row.DryRun, Actuated: *row.Actuated,
		DispatchOutcome: traceOutcome, ActionDisposition: disposition, Handler: row.Handler, MutationKind: row.MutationKind,
		ObjectsTouched: append([]string(nil), row.ObjectsTouched...), GracefulTermination: graceful,
		RawSHA256: "sha256:" + hex.EncodeToString(sum[:]), SourceRanges: append([]SourceRange(nil), ranges...),
	}, true, nil
}
