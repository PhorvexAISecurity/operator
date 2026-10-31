package mathlab

import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/cost/endpoint"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

const StudyCandidatesSchema = "math-lab.study-candidates.v1"

// StudyCandidates binds the full pre-cost generator output to a verified
// snapshot. Only endpoint measurement/history and declared study settings may
// be enriched by the observer; source-owned candidate fields stay immutable.
type StudyCandidates struct {
	Schema                 string               `json:"schema"`
	SnapshotDigest         string               `json:"snapshot_digest"`
	SourceRevision         string               `json:"source_revision"`
	SnapshotSourceRevision string               `json:"snapshot_source_revision"`
	CrossVersion           bool                 `json:"cross_version"`
	Observational          bool                 `json:"observational"`
	Namespace              string               `json:"namespace"`
	PolicyName             string               `json:"policy_name"`
	PolicyUID              string               `json:"policy_uid"`
	PolicyGeneration       int64                `json:"policy_generation"`
	TickID                 string               `json:"tick_id"`
	At                     float64              `json:"at"`
	CapturedAt             float64              `json:"captured_at"`
	WorkloadUID            string               `json:"workload_uid"`
	SpecReplicas           *int                 `json:"spec_replicas"`
	MaxMovesPerTick        int                  `json:"max_moves_per_tick"`
	CandidateSetComplete   bool                 `json:"candidate_set_complete"`
	Missing                []string             `json:"missing"`
	MandatoryID            string               `json:"mandatory_id,omitempty"`
	Candidates             []endpoint.Candidate `json:"candidates"`
	BaselineReproduced     bool                 `json:"baseline_reproduced"`
	FinalDecisions         []model.Decision     `json:"final_decisions"`
	preparation            decision.StudyPreparation
}

// StudySource records the actual embedded replay identity. Cross-source use is
// explicit and remains observational even when legacy decisions reproduce.
type StudySource struct {
	ReplayGitSHA      string
	AllowCrossVersion bool
}

// ExportStudyCandidates runs exact baseline replay first, then the real shared
// preparation with recorded impure collaborators and isolated owner state.
func ExportStudyCandidates(s *Snapshot, source StudySource) StudyCandidates {
	out := StudyCandidates{Schema: StudyCandidatesSchema, SnapshotDigest: s.Digest, SourceRevision: source.ReplayGitSHA,
		SnapshotSourceRevision: s.Header.GitSHA, CrossVersion: source.ReplayGitSHA != s.Header.GitSHA, Observational: source.ReplayGitSHA != s.Header.GitSHA,
		Namespace: s.Header.Namespace, PolicyName: s.Header.PolicyName, PolicyUID: s.Header.PolicyUID,
		PolicyGeneration: s.Header.PolicyGeneration, TickID: s.Header.TickID,
		At: float64(s.Header.DecidedAt.UnixNano()) / 1e9, CapturedAt: float64(s.Header.CapturedAt.UnixNano()) / 1e9,
		MaxMovesPerTick: s.Inputs.Policy.MaxMovesPerTick, Missing: []string{}, Candidates: []endpoint.Candidate{}, FinalDecisions: []model.Decision{}}
	if s.Final != nil {
		out.FinalDecisions = s.Final.Decisions
	}
	if !fullGitSHA(source.ReplayGitSHA) || !fullGitSHA(s.Header.GitSHA) || (out.CrossVersion && !source.AllowCrossVersion) {
		out.Missing = append(out.Missing, "VERSION_MISMATCH")
		return out
	}
	baseline, err := Replay(s, ReplayOptions{Arms: []Arm{{ID: "baseline"}}})
	if err != nil || len(baseline) != 1 || baseline[0].Status != StatusOK || baseline[0].Baseline == nil || !baseline[0].Baseline.Reproduced {
		out.Missing = append(out.Missing, "BASELINE_NOT_EXACT")
		return out
	}
	out.BaselineReproduced = true
	if out.PolicyUID == "" || out.PolicyUID != s.Inputs.Policy.PolicyUID || out.Namespace != s.Inputs.Policy.Namespace {
		out.Missing = append(out.Missing, "POLICY_IDENTITY_MISMATCH")
		return out
	}
	for _, v := range s.Inputs.Views {
		o := v.Pod.WorkloadSpec
		if !o.Known || v.Pod.UID == "" || o.PodUID != v.Pod.UID || o.Workload.UID == "" || o.SpecReplicas <= 0 || v.Pod.Namespace != out.Namespace || o.Workload.Namespace != out.Namespace {
			out.Missing = append(out.Missing, "WORKLOAD_SPEC_REPLICAS_MISSING:"+v.Pod.Name)
			continue
		}
		n := int(o.SpecReplicas)
		if out.WorkloadUID != "" && (out.WorkloadUID != o.Workload.UID || out.SpecReplicas == nil || *out.SpecReplicas != n) {
			out.Missing = append(out.Missing, "STUDY_SCOPE_REQUIRES_ONE_WORKLOAD_UID_AND_SPEC")
			continue
		}
		out.WorkloadUID, out.SpecReplicas = o.Workload.UID, &n
	}
	if out.WorkloadUID == "" {
		out.Missing = append(out.Missing, "WORKLOAD_IDENTITY_MISSING")
	}
	err = withGlobals(s.Header, func() error {
		engine := decision.NewCoverageEngine()
		if engine.Recon == nil || engine.Recon.Name() != s.Header.ReconProfile || engine.Context == nil || engine.Context.Name() != s.Header.ContextProvider {
			return fmt.Errorf("STUDY_ENGINE_PROFILE_MISMATCH")
		}
		engine.Now = func() time.Time { return s.Header.DecidedAt }
		if err := engine.RestoreOwnerState(s.Inputs.Engine); err != nil {
			return err
		}
		pb := newPlayback(s.Outcome)
		if s.Outcome.CapabilityWired {
			engine.Capability, engine.ShadowCapability = pb.capability, pb.capability
		}
		if s.Outcome.FailureWired {
			engine.FailureExclusion = pb.failure
		}
		views, err := cloneViews(s.Inputs.Views)
		if err != nil {
			return err
		}
		out.preparation, err = engine.PrepareEndpointStudy(views, s.Inputs.Policy)
		out.Candidates = out.preparation.Candidates
		out.Missing = append(out.Missing, pb.missed()...)
		return err
	})
	if err != nil {
		out.Missing = append(out.Missing, err.Error())
	}
	if out.preparation.Mandatory {
		// Retain the recorded deterministic containment winner. If the real
		// baseline could not select containment, the study may not invent a fix.
		out.MandatoryID = "required-containment-unavailable"
		for _, d := range s.Outcome.Production {
			if !d.Selected || d.Existential == nil || !d.Existential.Present {
				continue
			}
			for _, v := range s.Inputs.Views {
				if d.Namespace == v.Pod.Namespace && d.Pod == v.Pod.Name {
					out.MandatoryID = decision.StudyCandidateID(out.PolicyUID, v.Pod.UID, d.Action)
				}
			}
		}
		if out.MandatoryID == "required-containment-unavailable" {
			out.Missing = append(out.Missing, "RECORDED_CONTAINMENT_PRIORITY_UNAVAILABLE")
		}
	}
	out.CandidateSetComplete = len(out.Missing) == 0
	return out
}

type EndpointStudyResult struct {
	endpoint.Result
	ReplayGitSHA           string   `json:"replay_git_sha"`
	SnapshotSourceRevision string   `json:"snapshot_source_revision"`
	CrossVersion           bool     `json:"cross_version"`
	Observational          bool     `json:"observational"`
	BaselineExactCount     int      `json:"baseline_exact_count"`
	SnapshotDigests        []string `json:"snapshot_digests"`
	BrainParity            bool     `json:"brain_selection_parity"`
}

// RunEndpointStudy binds every normalized row to the actual pinned brain
// preparation, then executes the shared brain selection loop for both arms.
// Source fields are compared before the shared kernel sees enriched telemetry.
func RunEndpointStudy(snapshots []*Snapshot, trace endpoint.Trace, cfg endpoint.Config, store endpoint.StateStore, source StudySource) (EndpointStudyResult, error) {
	var out EndpointStudyResult
	if trace.Evidence != "recorded" || len(snapshots) != len(trace.Ticks) || source.ReplayGitSHA != trace.SourceRevision {
		return out, fmt.Errorf("BRAIN_STUDY_REQUIRES_EXACT_RECORDED_COHORT")
	}
	if err := endpoint.ValidateTrace(trace); err != nil {
		return out, err
	}
	exports := map[string]StudyCandidates{}
	scope := ""
	for _, s := range snapshots {
		if s == nil || exports[s.Digest].SnapshotDigest != "" || (out.SnapshotSourceRevision != "" && out.SnapshotSourceRevision != s.Header.GitSHA) {
			return out, fmt.Errorf("BRAIN_STUDY_SOURCE_OR_DUPLICATE_SNAPSHOT")
		}
		out.SnapshotSourceRevision = s.Header.GitSHA
		ex := ExportStudyCandidates(s, source)
		if !ex.BaselineReproduced || !ex.CandidateSetComplete {
			return out, fmt.Errorf("BRAIN_STUDY_SOURCE_UNAVAILABLE %s: %v", s.Digest, ex.Missing)
		}
		identity := ex.Namespace + "\x00" + ex.PolicyUID + "\x00" + ex.WorkloadUID
		if scope != "" && scope != identity {
			return out, fmt.Errorf("BRAIN_STUDY_COHORT_REQUIRES_ONE_POLICY_AND_WORKLOAD")
		}
		scope = identity
		exports[s.Digest] = ex
		out.SnapshotDigests = append(out.SnapshotDigests, s.Digest)
		out.BaselineExactCount++
	}
	for _, t := range trace.Ticks {
		ex, ok := exports[t.ID]
		if !ok || t.At != ex.At || t.PolicyUID != ex.PolicyUID || t.WorkloadUID != ex.WorkloadUID || !reflect.DeepEqual(t.SpecReplicas, ex.SpecReplicas) || !t.CandidateSetComplete || t.MandatoryID != ex.MandatoryID {
			return out, fmt.Errorf("BRAIN_STUDY_TICK_IDENTITY_MISMATCH: %s", t.ID)
		}
		if len(t.Candidates) != len(ex.Candidates) {
			return out, fmt.Errorf("BRAIN_STUDY_CANDIDATE_POPULATION_MISMATCH: %s", t.ID)
		}
		byID := map[string]endpoint.Candidate{}
		for _, c := range ex.Candidates {
			byID[c.ID] = c
		}
		for _, c := range t.Candidates {
			source, ok := byID[c.ID]
			if !ok || c.PodUID != source.PodUID || c.Action != source.Action || c.Class != source.Class || c.Containment != source.Containment || c.FactsKnown != source.FactsKnown || c.GatesKnown != source.GatesKnown || !reflect.DeepEqual(c.Facts, source.Facts) || !reflect.DeepEqual(c.Gates, source.Gates) || (source.K != nil && !reflect.DeepEqual(c.K, source.K)) {
				return out, fmt.Errorf("BRAIN_STUDY_SOURCE_CANDIDATE_MISMATCH: %s/%s", t.ID, c.ID)
			}
		}
	}
	result, err := endpoint.Run(trace, cfg, store)
	if err != nil {
		return out, err
	}
	byTick := map[string]endpoint.Tick{}
	for _, t := range trace.Ticks {
		byTick[t.ID] = t
	}
	for _, r := range result.Ticks {
		ex := exports[r.ID]
		for _, arm := range []endpoint.ArmResult{r.V2, r.V3} {
			lambda := 0.0
			if arm.Arm == "v3" {
				lambda = r.Lambda.Effective
			}
			pick, err := ex.preparation.SelectEndpointStudy(byTick[r.ID], arm, lambda)
			if err != nil || !reflect.DeepEqual(pick, arm.Pick) {
				return out, fmt.Errorf("BRAIN_STUDY_SELECTION_PARITY_FAILED: %s/%s: %v", r.ID, arm.Arm, err)
			}
		}
	}
	out.Result, out.BrainParity = result, true
	out.ReplayGitSHA = source.ReplayGitSHA
	out.CrossVersion = source.ReplayGitSHA != out.SnapshotSourceRevision
	out.Observational = out.CrossVersion
	out.Mode = "PAIRED_BRAIN_REPLAY"
	sort.Strings(out.SnapshotDigests)
	out.Limitations = append(out.Limitations, "Both arms execute the pinned brain's shared non-cost preparation and selection predicates; shared endpoint pricing is experimental and offline. Recorded baseline replay is exact. No counterfactual action was actuated.")
	return out, nil
}

func fullGitSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
