package cataloguecollector

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

const (
	IndexSchema  = "phorvex.catalogue-run-index.v1"
	ReportSchema = "phorvex.catalogue-functional-report.v1"
)

type Index struct {
	Schema  string      `json:"schema"`
	Records []RunRecord `json:"records"`
}

type RunRecord struct {
	ID                      string           `json:"id"`
	ProfileID               string           `json:"profileID"`
	SuiteFile               string           `json:"suiteFile"`
	SuiteSHA256             string           `json:"suiteSHA256"`
	SourceRevision          string           `json:"sourceRevision"`
	HarnessSHA256           string           `json:"harnessSHA256"`
	ConfigSHA256            string           `json:"configSHA256"`
	MetricsFile             string           `json:"metricsFile"`
	MetricsSHA256           string           `json:"metricsSHA256"`
	WorkloadSchedule        string           `json:"workloadSchedule"`
	State                   string           `json:"state"` // available, missing, failed
	FailureReason           string           `json:"failureReason,omitempty"`
	ExternalReviewState     string           `json:"externalReviewState"`
	ExternalReviewReference string           `json:"externalReviewReference"`
	NATSIdentity            *NATSRunIdentity `json:"natsIdentity,omitempty"`
}

// NATSRunIdentity is supplied by the explicit run index. The collector checks
// every retained receipt against this authority but does not claim to have
// independently resolved these live identities.
type NATSRunIdentity struct {
	Mode             string   `json:"mode"`
	FixtureNonce     string   `json:"fixtureNonce"`
	NodeName         string   `json:"nodeName"`
	NodeUID          string   `json:"nodeUID"`
	ConnectedMember  string   `json:"connectedMember"`
	StorageClass     string   `json:"storageClass"`
	StorageClassUID  string   `json:"storageClassUID"`
	PodUIDs          []string `json:"podUIDs"`
	PVCUIDs          []string `json:"pvcUIDs"`
	PVUIDs           []string `json:"pvUIDs"`
	StorePathSHA256s []string `json:"storePathSHA256s"`
	InitialServerIDs []string `json:"initialServerIDs"`
}

type Report struct {
	Schema           string        `json:"schema"`
	IndexSHA256      string        `json:"indexSHA256"`
	Runs             []RunResult   `json:"runs"`
	Groups           []GroupResult `json:"groups"`
	ComparisonStatus string        `json:"comparisonStatus"`
	ClaimLimits      []string      `json:"claimLimits"`
}

type RunResult struct {
	ID                        string                   `json:"id"`
	ProfileID                 string                   `json:"profileID"`
	SuiteFile                 string                   `json:"suiteFile"`
	SuiteRevision             string                   `json:"suiteRevision"`
	SuiteSHA256               string                   `json:"suiteSHA256"`
	SourceRevision            string                   `json:"sourceRevision"`
	HarnessSHA256             string                   `json:"harnessSHA256"`
	ConfigSHA256              string                   `json:"configSHA256"`
	MetricsFile               string                   `json:"metricsFile"`
	MetricsSHA256             string                   `json:"metricsSHA256"`
	WorkloadSchedule          string                   `json:"workloadSchedule"`
	State                     string                   `json:"state"`
	MeasurementStatus         string                   `json:"measurementStatus"`
	FailureReasons            []string                 `json:"failureReasons,omitempty"`
	ExternalReviewState       string                   `json:"externalReviewState"`
	ExternalReviewReference   string                   `json:"externalReviewReference"`
	TrialDenominator          int                      `json:"trialDenominator"`
	RequestedTrialDenominator int                      `json:"requestedTrialDenominator"`
	AnchorTrialDenominator    int                      `json:"anchorTrialDenominator"`
	ValidTrials               int                      `json:"validTrials"`
	InvalidTrials             int                      `json:"invalidTrials"`
	RequestedValidTrials      int                      `json:"requestedValidTrials"`
	RequestedInvalidTrials    int                      `json:"requestedInvalidTrials"`
	AnchorValidTrials         int                      `json:"anchorValidTrials"`
	AnchorInvalidTrials       int                      `json:"anchorInvalidTrials"`
	Trials                    []TrialResult            `json:"trials"`
	InstalledSession          *InstalledSessionSummary `json:"installedSession,omitempty"`
	NATSJetStream             *NATSJetStreamSummary    `json:"natsJetStream,omitempty"`
}

type TrialResult struct {
	Scenario         string                   `json:"scenario"`
	Defender         string                   `json:"defender"`
	Trial            int                      `json:"trial"`
	AnchorOnly       bool                     `json:"anchorOnly"`
	Status           string                   `json:"status"`
	Reasons          []string                 `json:"reasons,omitempty"`
	InstalledSession *InstalledSessionSummary `json:"installedSession,omitempty"`
	NATSJetStream    *NATSJetStreamSummary    `json:"natsJetStream,omitempty"`
}

type NATSJetStreamSummary struct {
	IdentityAuthority                string   `json:"identityAuthority"`
	Mode                             string   `json:"mode"`
	FixtureNonce                     string   `json:"fixtureNonce"`
	ReceiptSHA256                    string   `json:"receiptSHA256"`
	ProtocolStatus                   string   `json:"protocolStatus"`
	Stream                           string   `json:"stream"`
	Consumer                         string   `json:"consumer"`
	Replicas                         int      `json:"replicas"`
	FinalMessages                    uint64   `json:"finalMessages"`
	FinalFirstSequence               uint64   `json:"finalFirstSequence"`
	FinalLastSequence                uint64   `json:"finalLastSequence"`
	FinalAckFloor                    uint64   `json:"finalAckFloor"`
	FinalAckPending                  int      `json:"finalAckPending"`
	FinalConsumerPending             uint64   `json:"finalConsumerPending"`
	FinalConsumerRedelivered         int      `json:"finalConsumerRedelivered"`
	MessageASequence                 uint64   `json:"messageASequence"`
	MessageBSequence                 uint64   `json:"messageBSequence,omitempty"`
	MessageXSequence                 uint64   `json:"messageXSequence,omitempty"`
	MessageYSequence                 uint64   `json:"messageYSequence,omitempty"`
	ActionAttempted                  bool     `json:"actionAttempted"`
	ActionCompleted                  bool     `json:"actionCompleted"`
	ActionCount                      int      `json:"actionCount"`
	RestartBoundaryNanos             int64    `json:"restartBoundaryNanos,omitempty"`
	ReplicaRecoveryNanos             int64    `json:"replicaRecoveryNanos,omitempty"`
	QuorumPauseObservedNanos         int64    `json:"quorumPauseObservedNanos,omitempty"`
	QuorumPauseMaximumNanos          int64    `json:"quorumPauseMaximumNanos,omitempty"`
	DuringPausePublicationStatus     string   `json:"duringPausePublicationStatus,omitempty"`
	DuringPausePublicationErrorClass string   `json:"duringPausePublicationErrorClass,omitempty"`
	DuringPausePingReachable         bool     `json:"duringPausePingReachable,omitempty"`
	PausedMembers                    []string `json:"pausedMembers,omitempty"`
	PodUIDs                          []string `json:"podUIDs"`
	VolumeUIDs                       []string `json:"volumeUIDs"`
	InitialServerIDs                 []string `json:"initialServerIDs"`
	CleanupComplete                  bool     `json:"cleanupComplete"`
	CleanupVerified                  bool     `json:"cleanupVerified"`
	SecurityOutcome                  string   `json:"securityOutcome"`
	InstalledDispatchProven          bool     `json:"installedDispatchProven"`
	DirectNativeActuatorProven       bool     `json:"directNativeActuatorProven"`
}

type InstalledSessionSummary struct {
	SampleDenominator                 int            `json:"sampleDenominator"`
	KnownApplicationResponse          int            `json:"knownApplicationResponses"`
	SessionPresentHTTP200             int            `json:"sessionPresentHTTP200"`
	NoSessionHTTP404                  int            `json:"noSessionHTTP404"`
	NoSessionHTTP404ByPodUID          map[string]int `json:"noSessionHTTP404ByPodUID"`
	Unknown                           int            `json:"unknown"`
	UnknownCategoryCounts             map[string]int `json:"unknownCategoryCounts"`
	UnknownErrorClassCounts           map[string]int `json:"unknownErrorClassCounts"`
	PodUIDCounts                      map[string]int `json:"podUIDCounts"`
	SegmentCount                      int            `json:"segmentCount"`
	SampledWindowSeconds              float64        `json:"sampledWindowSeconds"`
	ElapsedSpanSeconds                float64        `json:"elapsedObservationSpanSeconds"`
	InterSegmentGapSeconds            []float64      `json:"interSegmentUnobservedSeconds"`
	OriginalPodUID                    string         `json:"originalPodUID"`
	PeerPodUID                        string         `json:"peerPodUID"`
	ReplacementPodUID                 string         `json:"replacementPodUID,omitempty"`
	CoordinationUsed                  bool           `json:"coordinationUsed"`
	CoordinationDisposition           string         `json:"coordinationDisposition,omitempty"`
	CoordinationAttributionComplete   bool           `json:"coordinationAttributionComplete"`
	CoordinationTargetUID             string         `json:"coordinationTargetUID,omitempty"`
	CoordinationTargetResourceVersion string         `json:"coordinationTargetResourceVersion,omitempty"`
	CoordinationRequestedGraceSeconds int            `json:"coordinationRequestedGraceSeconds"`
	PolicyName                        string         `json:"policyName"`
	PolicyUID                         string         `json:"policyUID"`
	PolicyInitialMinimum              int            `json:"policyInitialMinimum"`
	PolicyEligibleMinimum             int            `json:"policyEligibleMinimum"`
	EffectStatus                      string         `json:"effectStatus"`
	EffectAttribution                 string         `json:"effectAttribution,omitempty"`
	DefensiveActions                  int            `json:"defensiveActions"`
	FalseDefensiveActions             int            `json:"falseDefensiveActions"`
	ContinuousAvailability            bool           `json:"continuousAvailability"`
}

type GroupResult struct {
	ProfileID        string   `json:"profileID"`
	SuiteRevision    string   `json:"suiteRevision"`
	SuiteSHA256      string   `json:"suiteSHA256"`
	SourceRevision   string   `json:"sourceRevision"`
	HarnessSHA256    string   `json:"harnessSHA256"`
	ConfigSHA256     string   `json:"configSHA256"`
	WorkloadSchedule string   `json:"workloadSchedule"`
	RunIDs           []string `json:"runIDs"`
	ComparisonStatus string   `json:"comparisonStatus"`
}

type suite struct {
	Schema               string          `json:"schema"`
	Revision             string          `json:"revision"`
	Status               json.RawMessage `json:"status"`
	Purpose              json.RawMessage `json:"purpose"`
	ImplementationStatus json.RawMessage `json:"implementationStatus"`
	GlobalRules          json.RawMessage `json:"globalRules"`
	Entries              json.RawMessage `json:"entries"`
	Profiles             []struct {
		ID                    string          `json:"id"`
		ScenarioFilter        []string        `json:"scenarioFilter"`
		DefenderFilter        []string        `json:"defenderFilter"`
		TrialsPerArm          int             `json:"trialsPerArm"`
		ExecutionKind         json.RawMessage `json:"executionKind"`
		RequiredFixtures      json.RawMessage `json:"requiredFixtures"`
		RequiredRelationships json.RawMessage `json:"requiredRelationships"`
		RequiredConfigValues  json.RawMessage `json:"requiredConfigValues"`
		OutputIsolation       json.RawMessage `json:"outputIsolation"`
	} `json:"profiles"`
	ComparisonContract   json.RawMessage `json:"comparisonContract"`
	ExcludedCapabilities json.RawMessage `json:"excludedCapabilities"`
	LiveStatusAuthority  json.RawMessage `json:"liveStatusAuthority"`
	SourceHashSemantics  json.RawMessage `json:"sourceHashSemantics"`
}

type profile struct {
	scenarios map[string]bool
	defenders map[string]bool
	trials    int
}

// Collect reads only the explicit files named by indexPath. It never scans for
// runs and performs no process, network, or Kubernetes operation.
func Collect(indexPath string) (Report, error) {
	indexRaw, err := os.ReadFile(indexPath)
	if err != nil {
		return Report{}, err
	}
	var idx Index
	if err := strictJSON(indexRaw, &idx); err != nil {
		return Report{}, fmt.Errorf("index: %w", err)
	}
	if idx.Schema != IndexSchema || len(idx.Records) == 0 {
		return Report{}, errors.New("index schema or records invalid")
	}
	base := filepath.Dir(indexPath)
	report := Report{Schema: ReportSchema, IndexSHA256: sum(indexRaw), ComparisonStatus: "COMPARISON_NOT_ESTABLISHED", ClaimLimits: []string{
		"Functional observations only; no security efficacy, monetary ROI, attacker mitigation, or green campaign verdict.",
		"Known HTTP 404 is an application response without the session, not a successful session read.",
		"Sampling gaps are unobserved time; no continuous availability claim.",
		"A timed-out NATS quorum-loss publication is an unknown initial outcome, not message loss or acknowledged success.",
		"NATS nonce, node, workload, volume, storage, and initial server identities are supplied run-index authority checked against retained receipts.",
		"External review state is supplied input and is not issued by this collector.",
		"Source, harness, and configuration hashes are supplied provenance pins; referenced file hashes are checked, but binary lineage is not independently established.",
	}}
	ids := map[string]bool{}
	usedMetrics := map[string]string{}
	usedMetricDigests := map[string]string{}
	type suiteCacheEntry struct {
		raw      []byte
		parsed   suite
		profiles map[string]profile
	}
	suites := map[string]suiteCacheEntry{}
	groups := map[string]*GroupResult{}
	for _, rec := range idx.Records {
		if ids[rec.ID] || rec.ID == "" {
			return Report{}, fmt.Errorf("duplicate or empty record id %q", rec.ID)
		}
		ids[rec.ID] = true
		if err := validateRecord(rec); err != nil {
			return Report{}, fmt.Errorf("record %s: %w", rec.ID, err)
		}
		suitePath, err := localPath(base, rec.SuiteFile)
		if err != nil {
			return Report{}, err
		}
		cached, ok := suites[suitePath]
		if !ok {
			raw, err := readHashed(suitePath, rec.SuiteSHA256)
			if err != nil {
				return Report{}, fmt.Errorf("record %s suite: %w", rec.ID, err)
			}
			var s suite
			if err := strictJSON(raw, &s); err != nil {
				return Report{}, fmt.Errorf("suite: %w", err)
			}
			if s.Schema != "phorvex.catalogue-suite.v1" || s.Revision == "" {
				return Report{}, errors.New("unsupported suite")
			}
			ps := map[string]profile{}
			for _, p := range s.Profiles {
				if _, exists := ps[p.ID]; exists {
					return Report{}, fmt.Errorf("duplicate suite profile %q", p.ID)
				}
				pp := profile{scenarios: map[string]bool{}, defenders: map[string]bool{}, trials: p.TrialsPerArm}
				for _, v := range p.ScenarioFilter {
					pp.scenarios[v] = true
				}
				for _, v := range p.DefenderFilter {
					pp.defenders[v] = true
				}
				ps[p.ID] = pp
			}
			cached = suiteCacheEntry{raw: raw, parsed: s, profiles: ps}
			suites[suitePath] = cached
		} else if sum(cached.raw) != rec.SuiteSHA256 {
			return Report{}, fmt.Errorf("record %s suite hash conflicts", rec.ID)
		}
		p, ok := cached.profiles[rec.ProfileID]
		if !ok {
			return Report{}, fmt.Errorf("record %s unknown profile %q", rec.ID, rec.ProfileID)
		}
		isNATSProfile := strings.HasPrefix(rec.ProfileID, "nats-")
		if isNATSProfile {
			if rec.State == "available" || rec.NATSIdentity != nil {
				if err := validateNATSAuthority(rec.ProfileID, rec.NATSIdentity); err != nil {
					return Report{}, fmt.Errorf("record %s NATS identity: %w", rec.ID, err)
				}
			}
		} else if rec.NATSIdentity != nil {
			return Report{}, fmt.Errorf("record %s supplies NATS identity for non-NATS profile", rec.ID)
		}
		requestedDenominator := p.trials * len(p.defenders) * len(p.scenarios)
		anchorDenominator := 0
		if !p.defenders["d-nomtd"] {
			anchorDenominator = p.trials * len(p.scenarios)
		}
		rr := RunResult{ID: rec.ID, ProfileID: rec.ProfileID, SuiteFile: rec.SuiteFile, SuiteRevision: cached.parsed.Revision, SuiteSHA256: rec.SuiteSHA256, SourceRevision: rec.SourceRevision, HarnessSHA256: rec.HarnessSHA256, ConfigSHA256: rec.ConfigSHA256, MetricsFile: rec.MetricsFile, MetricsSHA256: rec.MetricsSHA256, WorkloadSchedule: rec.WorkloadSchedule, State: rec.State, ExternalReviewState: rec.ExternalReviewState, ExternalReviewReference: rec.ExternalReviewReference, TrialDenominator: requestedDenominator + anchorDenominator, RequestedTrialDenominator: requestedDenominator, AnchorTrialDenominator: anchorDenominator}
		if rec.State != "available" {
			rr.MeasurementStatus = strings.ToUpper(rec.State)
			rr.FailureReasons = []string{rec.FailureReason}
			report.Runs = append(report.Runs, rr)
		} else {
			metricsPath, err := localPath(base, rec.MetricsFile)
			if err != nil {
				return Report{}, err
			}
			if prev, exists := usedMetrics[metricsPath]; exists {
				return Report{}, fmt.Errorf("metrics file reused by records %s and %s", prev, rec.ID)
			}
			usedMetrics[metricsPath] = rec.ID
			raw, err := readHashed(metricsPath, rec.MetricsSHA256)
			if err != nil {
				return Report{}, fmt.Errorf("record %s metrics: %w", rec.ID, err)
			}
			if prev, exists := usedMetricDigests[rec.MetricsSHA256]; exists {
				return Report{}, fmt.Errorf("metrics evidence digest reused by records %s and %s", prev, rec.ID)
			}
			usedMetricDigests[rec.MetricsSHA256] = rec.ID
			rows, err := decodeMetrics(raw)
			if err != nil {
				return Report{}, fmt.Errorf("record %s metrics: %w", rec.ID, err)
			}
			if len(rows) != rr.TrialDenominator {
				return Report{}, fmt.Errorf("record %s rows=%d want %d", rec.ID, len(rows), rr.TrialDenominator)
			}
			requestedRows := make([]core.Metric, 0, requestedDenominator)
			seenTrials := map[string]bool{}
			for _, m := range rows {
				isAnchor := m.AnchorOnly && m.Defender == "d-nomtd" && !p.defenders["d-nomtd"]
				if !p.scenarios[m.Scenario] || (!p.defenders[m.Defender] && !isAnchor) || m.Trial < 0 || m.Trial >= p.trials {
					return Report{}, fmt.Errorf("record %s contains unselected %s/%s", rec.ID, m.Scenario, m.Defender)
				}
				if p.defenders[m.Defender] && m.AnchorOnly {
					return Report{}, fmt.Errorf("record %s marks requested arm as anchor", rec.ID)
				}
				key := fmt.Sprintf("%s\x00%s\x00%d\x00%t", m.Scenario, m.Defender, m.Trial, isAnchor)
				if seenTrials[key] {
					return Report{}, fmt.Errorf("record %s contains duplicate trial identity", rec.ID)
				}
				seenTrials[key] = true
				tr := TrialResult{Scenario: m.Scenario, Defender: m.Defender, Trial: m.Trial, AnchorOnly: isAnchor, Status: string(m.MeasurementState().Status), Reasons: append([]string(nil), m.MeasurementState().Reasons...)}
				rowErr := functionalRowError(m)
				if rowErr == nil && strings.HasPrefix(rec.ProfileID, "manager-session-") {
					summary, err := decodeInstalled(m)
					if err != nil {
						return Report{}, fmt.Errorf("record %s installed %s row evidence: %w", rec.ID, map[bool]string{true: "anchor", false: "requested"}[isAnchor], err)
					}
					tr.InstalledSession = &summary
				}
				if isNATSProfile {
					summary, err := decodeNATS(m, rec.ProfileID, rec.NATSIdentity)
					if err != nil {
						return Report{}, fmt.Errorf("record %s NATS row evidence: %w", rec.ID, err)
					}
					tr.NATSJetStream = &summary
				}
				if rowErr == nil {
					rr.ValidTrials++
					if isAnchor {
						rr.AnchorValidTrials++
					} else {
						rr.RequestedValidTrials++
					}
				} else {
					rr.InvalidTrials++
					if isAnchor {
						rr.AnchorInvalidTrials++
					} else {
						rr.RequestedInvalidTrials++
					}
					rr.FailureReasons = append(rr.FailureReasons, rowErr.Error())
				}
				rr.Trials = append(rr.Trials, tr)
				if !isAnchor {
					requestedRows = append(requestedRows, m)
				}
			}
			if strings.HasPrefix(rec.ProfileID, "manager-session-") {
				if len(requestedRows) != requestedDenominator {
					return Report{}, fmt.Errorf("record %s installed profile requested rows=%d want %d", rec.ID, len(requestedRows), requestedDenominator)
				}
				if rr.RequestedInvalidTrials > 0 {
					rr.MeasurementStatus = "INVALID"
				} else {
					for i := range rr.Trials {
						if !rr.Trials[i].AnchorOnly {
							rr.InstalledSession = rr.Trials[i].InstalledSession
							break
						}
					}
					if rr.InstalledSession == nil {
						return Report{}, fmt.Errorf("record %s requested installed summary missing", rec.ID)
					}
					rr.MeasurementStatus = "DECODED_FUNCTIONAL"
					if rr.AnchorInvalidTrials > 0 {
						rr.MeasurementStatus = "DECODED_FUNCTIONAL_WITH_INVALID_ANCHOR"
					}
				}
			} else if isNATSProfile {
				if len(rr.Trials) != 1 || rr.Trials[0].NATSJetStream == nil {
					return Report{}, fmt.Errorf("record %s requested NATS summary missing", rec.ID)
				}
				rr.NATSJetStream = rr.Trials[0].NATSJetStream
				if rr.RequestedInvalidTrials > 0 {
					rr.MeasurementStatus = "INVALID"
				} else {
					rr.MeasurementStatus = "DECODED_FUNCTIONAL"
				}
			} else {
				if rr.InvalidTrials > 0 {
					rr.MeasurementStatus = "INVALID"
				} else {
					rr.MeasurementStatus = "UNSUPPORTED_MEASUREMENT_SCHEMA"
				}
			}
			report.Runs = append(report.Runs, rr)
		}
		key := strings.Join([]string{rec.ProfileID, cached.parsed.Revision, rec.SuiteSHA256, rec.SourceRevision, rec.HarnessSHA256, rec.ConfigSHA256, rec.WorkloadSchedule}, "\x00")
		g := groups[key]
		if g == nil {
			g = &GroupResult{ProfileID: rec.ProfileID, SuiteRevision: cached.parsed.Revision, SuiteSHA256: rec.SuiteSHA256, SourceRevision: rec.SourceRevision, HarnessSHA256: rec.HarnessSHA256, ConfigSHA256: rec.ConfigSHA256, WorkloadSchedule: rec.WorkloadSchedule, ComparisonStatus: "COMPARISON_NOT_ESTABLISHED"}
			groups[key] = g
		}
		g.RunIDs = append(g.RunIDs, rec.ID)
	}
	for _, g := range groups {
		sort.Strings(g.RunIDs)
		report.Groups = append(report.Groups, *g)
	}
	sort.Slice(report.Groups, func(i, j int) bool {
		return strings.Join(report.Groups[i].RunIDs, "\x00") < strings.Join(report.Groups[j].RunIDs, "\x00")
	})
	return report, nil
}

func validateRecord(r RunRecord) error {
	for n, v := range map[string]string{"profileID": r.ProfileID, "suiteFile": r.SuiteFile, "suiteSHA256": r.SuiteSHA256, "sourceRevision": r.SourceRevision, "harnessSHA256": r.HarnessSHA256, "configSHA256": r.ConfigSHA256, "metricsFile": r.MetricsFile, "metricsSHA256": r.MetricsSHA256, "workloadSchedule": r.WorkloadSchedule, "state": r.State, "externalReviewState": r.ExternalReviewState, "externalReviewReference": r.ExternalReviewReference} {
		if v == "" {
			return fmt.Errorf("%s is required", n)
		}
	}
	for n, v := range map[string]string{"suite": r.SuiteSHA256, "harness": r.HarnessSHA256, "config": r.ConfigSHA256, "metrics": r.MetricsSHA256} {
		if !isHash(v) {
			return fmt.Errorf("%s hash invalid", n)
		}
	}
	if !isHash(r.SourceRevision) {
		return errors.New("sourceRevision must be a full SHA-1 or SHA-256")
	}
	if r.State != "available" && r.State != "missing" && r.State != "failed" {
		return errors.New("state invalid")
	}
	if r.State != "available" && r.FailureReason == "" {
		return errors.New("non-available record needs failureReason")
	}
	if !map[string]bool{"unreviewed": true, "submitted": true, "accepted": true, "rejected": true, "supplied-pass": true, "supplied-fail": true}[r.ExternalReviewState] {
		return errors.New("externalReviewState invalid")
	}
	if filepath.IsAbs(r.ExternalReviewReference) {
		return errors.New("externalReviewReference must not be an absolute private path")
	}
	return nil
}

func localPath(base, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name {
		return "", fmt.Errorf("path %q must be clean and relative", name)
	}
	return filepath.Join(base, name), nil
}
func readHashed(path, want string) ([]byte, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if sum(b) != want {
		return nil, fmt.Errorf("hash mismatch for %s", filepath.Base(path))
	}
	return b, nil
}
func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func isHash(v string) bool {
	if len(v) != 40 && len(v) != 64 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}

func decodeMetrics(raw []byte) ([]core.Metric, error) {
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		return nil, errors.New("empty metrics")
	}
	rows := make([]core.Metric, 0, len(lines))
	for i, line := range lines {
		var m core.Metric
		if err := strictJSON(line, &m); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		rows = append(rows, m)
	}
	return rows, nil
}

type segmentReceipt struct {
	SchemaVersion string    `json:"schemaVersion"`
	Segments      []segment `json:"segments"`
}
type segment struct {
	Segment         int          `json:"segment"`
	Status          string       `json:"status"`
	Availability    availability `json:"availability"`
	PrefixValidated bool         `json:"availabilityPrefixValidated"`
	StdoutBytes     int          `json:"stdoutBytes"`
	StdoutSHA       string       `json:"stdoutSHA256"`
	StderrBytes     int          `json:"stderrBytes"`
	StderrSHA       string       `json:"stderrSHA256"`
	ExitCode        int          `json:"exitCode"`
}
type availability struct {
	Version        int           `json:"version"`
	ServiceURL     string        `json:"serviceURL"`
	SessionID      string        `json:"sessionID"`
	DurationMillis int           `json:"durationMillis"`
	CadenceMillis  int           `json:"cadenceMillis"`
	Started        string        `json:"startedAtUTC"`
	Ended          string        `json:"endedAtUTC"`
	Observations   []observation `json:"observations"`
}
type observation struct {
	At         string `json:"atUTC"`
	Known      bool   `json:"known"`
	Category   string `json:"category"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	PodUID     string `json:"podUID,omitempty"`
	ErrorClass string `json:"errorClass,omitempty"`
}

func decodeInstalled(m core.Metric) (InstalledSessionSummary, error) {
	if err := functionalRowError(m); err != nil {
		return InstalledSessionSummary{}, err
	}
	e := m.BenchmarkEvidence
	if e["schema"] != "phorvex.installed-session-benchmark-evidence.v1" || e["availability.segmentReceiptsSchema"] != "phorvex.installed-session-availability.v2" || e["availability.segmentReceiptsEncoding"] != "base64" {
		return InstalledSessionSummary{}, errors.New("installed evidence schema invalid")
	}
	chunks, err := atoi(e, "availability.segmentReceiptChunks")
	if err != nil || chunks < 1 {
		return InstalledSessionSummary{}, errors.New("chunk count invalid")
	}
	var enc strings.Builder
	for i := 0; i < chunks; i++ {
		k := fmt.Sprintf("availability.segmentReceiptChunk.%03d", i)
		if e[k] == "" {
			return InstalledSessionSummary{}, fmt.Errorf("missing %s", k)
		}
		enc.WriteString(e[k])
	}
	b, err := base64.StdEncoding.Strict().DecodeString(enc.String())
	if err != nil {
		return InstalledSessionSummary{}, err
	}
	n, err := atoi(e, "availability.segmentReceiptsBytes")
	if err != nil || n != len(b) || sum(b) != e["availability.segmentReceiptsSHA256"] {
		return InstalledSessionSummary{}, errors.New("receipt bytes/hash mismatch")
	}
	var receipt segmentReceipt
	if err := strictJSON(b, &receipt); err != nil {
		return InstalledSessionSummary{}, err
	}
	if receipt.SchemaVersion != "phorvex.installed-session-availability.v2" {
		return InstalledSessionSummary{}, errors.New("receipt schema mismatch")
	}
	segCount, err := atoi(e, "availability.segmentCount")
	if err != nil || segCount != len(receipt.Segments) {
		return InstalledSessionSummary{}, errors.New("segment count mismatch")
	}
	initialMinimum, err := atoi(e, "availabilityPolicy.initialMinimum")
	if err != nil {
		return InstalledSessionSummary{}, err
	}
	eligibleMinimum, err := atoi(e, "availabilityPolicy.eligibleMinimum")
	if err != nil {
		return InstalledSessionSummary{}, err
	}
	grace, err := atoi(e, "coordination.requestedGraceSeconds")
	if err != nil {
		return InstalledSessionSummary{}, err
	}
	out := InstalledSessionSummary{PodUIDCounts: map[string]int{}, NoSessionHTTP404ByPodUID: map[string]int{}, UnknownCategoryCounts: map[string]int{}, UnknownErrorClassCounts: map[string]int{}, SegmentCount: len(receipt.Segments), OriginalPodUID: e["original.podUID"], PeerPodUID: e["peer.podUID"], ReplacementPodUID: e["replacement.podUID"], CoordinationUsed: e["coordination.used"] == "true", CoordinationDisposition: e["coordination.disposition"], CoordinationAttributionComplete: e["coordination.attributionComplete"] == "true", CoordinationTargetUID: e["coordination.targetUID"], CoordinationTargetResourceVersion: e["coordination.targetResourceVersion"], CoordinationRequestedGraceSeconds: grace, PolicyName: e["availabilityPolicy.name"], PolicyUID: e["availabilityPolicy.uid"], PolicyInitialMinimum: initialMinimum, PolicyEligibleMinimum: eligibleMinimum, EffectStatus: e["effect.status"], EffectAttribution: e["effect.attribution"], DefensiveActions: m.DefensiveActions, FalseDefensiveActions: m.FalseDefensiveActions, ContinuousAvailability: false}
	if out.OriginalPodUID == "" || out.PeerPodUID == "" || out.OriginalPodUID == out.PeerPodUID || out.PolicyName == "" || out.PolicyUID == "" || out.EffectStatus == "" {
		return out, errors.New("installed policy, Pod identity, or effect disposition missing")
	}
	if out.CoordinationUsed && (out.CoordinationTargetUID == "" || out.CoordinationTargetResourceVersion == "" || out.CoordinationDisposition == "") {
		return out, errors.New("used coordination lacks target identity or disposition")
	}
	flat := []observation{}
	var first, last time.Time
	var priorObservation time.Time
	cadence := -1
	declaredMillis := 0
	serviceURL, sessionID := "", ""
	for i, s := range receipt.Segments {
		if s.Segment != i || s.Status != "complete" || !s.PrefixValidated || s.ExitCode != 0 || s.StdoutBytes <= 0 || !isHash(s.StdoutSHA) || s.StderrBytes != 0 || !isHash(s.StderrSHA) {
			return out, fmt.Errorf("segment %d incomplete or malformed", i)
		}
		a := s.Availability
		if a.Version != 1 || a.ServiceURL == "" || a.SessionID == "" || a.DurationMillis <= 0 || a.CadenceMillis <= 0 || len(a.Observations) == 0 {
			return out, fmt.Errorf("segment %d availability invalid", i)
		}
		if cadence < 0 {
			cadence = a.CadenceMillis
			serviceURL, sessionID = a.ServiceURL, a.SessionID
		} else if cadence != a.CadenceMillis {
			return out, errors.New("segment cadence differs")
		} else if a.ServiceURL != serviceURL || a.SessionID != sessionID {
			return out, errors.New("segment service URL or session ID differs")
		}
		declaredMillis += a.DurationMillis
		start, er1 := time.Parse(time.RFC3339Nano, a.Started)
		end, er2 := time.Parse(time.RFC3339Nano, a.Ended)
		if er1 != nil || er2 != nil || !end.After(start) || math.Abs(end.Sub(start).Seconds()-float64(a.DurationMillis)/1000) > .1 {
			return out, fmt.Errorf("segment %d interval invalid", i)
		}
		if i == 0 {
			first = start
		} else {
			if !start.After(last) {
				return out, errors.New("segments overlap or are unordered")
			}
			out.InterSegmentGapSeconds = append(out.InterSegmentGapSeconds, start.Sub(last).Seconds())
		}
		last = end
		out.SampledWindowSeconds += end.Sub(start).Seconds()
		for _, o := range a.Observations {
			at, er := time.Parse(time.RFC3339Nano, o.At)
			if er != nil || at.Before(start) || at.After(end) || !priorObservation.IsZero() && !at.After(priorObservation) {
				return out, errors.New("observation timestamp outside segment")
			}
			priorObservation = at
			if o.Known {
				if o.Category != "application-response" || (o.HTTPStatus != 200 && o.HTTPStatus != 404) || o.PodUID == "" || o.ErrorClass != "" {
					return out, errors.New("known observation invalid")
				}
				out.KnownApplicationResponse++
				if o.PodUID != out.OriginalPodUID && o.PodUID != out.PeerPodUID && (out.ReplacementPodUID == "" || o.PodUID != out.ReplacementPodUID) {
					return out, errors.New("observation references an unknown Pod identity")
				}
				out.PodUIDCounts[o.PodUID]++
				if o.HTTPStatus == 200 {
					out.SessionPresentHTTP200++
				} else {
					out.NoSessionHTTP404++
					out.NoSessionHTTP404ByPodUID[o.PodUID]++
				}
			} else {
				if o.Category == "" || o.HTTPStatus != 0 || o.PodUID != "" || o.ErrorClass == "" {
					return out, errors.New("unknown observation invalid")
				}
				out.Unknown++
				out.UnknownCategoryCounts[o.Category]++
				out.UnknownErrorClassCounts[o.ErrorClass]++
			}
			flat = append(flat, o)
		}
	}
	if len(receipt.Segments) > 0 {
		out.ElapsedSpanSeconds = last.Sub(first).Seconds()
	}
	out.SampleDenominator = len(flat)
	attempts, _ := atoi(e, "availability.attempts")
	known, _ := atoi(e, "availability.known")
	unknown, _ := atoi(e, "availability.unknown")
	count, _ := atoi(e, "availability.observationCount")
	windowMillis, _ := atoi(e, "availability.windowMillis")
	aggregateCadence, _ := atoi(e, "availability.cadenceMillis")
	aggregateStart, startErr := time.Parse(time.RFC3339Nano, e["availability.startedAtUTC"])
	aggregateEnd, endErr := time.Parse(time.RFC3339Nano, e["availability.endedAtUTC"])
	if attempts != len(flat) || count != len(flat) || known != out.KnownApplicationResponse || unknown != out.Unknown {
		return out, errors.New("flattened counts differ")
	}
	if windowMillis != declaredMillis || aggregateCadence != cadence || startErr != nil || endErr != nil || !aggregateStart.Equal(first) || !aggregateEnd.Equal(last) {
		return out, errors.New("aggregate interval differs from segment receipts")
	}
	for i, o := range flat {
		key := fmt.Sprintf("availability.observation.%03d", i)
		raw, ok := e[key]
		if !ok {
			return out, fmt.Errorf("missing %s", key)
		}
		var got observation
		if err := strictJSON([]byte(raw), &got); err != nil {
			return out, err
		}
		if got != o {
			return out, fmt.Errorf("flattened observation %d differs", i)
		}
	}
	if _, extra := e[fmt.Sprintf("availability.observation.%03d", len(flat))]; extra {
		return out, errors.New("extra flattened observation")
	}
	return out, nil
}
func functionalRowError(m core.Metric) error {
	v := m.MeasurementState()
	const benignReason = "benign functional-effect control is excluded from attack, security and economics scoring"
	if !m.ScenarioBenignControl || m.ScenarioRealism != core.RealismExecutable {
		return errors.New("row is not an explicit executable benign functional control")
	}
	if v.Status != core.MeasurementValid || v.Phase != core.PhaseComplete || !v.AttackExecuted || !v.OracleObserved || !v.CostObserved || v.Scored || v.UnscoredReason != benignReason || m.IsScored() || !m.Skipped || m.SkipReason != "UNSCORED(benign-control): "+benignReason || !v.Cleanup.Complete || !v.Cleanup.Verified {
		return errors.New("row is not valid, complete, benign-unscored, and cleanup-verified")
	}
	if m.DisruptionVsOracle != 0 || m.SecurityPerCost != 0 || m.ROI != nil || m.Schwartau != nil || m.MTDEffect != "" || m.Reuse != nil {
		return errors.New("benign row contains security/economics derivation")
	}
	if m.NegativeControl || m.FalseDefensiveActions != -1 {
		return errors.New("ordinary row false-action sentinel invalid")
	}
	return nil
}
func atoi(e map[string]string, k string) (int, error) {
	n, err := strconv.Atoi(e[k])
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s invalid", k)
	}
	return n, nil
}

func strictJSON(raw []byte, dst any) error {
	if err := rejectDuplicateKeys(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}
func rejectDuplicateKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	type frame struct {
		object    bool
		keys      map[string]bool
		expectKey bool
	}
	stack := []frame{}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, frame{object: true, keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, frame{})
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("unbalanced JSON")
				}
				stack = stack[:len(stack)]
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				f := &stack[len(stack)-1]
				if f.keys[v] {
					return fmt.Errorf("duplicate JSON key %q", v)
				}
				f.keys[v] = true
				f.expectKey = false
				continue
			}
		}
		if len(stack) > 0 && stack[len(stack)-1].object && !stack[len(stack)-1].expectKey {
			stack[len(stack)-1].expectKey = true
		}
	}
	return nil
}

func MarshalReport(r Report) ([]byte, error) { return json.MarshalIndent(r, "", "  ") }
func Markdown(r Report) string {
	var b strings.Builder
	b.WriteString("# Functional benchmark collection\n\n")
	b.WriteString("Comparison status: **COMPARISON_NOT_ESTABLISHED**. External review states are supplied inputs.\n\n| Run | Profile | State | Measurement | Trials | Samples | 200 session | 404 no session | Unknown |\n|---|---|---|---|---:|---:|---:|---:|---:|\n")
	for _, x := range r.Runs {
		s, k, p, n, u := 0, 0, 0, 0, 0
		if x.InstalledSession != nil {
			s = x.InstalledSession.SampleDenominator
			k = x.InstalledSession.KnownApplicationResponse
			p = x.InstalledSession.SessionPresentHTTP200
			n = x.InstalledSession.NoSessionHTTP404
			u = x.InstalledSession.Unknown
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %d (%d known) | %d | %d | %d |\n", x.ID, x.ProfileID, x.State, x.MeasurementStatus, x.TrialDenominator, s, k, p, n, u)
	}
	b.WriteString("\n## NATS JetStream protocol receipts\n\n| Run | Qualification | Mode | Protocol | Final messages | Sequences | Initial X publication | Actions | Restart ns | Recovery ns | Quorum overlap ns | Cleanup |\n|---|---|---|---|---:|---|---|---:|---:|---:|---:|---|\n")
	for _, x := range r.Runs {
		if x.NATSJetStream == nil {
			continue
		}
		n := x.NATSJetStream
		sequences := fmt.Sprintf("A=%d", n.MessageASequence)
		if n.MessageBSequence != 0 {
			sequences += fmt.Sprintf(" B=%d", n.MessageBSequence)
		}
		if n.MessageXSequence != 0 {
			sequences += fmt.Sprintf(" X=%d", n.MessageXSequence)
		}
		if n.MessageYSequence != 0 {
			sequences += fmt.Sprintf(" Y=%d", n.MessageYSequence)
		}
		initial := n.DuringPausePublicationStatus
		if initial == "" {
			initial = "not-applicable"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %s | %s | %d | %d | %d | %d | complete=%t verified=%t |\n", x.ID, x.MeasurementStatus, n.Mode, n.ProtocolStatus, n.FinalMessages, sequences, initial, n.ActionCount, n.RestartBoundaryNanos, n.ReplicaRecoveryNanos, n.QuorumPauseObservedNanos, n.CleanupComplete, n.CleanupVerified)
	}
	b.WriteString("\nA reconstructed protocol receipt does not qualify a row whose benign scoring or cleanup disposition is invalid. A timeout-unknown initial NATS publication is neither loss nor acknowledged success. Known 404 responses are not session successes. Inter-segment time is unobserved; the report makes no continuous-availability, security, ROI, attacker-mitigation, installed-action, or campaign-PASS claim. Source, harness, and configuration hashes are supplied pins, not independently established binary lineage.\n")
	return b.String()
}
