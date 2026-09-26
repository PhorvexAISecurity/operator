package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/phorvex/phorvex/internal/audittransport"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	podBoundRequestFile              = "pod-bound-token-request.json"
	podBoundBarrierFile              = "pod-bound-token-barrier.json"
	podBoundArtifactFile             = "pod-bound-token-artifact.json"
	podBoundTerminalFile             = "pod-bound-token-terminal.json"
	podBoundSealFile                 = "pod-bound-token-audit-seal.json"
	podBoundObservationEndFile       = "pod-bound-token-observation-end.json"
	podBoundObservationCommittedFile = "pod-bound-token-observation-committed.json"
	podBoundEventCleanupFile         = "pod-bound-token-event-cleanup.json"
	podBoundReplayFile               = "pod-bound-token-replays.jsonl"
	podBoundCoordinatorFailureFile   = "pod-bound-token-coordinator-failure.json"
)

type podBoundReplayRow struct {
	Schema    string `json:"schema"`
	RunID     string `json:"runID"`
	Nonce     string `json:"nonce"`
	Phase     string `json:"phase"`
	HTTP      int    `json:"http"`
	RequestAt string `json:"requestAt,omitempty"`
	At        string `json:"at"`
	CaptureID string `json:"captureID"`
}

func verifyPodBoundReplayJournal(out string, req podBoundTokenRequest, result PodBoundTokenResult, observationEnd string) error {
	raw, err := readNATSResponseSizedFile(out, podBoundReplayFile, 64<<10)
	if err != nil {
		return err
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return errors.New("Pod-bound token replay journal incomplete")
	}
	seen := map[string]int{}
	var sourceAfter podBoundReplayRow
	var lastAt time.Time
	requested, err := time.Parse(time.RFC3339Nano, req.RequestedAt)
	if err != nil {
		return errors.New("Pod-bound token request time unavailable")
	}
	end, endErr := time.Parse(time.RFC3339Nano, observationEnd)
	expiry, expiryErr := time.Parse(time.RFC3339Nano, req.SourceExpiry)
	if endErr != nil || expiryErr != nil {
		return errors.New("Pod-bound token replay window unavailable")
	}
	cpu := req.CaseID == podBoundTokenCPUCaseID
	var peerExpiry time.Time
	if cpu {
		peerExpiry, err = time.Parse(time.RFC3339Nano, req.PeerExpiry)
		if err != nil {
			return errors.New("CPU token peer expiry unavailable")
		}
	}
	for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
		if len(line) == 0 || len(line) > 2048 {
			return errors.New("Pod-bound token replay row invalid")
		}
		if err := rejectNATSNestedDuplicates(line); err != nil {
			return err
		}
		var row podBoundReplayRow
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		if d.Decode(&row) != nil || row.Schema != "pod-bound-token-replay-v1" ||
			row.RunID != req.RunID || row.Nonce != req.Nonce || row.CaptureID == "" {
			return errors.New("Pod-bound token replay identity differs")
		}
		at, e := time.Parse(time.RFC3339Nano, row.At)
		if e != nil || at.IsZero() || at.After(end) || (!lastAt.IsZero() && !at.After(lastAt)) {
			return errors.New("Pod-bound token replay time invalid")
		}
		if cpu {
			bound := expiry
			if strings.HasPrefix(row.Phase, "peer-") {
				bound = peerExpiry
			}
			started, parseErr := time.Parse(time.RFC3339Nano, row.RequestAt)
			if parseErr != nil || (!lastAt.IsZero() && started.Before(lastAt)) || !podBoundCPUReplayTimes(row.RequestAt, row.At, bound) {
				return errors.New("CPU token original replay crossed expiry margin")
			}
		}
		lastAt = at
		seen[row.Phase]++
		switch row.Phase {
		case "source-before":
			if seen[row.Phase] != 1 || row.HTTP != req.SourceBeforeHTTP || row.CaptureID != req.SourceCaptureID || at.After(requested) {
				return errors.New("Pod-bound token source baseline differs")
			}
			if cpu && (row.RequestAt != req.SourceBeforeRequestAt || row.At != req.SourceBeforeAt || row.At != result.Replay.SourceBeforeAt || row.RequestAt != result.Replay.SourceBeforeRequestAt) {
				return errors.New("CPU token source baseline time differs")
			}
		case "peer-before":
			if seen[row.Phase] != 1 || seen["source-before"] != 1 || row.HTTP != req.PeerBeforeHTTP || row.CaptureID != req.PeerCaptureID || at.After(requested) {
				return errors.New("Pod-bound token peer baseline differs")
			}
			if cpu && (row.RequestAt != req.PeerBeforeRequestAt || row.At != req.PeerBeforeAt || row.At != result.Replay.PeerBeforeAt || row.RequestAt != result.Replay.PeerBeforeRequestAt) {
				return errors.New("CPU token peer baseline time differs")
			}
		case "source-after":
			if seen["peer-before"] != 1 || seen["peer-after"] != 0 || at.Before(requested) || !at.Before(expiry) || row.CaptureID != req.SourceCaptureID {
				return errors.New("Pod-bound token source handle recaptured")
			}
			sourceAfter = row
		case "peer-after":
			if seen[row.Phase] != 1 || seen["source-after"] == 0 || row.HTTP != result.Replay.PeerAfterHTTP || row.CaptureID != req.PeerCaptureID {
				return errors.New("Pod-bound token peer replay differs")
			}
			if cpu && (row.RequestAt != result.Replay.PeerAfterRequestAt || row.At != result.Replay.PeerAfterAt) {
				return errors.New("CPU token peer outcome time differs")
			}
		default:
			return errors.New("Pod-bound token unknown replay phase")
		}
	}
	if seen["source-before"] != 1 || seen["peer-before"] != 1 || seen["source-after"] == 0 || seen["peer-after"] != 1 ||
		sourceAfter.HTTP != result.Replay.SourceAfterHTTP || sourceAfter.At != result.Replay.SourceAfterAt {
		return errors.New("Pod-bound token original replay status differs")
	}
	if cpu && (sourceAfter.RequestAt != result.Replay.SourceAfterRequestAt || !podBoundCPUResultTimesValid(result)) {
		return errors.New("CPU token original outcome window differs")
	}
	return nil
}

type podBoundTokenRequest struct {
	Schema                string  `json:"schema"`
	CaseID                string  `json:"caseID,omitempty"`
	RunID                 string  `json:"runID"`
	Nonce                 string  `json:"nonce"`
	ClusterUID            string  `json:"clusterUID"`
	Namespace             string  `json:"namespace"`
	NamespaceUID          string  `json:"namespaceUID"`
	SourcePodName         string  `json:"sourcePodName"`
	SourcePodUID          string  `json:"sourcePodUID"`
	PeerPodName           string  `json:"peerPodName"`
	PeerPodUID            string  `json:"peerPodUID"`
	ServiceName           string  `json:"serviceName"`
	ServiceUID            string  `json:"serviceUID"`
	PDBUID                string  `json:"pdbUID,omitempty"`
	DeploymentUID         string  `json:"deploymentUID"`
	ReplicaSetUID         string  `json:"replicaSetUID"`
	PolicyName            string  `json:"policyName"`
	PolicyUID             string  `json:"policyUID"`
	PolicyGeneration      int64   `json:"policyGeneration"`
	PolicySpecSHA256      string  `json:"policySpecSHA256"`
	ManagerPodUID         string  `json:"managerPodUID"`
	ManagerContainerID    string  `json:"managerContainerID"`
	ManagerImageID        string  `json:"managerImageID"`
	ProfileSHA256         string  `json:"profileSHA256"`
	SourceBeforeHTTP      int     `json:"sourceBeforeHTTP"`
	PeerBeforeHTTP        int     `json:"peerBeforeHTTP"`
	ServiceBeforeHTTP     int     `json:"serviceBeforeHTTP"`
	SourceExpiry          string  `json:"sourceExpiry"`
	PeerExpiry            string  `json:"peerExpiry,omitempty"`
	SourceBeforeRequestAt string  `json:"sourceBeforeRequestAt,omitempty"`
	SourceBeforeAt        string  `json:"sourceBeforeAt,omitempty"`
	PeerBeforeRequestAt   string  `json:"peerBeforeRequestAt,omitempty"`
	PeerBeforeAt          string  `json:"peerBeforeAt,omitempty"`
	RequestedAt           string  `json:"requestedAt"`
	SourceCaptureID       string  `json:"sourceCaptureID"`
	PeerCaptureID         string  `json:"peerCaptureID"`
	MetricStatus          string  `json:"metricStatus"`
	MetricFirstAt         string  `json:"metricFirstAt"`
	MetricSecondAt        string  `json:"metricSecondAt"`
	MetricFirstValue      float64 `json:"metricFirstValue"`
	MetricSecondValue     float64 `json:"metricSecondValue"`
	MetricSourcePodName   string  `json:"metricSourcePodName"`
	PodMonitorUID         string  `json:"podMonitorUID"`
	MetricQuerySHA256     string  `json:"metricQuerySHA256"`
}

type podBoundTokenBarrier struct {
	Schema         string                 `json:"schema"`
	RunID          string                 `json:"runID"`
	Nonce          string                 `json:"nonce"`
	RequestSHA256  string                 `json:"requestSHA256"`
	Event          PodBoundTokenEvent     `json:"event"`
	Decision       PodBoundTokenDecision  `json:"decision"`
	Operation      PodBoundTokenOperation `json:"operation"`
	DecisionRowSHA string                 `json:"decisionRowSHA256"`
	ObservedAt     string                 `json:"observedAt"`
}

type podBoundTokenArtifact struct {
	Result             PodBoundTokenResult `json:"result"`
	RequestSHA256      string              `json:"requestSHA256"`
	BarrierSHA256      string              `json:"barrierSHA256"`
	PhaseJournalSHA256 string              `json:"phaseJournalSHA256"`
	ObservationEndedAt string              `json:"observationEndedAt"`
}

type podBoundTokenTerminal struct {
	Schema                     string `json:"schema"`
	RunID                      string `json:"runID"`
	Nonce                      string `json:"nonce"`
	ArtifactSHA256             string `json:"artifactSHA256"`
	CleanupStatus              string `json:"cleanupStatus"`
	ProtectedReservationAbsent bool   `json:"protectedReservationAbsent"`
	FinishedAt                 string `json:"finishedAt"`
}

type podBoundTokenAuditSeal struct {
	Schema                  string                         `json:"schema"`
	RunID                   string                         `json:"runID"`
	Nonce                   string                         `json:"nonce"`
	SourceIdentity          string                         `json:"sourceIdentity"`
	RequestSHA256           string                         `json:"requestSHA256"`
	BarrierSHA256           string                         `json:"barrierSHA256"`
	ArtifactSHA256          string                         `json:"artifactSHA256"`
	ObservationCommitSHA256 string                         `json:"observationCommitSHA256"`
	Exact                   audittransport.ExactWindowSeal `json:"exact"`
	SealedAt                string                         `json:"sealedAt"`
}

type podBoundTokenAuditStart struct {
	Schema         string                 `json:"schema"`
	RunID          string                 `json:"runID"`
	Nonce          string                 `json:"nonce"`
	SourceIdentity string                 `json:"sourceIdentity"`
	Segment        audittransport.Segment `json:"segment"`
	Offset         int64                  `json:"offset"`
	RequestSHA256  string                 `json:"requestSHA256"`
}

type podBoundTokenObservationEnd struct {
	Schema             string `json:"schema"`
	RunID              string `json:"runID"`
	Nonce              string `json:"nonce"`
	RequestSHA256      string `json:"requestSHA256"`
	BarrierSHA256      string `json:"barrierSHA256"`
	ObservationEndedAt string `json:"observationEndedAt"`
}

type podBoundTokenObservationCommitted struct {
	Schema               string                               `json:"schema"`
	RunID                string                               `json:"runID"`
	Nonce                string                               `json:"nonce"`
	ObservationEndSHA256 string                               `json:"observationEndSHA256"`
	RequestSHA256        string                               `json:"requestSHA256"`
	BarrierSHA256        string                               `json:"barrierSHA256"`
	SourceIdentity       string                               `json:"sourceIdentity"`
	Commitment           audittransport.ExactWindowCommitment `json:"commitment"`
}

type podBoundTokenEventCleanup struct {
	Schema     string `json:"schema"`
	RunID      string `json:"runID"`
	Nonce      string `json:"nonce"`
	EventUID   string `json:"eventUID"`
	Status     string `json:"status"`
	ObservedAt string `json:"observedAt"`
}

func podBoundHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func podBoundDecisionRowTime(raw []byte) (time.Time, error) {
	var row struct {
		Time time.Time `json:"time"`
	}
	if err := json.Unmarshal(raw, &row); err != nil || row.Time.IsZero() {
		return time.Time{}, errors.New("Pod-bound token audit decision time unavailable")
	}
	return row.Time, nil
}

func readPodBoundJSON(out, name string, dst any) ([]byte, error) {
	limit := int64(256 << 10)
	if name == podBoundSealFile {
		limit = 8 << 20
	}
	raw, err := readNATSResponseSizedFile(out, name, limit)
	if err != nil {
		return nil, err
	}
	if err := rejectNATSNestedDuplicates(raw); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing or malformed Pod-bound result data")
	}
	return raw, nil
}

func readPodBoundTokenResult(out, id string) (PodBoundTokenResult, error) {
	if _, err := os.Lstat(filepath.Join(out, "pod-bound-token-unsafe.json")); err == nil {
		return PodBoundTokenResult{}, errors.New("Pod-bound token early unsafe receipt cannot be promoted to a terminal result")
	} else if !errors.Is(err, os.ErrNotExist) {
		return PodBoundTokenResult{}, err
	}
	var a podBoundTokenArtifact
	artifactRaw, err := readPodBoundJSON(out, podBoundArtifactFile, &a)
	if err != nil {
		return PodBoundTokenResult{}, err
	}
	var t podBoundTokenTerminal
	if _, err = readPodBoundJSON(out, podBoundTerminalFile, &t); err != nil {
		return PodBoundTokenResult{}, err
	}
	if t.Schema != "pod-bound-token-terminal-v1" || t.RunID != id ||
		t.Nonce != a.Result.Nonce || t.ArtifactSHA256 != podBoundHash(artifactRaw) ||
		t.CleanupStatus != a.Result.Cleanup.Status ||
		(t.CleanupStatus == "CONFIRMED_ABSENT" && !t.ProtectedReservationAbsent) {
		return PodBoundTokenResult{}, errors.New("Pod-bound token terminal or protected reservation differs")
	}
	if err := validatePodBoundTokenResult(a.Result); err != nil {
		return PodBoundTokenResult{}, err
	}
	if a.Result.RunID != id || !mongoSHA.MatchString(a.RequestSHA256) || !mongoSHA.MatchString(a.BarrierSHA256) {
		return PodBoundTokenResult{}, errors.New("Pod-bound token artifact join absent")
	}
	var observationEnd podBoundTokenObservationEnd
	endRaw, err := readPodBoundJSON(out, podBoundObservationEndFile, &observationEnd)
	if err != nil || observationEnd.Schema != "pod-bound-token-observation-end-v1" ||
		observationEnd.RunID != id || observationEnd.Nonce != a.Result.Nonce ||
		observationEnd.RequestSHA256 != a.RequestSHA256 ||
		observationEnd.BarrierSHA256 != a.BarrierSHA256 ||
		observationEnd.ObservationEndedAt != a.ObservationEndedAt {
		return PodBoundTokenResult{}, errors.New("Pod-bound token declared observation end differs")
	}
	var committed podBoundTokenObservationCommitted
	commitRaw, err := readPodBoundJSON(out, podBoundObservationCommittedFile, &committed)
	if err != nil || committed.Schema != "pod-bound-token-observation-committed-v1" ||
		committed.RunID != id || committed.Nonce != a.Result.Nonce ||
		committed.ObservationEndSHA256 != podBoundHash(endRaw) ||
		committed.RequestSHA256 != a.RequestSHA256 ||
		committed.BarrierSHA256 != a.BarrierSHA256 ||
		committed.SourceIdentity == "" ||
		!mongoSHA.MatchString(committed.Commitment.WindowSHA256) {
		return PodBoundTokenResult{}, errors.New("Pod-bound token authenticated observation commitment differs")
	}
	var req podBoundTokenRequest
	rawReq, err := readPodBoundJSON(out, podBoundRequestFile, &req)
	if err != nil || podBoundHash(rawReq) != a.RequestSHA256 || req.RunID != id ||
		req.Schema != "pod-bound-token-request-v1" || podBoundProfileForNamespace(req.Namespace) == "" ||
		(req.Namespace == podBoundTokenCPUNamespace && req.CaseID != podBoundTokenCPUCaseID) ||
		(req.Namespace == podBoundTokenNamespace && req.CaseID != "" && req.CaseID != podBoundTokenVoiceCaseID) ||
		req.CaseID != a.Result.CaseID ||
		req.PolicyName != "pod-token-"+req.Nonce || req.ServiceName != req.PolicyName ||
		req.SourcePodName == "" || req.PeerPodName == "" || req.SourcePodName == req.PeerPodName ||
		req.Nonce != a.Result.Nonce || req.SourcePodUID != a.Result.Admission.SourcePodUID ||
		req.PeerPodUID != a.Result.Admission.PeerPodUID ||
		req.ServiceUID != a.Result.Admission.ServiceUID ||
		(req.Namespace == podBoundTokenCPUNamespace && req.PDBUID != a.Result.Admission.PDBUID) ||
		req.DeploymentUID != a.Result.Admission.DeploymentUID ||
		req.ReplicaSetUID != a.Result.Admission.ReplicaSetUID ||
		req.PolicyUID != a.Result.Admission.PolicyUID ||
		req.PolicyGeneration != a.Result.Admission.PolicyGeneration ||
		req.PolicySpecSHA256 != a.Result.Admission.PolicySpecSHA256 ||
		req.ManagerPodUID != a.Result.Admission.ManagerPodUID ||
		req.ManagerContainerID != a.Result.Admission.ManagerContainerID ||
		req.ManagerImageID != a.Result.Admission.ManagerImageID ||
		req.ProfileSHA256 != a.Result.Admission.ProfileSHA256 ||
		req.ClusterUID != a.Result.Admission.ClusterUID ||
		req.Namespace != a.Result.Admission.Namespace ||
		req.NamespaceUID != a.Result.Admission.NamespaceUID ||
		req.SourceBeforeHTTP != a.Result.Replay.SourceBeforeHTTP ||
		req.PeerBeforeHTTP != a.Result.Replay.PeerBeforeHTTP ||
		req.ServiceBeforeHTTP != a.Result.Replay.ServiceBeforeHTTP ||
		req.SourceExpiry != a.Result.Replay.SourceExpiry ||
		(req.Namespace == podBoundTokenCPUNamespace && (req.PeerExpiry != a.Result.Replay.PeerExpiry ||
			req.SourceBeforeRequestAt != a.Result.Replay.SourceBeforeRequestAt ||
			req.SourceBeforeAt != a.Result.Replay.SourceBeforeAt ||
			req.PeerBeforeRequestAt != a.Result.Replay.PeerBeforeRequestAt ||
			req.PeerBeforeAt != a.Result.Replay.PeerBeforeAt)) ||
		!mongoNonce.MatchString(req.SourceCaptureID) ||
		!mongoNonce.MatchString(req.PeerCaptureID) ||
		req.SourceCaptureID == req.PeerCaptureID ||
		req.SourceCaptureID != a.Result.Replay.SourceBeforeCaptureID ||
		req.SourceCaptureID != a.Result.Replay.SourceAfterCaptureID ||
		req.PeerCaptureID != a.Result.Replay.PeerBeforeCaptureID ||
		req.PeerCaptureID != a.Result.Replay.PeerAfterCaptureID ||
		req.MetricSourcePodName != req.SourcePodName ||
		req.MetricStatus != a.Result.Telemetry.ProducerStatus ||
		req.MetricFirstAt != a.Result.Telemetry.FirstAt ||
		req.MetricSecondAt != a.Result.Telemetry.SecondAt ||
		req.MetricFirstValue != a.Result.Telemetry.FirstValue ||
		req.MetricSecondValue != a.Result.Telemetry.SecondValue ||
		req.MetricSourcePodName != a.Result.Telemetry.SourcePodName ||
		req.PodMonitorUID != a.Result.Telemetry.PodMonitorUID ||
		req.MetricQuerySHA256 != a.Result.Telemetry.QuerySHA256 {
		return PodBoundTokenResult{}, errors.New("Pod-bound token original request differs")
	}
	if req.Namespace == podBoundTokenCPUNamespace {
		requestedAt, parseErr := time.Parse(time.RFC3339Nano, req.RequestedAt)
		if req.PDBUID == "" || req.MetricStatus != "MEASURED_FRESH" || parseErr != nil || !podBoundCPURequestTimeValid(req, requestedAt) {
			return PodBoundTokenResult{}, errors.New("CPU token original request authority or timing differs")
		}
	}
	if req.MetricStatus == "MEASURED_FRESH" {
		first, e1 := time.Parse(time.RFC3339Nano, req.MetricFirstAt)
		second, e2 := time.Parse(time.RFC3339Nano, req.MetricSecondAt)
		requested, e3 := time.Parse(time.RFC3339Nano, req.RequestedAt)
		if e1 != nil || e2 != nil || e3 != nil ||
			second.Sub(first) < 15*time.Second || second.After(requested) ||
			requested.Sub(second) > 90*time.Second ||
			req.MetricFirstValue < 0 || req.MetricSecondValue <= req.MetricFirstValue ||
			req.PodMonitorUID == "" || !mongoSHA.MatchString(req.MetricQuerySHA256) {
			return PodBoundTokenResult{}, errors.New("Pod-bound token producer metric samples are not fresh")
		}
	}
	var start podBoundTokenAuditStart
	if _, err := readPodBoundJSON(out, "pod-bound-token-audit-start.json", &start); err != nil ||
		start.Schema != "pod-bound-token-audit-start-v1" || start.RunID != id ||
		start.Nonce != req.Nonce || start.RequestSHA256 != a.RequestSHA256 ||
		start.SourceIdentity != committed.SourceIdentity ||
		start.Segment.ID != committed.Commitment.Segment.ID ||
		start.Segment.Generation != committed.Commitment.Segment.Generation ||
		start.Segment.Anchor != committed.Commitment.Segment.Anchor ||
		start.Offset != committed.Commitment.StartOffset {
		return PodBoundTokenResult{}, errors.New("Pod-bound token authenticated audit start differs")
	}
	if err := verifyPodBoundReplayJournal(out, req, a.Result, a.ObservationEndedAt); err != nil &&
		a.Result.TerminalStatus == "COMPLETE" {
		return PodBoundTokenResult{}, err
	}
	var barrier podBoundTokenBarrier
	rawBarrier, err := readPodBoundJSON(out, podBoundBarrierFile, &barrier)
	if err != nil || podBoundHash(rawBarrier) != a.BarrierSHA256 ||
		barrier.Schema != "pod-bound-token-barrier-v1" || barrier.RunID != id || barrier.Nonce != req.Nonce ||
		barrier.RequestSHA256 != a.RequestSHA256 ||
		barrier.Event != a.Result.Event || barrier.Decision != a.Result.Decision ||
		barrier.Operation.TerminationStatus != a.Result.Operation.TerminationStatus ||
		barrier.Operation.ReceiptSHA256 != a.Result.Operation.ReceiptSHA256 ||
		(barrier.Operation.OriginalPodAbsent && !a.Result.Operation.OriginalPodAbsent) {
		return PodBoundTokenResult{}, errors.New("Pod-bound token decision barrier differs")
	}
	if a.Result.TerminalStatus == "COMPLETE" {
		if !mongoSHA.MatchString(a.PhaseJournalSHA256) {
			return PodBoundTokenResult{}, errors.New("Pod-bound token phase journal digest absent")
		}
		if err := verifyPodBoundPhaseJournal(out, req, barrier, a); err != nil {
			return PodBoundTokenResult{}, err
		}
	}
	var seal podBoundTokenAuditSeal
	if _, err := readPodBoundJSON(out, podBoundSealFile, &seal); err != nil {
		return PodBoundTokenResult{}, err
	}
	if seal.Schema != "pod-bound-token-audit-seal-v1" || seal.RunID != id ||
		seal.Nonce != req.Nonce || seal.RequestSHA256 != a.RequestSHA256 ||
		seal.BarrierSHA256 != a.BarrierSHA256 || seal.ArtifactSHA256 != podBoundHash(artifactRaw) ||
		seal.SourceIdentity != committed.SourceIdentity ||
		seal.ObservationCommitSHA256 != podBoundHash(commitRaw) ||
		seal.Exact.Segment != committed.Commitment.Segment ||
		seal.Exact.StartOffset != committed.Commitment.StartOffset ||
		seal.Exact.EndOffset != committed.Commitment.EndOffset ||
		seal.Exact.ScanSHA256 != committed.Commitment.WindowSHA256 ||
		seal.Exact.Namespace != req.Namespace ||
		seal.Exact.PodName != req.SourcePodName || seal.Exact.PodUID != req.SourcePodUID ||
		seal.Exact.PolicyUID != req.PolicyUID || seal.Exact.CoveredThrough != seal.Exact.EndOffset {
		return PodBoundTokenResult{}, errors.New("Pod-bound token immutable audit seal differs")
	}
	found := false
	attributed := 0
	declaredEnd, endErr := time.Parse(time.RFC3339Nano, a.ObservationEndedAt)
	if endErr != nil {
		return PodBoundTokenResult{}, endErr
	}
	previousEnd := seal.Exact.StartOffset
	for _, row := range seal.Exact.Rows {
		if row.Offset < previousEnd || row.EndOffset > seal.Exact.EndOffset ||
			row.EndOffset != row.Offset+int64(len(row.Raw))+1 ||
			podBoundHash(row.Raw) != row.SHA256 {
			return PodBoundTokenResult{}, errors.New("Pod-bound token retained audit row changed")
		}
		previousEnd = row.EndOffset
		decision, operation, projectErr := podBoundTypedDecision(row.Raw, req, barrier.Event.UID)
		if projectErr != nil && strings.Contains(projectErr.Error(), "typed event attribution absent") {
			if podBoundCompetingUnattributedOperation(row.Raw) {
				return PodBoundTokenResult{}, errors.New("Pod-bound token unattributed source operation confounds replay")
			}
			continue
		}
		if projectErr != nil {
			return PodBoundTokenResult{}, errors.New("Pod-bound token retained target decision malformed")
		}
		rowAt, timeErr := podBoundDecisionRowTime(row.Raw)
		if timeErr != nil || rowAt.After(declaredEnd) {
			return PodBoundTokenResult{}, errors.New("Pod-bound token attributed decision escaped observation window")
		}
		attributed++
		if decision.SelectedAction != barrier.Decision.SelectedAction ||
			decision.DispatchOutcome != barrier.Decision.DispatchOutcome ||
			(decision.DispatchOutcome == "emitted" && decision.ID != barrier.Decision.ID) {
			return PodBoundTokenResult{}, errors.New("Pod-bound token competing attributed decision in sealed window")
		}
		if row.SHA256 != barrier.DecisionRowSHA {
			continue
		}
		if projectErr != nil || decision != barrier.Decision || operation != barrier.Operation || found {
			return PodBoundTokenResult{}, errors.New("Pod-bound token retained decision projection differs")
		}
		found = true
	}
	if !found || attributed == 0 || !mongoSHA.MatchString(seal.Exact.ScanSHA256) {
		return PodBoundTokenResult{}, errors.New("Pod-bound token decision not retained in authenticated seal")
	}
	var eventCleanup podBoundTokenEventCleanup
	if _, err := readPodBoundJSON(out, podBoundEventCleanupFile, &eventCleanup); err != nil && a.Result.TerminalStatus == "COMPLETE" {
		return PodBoundTokenResult{}, err
	}
	if a.Result.TerminalStatus == "COMPLETE" && (eventCleanup.Schema != "pod-bound-token-event-cleanup-v1" ||
		eventCleanup.RunID != id || eventCleanup.Nonce != req.Nonce ||
		eventCleanup.EventUID != barrier.Event.UID || eventCleanup.Status != "CONFIRMED_ABSENT") {
		return PodBoundTokenResult{}, errors.New("Pod-bound token exact event cleanup differs")
	}
	end, e1 := time.Parse(time.RFC3339Nano, a.ObservationEndedAt)
	sealed, e2 := time.Parse(time.RFC3339Nano, seal.SealedAt)
	finished, e3 := time.Parse(time.RFC3339Nano, t.FinishedAt)
	requested, e4 := time.Parse(time.RFC3339Nano, req.RequestedAt)
	barrierAt, e5 := time.Parse(time.RFC3339Nano, barrier.ObservedAt)
	captured := time.Unix(0, committed.Commitment.CapturedAtUnixNano).UTC()
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || captured.IsZero() ||
		barrierAt.Before(requested) || barrierAt.After(end) ||
		end.After(captured) || captured.After(finished) || finished.After(sealed) {
		return PodBoundTokenResult{}, errors.New("Pod-bound token observation end or seal chronology differs")
	}
	if a.Result.TerminalStatus == "COMPLETE" {
		outcomeAt, e6 := time.Parse(time.RFC3339Nano, a.Result.Stages[7].ObservedAt)
		cleanupAt, e7 := time.Parse(time.RFC3339Nano, eventCleanup.ObservedAt)
		stageCleanupAt, e8 := time.Parse(time.RFC3339Nano, a.Result.Stages[8].ObservedAt)
		if e6 != nil || e7 != nil || e8 != nil || outcomeAt.After(end) ||
			cleanupAt.Before(captured) || cleanupAt.After(stageCleanupAt) || stageCleanupAt.After(finished) {
			return PodBoundTokenResult{}, errors.New("Pod-bound token observation or cleanup phase escaped the committed window")
		}
	}
	return a.Result, nil
}

func (rm *RunManager) PodBoundTokenResult(id string) (*PodBoundTokenResult, error) {
	rm.mu.Lock()
	st := rm.runs[id]
	out := rm.runOut[id]
	rm.mu.Unlock()
	if st == nil || !podBoundNamedCase(st.Config) || out == "" {
		return nil, nil
	}
	r, err := readPodBoundTokenResult(rm.cfg.runOutputPath(out), id)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func writePodBoundOwnedFile(out, name string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if err := publishPodBoundOwnedFile(out, name, raw); err != nil {
		return "", err
	}
	return podBoundHash(raw), nil
}

var podBoundOwnedName = regexp.MustCompile(`^pod-bound-token-[a-z0-9-]+\.json$`)

func publishPodBoundOwnedFile(out, name string, raw []byte) error {
	if !podBoundOwnedName.MatchString(name) || len(raw) == 0 || len(raw) > 8<<20 {
		return errors.New("Pod-bound token output name or size invalid")
	}
	root, err := natsResponseRoot(out)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(name); err == nil {
		return errors.New("Pod-bound token output already published")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile(name+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = root.Link(name+".tmp", name); err != nil {
		return err
	}
	if err = root.Remove(name + ".tmp"); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func podBoundTokenWaitFile(ctx context.Context, out, name string, dst any) ([]byte, error) {
	for {
		raw, err := readPodBoundJSON(out, name, dst)
		if err == nil {
			return raw, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s did not arrive: %w", filepath.Base(name), ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
