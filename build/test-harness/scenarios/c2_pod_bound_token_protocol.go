package scenarios

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const (
	podTokenRequestFile            = "pod-bound-token-request.json"
	podTokenBarrierFile            = "pod-bound-token-barrier.json"
	podTokenArtifactFile           = "pod-bound-token-artifact.json"
	podTokenTerminalFile           = "pod-bound-token-terminal.json"
	podTokenCoordinatorFailureFile = "pod-bound-token-coordinator-failure.json"
)

type podTokenCoordinatorFailure struct {
	Schema        string `json:"schema"`
	RunID         string `json:"runID"`
	Nonce         string `json:"nonce"`
	RequestSHA256 string `json:"requestSHA256"`
	Stage         string `json:"stage"`
	Reason        string `json:"reason"`
	ErrorSHA256   string `json:"errorSHA256"`
	RecordedAt    string `json:"recordedAt"`
}

func readPodTokenCoordinatorFailure(dir string, req podTokenRequest, reqSHA string) (*podTokenCoordinatorFailure, error) {
	raw, err := os.ReadFile(filepath.Join(dir, podTokenCoordinatorFailureFile))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, errors.New("Pod token coordinator diagnostic invalid")
	}
	var failure podTokenCoordinatorFailure
	if err := json.Unmarshal(raw, &failure); err != nil {
		return nil, errors.New("Pod token coordinator diagnostic malformed")
	}
	if failure.Schema != "pod-bound-token-coordinator-failure-v1" ||
		failure.RunID != req.RunID || failure.Nonce != req.Nonce || failure.RequestSHA256 != reqSHA {
		return nil, os.ErrNotExist // A foreign receipt cannot terminate this request.
	}
	reasonByStage := map[string]string{
		"request-validation": "REQUEST_INVALID", "authorization": "AUTHORIZATION_FAILED",
		"source-validation": "SOURCE_VALIDATION_FAILED", "audit-start": "AUDIT_START_FAILED",
		"post-audit-authorization": "AUTHORIZATION_CHANGED", "post-audit-source": "SOURCE_RECHECK_FAILED",
		"post-audit-source-manifest": "SOURCE_MANIFEST_FAILED", "post-audit-disjointness": "DISJOINTNESS_FAILED",
		"signal-intent": "SIGNAL_INTENT_FAILED", "typed-event-create": "EVENT_CREATION_FAILED",
		"decision-observation": "DECISION_OBSERVATION_FAILED", "observation-commit": "OBSERVATION_COMMIT_FAILED",
		"event-cleanup": "EVENT_CLEANUP_FAILED",
	}
	_, hashErr := hex.DecodeString(failure.ErrorSHA256)
	if reasonByStage[failure.Stage] == "" || failure.Reason != reasonByStage[failure.Stage] ||
		len(failure.ErrorSHA256) != 64 || hashErr != nil {
		return nil, errors.New("Pod token coordinator diagnostic invalid")
	}
	requested, reqTimeErr := time.Parse(time.RFC3339Nano, req.RequestedAt)
	recorded, recordedErr := time.Parse(time.RFC3339Nano, failure.RecordedAt)
	if reqTimeErr != nil || recordedErr != nil || recorded.Before(requested) || recorded.After(time.Now().Add(2*time.Second)) {
		return nil, errors.New("Pod token coordinator diagnostic time invalid")
	}
	return &failure, nil
}

type podTokenRequest struct {
	Schema                string  `json:"schema"`
	CaseID                string  `json:"caseID,omitempty"`
	RunID                 string  `json:"runID"`
	Nonce                 string  `json:"nonce"`
	ClusterUID            string  `json:"clusterUID"`
	Namespace             string  `json:"namespace"`
	NamespaceUID          string  `json:"namespaceUID"`
	SourcePodName         string  `json:"sourcePodName"`
	SourcePodUID          string  `json:"sourcePodUID"`
	DeploymentUID         string  `json:"deploymentUID"`
	ReplicaSetUID         string  `json:"replicaSetUID"`
	PeerPodName           string  `json:"peerPodName"`
	PeerPodUID            string  `json:"peerPodUID"`
	ServiceName           string  `json:"serviceName"`
	ServiceUID            string  `json:"serviceUID"`
	PDBUID                string  `json:"pdbUID,omitempty"`
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

type podTokenStage struct {
	Name           string `json:"name"`
	Status         string `json:"status"`
	ObservedAt     string `json:"observedAt,omitempty"`
	EvidenceSHA256 string `json:"evidenceSHA256,omitempty"`
	Reason         string `json:"reason,omitempty"`
}
type podTokenAdmission struct {
	ClusterUID         string `json:"clusterUID"`
	Namespace          string `json:"namespace"`
	NamespaceUID       string `json:"namespaceUID"`
	ManagerPodUID      string `json:"managerPodUID"`
	ManagerContainerID string `json:"managerContainerID"`
	ManagerImageID     string `json:"managerImageID"`
	DeploymentUID      string `json:"deploymentUID"`
	ReplicaSetUID      string `json:"replicaSetUID"`
	PolicyUID          string `json:"policyUID"`
	PolicyGeneration   int64  `json:"policyGeneration"`
	PolicySpecSHA256   string `json:"policySpecSHA256"`
	SourcePodUID       string `json:"sourcePodUID"`
	PeerPodUID         string `json:"peerPodUID"`
	ServiceUID         string `json:"serviceUID"`
	PDBUID             string `json:"pdbUID,omitempty"`
	ProfileSHA256      string `json:"profileSHA256"`
	Available          bool   `json:"available"`
	UnavailableReason  string `json:"unavailableReason,omitempty"`
}
type podTokenEvent struct {
	UID           string `json:"uid"`
	Kind          string `json:"kind"`
	Creator       string `json:"creator"`
	SourcePodUID  string `json:"sourcePodUID"`
	TrustVerified bool   `json:"trustVerified"`
}
type podTokenDecision struct {
	ID                 string  `json:"id"`
	SelectedAction     string  `json:"selectedAction"`
	DispatchOutcome    string  `json:"dispatchOutcome"`
	CostCeiling        float64 `json:"costCeiling"`
	RotateStatus       string  `json:"rotateStatus"`
	RotateReason       string  `json:"rotateReason"`
	RotateExpectedCost float64 `json:"rotateExpectedCost"`
	RotateHighCost     float64 `json:"rotateHighCost"`
	RequestRateStatus  string  `json:"requestRateStatus"`
	FlowRegime         string  `json:"flowRegime"`
	QuarantineStatus   string  `json:"quarantineStatus"`
	QuarantineReason   string  `json:"quarantineReason"`
	QuarantineUsed     int     `json:"quarantineUsed"`
	QuarantineLimit    int     `json:"quarantineLimit"`
	AuditCoverage      string  `json:"auditCoverage"`
}
type podTokenOperation struct {
	TerminationStatus string `json:"terminationStatus"`
	OriginalPodAbsent bool   `json:"originalPodAbsent"`
	ReceiptSHA256     string `json:"receiptSHA256"`
}
type podTokenReplay struct {
	SourceBeforeHTTP                int    `json:"sourceBeforeHTTP"`
	SourceBeforeRequestAt           string `json:"sourceBeforeRequestAt,omitempty"`
	SourceBeforeAt                  string `json:"sourceBeforeAt,omitempty"`
	SourceAfterHTTP                 int    `json:"sourceAfterHTTP"`
	SourceAfterRequestAt            string `json:"sourceAfterRequestAt,omitempty"`
	SourceExpiry                    string `json:"sourceExpiry"`
	SourceAfterAt                   string `json:"sourceAfterAt"`
	PeerBeforeHTTP                  int    `json:"peerBeforeHTTP"`
	PeerBeforeRequestAt             string `json:"peerBeforeRequestAt,omitempty"`
	PeerBeforeAt                    string `json:"peerBeforeAt,omitempty"`
	PeerAfterHTTP                   int    `json:"peerAfterHTTP"`
	PeerAfterRequestAt              string `json:"peerAfterRequestAt,omitempty"`
	PeerAfterAt                     string `json:"peerAfterAt,omitempty"`
	PeerExpiry                      string `json:"peerExpiry,omitempty"`
	ServiceBeforeHTTP               int    `json:"serviceBeforeHTTP"`
	ServiceAfterHTTP                int    `json:"serviceAfterHTTP"`
	SameSourceHandle                bool   `json:"sameSourceHandle"`
	SamePeerHandle                  bool   `json:"samePeerHandle"`
	SourceBeforeCaptureID           string `json:"sourceBeforeCaptureID"`
	SourceAfterCaptureID            string `json:"sourceAfterCaptureID"`
	PeerBeforeCaptureID             string `json:"peerBeforeCaptureID"`
	PeerAfterCaptureID              string `json:"peerAfterCaptureID"`
	ServiceMemberPodUID             string `json:"serviceMemberPodUID"`
	ServiceAfterAt                  string `json:"serviceAfterAt"`
	ServiceAfterServiceUID          string `json:"serviceAfterServiceUID"`
	ServiceAfterEndpointSliceUID    string `json:"serviceAfterEndpointSliceUID"`
	ServiceMemberReady              bool   `json:"serviceMemberReady"`
	ServiceMemberOwnerDeploymentUID string `json:"serviceMemberOwnerDeploymentUID"`
}
type podTokenTelemetry struct {
	ProducerStatus string  `json:"producerStatus"`
	FirstAt        string  `json:"firstAt"`
	SecondAt       string  `json:"secondAt"`
	FirstValue     float64 `json:"firstValue"`
	SecondValue    float64 `json:"secondValue"`
	SourcePodName  string  `json:"sourcePodName"`
	PodMonitorUID  string  `json:"podMonitorUID"`
	QuerySHA256    string  `json:"querySHA256"`
}
type podTokenCleanup struct {
	Status          string `json:"status"`
	InventorySHA256 string `json:"inventorySHA256"`
	Absent          bool   `json:"absent"`
}
type podTokenResult struct {
	Schema            string            `json:"schema"`
	CaseID            string            `json:"caseID,omitempty"`
	RunID             string            `json:"runID"`
	Nonce             string            `json:"nonce"`
	TerminalStatus    string            `json:"terminalStatus"`
	MechanismObserved bool              `json:"mechanismObserved"`
	SecurityEfficacy  string            `json:"securityEfficacy"`
	SignalMode        string            `json:"signalMode"`
	Stages            []podTokenStage   `json:"stages"`
	Admission         podTokenAdmission `json:"admission"`
	Event             podTokenEvent     `json:"event"`
	Decision          podTokenDecision  `json:"decision"`
	Operation         podTokenOperation `json:"operation"`
	Replay            podTokenReplay    `json:"replay"`
	Telemetry         podTokenTelemetry `json:"telemetry"`
	Cleanup           podTokenCleanup   `json:"cleanup"`
}
type podTokenBarrier struct {
	Schema         string            `json:"schema"`
	RunID          string            `json:"runID"`
	Nonce          string            `json:"nonce"`
	RequestSHA256  string            `json:"requestSHA256"`
	Event          podTokenEvent     `json:"event"`
	Decision       podTokenDecision  `json:"decision"`
	Operation      podTokenOperation `json:"operation"`
	DecisionRowSHA string            `json:"decisionRowSHA256"`
	ObservedAt     string            `json:"observedAt"`
}
type podTokenArtifact struct {
	Result             podTokenResult `json:"result"`
	RequestSHA256      string         `json:"requestSHA256"`
	BarrierSHA256      string         `json:"barrierSHA256"`
	PhaseJournalSHA256 string         `json:"phaseJournalSHA256"`
	ObservationEndedAt string         `json:"observationEndedAt"`
}
type podTokenTerminal struct {
	Schema                     string `json:"schema"`
	RunID                      string `json:"runID"`
	Nonce                      string `json:"nonce"`
	ArtifactSHA256             string `json:"artifactSHA256"`
	CleanupStatus              string `json:"cleanupStatus"`
	ProtectedReservationAbsent bool   `json:"protectedReservationAbsent"`
	FinishedAt                 string `json:"finishedAt"`
}

func podTokenHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func writePodTokenFile(dir, name string, value any) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	fd, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return "", err
	}
	tmp := fd.Name()
	defer os.Remove(tmp)
	if n, e := fd.Write(raw); e != nil || n != len(raw) {
		fd.Close()
		return "", errors.New("Pod token protocol write incomplete")
	}
	if err := fd.Sync(); err != nil {
		fd.Close()
		return "", err
	}
	if err := fd.Close(); err != nil {
		return "", err
	}
	// Link is create-once: readers see either no final name or the complete,
	// synced file, and a competing writer cannot replace an existing receipt.
	if err := os.Link(tmp, filepath.Join(dir, name)); err != nil {
		return "", err
	}
	dirFD, err := os.Open(dir)
	if err != nil {
		return "", err
	}
	defer dirFD.Close()
	if err := dirFD.Sync(); err != nil {
		return "", err
	}
	return podTokenHash(raw), nil
}

func readPodTokenBarrier(dir string, req podTokenRequest, reqHash string) (podTokenBarrier, string, error) {
	var b podTokenBarrier
	raw, err := os.ReadFile(filepath.Join(dir, podTokenBarrierFile))
	if err != nil {
		return b, "", err
	}
	if len(raw) == 0 || len(raw) > 128<<10 || json.Unmarshal(raw, &b) != nil ||
		b.Schema != "pod-bound-token-barrier-v1" || b.RunID != req.RunID ||
		b.Nonce != req.Nonce || b.RequestSHA256 != reqHash ||
		b.Event.UID == "" || !b.Event.TrustVerified ||
		b.Event.SourcePodUID != req.SourcePodUID || b.Decision.ID == "" ||
		b.Decision.AuditCoverage != "COMPLETE" || b.DecisionRowSHA == "" {
		return b, "", errors.New("Pod token decision barrier identity differs")
	}
	return b, podTokenHash(raw), nil
}

func podTokenUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }
