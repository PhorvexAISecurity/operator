package console

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	"sigs.k8s.io/yaml"
)

const (
	podBoundTokenConfig    = "pod-bound-api-auth-response"
	podBoundTokenSchema    = "pod-bound-token-result-v1"
	podBoundTokenNamespace = "voice"
)

var podBoundTokenNonce = regexp.MustCompile(`^[0-9a-f]{24}$`)

type podBoundTokenProfile struct {
	Context              string   `json:"context"`
	Namespace            string   `json:"namespace"`
	Kubeconfig           string   `json:"kubeconfig"`
	ExpectedNamespaceUID string   `json:"expectedNamespaceUID"`
	OwnedAck             bool     `json:"ownedAck"`
	TrialsPerArm         int      `json:"trialsPerArm"`
	ScenarioFilter       []string `json:"scenarioFilter"`
	DefenderFilter       []string `json:"defenderFilter"`
	Fixture              struct {
		RunID                string `json:"runID"`
		Nonce                string `json:"nonce"`
		Transport            string `json:"transport"`
		ClusterUID           string `json:"clusterUID"`
		ManagerNamespace     string `json:"managerNamespace"`
		ManagerDeployment    string `json:"managerDeployment"`
		ManagerImageID       string `json:"managerImageID"`
		FixtureImageID       string `json:"fixtureImageID"`
		SourceManifestSHA256 string `json:"sourceManifestSHA256"`
		SourceManifestPath   string `json:"sourceManifestPath"`
		ProtectedLedgerName  string `json:"protectedLedgerName"`
		EventCreator         string `json:"eventCreator"`
		PrometheusURL        string `json:"prometheusURL"`
		ScrapeKind           string `json:"scrapeKind"`
		ScrapeNamespace      string `json:"scrapeNamespace"`
		AllowedNodeName      string `json:"allowedNodeName"`
		MaxRunSeconds        int    `json:"maxRunSeconds"`
	} `json:"podBoundTokenFixture"`
}

func parsePodBoundTokenProfile(raw []byte) (podBoundTokenProfile, error) {
	var p podBoundTokenProfile
	if len(raw) == 0 || len(raw) > 64<<10 || bytes.Contains(raw, []byte("__SET_")) ||
		yaml.Unmarshal(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &p) != nil {
		return p, errors.New("Pod-bound token profile lacks reviewed source, creator or scrape pins")
	}
	f := p.Fixture
	if p.Context == "" || p.Context == "in-cluster" || p.Kubeconfig != "" ||
		p.Namespace != podBoundTokenNamespace || p.ExpectedNamespaceUID != "" ||
		!p.OwnedAck || p.TrialsPerArm != 1 || len(p.DefenderFilter) != 0 ||
		len(p.ScenarioFilter) != 1 || p.ScenarioFilter[0] != "c2-pod-bound-api-auth-response" ||
		f.Transport != "in-cluster" || !mongoKubeUID.MatchString(f.ClusterUID) ||
		f.ManagerNamespace != "phorvex-system" || !nsRe.MatchString(f.ManagerDeployment) ||
		!mongoPinnedImage.MatchString(f.ManagerImageID) ||
		!mongoPinnedImage.MatchString(f.FixtureImageID) ||
		!mongoSHA.MatchString(f.SourceManifestSHA256) ||
		!filepath.IsAbs(f.SourceManifestPath) ||
		!regexp.MustCompile(`^phorvex-quarantine-capacity-[0-9a-f]{40}$`).MatchString(f.ProtectedLedgerName) ||
		f.EventCreator != "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector" ||
		f.PrometheusURL == "" || f.ScrapeKind != "podmonitor" ||
		f.ScrapeNamespace != p.Namespace || !nsRe.MatchString(f.AllowedNodeName) ||
		f.MaxRunSeconds < 300 || f.MaxRunSeconds > 900 {
		return p, errors.New("Pod-bound token profile has incomplete fixed destination or authority")
	}
	return p, nil
}

func (rm *RunManager) podBoundTokenDestination(raw []byte, dest runDestination) (runDestination, error) {
	if !rm.cfg.PodBoundTokenEnabled || rm.cfg.AuditSource == nil || rm.cfg.AuditSourceIdentity == "" {
		return dest, errors.New("Pod-bound token fixture, trusted creator or authenticated audit is disabled")
	}
	p, err := parsePodBoundTokenProfile(raw)
	if err != nil {
		return dest, err
	}
	if !mongoSHA.MatchString(rm.cfg.PodBoundTokenProfileSHA256) ||
		podBoundHash(raw) != rm.cfg.PodBoundTokenProfileSHA256 {
		return dest, errors.New("Pod-bound token profile differs from installed reviewed digest")
	}
	if _, err := verifyPodBoundTokenSourceManifest(p); err != nil {
		return dest, err
	}
	h := sha256.Sum256(raw)
	return runDestination{Targets: []string{hostTargetID, p.Context},
		Tenants: []string{podBoundTokenNamespace}, ScopeTarget: p.Context,
		ScopeTenant: podBoundTokenNamespace, SuiteSHA256: hex.EncodeToString(h[:])}, nil
}

func (c *Config) podBoundTokenCatalogueItem() CatalogItem {
	dest, err := (&RunManager{cfg: *c}).SuiteDestination(podBoundTokenConfig)
	item := CatalogItem{
		EntryID: "c2-pod-bound-api-auth-response", Name: "c2-pod-bound-api-auth-response",
		Product: "application", Category: "Injected response control", R6Tag: "not-applicable",
		Techniques: []string{}, ExercisedTechniques: []string{}, Caps: []string{},
		Realism: "executable-mechanism", BenignControl: boolPtr(false),
		ExpectedActuators: []string{}, ResponseGuidanceBasis: "explicit-response-control",
		ResponseGuidance: "One trusted typed event is explicitly injected. The brain may select no action; only an exact rotate receipt and same-bearer 200 to 401 replay with peer and Service controls can establish this narrow mechanism.",
		MeaningfulWhen:   "Shows an exact source Pod-bound bearer, attributed brain decision, native operation and independent replay; natural detection and broader credential efficacy are not evaluated.",
		RunnableNote:     "Default-off server-owned Voice fixture with installed-source, trusted creator, real request-rate scrape and authenticated audit pins.",
		Prereqs:          []string{"reviewed fixed Voice profile and source pins", "host and cluster target plus voice grant", "trusted E2E creator admission", "nonce-owned PodMonitor with fresh source-Pod request rate", "authenticated exact-window audit"},
		LaunchKind:       "named-suite", ClaimClass: "effect", Profile: podBoundTokenConfig, Available: err == nil,
	}
	if err == nil {
		item.RuntimeContext = dest.ScopeTarget
	} else {
		item.UnavailableReason = err.Error()
	}
	return item
}

type PodBoundTokenStage struct {
	Name           string `json:"name"`
	Status         string `json:"status"`
	ObservedAt     string `json:"observedAt,omitempty"`
	EvidenceSHA256 string `json:"evidenceSHA256,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type PodBoundTokenAdmission struct {
	ClusterUID         string `json:"clusterUID"`
	Namespace          string `json:"namespace"`
	NamespaceUID       string `json:"namespaceUID"`
	ManagerPodUID      string `json:"managerPodUID"`
	ManagerContainerID string `json:"managerContainerID"`
	ManagerImageID     string `json:"managerImageID"`
	PolicyUID          string `json:"policyUID"`
	PolicyGeneration   int64  `json:"policyGeneration"`
	PolicySpecSHA256   string `json:"policySpecSHA256"`
	SourcePodUID       string `json:"sourcePodUID"`
	PeerPodUID         string `json:"peerPodUID"`
	ServiceUID         string `json:"serviceUID"`
	DeploymentUID      string `json:"deploymentUID"`
	ReplicaSetUID      string `json:"replicaSetUID"`
	ProfileSHA256      string `json:"profileSHA256"`
	Available          bool   `json:"available"`
	UnavailableReason  string `json:"unavailableReason,omitempty"`
}

type PodBoundTokenEvent struct {
	UID           string `json:"uid"`
	Kind          string `json:"kind"`
	Creator       string `json:"creator"`
	SourcePodUID  string `json:"sourcePodUID"`
	TrustVerified bool   `json:"trustVerified"`
}

type PodBoundTokenDecision struct {
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

type PodBoundTokenOperation struct {
	TerminationStatus string `json:"terminationStatus"`
	OriginalPodAbsent bool   `json:"originalPodAbsent"`
	ReceiptSHA256     string `json:"receiptSHA256"`
}

type PodBoundTokenReplay struct {
	SourceBeforeHTTP                int    `json:"sourceBeforeHTTP"`
	SourceAfterHTTP                 int    `json:"sourceAfterHTTP"`
	SourceExpiry                    string `json:"sourceExpiry"`
	SourceAfterAt                   string `json:"sourceAfterAt"`
	PeerBeforeHTTP                  int    `json:"peerBeforeHTTP"`
	PeerAfterHTTP                   int    `json:"peerAfterHTTP"`
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

type PodBoundTokenCleanup struct {
	Status          string `json:"status"`
	InventorySHA256 string `json:"inventorySHA256"`
	Absent          bool   `json:"absent"`
}

type PodBoundTokenTelemetry struct {
	ProducerStatus string  `json:"producerStatus"`
	FirstAt        string  `json:"firstAt"`
	SecondAt       string  `json:"secondAt"`
	FirstValue     float64 `json:"firstValue"`
	SecondValue    float64 `json:"secondValue"`
	SourcePodName  string  `json:"sourcePodName"`
	PodMonitorUID  string  `json:"podMonitorUID"`
	QuerySHA256    string  `json:"querySHA256"`
}

type PodBoundTokenResult struct {
	Schema            string                 `json:"schema"`
	RunID             string                 `json:"runID"`
	Nonce             string                 `json:"nonce"`
	TerminalStatus    string                 `json:"terminalStatus"`
	MechanismObserved bool                   `json:"mechanismObserved"`
	SecurityEfficacy  string                 `json:"securityEfficacy"`
	SignalMode        string                 `json:"signalMode"`
	Stages            []PodBoundTokenStage   `json:"stages"`
	Admission         PodBoundTokenAdmission `json:"admission"`
	Event             PodBoundTokenEvent     `json:"event"`
	Decision          PodBoundTokenDecision  `json:"decision"`
	Operation         PodBoundTokenOperation `json:"operation"`
	Replay            PodBoundTokenReplay    `json:"replay"`
	Cleanup           PodBoundTokenCleanup   `json:"cleanup"`
	Telemetry         PodBoundTokenTelemetry `json:"telemetry"`
}

func validatePodBoundTokenResult(r PodBoundTokenResult) error {
	if r.Schema != podBoundTokenSchema || r.RunID == "" || !podBoundTokenNonce.MatchString(r.Nonce) ||
		r.SecurityEfficacy != "NOT_EVALUATED" || r.SignalMode != "explicit-injected-typed-event" ||
		(r.TerminalStatus != "COMPLETE" && r.TerminalStatus != "INCOMPLETE" && r.TerminalStatus != "UNSAFE") {
		return errors.New("Pod-bound token result identity or claim differs")
	}
	if len(r.Stages) != 9 {
		return errors.New("Pod-bound token stage chain incomplete")
	}
	if r.MechanismObserved {
		afterAt, aerr := time.Parse(time.RFC3339Nano, r.Replay.SourceAfterAt)
		expiry, eerr := time.Parse(time.RFC3339Nano, r.Replay.SourceExpiry)
		serviceAt, serr := time.Parse(time.RFC3339Nano, r.Replay.ServiceAfterAt)
		operationAt, oerr := time.Parse(time.RFC3339Nano, r.Stages[6].ObservedAt)
		outcomeAt, uerr := time.Parse(time.RFC3339Nano, r.Stages[7].ObservedAt)
		if r.TerminalStatus != "COMPLETE" || r.Decision.SelectedAction != "rotate" ||
			r.Decision.DispatchOutcome != "emitted" ||
			r.Decision.AuditCoverage != "COMPLETE" ||
			r.Decision.RequestRateStatus != "MEASURED_FRESH" ||
			r.Telemetry.ProducerStatus != "MEASURED_FRESH" ||
			r.Event.Kind != "phorvex.attack.pod-bound-api-auth" || !r.Event.TrustVerified ||
			r.Operation.TerminationStatus != "REQUEST_CONFIRMED" || !r.Operation.OriginalPodAbsent ||
			r.Replay.SourceBeforeHTTP != 200 || r.Replay.SourceAfterHTTP != 401 ||
			r.Replay.PeerBeforeHTTP != 200 || r.Replay.PeerAfterHTTP != 200 ||
			r.Replay.ServiceBeforeHTTP != 200 || r.Replay.ServiceAfterHTTP != 200 ||
			!r.Replay.SameSourceHandle || !r.Replay.SamePeerHandle ||
			aerr != nil || eerr != nil || serr != nil || oerr != nil || uerr != nil ||
			!afterAt.Before(expiry) || !afterAt.After(operationAt) || afterAt.After(outcomeAt) ||
			!serviceAt.After(operationAt) || serviceAt.After(outcomeAt) ||
			r.Replay.ServiceAfterServiceUID != r.Admission.ServiceUID ||
			r.Replay.ServiceAfterEndpointSliceUID == "" ||
			r.Replay.ServiceMemberPodUID == "" ||
			r.Replay.ServiceMemberPodUID == r.Admission.SourcePodUID ||
			!r.Replay.ServiceMemberReady ||
			r.Replay.ServiceMemberOwnerDeploymentUID != r.Admission.DeploymentUID ||
			r.Admission.DeploymentUID == "" || r.Admission.ReplicaSetUID == "" ||
			r.Cleanup.Status != "CONFIRMED_ABSENT" || !r.Cleanup.Absent {
			return fmt.Errorf("Pod-bound token mechanism claim lacks exact operation, replay or cleanup")
		}
	}
	names := [...]string{"ADMISSION", "OWNED_FIXTURE", "CREDENTIAL_AND_ROUTE_BASELINE", "AUDIT_START", "SOLE_TYPED_SIGNAL", "BRAIN_DECISION", "NATIVE_OPERATION", "INDEPENDENT_OUTCOME", "CLEANUP"}
	var previous time.Time
	for i, stage := range r.Stages {
		if stage.Name != names[i] || (stage.Status != "CONFIRMED" && stage.Status != "REFUSED" && stage.Status != "UNKNOWN") {
			return errors.New("Pod-bound token stage identity or status differs")
		}
		if stage.ObservedAt == "" {
			if r.TerminalStatus == "COMPLETE" {
				return errors.New("complete Pod-bound token stage time missing")
			}
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, stage.ObservedAt)
		if err != nil || (!previous.IsZero() && !at.After(previous)) {
			return errors.New("Pod-bound token stage chronology differs")
		}
		previous = at
	}
	if r.TerminalStatus == "COMPLETE" {
		for _, stage := range r.Stages {
			if stage.Status != "CONFIRMED" {
				return errors.New("complete Pod-bound token observation has an unknown stage")
			}
		}
	}
	if r.TerminalStatus == "COMPLETE" && (r.Admission.Namespace != podBoundTokenNamespace ||
		r.Admission.SourcePodUID == "" || r.Admission.SourcePodUID != r.Event.SourcePodUID ||
		r.Admission.PeerPodUID == "" || r.Admission.PeerPodUID == r.Admission.SourcePodUID ||
		r.Admission.ServiceUID == "" || r.Admission.PolicyUID == "" ||
		r.Admission.PolicyGeneration < 1 || !mongoSHA.MatchString(r.Admission.PolicySpecSHA256) ||
		r.Admission.ManagerPodUID == "" || !mongoSHA.MatchString(r.Admission.ProfileSHA256) ||
		r.Event.UID == "" || r.Event.Creator != "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector" ||
		r.Decision.ID == "" || r.Decision.AuditCoverage != "COMPLETE") {
		return errors.New("Pod-bound token exact source, event or audit identity differs")
	}
	return nil
}
