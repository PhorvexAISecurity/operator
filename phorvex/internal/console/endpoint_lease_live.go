package console

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var endpointLeaseInFlight atomic.Bool

type endpointLeaseProbeResult struct {
	Schema                     string   `json:"schema"`
	Status                     string   `json:"status"`
	ScenarioID                 string   `json:"scenarioId"`
	SignalMode                 string   `json:"signalMode"`
	DefenseScope               string   `json:"defenseScope"`
	TargetPodUID               string   `json:"targetPodUID,omitempty"`
	ServiceUID                 string   `json:"serviceUID,omitempty"`
	PolicyUID                  string   `json:"policyUID,omitempty"`
	ProxySourceSHA256          string   `json:"proxySourceSHA256,omitempty"`
	FirstAccepted              bool     `json:"firstAccepted"`
	InitialAStatus             int      `json:"initialAStatus,omitempty"`
	InitialBStatus             int      `json:"initialBStatus,omitempty"`
	InitialAResponseSHA256     string   `json:"initialAResponseSHA256,omitempty"`
	InitialBResponseSHA256     string   `json:"initialBResponseSHA256,omitempty"`
	EventUID                   string   `json:"eventUID,omitempty"`
	SelectedAction             string   `json:"selectedAction,omitempty"`
	SelectedDecisionID         string   `json:"selectedDecisionId,omitempty"`
	SelectedTickID             string   `json:"selectedTickId,omitempty"`
	NoopReason                 string   `json:"noopReason,omitempty"`
	ActionExclusion            string   `json:"actionExclusion,omitempty"`
	ProtectedJournalTerminal   bool     `json:"protectedJournalTerminal"`
	EveryServingPodEffective   bool     `json:"everyServingPodEffective"`
	TerminalAfterDispatchError bool     `json:"terminalAfterDispatchError"`
	ProtectionRevalidated      bool     `json:"protectionRevalidated"`
	HistoricalOperationID      string   `json:"historicalOperationId,omitempty"`
	HistoricalEventName        string   `json:"historicalEventName,omitempty"`
	HistoricalEventUID         string   `json:"historicalEventUID,omitempty"`
	HistoricalTickID           string   `json:"historicalTickId,omitempty"`
	HistoricalJournalSHA256    string   `json:"historicalJournalSHA256,omitempty"`
	CurrentStateSHA256         string   `json:"currentStateSHA256,omitempty"`
	CurrentRevision            uint64   `json:"currentRevision,omitempty"`
	PostAResponseSHA256        string   `json:"postAResponseSHA256,omitempty"`
	PostBResponseSHA256        string   `json:"postBResponseSHA256,omitempty"`
	PostAStatus                int      `json:"postAStatus,omitempty"`
	PostBStatus                int      `json:"postBStatus,omitempty"`
	PostAExactDenial           bool     `json:"postAExactDenial"`
	PostBValidCompletion       bool     `json:"postBValidCompletion"`
	Cleanup                    string   `json:"cleanup"`
	Issues                     []string `json:"issues"`
}

func (s *Server) startEndpointLease(p endpointLeaseProfile) (string, error) {
	run, err := drainNonce()
	if err != nil {
		endpointLeaseInFlight.Store(false)
		return "", errors.New("endpoint lease run identity unavailable")
	}
	started := s.cfg.now().UTC()
	id := "endpoint-lease-" + run
	probe := &endpointLeaseProbeResult{Schema: "vllm-endpoint-lease-live-v1", Status: "UNKNOWN",
		ScenarioID: endpointLeaseScenario, SignalMode: "NONE",
		DefenseScope: "one owner-provisioned stolen caller A on the public inference Service; B remains legitimate; no SSRF or extraction claim",
		Cleanup:      "NOT_NEEDED", Issues: []string{}}
	record := &attackRecord{ID: id, FiredAt: started.Format(time.RFC3339Nano), Service: "vllm", Namespace: "vllm",
		Attack: "Stolen inference credential reuse", AttackID: endpointLeaseAction, Expected: endpointLeaseAction,
		EvidenceKind: "vllm-endpoint-lease-live", OutcomeClass: "endpoint-lease-UNKNOWN", Status: "running",
		ProducerRoute: endpointLeaseRoute, ResultSchema: probe.Schema,
		ObservationStart: started.Format(time.RFC3339Nano), ObservationEnd: started.Add(900 * time.Second).Format(time.RFC3339Nano),
		EndpointLeaseProbe: probe, started: started, accepted: started}
	publishAttack(record)
	go s.runEndpointLease(record, p, run)
	return id, nil
}

func endpointLeasePrivateDir(cfg Config, id string) (string, error) {
	path := cfg.statePath(filepath.Join("endpoint-lease", id))
	if path == "" || os.MkdirAll(path, 0700) != nil {
		return "", errors.New("endpoint lease private evidence directory unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("endpoint lease private evidence directory not private")
	}
	return path, nil
}

func endpointLeaseSameBefore(a, b endpointLeaseSnapshot) bool {
	if a.ServiceUID != b.ServiceUID || a.PolicyUID != b.PolicyUID || a.PolicyGeneration != b.PolicyGeneration ||
		a.ConfigMapUID != b.ConfigMapUID || a.SecretUID != b.SecretUID || a.SourceConfigMapUID != b.SourceConfigMapUID ||
		a.JournalUID != b.JournalUID || a.StateSHA256 != b.StateSHA256 || len(a.Pods) != len(b.Pods) {
		return false
	}
	return endpointLeaseSameProxyIncarnations(a.Pods, b.Pods)
}

func (s *Server) runEndpointLease(record *attackRecord, p endpointLeaseProfile, run string) {
	probe := record.EndpointLeaseProbe
	defer endpointLeaseInFlight.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.MaxRunSeconds)*time.Second)
	defer cancel()
	defer s.finishEndpointLease(record)
	privateDir, err := endpointLeasePrivateDir(s.cfg, record.ID)
	if err != nil {
		probe.Issues = append(probe.Issues, err.Error())
		return
	}
	tokens, err := endpointLeaseMountedTokens(p)
	if err != nil {
		probe.Issues = append(probe.Issues, "reviewed caller Secret copy unavailable")
		return
	}
	kube, err := clientForContext("")
	if err != nil {
		probe.Issues = append(probe.Issues, "Kubernetes source authority unavailable")
		return
	}
	snap, err := s.endpointLeaseSnapshot(ctx, kube, p, tokens)
	if err != nil {
		probe.Issues = append(probe.Issues, "public Service, proxy, policy, source, caller or journal preflight unavailable")
		return
	}
	probe.ServiceUID, probe.PolicyUID, probe.ProxySourceSHA256 = snap.ServiceUID, snap.PolicyUID, p.ProxySourceSHA256
	journalCM, err := kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, endpointLeaseJournalCM, metav1.GetOptions{})
	if err != nil || string(journalCM.UID) != p.JournalUID {
		probe.Issues = append(probe.Issues, "protected journal identity unavailable")
		return
	}
	priorJournal, err := parseEndpointLeaseJournal([]byte(journalCM.Data["receipts.json"]))
	if err != nil || !endpointLeasePreflightJournal(priorJournal, snap.State) {
		probe.Issues = append(probe.Issues, "protected journal contains unresolved operation")
		return
	}
	if len(snap.State.RevokedClientHMACs) > 0 || !endpointLeaseBefore(snap.State, p) {
		s.revalidateEndpointLease(ctx, record, p, snap, journalCM, tokens, kube, privateDir)
		return
	}
	target := snap.Pods[0]
	probe.TargetPodUID = string(target.UID)
	record.Pod, record.TargetUID = target.Name, string(target.UID)
	preflightIntent, _ := json.Marshal(map[string]any{"schema": "endpoint-lease-preflight-v1",
		"serviceUID": snap.ServiceUID, "policyUID": snap.PolicyUID, "policyGeneration": snap.PolicyGeneration,
		"policyConfigMapUID": snap.ConfigMapUID, "policyStateSHA256": snap.StateSHA256,
		"sourceConfigMapUID": snap.SourceConfigMapUID, "journalUID": snap.JournalUID,
		"secretUID": snap.SecretUID, "targetPodUID": string(target.UID),
		"requestSHA256": endpointLeaseSHA(endpointLeaseRequestBody())})
	if publishMongoAuditFile(privateDir, "preflight-intent.json", preflightIntent, 4096) != nil {
		probe.Issues = append(probe.Issues, "private preflight intent unavailable")
		return
	}
	config, err := restConfigFor("")
	if err != nil {
		probe.Issues = append(probe.Issues, "proxy state transport unavailable")
		return
	}
	for _, pod := range snap.Pods {
		state, readErr := endpointLeaseAdminState(ctx, config, kube, pod, p)
		if readErr != nil || !endpointLeaseStatusMatches(state, p, snap, pod, false) {
			probe.Issues = append(probe.Issues, "initial authoritative A/B proxy state differs")
			return
		}
	}
	a, err := endpointLeasePublicCall(ctx, tokens.A)
	if err != nil || publishMongoAuditFile(privateDir, "first-A-original.json", a.Raw, 8192) != nil {
		probe.Issues = append(probe.Issues, "original A public Service response unresolved; no event emitted")
		return
	}
	probe.InitialAStatus, probe.InitialAResponseSHA256 = a.Status, a.ResponseSHA256
	if a.Status != 200 || !a.ValidCompletion {
		probe.Issues = append(probe.Issues, "A was not proven accepted by the real model; no event emitted")
		return
	}
	probe.FirstAccepted = true
	probe.Status = "LANDED"
	record.Outcome = "LANDED"
	observedAt := time.Now().UTC()
	b, err := endpointLeasePublicCall(ctx, tokens.B)
	if err != nil || publishMongoAuditFile(privateDir, "baseline-B-original.json", b.Raw, 8192) != nil {
		probe.Issues = append(probe.Issues, "legitimate B baseline unavailable; initial A acceptance remains landed")
		return
	}
	probe.InitialBStatus, probe.InitialBResponseSHA256 = b.Status, b.ResponseSHA256
	if b.Status != 200 || !b.ValidCompletion {
		probe.Issues = append(probe.Issues, "legitimate B model completion unavailable; no event emitted")
		return
	}
	beforeEvent, err := s.endpointLeaseSnapshot(ctx, kube, p, tokens)
	if err != nil || !endpointLeaseSameBefore(snap, beforeEvent) {
		probe.Issues = append(probe.Issues, "public route or source changed before event")
		return
	}
	event, err := s.createEndpointLeaseEvent(ctx, privateDir, run, p, snap, target, a, b, observedAt)
	if event != nil {
		record.StimulusEvidence = event
		probe.EventUID = event.EventUID
		if event.EventUID != "" {
			probe.Cleanup = "PENDING"
			defer func() {
				if endpointLeaseDeleteEvent(event.EventName, event.EventUID) != nil {
					probe.Cleanup = "UNKNOWN"
					probe.Issues = append(probe.Issues, "exact test event cleanup unresolved")
					if probe.Status == "DEFENDED" {
						probe.Status = "LANDED"
						record.Outcome, record.Containment = "LANDED", ""
					}
					return
				}
				probe.Cleanup = "ABSENT"
				if publishMongoAuditFile(privateDir, "event-cleanup.json", []byte(`{"status":"ABSENT"}`), 1024) != nil {
					probe.Cleanup = "ABSENT_RECEIPT_UNAVAILABLE"
					probe.Issues = append(probe.Issues, "exact event cleanup receipt unavailable")
					if probe.Status == "DEFENDED" {
						probe.Status = "LANDED"
						record.Outcome, record.Containment = "LANDED", ""
					}
				}
			}()
		}
	}
	if err != nil || event == nil || event.EventUID == "" {
		probe.SignalMode = "TEST_INJECTED_ADMISSION_UNKNOWN"
		probe.Issues = append(probe.Issues, "test event admission unresolved; no response credit")
		return
	}
	probe.SignalMode = "TEST_INJECTED_AFTER_A_AND_B_200"
	decision, err := s.waitEndpointLeaseDecision(ctx, record, snap, event.EventUID, event.EventName, p.EventCreator)
	probe.SelectedAction, probe.SelectedDecisionID, probe.SelectedTickID = decision.Action, decision.DecisionID, decision.TickID
	probe.NoopReason, probe.ActionExclusion = decision.NoopReason, decision.Exclusion
	if decision.TickID != "" {
		decisionRaw, _ := json.Marshal(decision)
		if publishMongoAuditFile(privateDir, "brain-decision.json", decisionRaw, 8192) != nil {
			probe.Issues = append(probe.Issues, "brain decision receipt not retained")
			return
		}
	}
	if err != nil || !decision.Selected || decision.Action != endpointLeaseAction {
		probe.Issues = append(probe.Issues, "normal brain did not select endpoint lease revocation; exact NOOP retained if observed")
		return
	}
	record.Action = decision.Action
	after, err := s.waitEndpointLeaseEffect(ctx, kube, p, snap, priorJournal, decision, event, target, tokens)
	if err != nil {
		probe.Issues = append(probe.Issues, "protected terminal and all current proxy readbacks unavailable")
		return
	}
	probe.ProtectedJournalTerminal, probe.EveryServingPodEffective = true, true
	probe.TerminalAfterDispatchError = !decision.Actuated
	postA, err := endpointLeasePublicCall(ctx, tokens.A)
	if err != nil || publishMongoAuditFile(privateDir, "post-A-original.json", postA.Raw, 8192) != nil {
		probe.Issues = append(probe.Issues, "fresh A public response unavailable")
		return
	}
	probe.PostAStatus, probe.PostAExactDenial = postA.Status, postA.ExactDenial
	postB, err := endpointLeasePublicCall(ctx, tokens.B)
	if err != nil || publishMongoAuditFile(privateDir, "post-B-original.json", postB.Raw, 8192) != nil {
		probe.Issues = append(probe.Issues, "fresh B public response unavailable")
		return
	}
	probe.PostBStatus, probe.PostBValidCompletion = postB.Status, postB.ValidCompletion
	final, err := s.endpointLeaseSnapshot(ctx, kube, p, tokens)
	if err != nil || final.ConfigMapUID != after.ConfigMapUID || final.StateSHA256 != after.StateSHA256 ||
		final.ServiceUID != after.ServiceUID || final.SecretUID != after.SecretUID ||
		!postA.ExactDenial || postA.Status != 401 || !postB.ValidCompletion || postB.Status != 200 {
		probe.Issues = append(probe.Issues, "exact fresh A-401/B-200 or final durable policy continuity unverified")
		return
	}
	probe.Status = "DEFENDED"
	record.Outcome, record.Containment = "DEFENDED", "exact-owned-caller-A-revoked-B-preserved"
}

func (s *Server) finishEndpointLease(record *attackRecord) {
	probe := record.EndpointLeaseProbe
	if probe == nil {
		return
	}
	if probe.Status == "UNKNOWN" && probe.FirstAccepted {
		record.Outcome = "LANDED"
	}
	record.OutcomeClass = "endpoint-lease-" + probe.Status
	record.Actuated = probe.Status == "DEFENDED" && probe.Cleanup == "ABSENT" && probe.ProtectedJournalTerminal && probe.EveryServingPodEffective &&
		probe.PostAExactDenial && probe.PostBValidCompletion
	record.Status = "done"
	if err := s.persistAttack(record); err != nil {
		probe.Issues = append(probe.Issues, "durable terminal attack record unavailable")
		probe.Status = "UNKNOWN"
		record.OutcomeClass = "endpoint-lease-UNKNOWN"
		record.Actuated, record.Containment = false, ""
		if probe.FirstAccepted {
			record.Outcome = "LANDED"
		} else {
			record.Outcome = ""
		}
		record.PersistenceError = "endpoint lease terminal persistence unavailable"
		record.Status = "partial"
	}
	publishAttack(record)
}
