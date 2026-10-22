package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/crmrefund"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

// The CRM Live attack performs a real cross-account refund against the deliberately
// unauthenticated mini-CRM (it lands by design — the confused-deputy capability), then,
// only after that first loss, stamps one trusted SecurityEvent carrying the exact abused
// order so the brain's crm-refund-revoke actuator can revoke it across every serving Pod
// while legitimate refunds continue. The producer is HTTP-driven end to end: the console
// ServiceAccount reads the Service, Pods, policy and the deny-guard ConfigMap UID, calls the
// CRM app over the in-cluster Service, and creates the SecurityEvent. It never execs into a
// Pod and never writes the guard (the actuator owns it).
const (
	crmLiveScenario   = "ai2-cross-record-refund"
	crmLivePolicyName = "crm-defense"
	crmLiveRoute      = "/api/crm/live/fire"
	crmLiveBaseURL    = "http://crm.crm.svc.cluster.local:8080"
	// The seeded confused-deputy pair: order OR-5002 belongs to account AC-1002, abused on
	// behalf of the unrelated caller AC-1001. These are the mini-CRM's fixed seed corpus
	// (deploy/apps/crm/app.py); the producer verifies the ownership live before abusing it.
	crmLiveOrderID         = "OR-5002"
	crmLiveOrderAccountID  = "AC-1002"
	crmLiveOrderPhone      = "+15551230002"
	crmLiveCallerAccountID = "AC-1001"
	crmLiveMaxRunSeconds   = 300
)

var crmLiveRunning atomic.Bool

// crmLiveProbeResult is the console-visible, reviewable record of the bounded CRM trial:
// the live boundary identities it bound, whether the real cross-account refund landed, the
// stamped event, the brain's selected decision, and whether every serving Pod ends up
// enforcing the revoke. No account data or refund body is retained verbatim.
type crmLiveProbeResult struct {
	Schema             string   `json:"schema"`
	Status             string   `json:"status"`
	ScenarioID         string   `json:"scenarioId"`
	CaseID             string   `json:"caseId"`
	SignalMode         string   `json:"signalMode"`
	DefenseScope       string   `json:"defenseScope"`
	ServiceUID         string   `json:"serviceUID,omitempty"`
	GuardConfigMapUID  string   `json:"guardConfigMapUID,omitempty"`
	TargetPodUID       string   `json:"targetPodUID,omitempty"`
	PeerPodUID         string   `json:"peerPodUID,omitempty"`
	PolicyUID          string   `json:"policyUID,omitempty"`
	PolicyGeneration   int64    `json:"policyGeneration,omitempty"`
	OrderSHA256        string   `json:"orderSHA256,omitempty"`
	OwnershipVerified  bool     `json:"ownershipVerified"`
	FirstRefundLanded  bool     `json:"firstRefundLanded"`
	AlreadyRevoked     bool     `json:"alreadyRevoked"`
	EventUID           string   `json:"eventUID,omitempty"`
	SelectedAction     string   `json:"selectedAction,omitempty"`
	SelectedDecisionID string   `json:"selectedDecisionId,omitempty"`
	SelectedTickID     string   `json:"selectedTickId,omitempty"`
	EveryPodDenied     bool     `json:"everyServingPodDenied"`
	BenignRefundKept   bool     `json:"benignRefundMaintained"`
	Issues             []string `json:"issues"`
}

// crmLivePod is one serving CRM Pod as the console SA reads it.
type crmLivePod struct {
	Name string
	UID  string
	IP   string
}

// crmLiveSnapshot is the live boundary the console SA can observe without configmap-data,
// exec or guard-write authority: Service UID, the guard ConfigMap UID, the selecting
// policy epoch and the two serving Pods.
type crmLiveSnapshot struct {
	ServiceUID        string
	GuardConfigMapUID string
	PolicyUID         string
	PolicyGeneration  int64
	Pods              []crmLivePod
}

func (s *Server) crmRefundLiveFire(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	if s.cfg.liveAttackDisabled("crm", crmLiveScenario) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "crm Live attack ai2-cross-record-refund is retired by operator"})
		return
	}
	if !s.cfg.CRMRefundLiveEnabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "CRM Live producer is not enabled in this console"})
		return
	}
	var request struct {
		Scenario string `json:"scenario"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || request.Scenario != crmLiveScenario {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "one reviewed CRM scenario is required"})
		return
	}
	if !crmLiveRunning.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "one CRM Live run is already active"})
		return
	}
	id, err := voiceMemoryID()
	if err != nil {
		crmLiveRunning.Store(false)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "run identity unavailable"})
		return
	}
	if err = s.persistEffectIntent(crmLiveRoute, actorOf(r), "crm", crmLiveScenario); err != nil {
		crmLiveRunning.Store(false)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "CRM Fire intent unavailable"})
		return
	}
	started := s.cfg.now().UTC()
	attackID := "crm-refund-" + id
	probe := &crmLiveProbeResult{Schema: "crm-refund-live-v1", Status: "UNKNOWN", ScenarioID: crmLiveScenario,
		CaseID: attackID, SignalMode: "NONE", DefenseScope: "the single abused order id only",
		OrderSHA256: voiceAgencyStringDigest(crmLiveOrderID), Issues: []string{}}
	record := &attackRecord{ID: attackID, FiredAt: started.Format(time.RFC3339Nano), Service: "crm",
		Namespace: "crm", Attack: "CRM cross-account refund abuse", AttackID: crmLiveScenario,
		MITRE: "OWASP LLM06 / confused-deputy", Expected: string(model.ActionCRMRefundRevoke),
		EvidenceKind: "crm-refund-live", OutcomeClass: "crm-refund-UNKNOWN", Status: "running",
		ProducerRoute: crmLiveRoute, ResultSchema: "crm-refund-live-v1",
		ObservationStart: started.Format(time.RFC3339Nano),
		ObservationEnd:   started.Add(crmLiveMaxRunSeconds * time.Second).Format(time.RFC3339Nano),
		started:          started, accepted: started}
	// Stash the probe on the generic evidence slot; the CRM probe rides the record via the
	// producer and is persisted with it.
	record.CRMLiveProbe = probe
	publishAttack(record)
	go s.runCRMRefundLive(record)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "attackId": attackID, "scenario": crmLiveScenario,
		"status": "running", "message": "A bounded CRM trial is measuring. A real cross-account refund lands first; a trusted event is stamped only after that loss, and defense requires the brain to revoke exactly that order on every serving Pod while legitimate refunds continue."})
}

func (s *Server) runCRMRefundLive(record *attackRecord) {
	probe := record.CRMLiveProbe
	defer crmLiveRunning.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), crmLiveMaxRunSeconds*time.Second)
	defer cancel()
	defer func() {
		record.OutcomeClass = "crm-refund-" + probe.Status
		record.Status = "done"
		s.attachLiveProbeDecision("", record)
		if err := s.persistAttack(record); err != nil {
			record.PersistenceError = "CRM terminal persistence unavailable"
			record.Status = "partial"
		}
		publishAttack(record)
	}()

	snap, err := s.crmLiveSnapshot(ctx)
	if err != nil {
		probe.Issues = append(probe.Issues, "CRM Service, serving roster, policy or deny-guard identity unavailable")
		return
	}
	target, peer := snap.Pods[0], snap.Pods[1]
	probe.ServiceUID, probe.GuardConfigMapUID = snap.ServiceUID, snap.GuardConfigMapUID
	probe.TargetPodUID, probe.PeerPodUID = target.UID, peer.UID
	probe.PolicyUID, probe.PolicyGeneration = snap.PolicyUID, snap.PolicyGeneration
	record.Pod, record.TargetUID, record.Deploy, record.OwnerUID = target.Name, target.UID, "crm", snap.PolicyUID

	// If the order is already revoked on every serving Pod, a prior decision is still in
	// force: the abuse cannot land, so this is a protected revalidation, not a fresh loss.
	if denied, derr := crmLiveAllPodsDeny(ctx, snap, crmLiveOrderID); derr == nil && denied {
		probe.AlreadyRevoked, probe.EveryPodDenied = true, true
		probe.Status, record.Outcome, record.Containment = "PROTECTED", "PROTECTED", "prior-revoke-revalidated"
		record.Action = string(model.ActionCRMRefundRevoke)
		return
	}

	// Verify the abused order genuinely belongs to a different account than the caller.
	ownerOrders, err := crmLiveOrdersByPhone(ctx, crmLiveOrderPhone)
	if err != nil || ownerOrders.AccountID != crmLiveOrderAccountID || crmLiveOrderAccountID == crmLiveCallerAccountID ||
		!crmLiveHasOrder(ownerOrders, crmLiveOrderID) {
		probe.Issues = append(probe.Issues, "CRM cross-account order ownership could not be confirmed")
		return
	}
	probe.OwnershipVerified = true

	// The real confused-deputy abuse: refund an order owned by another account. It lands by
	// design against the unauthenticated CRM unless an operator revoke already denies it.
	landed, observedAt, abuseErr := crmLiveAbuseRefund(ctx)
	if abuseErr != nil || !landed {
		probe.Issues = append(probe.Issues, "cross-account refund did not land; CRM behaviour or deny-guard changed")
		return
	}
	probe.FirstRefundLanded = true
	probe.Status, record.Outcome = "LANDED", "LANDED"
	record.OutcomeClass = "crm-refund-LANDED"
	publishAttack(record)

	// Re-read the boundary; the roster/policy/guard must be unchanged before stamping.
	current, err := s.crmLiveSnapshot(ctx)
	if err != nil || current.ServiceUID != snap.ServiceUID || current.GuardConfigMapUID != snap.GuardConfigMapUID ||
		current.PolicyUID != snap.PolicyUID || current.PolicyGeneration != snap.PolicyGeneration ||
		!crmLiveSnapshotHasPod(current, target) || !crmLiveSnapshotHasPod(current, peer) {
		probe.Issues = append(probe.Issues, "CRM boundary changed before signaling; first loss remains LANDED")
		return
	}

	stimulus, err := s.createCRMRefundEvent(ctx, record.ID, snap, target, peer, observedAt)
	if err != nil {
		probe.Issues = append(probe.Issues, "CRM event creation or admitted identity unresolved")
		return
	}
	probe.EventUID, record.StimulusEvidence = stimulus.EventUID, stimulus
	probe.SignalMode = "TEST_INJECTED_AFTER_FIRST_LOSS"

	decision, err := s.waitCRMRefundDecision(ctx, record, snap, stimulus.EventUID)
	if err != nil {
		probe.Issues = append(probe.Issues, "no normal brain crm-refund-revoke decision for the exact event was observed (the action may not be enabled in crm-defense)")
		return
	}
	probe.SelectedAction, probe.SelectedDecisionID, probe.SelectedTickID = decision.Action, decision.DecisionID, decision.TickID
	record.Action, record.Actuated = decision.Action, decision.Actuated
	if decision.Action != string(model.ActionCRMRefundRevoke) {
		probe.Issues = append(probe.Issues, "brain selected another action; exact refund revoke not established")
		return
	}

	// The actuator writes the guard and reads it back on every Pod; the producer confirms the
	// same effect independently through the read-only guard-state endpoint.
	if denied, derr := crmLiveWaitAllPodsDeny(ctx, snap, crmLiveOrderID); derr != nil || !denied {
		probe.Issues = append(probe.Issues, "the order was not observed denied on every serving Pod")
		return
	}
	probe.EveryPodDenied, record.Actuated = true, true

	// Legitimacy: an unrelated owned order still refunds (the guard denies only the abused id).
	if kept, kerr := crmLiveBenignRefundKept(ctx); kerr != nil || !kept {
		probe.Issues = append(probe.Issues, "a legitimate unrelated refund did not continue; over-broad containment")
		return
	}
	probe.BenignRefundKept = true
	probe.Status, record.Outcome, record.Containment = "DEFENDED", "DEFENDED", "exact-order-refund-revoked"
}

// ── live boundary (console ServiceAccount reads only) ───────────────────────────────────

func (s *Server) crmLiveSnapshot(ctx context.Context) (crmLiveSnapshot, error) {
	var out crmLiveSnapshot
	svcText, err := s.cfg.execText(10*time.Second, "kubectl", "-n", "crm", "get", "service", crmrefund.ServiceName, "-o", "json")
	if err != nil {
		return out, errors.New("CRM Service unavailable")
	}
	var svc struct {
		Metadata struct{ UID string } `json:"metadata"`
		Spec     struct {
			Selector map[string]string `json:"selector"`
			Ports    []struct {
				Port       int `json:"port"`
				TargetPort int `json:"targetPort"`
			} `json:"ports"`
		} `json:"spec"`
	}
	if json.Unmarshal([]byte(svcText), &svc) != nil || svc.Metadata.UID == "" ||
		len(svc.Spec.Selector) != 1 || svc.Spec.Selector["app"] != "crm" ||
		len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 8080 || svc.Spec.Ports[0].TargetPort != 8080 {
		return out, errors.New("CRM Service selector or port differs")
	}
	out.ServiceUID = svc.Metadata.UID

	guardText, err := s.cfg.execText(10*time.Second, "kubectl", "-n", "crm", "get", "configmap", crmrefund.GuardConfigMapName, "-o", "json")
	if err != nil {
		return out, errors.New("CRM deny-guard ConfigMap unavailable")
	}
	var guard struct {
		Metadata struct {
			UID               string `json:"uid"`
			DeletionTimestamp string `json:"deletionTimestamp"`
		} `json:"metadata"`
	}
	if json.Unmarshal([]byte(guardText), &guard) != nil || guard.Metadata.UID == "" || guard.Metadata.DeletionTimestamp != "" {
		return out, errors.New("CRM deny-guard identity differs")
	}
	out.GuardConfigMapUID = guard.Metadata.UID

	policyText, err := s.cfg.execText(10*time.Second, "kubectl", "-n", "crm", "get", "phorvexpolicy", crmLivePolicyName, "-o", "json")
	if err != nil {
		return out, errors.New("CRM policy unavailable")
	}
	var policy struct {
		Metadata struct {
			UID        string `json:"uid"`
			Generation int64  `json:"generation"`
		} `json:"metadata"`
		Spec struct {
			Selector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"selector"`
		} `json:"spec"`
	}
	if json.Unmarshal([]byte(policyText), &policy) != nil || policy.Metadata.UID == "" || policy.Metadata.Generation < 1 ||
		policy.Spec.Selector.MatchLabels["app"] != "crm" {
		return out, errors.New("CRM policy selector or epoch differs")
	}
	out.PolicyUID, out.PolicyGeneration = policy.Metadata.UID, policy.Metadata.Generation

	podText, err := s.cfg.execText(10*time.Second, "kubectl", "-n", "crm", "get", "pods", "-l", "app=crm", "-o", "json")
	if err != nil {
		return out, errors.New("CRM serving roster unavailable")
	}
	var pods struct {
		Items []struct {
			Metadata struct {
				Name              string `json:"name"`
				UID               string `json:"uid"`
				DeletionTimestamp string `json:"deletionTimestamp"`
			} `json:"metadata"`
			Status struct {
				PodIP             string `json:"podIP"`
				ContainerStatuses []struct {
					Ready bool `json:"ready"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(podText), &pods) != nil || len(pods.Items) != 2 {
		return out, errors.New("CRM requires exactly two serving Pods")
	}
	seen := map[string]bool{}
	for _, p := range pods.Items {
		ready := false
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Ready {
				ready = true
			}
		}
		if p.Metadata.UID == "" || p.Metadata.Name == "" || p.Metadata.DeletionTimestamp != "" ||
			p.Status.PodIP == "" || !ready || net.ParseIP(p.Status.PodIP) == nil || seen[p.Metadata.UID] {
			return out, errors.New("CRM serving Pod lifetime differs")
		}
		seen[p.Metadata.UID] = true
		out.Pods = append(out.Pods, crmLivePod{Name: p.Metadata.Name, UID: p.Metadata.UID, IP: p.Status.PodIP})
	}
	sort.Slice(out.Pods, func(i, j int) bool { return out.Pods[i].UID < out.Pods[j].UID })
	return out, nil
}

func crmLiveSnapshotHasPod(snap crmLiveSnapshot, pod crmLivePod) bool {
	for _, p := range snap.Pods {
		if p.UID == pod.UID && p.Name == pod.Name {
			return true
		}
	}
	return false
}

// ── CRM app HTTP (in-cluster Service) ───────────────────────────────────────────────────

func crmLiveHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       8 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxIdleConns: 0},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("crm redirect refused") },
	}
}

type crmLiveOrders struct {
	AccountID string `json:"account_id"`
	Orders    []struct {
		OrderID   string `json:"order_id"`
		AccountID string `json:"account_id"`
	} `json:"orders"`
}

func crmLiveOrdersByPhone(ctx context.Context, phone string) (crmLiveOrders, error) {
	var out crmLiveOrders
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crmLiveBaseURL+"/orders/by-phone/"+phone, nil)
	if err != nil {
		return out, err
	}
	resp, err := crmLiveHTTPClient().Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || resp.StatusCode != http.StatusOK {
		return out, errors.New("crm order lookup unavailable")
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, errors.New("crm order lookup malformed")
	}
	return out, nil
}

func crmLiveHasOrder(o crmLiveOrders, orderID string) bool {
	for _, x := range o.Orders {
		if x.OrderID == orderID {
			return true
		}
	}
	return false
}

// crmLiveAbuseRefund issues the cross-account refund. A 200 with a refund id is the first
// loss; a 403 means an operator revoke already denies it (no fresh loss).
func crmLiveAbuseRefund(ctx context.Context) (bool, time.Time, error) {
	body, _ := json.Marshal(map[string]any{"order_id": crmLiveOrderID, "amount": 499.00,
		"reason": "phorvex-live-cross-account-abuse on behalf of " + crmLiveCallerAccountID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, crmLiveBaseURL+"/refunds", bytes.NewReader(body))
	if err != nil {
		return false, time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := crmLiveHTTPClient().Do(req)
	if err != nil {
		return false, time.Time{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	when := time.Now().UTC()
	if resp.StatusCode == http.StatusForbidden {
		return false, when, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, when, errors.New("crm refund call unexpected status")
	}
	var reply struct {
		RefundID string `json:"refund_id"`
		Status   string `json:"status"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.RefundID == "" || reply.Status != "issued" {
		return false, when, errors.New("crm refund reply malformed")
	}
	return true, when, nil
}

// crmLiveBenignRefundKept proves an unrelated owned order still refunds after the revoke.
func crmLiveBenignRefundKept(ctx context.Context) (bool, error) {
	body, _ := json.Marshal(map[string]any{"order_id": "OR-5003", "amount": 89.50, "reason": "phorvex-live-benign-control"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, crmLiveBaseURL+"/refunds", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := crmLiveHTTPClient().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	var reply struct {
		RefundID string `json:"refund_id"`
	}
	return json.Unmarshal(raw, &reply) == nil && reply.RefundID != "", nil
}

type crmGuardStateReply struct {
	DeniedOrderIDs []string `json:"denied_order_ids"`
}

func crmLivePodDenies(ctx context.Context, pod crmLivePod, orderID string) (bool, error) {
	url := "http://" + net.JoinHostPort(pod.IP, "8080") + "/phorvex-guard/state"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := crmLiveHTTPClient().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || resp.StatusCode != http.StatusOK {
		return false, errors.New("crm guard state unavailable")
	}
	var st crmGuardStateReply
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&st) != nil {
		return false, errors.New("crm guard state malformed")
	}
	for _, id := range st.DeniedOrderIDs {
		if id == orderID {
			return true, nil
		}
	}
	return false, nil
}

func crmLiveAllPodsDeny(ctx context.Context, snap crmLiveSnapshot, orderID string) (bool, error) {
	for _, pod := range snap.Pods {
		denied, err := crmLivePodDenies(ctx, pod, orderID)
		if err != nil {
			return false, err
		}
		if !denied {
			return false, nil
		}
	}
	return true, nil
}

// crmLiveWaitAllPodsDeny allows for the kubelet's projected-ConfigMap refresh (observed
// ~60-90s on this cluster), which the actuator's own bounded readback often outlasts.
func crmLiveWaitAllPodsDeny(ctx context.Context, snap crmLiveSnapshot, orderID string) (bool, error) {
	deadline := time.NewTimer(150 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		if denied, err := crmLiveAllPodsDeny(ctx, snap, orderID); err == nil && denied {
			return true, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-deadline.C:
			return false, nil
		case <-tick.C:
		}
	}
}

// ── SecurityEvent (trusted, stamped only after the first loss) ──────────────────────────

func (s *Server) createCRMRefundEvent(ctx context.Context, caseID string, snap crmLiveSnapshot,
	target, peer crmLivePod, observedAt time.Time) (*attackStimulusEvidence, error) {
	if observedAt.IsZero() || time.Since(observedAt) < 0 || time.Since(observedAt) >= 45*time.Second {
		return nil, errors.New("CRM first-loss observation is stale")
	}
	id, err := voiceMemoryID()
	if err != nil {
		return nil, err
	}
	name := "crm-refund-" + id
	observation := crmrefund.Observation{
		Version: 1, OrderID: crmLiveOrderID, OrderAccountID: crmLiveOrderAccountID, CallerAccountID: crmLiveCallerAccountID,
		GuardConfigMapUID: snap.GuardConfigMapUID, ServiceUID: snap.ServiceUID, TargetPodUID: target.UID, PeerPodUID: peer.UID,
		Objective: "ai2-cross-record-refund", ObservedAt: observedAt.UTC(), PolicyName: crmLivePolicyName,
		PolicyUID: snap.PolicyUID, PolicyGeneration: snap.PolicyGeneration,
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	if _, err = crmrefund.ParseObservation(string(raw)); err != nil {
		return nil, errors.New("CRM observation would not validate")
	}
	object := map[string]any{"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": name,
			"labels":      map[string]string{"phorvex.ai/redteam": "true", "phorvex.ai/attack-correlation": id},
			"annotations": map[string]string{model.ConsoleTargetPodUIDAnnotation: target.UID, crmrefund.ObservationAnnotation: string(raw)}},
		"spec": map[string]any{"description": "TEST_INJECTED after a real cross-account CRM refund landed",
			"targets":      []string{"crm/" + target.Name},
			"rule":         map[string]any{"type": crmrefund.RuleType, "threatLevel": "critical", "source": "redteam"},
			"anomalyScore": "0.9"}}
	manifest, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	candidate := &attackStimulusEvidence{Kind: "test-injected-after-real-cross-account-refund", TargetUID: target.UID,
		EventName: name, EventRule: crmrefund.RuleType, Correlation: id, BehavioralExecuted: true,
		Limitation: "bounded single abused order; the mini-CRM remains unauthenticated by design"}
	candidate.createManifest = manifest
	file, err := os.CreateTemp("", "crm-refund-event-*.json")
	if err != nil {
		return candidate, err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(manifest)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return candidate, errors.New("CRM event manifest unavailable")
	}
	reply, err := s.cfg.execText(10*time.Second, "kubectl", "create", "-f", file.Name(), "-o", "json")
	if err != nil || len(reply) == 0 || len(reply) > 65536 {
		return candidate, errors.New("CRM event create ambiguous; exact candidate may exist")
	}
	candidate.createReply = []byte(reply)
	var created vllmSecurityEvent
	if json.Unmarshal([]byte(reply), &created) != nil || created.Metadata.Name != name || created.Metadata.Namespace != "" ||
		created.Metadata.UID == "" || created.Metadata.CreationTimestamp == "" ||
		created.Metadata.Annotations["phorvex.ai/creator-identity"] != eventtrust.Injector() ||
		created.Metadata.Annotations[model.ConsoleTargetPodUIDAnnotation] != target.UID ||
		created.Metadata.Annotations[crmrefund.ObservationAnnotation] != string(raw) ||
		len(created.Spec.Targets) != 1 || created.Spec.Targets[0] != "crm/"+target.Name ||
		created.Spec.Rule.Type != crmrefund.RuleType || created.Spec.Rule.Source != "redteam" {
		return candidate, errors.New("CRM created event admission identity differs")
	}
	candidate.EventUID, candidate.EventCreatedAt, candidate.Observed = created.Metadata.UID, created.Metadata.CreationTimestamp, true
	_ = ctx
	return candidate, nil
}

// ── brain decision (shared audit decision window) ───────────────────────────────────────

type crmLiveDecision struct {
	Action, DecisionID, TickID string
	Selected, Actuated         bool
}

func (s *Server) waitCRMRefundDecision(ctx context.Context, record *attackRecord, snap crmLiveSnapshot, eventUID string) (crmLiveDecision, error) {
	deadline := time.NewTimer(120 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var observed crmLiveDecision
	for {
		select {
		case <-ctx.Done():
			return observed, ctx.Err()
		case <-deadline.C:
			if observed.Selected {
				return observed, nil
			}
			return observed, errors.New("exact CRM decision not observed")
		case <-ticker.C:
		}
		rows, err := s.readDecisionWindow(ctx, "")
		if err != nil {
			continue
		}
		for _, row := range rows {
			if candidate, ok := crmLiveSelectedDecision(row, record, snap, eventUID); ok {
				matched := row
				bindDecisionRecord(record, &matched)
				if !observed.Selected {
					observed = candidate
				} else if observed.DecisionID == candidate.DecisionID && candidate.Actuated {
					observed.Actuated = true
				}
				if observed.Actuated {
					return observed, nil
				}
			}
		}
	}
}

func crmLiveSelectedDecision(row audit.Record, record *attackRecord, snap crmLiveSnapshot, eventUID string) (crmLiveDecision, bool) {
	trace := row.DecisionTrace
	if row.Kind != "phorvex.decision" || row.Namespace != "crm" || row.Pod != record.Pod ||
		row.Time.Before(record.started) || !row.Selected || trace == nil ||
		trace.DecisionID == "" || trace.TickID == "" || trace.AssetNamespace != "crm" || trace.AssetName != record.Pod ||
		trace.AssetUID != record.TargetUID || trace.PolicyNamespace != "crm" ||
		trace.PolicyName != crmLivePolicyName || trace.PolicyUID != snap.PolicyUID ||
		trace.SelectedAction != row.Action {
		return crmLiveDecision{}, false
	}
	matched, trusted := false, 0
	for _, event := range row.Events {
		if event.TrustVerdict != "trusted" || event.Weight <= 0 {
			continue
		}
		trusted++
		matched = matched || (event.EventUID == eventUID && event.TargetPodUID == record.TargetUID)
	}
	if !matched || trusted != 1 {
		return crmLiveDecision{}, false
	}
	return crmLiveDecision{Action: row.Action, DecisionID: trace.DecisionID, TickID: trace.TickID, Selected: true,
		Actuated: row.Actuated && row.DispatchOutcome == model.DispatchEmitted && trace.DispatchOutcome == model.DispatchEmitted}, true
}
