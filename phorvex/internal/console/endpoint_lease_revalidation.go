package console

import (
	"context"
	"encoding/json"
	"errors"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// These reads reuse the normal current source/Secret/route checks. Revalidation
// has no event producer, chooser or actuator and never changes a protected row.
type endpointLeaseRevalidationReads struct {
	status   func(context.Context, corev1.Pod) (endpointLeaseStatus, error)
	public   func(context.Context, []byte) (endpointLeaseHTTPReceipt, error)
	snapshot func(context.Context) (endpointLeaseSnapshot, error)
	journal  func(context.Context) (*corev1.ConfigMap, error)
	archive  func(string, []byte) error
}

func endpointLeaseProtectionOrigin(snap endpointLeaseSnapshot, cm *corev1.ConfigMap, p endpointLeaseProfile) (endpointLeaseJournalReceipt, error) {
	bad := errors.New("exact historical A revocation or source-upgrade provenance unavailable")
	if cm == nil || cm.Namespace != "phorvex-system" || cm.Name != endpointLeaseJournalCM || string(cm.UID) != p.JournalUID || cm.ResourceVersion == "" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 ||
		len(snap.State.AllowedClientHMACs) != 1 || snap.State.AllowedClientHMACs[0] != p.ClientBHMAC ||
		len(snap.State.RevokedClientHMACs) != 1 || snap.State.RevokedClientHMACs[0] != p.ClientAHMAC {
		return endpointLeaseJournalReceipt{}, bad
	}
	raw := []byte(cm.Data["receipts.json"])
	j, err := parseEndpointLeaseJournal(raw)
	if err != nil || !retainedCallerAllowed(snap.State, j, p) ||
		p.SourceUpgrade != nil && endpointLeaseSHA(raw) != p.SourceUpgrade.PriorJournalSHA256 {
		return endpointLeaseJournalReceipt{}, bad
	}
	hash, revision, source := snap.StateSHA256, snap.State.Revision, p.ProxySourceSHA256
	if p.SourceUpgrade != nil {
		old, prior, priorErr := endpointLeaseUpgradePrior(p)
		if priorErr != nil {
			return endpointLeaseJournalReceipt{}, bad
		}
		hash, revision, source = p.SourceUpgrade.PriorStateSHA256, prior.Revision, old.ProxySourceSHA256
	}
	for _, row := range j.Receipts {
		if row.Phase == "terminal-full" && row.NewStateSHA256 == hash && row.NewRevision == revision &&
			row.OperationID == snap.State.LastOperationID && row.DecisionID == row.OperationID &&
			endpointLeaseOperationID.MatchString(row.OperationID) && staticUID.MatchString(row.EventUID) &&
			row.EventName != "" && row.TickID != "" && row.Namespace == "vllm" && row.PolicyName == p.PolicyName &&
			row.PolicyUID == p.PolicyUID && row.PolicyConfigMapUID == p.PolicyConfigMapUID && row.SecretUID == p.TenantSecretUID &&
			row.ServiceUID == p.ServiceUID && row.SeedSHA256 == p.SeedSHA256 && row.ProxySourceSHA256 == source &&
			row.RevokedClientHMAC == p.ClientAHMAC && row.RetainedClientHMAC == p.ClientBHMAC {
			return row, nil
		}
	}
	return endpointLeaseJournalReceipt{}, bad
}

func (s *Server) revalidateEndpointLease(ctx context.Context, record *attackRecord, p endpointLeaseProfile,
	snap endpointLeaseSnapshot, journal *corev1.ConfigMap, tokens endpointLeaseTokens, kube kubernetes.Interface, dir string) {
	config, err := restConfigFor("")
	if err != nil {
		record.EndpointLeaseProbe.Issues = append(record.EndpointLeaseProbe.Issues, "proxy state transport unavailable")
		return
	}
	reads := endpointLeaseRevalidationReads{
		status: func(ctx context.Context, pod corev1.Pod) (endpointLeaseStatus, error) {
			return endpointLeaseAdminState(ctx, config, kube, pod, p)
		},
		public: endpointLeasePublicCall,
		snapshot: func(ctx context.Context) (endpointLeaseSnapshot, error) {
			return s.endpointLeaseSnapshot(ctx, kube, p, tokens)
		},
		journal: func(ctx context.Context) (*corev1.ConfigMap, error) {
			return kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, endpointLeaseJournalCM, metav1.GetOptions{})
		},
		archive: func(name string, raw []byte) error { return publishMongoAuditFile(dir, name, raw, 256<<10) },
	}
	runEndpointLeaseRevalidation(ctx, record, p, snap, journal, tokens, reads)
}

func runEndpointLeaseRevalidation(ctx context.Context, record *attackRecord, p endpointLeaseProfile,
	snap endpointLeaseSnapshot, journal *corev1.ConfigMap, tokens endpointLeaseTokens, reads endpointLeaseRevalidationReads) {
	probe := record.EndpointLeaseProbe
	probe.SignalMode = "EXISTING_PROTECTION_REVALIDATION"
	probe.DefenseScope = "existing brain-issued revocation of this same owned caller A; current denial and legitimate B completion rechecked; no new selection or response credit"
	fail := func(reason string) { probe.Issues = append(probe.Issues, reason) }
	origin, err := endpointLeaseProtectionOrigin(snap, journal, p)
	if err != nil || len(snap.Pods) == 0 {
		fail("exact existing protection provenance unavailable")
		return
	}
	probe.HistoricalOperationID, probe.HistoricalEventName, probe.HistoricalEventUID, probe.HistoricalTickID = origin.OperationID, origin.EventName, origin.EventUID, origin.TickID
	probe.HistoricalJournalSHA256, probe.CurrentStateSHA256, probe.CurrentRevision = endpointLeaseSHA([]byte(journal.Data["receipts.json"])), snap.StateSHA256, snap.State.Revision
	probe.TargetPodUID = string(snap.Pods[0].UID)
	record.Pod, record.TargetUID = snap.Pods[0].Name, probe.TargetPodUID
	statusAll := func(stage string) bool {
		for _, pod := range snap.Pods {
			state, readErr := reads.status(ctx, pod)
			if readErr != nil || !endpointLeaseStatusMatches(state, p, snap, pod, true) {
				return false
			}
			raw, _ := json.Marshal(state)
			if reads.archive("revalidation-"+stage+"-"+string(pod.UID)+".json", raw) != nil {
				return false
			}
		}
		return true
	}
	if !statusAll("before") {
		fail("every current proxy effective A denial and B allowance unverified")
		return
	}
	if reads.archive("revalidation-journal-original.json", []byte(journal.Data["receipts.json"])) != nil {
		fail("historical protected journal archive unavailable")
		return
	}
	a, err := reads.public(ctx, tokens.A)
	if err != nil || reads.archive("revalidation-A-original.json", a.Raw) != nil {
		fail("actual A public response unavailable")
		return
	}
	probe.PostAStatus, probe.PostAExactDenial, probe.PostAResponseSHA256 = a.Status, a.ExactDenial, a.ResponseSHA256
	if a.Status == 200 && a.ValidCompletion {
		probe.Status, record.Outcome = "LANDED", "LANDED"
		fail("revoked A reached the real completion endpoint")
		return
	}
	if a.Status != 401 || !a.ExactDenial {
		fail("exact public A unauthorized denial unverified")
		return
	}
	b, err := reads.public(ctx, tokens.B)
	if err != nil || reads.archive("revalidation-B-original.json", b.Raw) != nil {
		fail("actual B public model completion unavailable")
		return
	}
	probe.PostBStatus, probe.PostBValidCompletion, probe.PostBResponseSHA256 = b.Status, b.ValidCompletion, b.ResponseSHA256
	if b.Status != 200 || !b.ValidCompletion {
		fail("legitimate B real valid completion unverified")
		return
	}
	if !statusAll("after") {
		fail("final every-proxy effective protection unverified")
		return
	}
	final, err := reads.snapshot(ctx)
	if err != nil || !endpointLeaseSameBefore(snap, final) || final.ConfigMapRV != snap.ConfigMapRV {
		fail("final source, route, policy or proxy incarnation changed")
		return
	}
	last, err := reads.journal(ctx)
	if err != nil || last == nil || last.UID != journal.UID || last.ResourceVersion != journal.ResourceVersion ||
		len(last.Data) != 1 || len(last.BinaryData) != 0 || last.Data["receipts.json"] != journal.Data["receipts.json"] {
		fail("final protected historical journal changed")
		return
	}
	probe.ProtectionRevalidated, probe.ProtectedJournalTerminal, probe.EveryServingPodEffective = true, true, true
	probe.Status, record.Outcome = "PROTECTION_REVALIDATED", "PROTECTION_REVALIDATED"
}
