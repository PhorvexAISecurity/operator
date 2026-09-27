package actuator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/endpointlease"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const endpointLeaseConsoleCreator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"

// Status is private, TLS authenticated, fixed Pod-IP/port/path, and contains
// HMAC IDs only. Neither the caller bearer nor its HMAC seed reaches this code.
func endpointLeaseStatus(ctx context.Context, ec EnactCtx, pod endpointlease.Pod, live endpointlease.Live,
	oldID, retainedID string, wantOldAllowed, wantDrained bool) error {
	var httpClient *http.Client
	token := ec.EndpointLeaseStatusToken
	if ec.EndpointLeaseStatusTransport != nil {
		httpClient = &http.Client{Transport: ec.EndpointLeaseStatusTransport, Timeout: 3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("endpoint lease status redirect refused")
			}}
	} else if ec.ServingAttempt != nil && !ec.ServingAttempt.legacy {
		httpClient, token = ec.ServingAttempt.client, ec.ServingAttempt.token
	}
	if httpClient == nil || len(token) < 32 || net.ParseIP(pod.IP) == nil {
		return errors.New("endpoint lease authenticated fixed-Pod status unavailable")
	}
	query := url.Values{"revokedClientHMAC": {oldID}, "retainedClientHMAC": {retainedID}}
	endpoint := "https://" + net.JoinHostPort(pod.IP, "8443") + endpointlease.StatusPath + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	contentType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || parseErr != nil || contentType != "application/json" {
		return errors.New("endpoint lease authenticated proxy status unavailable or wrong media type")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, endpointlease.MaxStatusBytes+1))
	if err != nil || len(raw) > endpointlease.MaxStatusBytes {
		return errors.New("endpoint lease status body unavailable or oversized")
	}
	status, err := endpointlease.ParseStatus(string(raw))
	if err != nil {
		return err
	}
	if status.PodUID != pod.UID || status.ServiceUID != live.ServiceUID || status.ProxySourceSHA256 != live.SourceSHA256 ||
		status.PolicyConfigMapUID != live.PolicyUID || status.SecretUID != live.SecretUID || status.SeedSHA256 != live.SeedSHA256 ||
		status.Revision != live.State.Revision || status.LastOperationID != live.State.LastOperationID || status.StateSHA256 != live.StateSHA256 ||
		status.RevokedClientHMAC != oldID || status.RetainedClientHMAC != retainedID || status.RevokedClientAllowed != wantOldAllowed ||
		!status.RetainedClientAllowed || !status.Ready || (wantDrained && status.OldRevisionInFlight != 0) {
		return errors.New("endpoint lease effective proxy state differs from durable policy or drain")
	}
	return nil
}

func endpointLeaseStatusAll(ctx context.Context, ec EnactCtx, live endpointlease.Live, oldID, retainedID string, wantOldAllowed, wantDrained bool) error {
	for _, pod := range live.Pods {
		if err := endpointLeaseStatus(ctx, ec, pod, live, oldID, retainedID, wantOldAllowed, wantDrained); err != nil {
			return fmt.Errorf("endpoint lease Pod %s status: %w", pod.UID, err)
		}
	}
	return nil
}

func endpointLeaseSameIncarnations(live endpointlease.Live, r endpointLeaseReceipt) bool {
	return reflect.DeepEqual(endpointLeasePreCASUIDs(live.Pods), r.PreCASPodUIDs) &&
		reflect.DeepEqual(endpointLeasePreCASContainerIDs(live.Pods), r.PreCASProxyContainerIDs)
}

func endpointLeaseCapability(ctx context.Context, reader client.Reader, journalNamespace string, t Target, security *ServingSecurityConfig,
	approvedSource, approvedImage, approvedEngineImage string, transport http.RoundTripper, testToken string) (bool, string) {
	if reader == nil || journalNamespace == "" || t.Namespace != endpointlease.Namespace || t.UID == "" || t.Pod == "" || t.PolicyName == "" || t.PolicyUID == "" {
		return false, "endpoint-lease-revoke: authoritative target/journal unavailable"
	}
	live, err := endpointlease.ValidateLive(ctx, reader, t.UID, approvedSource, approvedImage, approvedEngineImage)
	if err != nil {
		return false, "endpoint-lease-revoke: " + err.Error()
	}
	_, doc, err := endpointLeaseProtectedJournal(ctx, reader, journalNamespace)
	if err != nil || !doc.matchesState(live) {
		return false, "endpoint-lease-revoke: protected prior history unresolved"
	}
	if len(live.State.AllowedClientHMACs) < 2 {
		return false, "endpoint-lease-revoke: no A/B overlap available for reviewed cutover"
	}
	ec := EnactCtx{Reader: reader, EndpointLeaseStatusTransport: transport, EndpointLeaseStatusToken: testToken}
	if transport == nil {
		if security == nil || security.mode != ServingSecuritySecureRequired {
			return false, "endpoint-lease-revoke: secure admin binding unavailable"
		}
		binding, ok := security.binding(t.Namespace, t.PolicyName, t.PolicyUID, normalizeServiceAccount(t.ServiceAccount))
		if !ok {
			return false, "endpoint-lease-revoke: exact admin binding unavailable"
		}
		ec.ServingAttempt, err = security.snapshotForBinding(ctx, reader, binding)
		if err != nil {
			return false, "endpoint-lease-revoke: authenticated admin status unavailable"
		}
	}
	if err = endpointLeaseStatusAll(ctx, ec, live, live.State.AllowedClientHMACs[0], live.State.AllowedClientHMACs[1], true, false); err != nil {
		return false, "endpoint-lease-revoke: authenticated proxy A/B readiness unavailable"
	}
	return true, ""
}

func endpointLeaseDispatchAuthority(ctx context.Context, ec EnactCtx, req Request) (endpointlease.Live, error) {
	o := req.EndpointLeaseObservation
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || req.Action != model.ActionEndpointLeaseRevoke ||
		req.Namespace != endpointlease.Namespace || req.Pod == "" || !endpointlease.ValidUID(req.TargetUID) ||
		req.PolicyName == "" || !endpointlease.ValidUID(req.PolicyUID) || req.PolicyGeneration < 1 ||
		!endpointlease.ValidOperationID(req.OperationID) || req.TickID == "" || len(req.TickID) > 128 || o == nil ||
		!endpointlease.ValidSHA(ec.EndpointLeaseApprovedSourceSHA256) || ec.EndpointLeaseApprovedProxyImage == "" || ec.EndpointLeaseApprovedEngineImage == "" ||
		o.TargetPodUID != req.TargetUID || o.PolicyName != req.PolicyName || o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration ||
		o.CreatorIdentity != endpointLeaseConsoleCreator || o.ScenarioID != "ai2-endpoint-security" || o.EvidenceSource != "TEST_INJECTED" ||
		o.EventName == "" || !endpointlease.ValidUID(o.EventUID) || o.AcceptedStatus != 200 || o.RetainedBaselineStatus != 200 ||
		o.ObservedAt.IsZero() || o.ObservedAt.After(time.Now()) || time.Since(o.ObservedAt) >= 60*time.Second {
		return endpointlease.Live{}, errors.New("endpoint lease selected observation or trusted configuration incomplete")
	}
	live, err := endpointlease.ValidateLive(ctx, ec.Reader, req.TargetUID, ec.EndpointLeaseApprovedSourceSHA256, ec.EndpointLeaseApprovedProxyImage, ec.EndpointLeaseApprovedEngineImage)
	if err != nil {
		return live, err
	}
	if live.ServiceUID != o.ServiceUID || live.PolicyUID != o.PolicyConfigMapUID || live.SecretUID != o.SecretUID ||
		live.SeedSHA256 != o.SeedSHA256 || live.SourceSHA256 != o.ProxySourceSHA256 || live.State.Revision != o.PriorRevision {
		return live, errors.New("endpoint lease selected Service/policy/Secret/source revision drift")
	}
	found := false
	for _, p := range live.Pods {
		if p.UID == req.TargetUID && p.Name == req.Pod {
			found = true
		}
	}
	if !found {
		return live, errors.New("endpoint lease selected target Pod name/UID changed")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.PolicyName}, policy); err != nil {
		return live, err
	}
	if string(policy.UID) != req.PolicyUID || policy.Generation != req.PolicyGeneration || policy.DeletionTimestamp != nil || policy.Spec.IsDryRun() || !policyActionEnabled(policy, req.Action) {
		return live, errors.New("endpoint lease selecting policy epoch or action changed")
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || selector.Empty() {
		return live, errors.New("endpoint lease selecting policy selector invalid")
	}
	pod := &corev1.Pod{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		return live, err
	}
	if string(pod.UID) != req.TargetUID || !selector.Matches(labels.Set(pod.Labels)) || pod.Annotations["phorvex.ai/endpoint-lease-event-creator"] != endpointLeaseConsoleCreator {
		return live, errors.New("endpoint lease target left selecting policy or creator scope")
	}
	event := &amtdv1beta1.SecurityEvent{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, event); err != nil {
		return live, err
	}
	if event.DeletionTimestamp != nil || string(event.UID) != o.EventUID || event.Spec.Rule.Type != endpointlease.RuleType || event.Spec.Rule.Source != "redteam" ||
		event.Annotations["phorvex.ai/creator-identity"] != endpointLeaseConsoleCreator ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != req.TargetUID || len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod ||
		event.CreationTimestamp.IsZero() || o.ObservedAt.After(event.CreationTimestamp.Time.Add(time.Second)) ||
		event.CreationTimestamp.Time.Sub(o.ObservedAt) >= 60*time.Second || time.Since(event.CreationTimestamp.Time) >= 60*time.Second {
		return live, errors.New("endpoint lease exact trusted SecurityEvent changed")
	}
	parsed, err := endpointlease.ParseObservation(event.Annotations[endpointlease.ObservationAnnotation])
	if err != nil || parsed.ScenarioID != o.ScenarioID || parsed.EvidenceSource != o.EvidenceSource || parsed.PolicyName != o.PolicyName ||
		parsed.PolicyUID != o.PolicyUID || parsed.PolicyGeneration != o.PolicyGeneration || parsed.TargetPodUID != o.TargetPodUID ||
		parsed.ServiceUID != o.ServiceUID || parsed.PolicyConfigMapUID != o.PolicyConfigMapUID || parsed.ProxySourceSHA256 != o.ProxySourceSHA256 ||
		parsed.SecretUID != o.SecretUID || parsed.SeedSHA256 != o.SeedSHA256 || parsed.PriorRevision != o.PriorRevision ||
		parsed.RevokedClientHMAC != o.RevokedClientHMAC || parsed.RetainedClientHMAC != o.RetainedClientHMAC ||
		parsed.AcceptedStatus != o.AcceptedStatus || parsed.AcceptedResponseSHA256 != o.AcceptedResponseSHA256 ||
		parsed.RetainedBaselineStatus != o.RetainedBaselineStatus || parsed.RetainedBaselineResponseSHA256 != o.RetainedBaselineResponseSHA256 ||
		!parsed.ObservedAt.Equal(o.ObservedAt) {
		return live, errors.New("endpoint lease selected event assertion changed")
	}
	return live, nil
}

type endpointLeaseRevokeHandler struct{}

func (endpointLeaseRevokeHandler) Name() string { return string(model.ActionEndpointLeaseRevoke) }
func (endpointLeaseRevokeHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	live, err := endpointLeaseDispatchAuthority(ctx, ec, req)
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(err)
	}
	o := req.EndpointLeaseObservation
	next, err := live.State.Revoke(o.RevokedClientHMAC, o.RetainedClientHMAC, req.OperationID)
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(err)
	}
	nextRaw, err := endpointlease.EncodeState(next)
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(err)
	}
	receipt := endpointLeaseReceipt{Phase: "prepared", AbortReason: "", OperationID: req.OperationID, EventName: o.EventName, EventUID: o.EventUID,
		DecisionID: req.OperationID, TickID: req.TickID, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration,
		Namespace: req.Namespace, TargetPodName: req.Pod, TargetPodUID: req.TargetUID, ServiceUID: live.ServiceUID, ProxySourceSHA256: live.SourceSHA256,
		PolicyConfigMapUID: live.PolicyUID, SecretUID: live.SecretUID, SeedSHA256: live.SeedSHA256, OldRevision: live.State.Revision,
		NewRevision: next.Revision, OldStateSHA256: live.StateSHA256, NewStateSHA256: endpointlease.SHA256([]byte(nextRaw)),
		RevokedClientHMAC: o.RevokedClientHMAC, RetainedClientHMAC: o.RetainedClientHMAC,
		PreCASPodUIDs: endpointLeasePreCASUIDs(live.Pods), PreCASProxyContainerIDs: endpointLeasePreCASContainerIDs(live.Pods)}
	journal, doc, err := endpointLeaseProtectedJournal(ctx, ec.Reader, ec.JournalNamespace)
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(err)
	}
	if !doc.matchesState(live) {
		return HandlerResult{}, RefusedWithoutEffect(errors.New("endpoint lease prior protected history unresolved"))
	}
	if err = endpointLeaseStatusAll(ctx, ec, live, o.RevokedClientHMAC, o.RetainedClientHMAC, true, false); err != nil {
		return HandlerResult{}, RefusedWithoutEffect(err)
	}
	doc, err = doc.append(receipt)
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(err)
	}
	journal.Data[endpointlease.JournalKey] = endpointLeaseJournalRaw(doc)
	if err = ec.Client.Update(ctx, journal); err != nil {
		return HandlerResult{MutationKind: "partial"}, err
	}
	// The prepared intent is durable before any policy write. Re-read current
	// authority and send precisely one resourceVersion-CAS update.
	current, err := endpointlease.ValidateLive(ctx, ec.Reader, req.TargetUID, ec.EndpointLeaseApprovedSourceSHA256, ec.EndpointLeaseApprovedProxyImage, ec.EndpointLeaseApprovedEngineImage)
	if err != nil || current.PolicyUID != live.PolicyUID || current.PolicyRV != live.PolicyRV || current.StateSHA256 != live.StateSHA256 ||
		!endpointLeaseSameIncarnations(current, receipt) {
		if abortErr := endpointLeaseAbortNoWrite(ctx, ec, receipt, "pre-cas-authority-changed"); abortErr != nil {
			return HandlerResult{MutationKind: "partial"}, fmt.Errorf("endpoint lease pre-CAS authority changed; protected abort unresolved: %w", abortErr)
		}
		return HandlerResult{MutationKind: "partial"}, errors.New("endpoint lease pre-CAS policy or proxy authority changed")
	}
	policyCM := &corev1.ConfigMap{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: endpointlease.Namespace, Name: endpointlease.PolicyConfigMapName}, policyCM); err != nil {
		return HandlerResult{MutationKind: "partial"}, err
	}
	if string(policyCM.UID) != live.PolicyUID || policyCM.ResourceVersion != live.PolicyRV || endpointlease.SHA256([]byte(policyCM.Data[endpointlease.PolicyKey])) != live.StateSHA256 {
		if abortErr := endpointLeaseAbortNoWrite(ctx, ec, receipt, "pre-cas-authority-changed"); abortErr != nil {
			return HandlerResult{MutationKind: "partial"}, fmt.Errorf("endpoint lease policy changed before CAS; protected abort unresolved: %w", abortErr)
		}
		return HandlerResult{MutationKind: "partial"}, errors.New("endpoint lease policy changed before one CAS")
	}
	policyCM.Data[endpointlease.PolicyKey] = nextRaw
	if err = ec.Client.Update(ctx, policyCM); err != nil {
		// A 409 is a definite failed CAS only when a fresh exact policy read
		// still has the old state. A timeout/lost ACK is never classified so.
		if apierrors.IsConflict(err) {
			if abortErr := endpointLeaseAbortNoWrite(ctx, ec, receipt, "definitive-policy-conflict"); abortErr != nil {
				return HandlerResult{MutationKind: "partial"}, fmt.Errorf("endpoint lease CAS conflict; protected abort unresolved: %w", abortErr)
			}
		}
		return HandlerResult{MutationKind: "partial"}, err
	}
	if err = endpointLeaseAwaitReadback(ctx, ec, receipt); err != nil {
		return HandlerResult{MutationKind: "partial"}, err
	}
	if err = endpointLeaseTerminal(ctx, ec, receipt); err != nil {
		return HandlerResult{MutationKind: "partial"}, err
	}
	return HandlerResult{MutationKind: "forward-only", Emitted: true,
		ObjectsTouched: []string{req.Namespace + "/" + endpointlease.PolicyConfigMapName, ec.JournalNamespace + "/" + endpointlease.JournalName},
		Note:           "exact caller lease revoked after durable policy CAS and all original/current proxy drain readback"}, nil
}

func endpointLeaseReadback(ctx context.Context, ec EnactCtx, r endpointLeaseReceipt) error {
	live, err := endpointlease.ValidateLive(ctx, ec.Reader, r.TargetPodUID, ec.EndpointLeaseApprovedSourceSHA256, ec.EndpointLeaseApprovedProxyImage, ec.EndpointLeaseApprovedEngineImage)
	if err != nil {
		return err
	}
	if live.PolicyUID != r.PolicyConfigMapUID || live.ServiceUID != r.ServiceUID || live.SourceSHA256 != r.ProxySourceSHA256 ||
		live.SecretUID != r.SecretUID || live.SeedSHA256 != r.SeedSHA256 || live.State.Revision != r.NewRevision ||
		live.State.LastOperationID != r.OperationID || live.StateSHA256 != r.NewStateSHA256 || !endpointLeaseSameIncarnations(live, r) {
		return errors.New("endpoint lease durable policy or original proxy incarnation readback differs")
	}
	if err = endpointLeaseStatusAll(ctx, ec, live, r.RevokedClientHMAC, r.RetainedClientHMAC, false, true); err != nil {
		return err
	}
	// A replacement during HTTP readback cannot inherit old in-flight proof.
	final, err := endpointlease.ValidateLive(ctx, ec.Reader, r.TargetPodUID, ec.EndpointLeaseApprovedSourceSHA256, ec.EndpointLeaseApprovedProxyImage, ec.EndpointLeaseApprovedEngineImage)
	if err != nil || final.StateSHA256 != live.StateSHA256 || !endpointLeaseSameIncarnations(final, r) {
		return errors.New("endpoint lease Service membership changed during effective readback")
	}
	return nil
}

func endpointLeaseAwaitReadback(ctx context.Context, ec EnactCtx, r endpointLeaseReceipt) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var last error
	for {
		if last = endpointLeaseReadback(ctx, ec, r); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("endpoint lease effective readback pending: %w", last)
		case <-tick.C:
		}
	}
}

func endpointLeaseTerminal(ctx context.Context, ec EnactCtx, prepared endpointLeaseReceipt) error {
	journal, doc, err := endpointLeaseProtectedJournal(ctx, ec.Reader, ec.JournalNamespace)
	if err != nil {
		return err
	}
	i := doc.index(prepared.OperationID)
	if i < 0 || !reflect.DeepEqual(doc.Receipts[i], prepared) {
		return errors.New("endpoint lease protected prepared receipt changed")
	}
	doc.Receipts[i].Phase = "terminal-full"
	journal.Data[endpointlease.JournalKey] = endpointLeaseJournalRaw(doc)
	return ec.Client.Update(ctx, journal)
}

func endpointLeaseAbortNoWrite(ctx context.Context, ec EnactCtx, prepared endpointLeaseReceipt, reason string) error {
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: endpointlease.Namespace, Name: endpointlease.PolicyConfigMapName}, cm); err != nil {
		return err
	}
	if string(cm.UID) != prepared.PolicyConfigMapUID || endpointlease.SHA256([]byte(cm.Data[endpointlease.PolicyKey])) != prepared.OldStateSHA256 {
		return errors.New("endpoint lease aborted CAS cannot prove old policy unchanged")
	}
	journal, doc, err := endpointLeaseProtectedJournal(ctx, ec.Reader, ec.JournalNamespace)
	if err != nil {
		return err
	}
	i := doc.index(prepared.OperationID)
	if i < 0 || !reflect.DeepEqual(doc.Receipts[i], prepared) {
		return errors.New("endpoint lease protected abort receipt changed")
	}
	doc.Receipts[i].Phase = "aborted"
	doc.Receipts[i].AbortReason = reason
	journal.Data[endpointlease.JournalKey] = endpointLeaseJournalRaw(doc)
	return ec.Client.Update(ctx, journal)
}

func init() { HandlerRegistry.Register(endpointLeaseRevokeHandler{}) }
