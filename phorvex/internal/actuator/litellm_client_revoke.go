package actuator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const litellmStatusTokenPath = "/etc/phorvex-litellm-status/token"

type litellmRevokeReceipt struct {
	Version             int    `json:"version"`
	Phase               string `json:"phase"`
	AbortReason         string `json:"abortReason"`
	PolicyName          string `json:"policyName"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	TargetUID           string `json:"targetUID"`
	PeerUID             string `json:"peerUID"`
	EventName           string `json:"eventName"`
	EventUID            string `json:"eventUID"`
	ClientSHA256        string `json:"clientSHA256"`
	ConfigMapUID        string `json:"configMapUID"`
	ClientsConfigMapUID string `json:"clientsConfigMapUID"`
	SeedSHA256          string `json:"seedSHA256"`
	ServiceUID          string `json:"serviceUID"`
	SourceSHA256        string `json:"sourceSHA256"`
	OperationID         string `json:"operationId"`
	SelectionDecisionID string `json:"selectionDecisionId"`
	TickID              string `json:"tickId"`
}

func litellmClientCapability(ctx context.Context, reader client.Reader, journalNamespace string, t Target) (bool, string) {
	if reader == nil || journalNamespace == "" || t.Namespace != litellmclient.Namespace || t.UID == "" || t.Pod == "" {
		return false, "litellm-client-revoke: authoritative reader, journal or target unavailable"
	}
	live, e := litellmclient.ValidateLive(ctx, reader, t.UID, "")
	if e != nil {
		return false, "litellm-client-revoke: " + e.Error()
	}
	if len(live.State.Entries) >= 256 {
		return false, "litellm-client-revoke: owned-client policy capacity exhausted"
	}
	journal := &corev1.ConfigMap{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: journalNamespace, Name: litellmclient.JournalName}, journal); e != nil {
		return false, "litellm-client-revoke: protected journal unavailable"
	}
	doc, e := litellmReadJournal(journal)
	if e != nil || !doc.matchesPolicy(live.State) {
		return false, "litellm-client-revoke: protected prior history unresolved"
	}
	return true, ""
}

func litellmRevokeAuthority(ctx context.Context, ec EnactCtx, req Request) (litellmclient.Live, error) {
	o := req.LiteLLMClientObservation
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || req.Action != model.ActionLiteLLMClientRevoke ||
		req.Namespace != litellmclient.Namespace || req.TargetUID == "" || req.Pod == "" || req.PolicyName == "" ||
		req.PolicyUID == "" || req.PolicyGeneration < 1 || req.OperationID == "" || len(req.OperationID) > 128 || req.TickID == "" ||
		o == nil || o.TargetPodUID != req.TargetUID || o.PeerPodUID == "" || o.EventUID == "" ||
		o.PolicyName != req.PolicyName || o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration ||
		o.GatewaySourceSHA256 != litellmclient.ApprovedSourceSHA256 || !litellmclient.ValidSHA(o.ClientSHA256) ||
		o.ClientsConfigMapUID == "" || !litellmclient.ValidSHA(o.SeedSHA256) ||
		o.ObservedAt.IsZero() || time.Since(o.ObservedAt) < 0 || time.Since(o.ObservedAt) >= 60*time.Second {
		return litellmclient.Live{}, errors.New("owned-client request/observation authority incomplete")
	}
	live, e := litellmclient.ValidateLive(ctx, ec.Reader, o.TargetPodUID, o.PeerPodUID)
	if e != nil {
		return live, e
	}
	if live.ServiceUID != o.ServiceUID || live.PolicyUID != o.ConfigMapUID ||
		live.ClientsUID != o.ClientsConfigMapUID || live.SeedSHA256 != o.SeedSHA256 ||
		live.SourceSHA256 != o.GatewaySourceSHA256 {
		return live, errors.New("owned-client source, Service or credential drift")
	}
	foundTarget := false
	for _, pod := range live.Pods {
		if pod.UID == req.TargetUID && pod.Name == req.Pod {
			foundTarget = true
		}
	}
	if !foundTarget {
		return live, errors.New("owned-client selected Pod name/UID differs")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.PolicyName}, policy); e != nil {
		return live, e
	}
	if string(policy.UID) != req.PolicyUID || policy.Generation != req.PolicyGeneration || policy.DeletionTimestamp != nil {
		return live, errors.New("owned-client selecting policy epoch changed")
	}
	enabled := false
	for _, action := range policy.Spec.Actions.Enabled {
		if string(action) == string(model.ActionLiteLLMClientRevoke) {
			enabled = true
		}
	}
	if !enabled {
		return live, errors.New("owned-client action absent from selecting policy")
	}
	pod := &corev1.Pod{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); e != nil {
		return live, e
	}
	sel, e := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if e != nil || sel.Empty() || !sel.Matches(labels.Set(pod.Labels)) || string(pod.UID) != req.TargetUID {
		return live, errors.New("owned-client target left policy selector")
	}
	event := &amtdv1beta1.SecurityEvent{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, event); e != nil {
		return live, e
	}
	if event.DeletionTimestamp != nil || string(event.UID) != o.EventUID || event.Spec.Rule.Type != litellmclient.RuleType ||
		event.Spec.Rule.Source != "redteam" || !litellmEventTimeMatches(event.CreationTimestamp.Time, o.ObservedAt, time.Now()) ||
		event.Annotations["phorvex.ai/creator-identity"] != o.CreatorIdentity ||
		o.CreatorIdentity != "system:serviceaccount:phorvex-system:phorvex-phorvex-console" ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != req.TargetUID ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod ||
		event.Annotations[litellmclient.ObservationAnnotation] == "" {
		return live, errors.New("owned-client trusted exact SecurityEvent changed")
	}
	assertion, e := litellmclient.ParseObservation(event.Annotations[litellmclient.ObservationAnnotation])
	if e != nil || assertion.TargetPodUID != o.TargetPodUID || assertion.PeerPodUID != o.PeerPodUID ||
		assertion.ClientSHA256 != o.ClientSHA256 || assertion.ConfigMapUID != o.ConfigMapUID ||
		assertion.ClientsConfigMapUID != o.ClientsConfigMapUID || assertion.SeedSHA256 != o.SeedSHA256 ||
		assertion.ServiceUID != o.ServiceUID || assertion.PolicyName != o.PolicyName ||
		assertion.PolicyUID != o.PolicyUID || assertion.PolicyGeneration != o.PolicyGeneration ||
		!assertion.ObservedAt.Equal(o.ObservedAt) {
		return live, errors.New("owned-client SecurityEvent assertion changed after selection")
	}
	return live, nil
}

// Kubernetes SecurityEvent CreationTimestamp has second precision on common
// API-server paths. An observation made during that same second can therefore
// appear later than the stored creation time without being a future assertion.
func litellmEventTimeMatches(created, observed, now time.Time) bool {
	return !created.IsZero() && !observed.IsZero() &&
		!observed.After(created.Add(time.Second)) && created.Sub(observed) < 60*time.Second &&
		!created.After(now.Add(time.Second)) && now.Sub(created) < 60*time.Second &&
		!observed.After(now) && now.Sub(observed) < 60*time.Second
}

type litellmGatewayState struct {
	Version      int    `json:"version"`
	PodUID       string `json:"podUID"`
	SourceSHA256 string `json:"sourceSHA256"`
	SeedSHA256   string `json:"seedSHA256"`
	ConfigMapUID string `json:"configMapUID"`
	ClientSHA256 string `json:"clientSHA256"`
	Active       bool   `json:"active"`
	Revision     uint64 `json:"revision"`
	OperationID  string `json:"operationId"`
	Role         string `json:"role"`
	Ready        bool   `json:"ready"`
	Counters     struct {
		ForwardedRequests   uint64 `json:"forwardedRequests"`
		UpstreamCompletions uint64 `json:"upstreamCompletions"`
		DeniedRequests      uint64 `json:"deniedRequests"`
		UsageTokens         uint64 `json:"usageTokens"`
	} `json:"counters"`
}

func litellmStatusToken() (string, error) {
	f, e := os.Open(litellmStatusTokenPath)
	if e != nil {
		return "", e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 257))
	if e != nil {
		return "", e
	}
	if len(raw) < 32 || len(raw) > 256 || bytes.ContainsAny(raw, "\r\n ") {
		return "", errors.New("owned-client operator status credential invalid")
	}
	return string(raw), nil
}

func litellmCheckGatewayState(ctx context.Context, ec EnactCtx, live litellmclient.Live, clientSHA, opID string, wantActive bool) error {
	if !litellmclient.ValidSHA(clientSHA) {
		return errors.New("owned-client status query hash invalid")
	}
	token := ec.LiteLLMStatusToken
	if token == "" {
		var e error
		token, e = litellmStatusToken()
		if e != nil {
			return e
		}
	}
	transport := ec.LiteLLMStatusTransport
	if transport == nil {
		transport = &http.Transport{Proxy: nil, MaxIdleConns: 0, DisableKeepAlives: true}
	}
	hc := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("owned-client status redirect refused")
	}}
	for _, pod := range live.Pods {
		if net.ParseIP(pod.IP) == nil {
			return errors.New("owned-client Pod IP invalid")
		}
		url := "http://" + net.JoinHostPort(pod.IP, "4002") + "/v1/admission/state?clientSHA256=" + clientSHA
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := hc.Do(req)
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 8193))
		resp.Body.Close()
		if e != nil || resp.StatusCode != http.StatusOK || len(raw) > 8192 {
			return errors.New("owned-client gateway status unavailable")
		}
		var state litellmGatewayState
		var canonical map[string]any
		if json.Unmarshal(raw, &canonical) != nil {
			return errors.New("owned-client gateway status malformed")
		}
		statusKeys := []string{"version", "podUID", "sourceSHA256", "seedSHA256", "configMapUID", "clientSHA256",
			"active", "revision", "operationId", "role", "ready", "counters"}
		if len(canonical) != len(statusKeys) {
			return errors.New("owned-client gateway status keyset differs")
		}
		for _, key := range statusKeys {
			if _, ok := canonical[key]; !ok {
				return errors.New("owned-client gateway status keyset differs")
			}
		}
		counterMap, ok := canonical["counters"].(map[string]any)
		if !ok || len(counterMap) != 4 {
			return errors.New("owned-client gateway counters keyset differs")
		}
		for _, key := range []string{"forwardedRequests", "upstreamCompletions", "deniedRequests", "usageTokens"} {
			if _, ok := counterMap[key]; !ok {
				return errors.New("owned-client gateway counters keyset differs")
			}
		}
		reencoded, _ := json.Marshal(canonical)
		if !bytes.Equal(raw, reencoded) {
			return errors.New("owned-client gateway status noncanonical")
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&state) != nil || state.Version != 2 || state.PodUID != pod.UID ||
			state.SourceSHA256 != live.SourceSHA256 || state.ConfigMapUID != live.PolicyUID ||
			state.SeedSHA256 != live.SeedSHA256 || state.ClientSHA256 != clientSHA ||
			state.Active != wantActive || state.OperationID != opID || state.Role != "attacker" ||
			!state.Ready || state.Counters.ForwardedRequests == 0 || state.Counters.UpstreamCompletions == 0 {
			return errors.New("owned-client gateway effective state differs")
		}
		if state.Revision != live.State.Revision {
			return errors.New("owned-client gateway effective revision differs")
		}
	}
	return nil
}

func litellmReadback(ctx context.Context, ec EnactCtx, live litellmclient.Live, clientSHA, opID string) error {
	return litellmCheckGatewayState(ctx, ec, live, clientSHA, opID, true)
}

// Projected ConfigMap files can lag a successful API-server CAS. Observe both
// exact sidecars for a finite interval; never issue another policy write.
// errLiteLLMReadbackPending marks a readback that did not see the deny on both gateway Pods
// within its bounded wait. Each gateway reads the policy from a projected ConfigMap volume,
// which the kubelet refreshes on its own sync cadence, so this commonly outlasts the wait
// although the CAS already landed.
var errLiteLLMReadbackPending = errors.New("owned-client both-Pod effective readback deadline")

func litellmAwaitReadback(ctx context.Context, ec EnactCtx, live litellmclient.Live, clientSHA, opID string) error {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	var last error
	for {
		if last = litellmReadback(ctx, ec, live, clientSHA, opID); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("%w: %w", errLiteLLMReadbackPending, last)
		case <-tick.C:
		}
	}
}

type litellmClientRevokeHandler struct{}

func (litellmClientRevokeHandler) Name() string { return string(model.ActionLiteLLMClientRevoke) }
func (litellmClientRevokeHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	live, e := litellmRevokeAuthority(ctx, ec, req)
	if e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	o := req.LiteLLMClientObservation
	// Prove the next canonical policy value fits the mounted gateway reader
	// before persisting a prepared intent. The later RV CAS still rechecks it.
	preview, previewErr := live.State.Append(o.ClientSHA256, req.OperationID)
	if previewErr != nil {
		return HandlerResult{}, RefusedWithoutEffect(previewErr)
	}
	if _, previewErr = litellmclient.EncodeState(preview); previewErr != nil {
		return HandlerResult{}, RefusedWithoutEffect(previewErr)
	}
	receipt := litellmRevokeReceipt{Version: 2, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		PolicyGeneration: req.PolicyGeneration, TargetUID: req.TargetUID, PeerUID: o.PeerPodUID, EventName: o.EventName, EventUID: o.EventUID,
		ClientSHA256: o.ClientSHA256, ConfigMapUID: o.ConfigMapUID,
		ClientsConfigMapUID: o.ClientsConfigMapUID, SeedSHA256: o.SeedSHA256, ServiceUID: o.ServiceUID,
		SourceSHA256: o.GatewaySourceSHA256, OperationID: req.OperationID, SelectionDecisionID: req.OperationID, TickID: req.TickID}
	journal := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: ec.JournalNamespace, Name: litellmclient.JournalName}
	newPrepared := false
	if e = ec.Reader.Get(ctx, key, journal); e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	journalDoc, e := litellmReadJournal(journal)
	if e != nil {
		return HandlerResult{}, RefusedWithoutEffect(e)
	}
	index := journalDoc.index(o.ClientSHA256)
	if index >= 0 {
		stored := journalDoc.Receipts[index]
		comparison := stored
		comparison.Phase = "prepared"
		entry, exists := live.State.Entry(o.ClientSHA256)
		if comparison != receipt || !exists || entry.OperationID != req.OperationID {
			return HandlerResult{}, RefusedWithoutEffect(errors.New("owned-client prior protected entry differs from same operation"))
		}
		if stored.Phase == "terminal-full" {
			if e = litellmAwaitReadback(ctx, ec, live, o.ClientSHA256, req.OperationID); e != nil {
				return HandlerResult{MutationKind: "partial"}, e
			}
			return HandlerResult{MutationKind: "forward-only", NoEffect: NoEffectReconciled,
				ObjectsTouched: []string{req.Namespace + "/" + litellmclient.PolicyConfigMapName}}, nil
		}
	} else {
		if !journalDoc.matchesPolicy(live.State) {
			return HandlerResult{}, RefusedWithoutEffect(errors.New("owned-client prior protected history is not terminal and joined"))
		}
		if _, exists := live.State.Entry(o.ClientSHA256); exists {
			return HandlerResult{}, RefusedWithoutEffect(errors.New("owned client already denied without protected entry"))
		}
		if e = litellmCheckGatewayState(ctx, ec, live, o.ClientSHA256, "", false); e != nil {
			return HandlerResult{}, RefusedWithoutEffect(e)
		}
		journalDoc, e = journalDoc.append(receipt)
		if e != nil {
			return HandlerResult{}, RefusedWithoutEffect(e)
		}
		journal.Data[litellmclient.JournalKey] = litellmJournalRaw(journalDoc)
		if e = ec.Client.Update(ctx, journal); e != nil {
			return HandlerResult{MutationKind: "partial"}, e
		}
		newPrepared = true
	}
	if newPrepared {
		cm := &corev1.ConfigMap{}
		if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: litellmclient.PolicyConfigMapName}, cm); e != nil {
			return HandlerResult{MutationKind: "partial"}, e
		}
		prior, parseErr := litellmclient.ParseState(cm.Data[litellmclient.PolicyKey])
		if parseErr != nil || string(cm.UID) != live.PolicyUID || cm.ResourceVersion != live.PolicyRV ||
			len(prior.Entries) != len(live.State.Entries) {
			if parseErr == nil {
				if abortErr := litellmAbortNoWrite(ctx, ec, receipt, "pre-cas-authority-changed"); abortErr != nil {
					return HandlerResult{MutationKind: "partial"}, abortErr
				}
			}
			return HandlerResult{MutationKind: "partial"}, errors.New("owned-client pre-CAS policy authority changed")
		}
		next, appendErr := prior.Append(o.ClientSHA256, req.OperationID)
		if appendErr != nil {
			return HandlerResult{MutationKind: "partial"}, appendErr
		}
		encoded, encodeErr := litellmclient.EncodeState(next)
		if encodeErr != nil {
			return HandlerResult{MutationKind: "partial"}, encodeErr
		}
		cm.Data[litellmclient.PolicyKey] = encoded
		// One exact resourceVersion CAS. A lost acknowledgement is ambiguous and
		// never retried; the prepared journal prevents an unreviewed second write.
		if e = ec.Client.Update(ctx, cm); e != nil {
			if apierrors.IsConflict(e) {
				if abortErr := litellmAbortNoWrite(ctx, ec, receipt, "definitive-policy-conflict"); abortErr != nil {
					return HandlerResult{MutationKind: "partial"}, fmt.Errorf("policy CAS conflict; protected abort unresolved: %w", abortErr)
				}
			}
			return HandlerResult{MutationKind: "partial"}, e
		}
	}
	current, e := litellmclient.ValidateLive(ctx, ec.Reader, o.TargetPodUID, o.PeerPodUID)
	entry, exists := current.State.Entry(o.ClientSHA256)
	if e != nil || !exists || !entry.Active || entry.OperationID != req.OperationID ||
		current.PolicyUID != live.PolicyUID || current.ServiceUID != live.ServiceUID ||
		current.SourceSHA256 != live.SourceSHA256 || current.ClientsUID != live.ClientsUID ||
		current.SeedSHA256 != live.SeedSHA256 {
		return HandlerResult{MutationKind: "partial"}, errors.New("owned-client post-CAS authority not confirmed")
	}
	if e = litellmAwaitReadback(ctx, ec, current, o.ClientSHA256, req.OperationID); e != nil {
		if errors.Is(e, errLiteLLMReadbackPending) {
			// The deny is written and confirmed by the API above; only the Pods' projected
			// readback is outstanding. Report an emitted, unconfirmed effect so the runner
			// counts the actuation; the journal stays "prepared" and protected recovery
			// (recoverPreparedLiteLLMClient) completes it once both gateways read it back.
			return HandlerResult{MutationKind: "partial", Emitted: true,
				ObjectsTouched: []string{req.Namespace + "/" + litellmclient.PolicyConfigMapName, ec.JournalNamespace + "/" + litellmclient.JournalName},
				Note:           fmt.Sprintf("owned LiteLLM client deny written for operation %s; both-gateway readback pending protected recovery", req.OperationID)}, nil
		}
		return HandlerResult{MutationKind: "partial"}, e
	}
	receipt.Phase = "terminal-full"
	freshJournal := &corev1.ConfigMap{}
	if e = ec.Reader.Get(ctx, key, freshJournal); e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}
	journalDoc, e = litellmReadJournal(freshJournal)
	if e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}
	index = journalDoc.index(o.ClientSHA256)
	prepared := receipt
	prepared.Phase = "prepared"
	if index < 0 || journalDoc.Receipts[index].Phase != "prepared" ||
		journalDoc.Receipts[index] != prepared {
		return HandlerResult{MutationKind: "partial"}, errors.New("owned-client prepared journal entry changed")
	}
	journalDoc.Receipts[index] = receipt
	freshJournal.Data[litellmclient.JournalKey] = litellmJournalRaw(journalDoc)
	if e = ec.Client.Update(ctx, freshJournal); e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}
	return HandlerResult{MutationKind: "forward-only", Emitted: true,
		ObjectsTouched: []string{req.Namespace + "/" + litellmclient.PolicyConfigMapName, ec.JournalNamespace + "/" + litellmclient.JournalName},
		Note:           fmt.Sprintf("owned LiteLLM client deny effective on both gateway Pods for operation %s", req.OperationID)}, nil
}

func init() { HandlerRegistry.Register(litellmClientRevokeHandler{}) }

// litellmAbortNoWrite retires a protected intent only after a definite
// pre-write refusal and a fresh read proving its credential has no policy
// entry. A timeout or lost acknowledgement must never reach this path.
func litellmAbortNoWrite(ctx context.Context, ec EnactCtx, prepared litellmRevokeReceipt, reason string) error {
	policy := &corev1.ConfigMap{}
	if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: litellmclient.Namespace, Name: litellmclient.PolicyConfigMapName}, policy); e != nil {
		return e
	}
	if string(policy.UID) != prepared.ConfigMapUID {
		return errors.New("owned-client abort policy UID changed")
	}
	state, e := litellmclient.ParseState(policy.Data[litellmclient.PolicyKey])
	if e != nil {
		return e
	}
	if _, exists := state.Entry(prepared.ClientSHA256); exists {
		return errors.New("owned-client abort credential may have been committed")
	}
	journal := &corev1.ConfigMap{}
	if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: litellmclient.JournalName}, journal); e != nil {
		return e
	}
	doc, e := litellmReadJournal(journal)
	if e != nil {
		return e
	}
	index := doc.index(prepared.ClientSHA256)
	if index < 0 || doc.Receipts[index] != prepared || prepared.Phase != "prepared" {
		return errors.New("owned-client abort prepared receipt changed")
	}
	aborted := prepared
	aborted.Phase = "aborted"
	aborted.AbortReason = reason
	doc.Receipts[index] = aborted
	if !doc.matchesPolicy(state) {
		return errors.New("owned-client abort prior policy history differs")
	}
	journal.Data[litellmclient.JournalKey] = litellmJournalRaw(doc)
	return ec.Client.Update(ctx, journal)
}
