package actuator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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
	PolicyName          string `json:"policyName"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	TargetUID           string `json:"targetUID"`
	PeerUID             string `json:"peerUID"`
	EventName           string `json:"eventName"`
	EventUID            string `json:"eventUID"`
	ClientSHA256        string `json:"clientSHA256"`
	ConfigMapUID        string `json:"configMapUID"`
	ServiceUID          string `json:"serviceUID"`
	SourceSHA256        string `json:"sourceSHA256"`
	OperationID         string `json:"operationId"`
	SelectionDecisionID string `json:"selectionDecisionId"`
	TickID              string `json:"tickId"`
}

func litellmJournalName(policyUID, clientSHA string) string {
	h := sha256.Sum256([]byte(policyUID + ":" + clientSHA))
	return "phorvex-litellm-revoke-" + hex.EncodeToString(h[:12])
}

func litellmReceiptRaw(r litellmRevokeReceipt) string { raw, _ := json.Marshal(r); return string(raw) }
func litellmReadReceipt(cm *corev1.ConfigMap) (litellmRevokeReceipt, error) {
	var r litellmRevokeReceipt
	raw := cm.Data["receipt"]
	if len(raw) == 0 || len(raw) > 2048 {
		return r, errors.New("owned-client journal absent or oversized")
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&r); e != nil {
		return r, e
	}
	if _, e := d.Token(); e != io.EOF || raw != litellmReceiptRaw(r) || r.Version != 1 ||
		(r.Phase != "prepared" && r.Phase != "terminal-full") || !litellmclient.ValidSHA(r.ClientSHA256) ||
		!litellmclient.ValidSHA(r.SourceSHA256) || r.OperationID == "" || r.SelectionDecisionID != r.OperationID ||
		r.EventName == "" || r.EventUID == "" || r.TickID == "" {
		return litellmRevokeReceipt{}, errors.New("owned-client journal noncanonical or incomplete")
	}
	return r, nil
}

func litellmClientCapability(ctx context.Context, reader client.Reader, journalNamespace string, t Target) (bool, string) {
	if reader == nil || journalNamespace == "" || t.Namespace != litellmclient.Namespace || t.UID == "" || t.Pod == "" {
		return false, "litellm-client-revoke: authoritative reader, journal or target unavailable"
	}
	live, e := litellmclient.ValidateLive(ctx, reader, t.UID, "")
	if e != nil {
		return false, "litellm-client-revoke: " + e.Error()
	}
	if live.State.Active {
		return false, "litellm-client-revoke: owned client already denied"
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
		o.ObservedAt.IsZero() || time.Since(o.ObservedAt) < 0 || time.Since(o.ObservedAt) >= 60*time.Second {
		return litellmclient.Live{}, errors.New("owned-client request/observation authority incomplete")
	}
	live, e := litellmclient.ValidateLive(ctx, ec.Reader, o.TargetPodUID, o.PeerPodUID)
	if e != nil {
		return live, e
	}
	if live.ServiceUID != o.ServiceUID || live.PolicyUID != o.ConfigMapUID || live.ClientSHA256 != o.ClientSHA256 ||
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
		event.Spec.Rule.Source != "redteam" || event.CreationTimestamp.IsZero() ||
		event.CreationTimestamp.Time.Before(o.ObservedAt) || time.Since(event.CreationTimestamp.Time) >= 60*time.Second ||
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
		assertion.ServiceUID != o.ServiceUID || assertion.PolicyName != o.PolicyName ||
		assertion.PolicyUID != o.PolicyUID || assertion.PolicyGeneration != o.PolicyGeneration ||
		!assertion.ObservedAt.Equal(o.ObservedAt) {
		return live, errors.New("owned-client SecurityEvent assertion changed after selection")
	}
	return live, nil
}

type litellmGatewayState struct {
	Version      int                        `json:"version"`
	PodUID       string                     `json:"podUID"`
	SourceSHA256 string                     `json:"sourceSHA256"`
	ConfigMapUID string                     `json:"configMapUID"`
	ClientSHA256 string                     `json:"clientSHA256"`
	Active       bool                       `json:"active"`
	Revision     uint64                     `json:"revision"`
	OperationID  string                     `json:"operationId"`
	Ready        bool                       `json:"ready"`
	Counters     map[string]json.RawMessage `json:"counters"`
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

func litellmCheckGatewayState(ctx context.Context, ec EnactCtx, live litellmclient.Live, opID string, wantActive bool) error {
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
		url := "http://" + net.JoinHostPort(pod.IP, "4002") + "/v1/admission/state"
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
		reencoded, _ := json.Marshal(canonical)
		if !bytes.Equal(raw, reencoded) {
			return errors.New("owned-client gateway status noncanonical")
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&state) != nil || state.Version != 1 || state.PodUID != pod.UID ||
			state.SourceSHA256 != live.SourceSHA256 || state.ConfigMapUID != live.PolicyUID ||
			state.ClientSHA256 != live.ClientSHA256 || state.Active != wantActive ||
			state.OperationID != opID || !state.Ready || len(state.Counters) != 2 ||
			state.Counters["attacker"] == nil || state.Counters["control"] == nil {
			return errors.New("owned-client gateway effective state differs")
		}
		if (wantActive && state.Revision != 1) || (!wantActive && state.Revision != 0) {
			return errors.New("owned-client gateway effective revision differs")
		}
	}
	return nil
}

func litellmReadback(ctx context.Context, ec EnactCtx, live litellmclient.Live, opID string) error {
	return litellmCheckGatewayState(ctx, ec, live, opID, true)
}

// Projected ConfigMap files can lag a successful API-server CAS. Observe both
// exact sidecars for a finite interval; never issue another policy write.
func litellmAwaitReadback(ctx context.Context, ec EnactCtx, live litellmclient.Live, opID string) error {
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	var last error
	for {
		if last = litellmReadback(ctx, ec, live, opID); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("owned-client both-Pod effective readback deadline: %w", last)
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
	receipt := litellmRevokeReceipt{Version: 1, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		PolicyGeneration: req.PolicyGeneration, TargetUID: req.TargetUID, PeerUID: o.PeerPodUID, EventName: o.EventName, EventUID: o.EventUID,
		ClientSHA256: o.ClientSHA256, ConfigMapUID: o.ConfigMapUID, ServiceUID: o.ServiceUID,
		SourceSHA256: o.GatewaySourceSHA256, OperationID: req.OperationID, SelectionDecisionID: req.OperationID, TickID: req.TickID}
	journalName := litellmJournalName(req.PolicyUID, o.ClientSHA256)
	journal := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: ec.JournalNamespace, Name: journalName}
	newJournal := false
	if e = ec.Reader.Get(ctx, key, journal); apierrors.IsNotFound(e) {
		if live.State.Active {
			return HandlerResult{}, RefusedWithoutEffect(errors.New("owned client already denied without matching operation journal"))
		}
		if e = litellmCheckGatewayState(ctx, ec, live, "", false); e != nil {
			return HandlerResult{}, RefusedWithoutEffect(e)
		}
		journal = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ec.JournalNamespace, Name: journalName},
			Data: map[string]string{"receipt": litellmReceiptRaw(receipt)}}
		if e = ec.Client.Create(ctx, journal); e != nil {
			return HandlerResult{MutationKind: "partial"}, e
		}
		newJournal = true
	} else if e != nil {
		return HandlerResult{}, e
	} else {
		stored, parseErr := litellmReadReceipt(journal)
		comparison := stored
		comparison.Phase = "prepared"
		if parseErr != nil || comparison != receipt {
			return HandlerResult{}, RefusedWithoutEffect(errors.New("owned-client journal occupied by another operation"))
		}
		if !live.State.Active || live.State.OperationID != req.OperationID {
			return HandlerResult{MutationKind: "partial"}, errors.New("owned-client prepared journal requires reconciliation; no second CAS")
		}
		if stored.Phase == "terminal-full" {
			if e = litellmAwaitReadback(ctx, ec, live, req.OperationID); e != nil {
				return HandlerResult{MutationKind: "partial"}, e
			}
			return HandlerResult{MutationKind: "forward-only", NoEffect: NoEffectReconciled,
				ObjectsTouched: []string{req.Namespace + "/" + litellmclient.PolicyConfigMapName}}, nil
		}
	}
	if newJournal {
		cm := &corev1.ConfigMap{}
		if e = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: litellmclient.PolicyConfigMapName}, cm); e != nil {
			return HandlerResult{MutationKind: "partial"}, e
		}
		prior, parseErr := litellmclient.ParseState(cm.Data[litellmclient.PolicyKey])
		if parseErr != nil || string(cm.UID) != live.PolicyUID || cm.ResourceVersion != live.PolicyRV ||
			prior.Active || prior.ClientSHA256 != o.ClientSHA256 {
			return HandlerResult{MutationKind: "partial"}, errors.New("owned-client pre-CAS policy authority changed")
		}
		next := prior
		next.Active = true
		next.Revision = 1
		next.OperationID = req.OperationID
		encoded, encodeErr := litellmclient.EncodeState(next)
		if encodeErr != nil {
			return HandlerResult{MutationKind: "partial"}, encodeErr
		}
		cm.Data[litellmclient.PolicyKey] = encoded
		// One exact resourceVersion CAS. A lost acknowledgement is ambiguous and
		// never retried; the prepared journal prevents an unreviewed second write.
		if e = ec.Client.Update(ctx, cm); e != nil {
			return HandlerResult{MutationKind: "partial"}, e
		}
	}
	current, e := litellmclient.ValidateLive(ctx, ec.Reader, o.TargetPodUID, o.PeerPodUID)
	if e != nil || !current.State.Active || current.State.OperationID != req.OperationID ||
		current.PolicyUID != live.PolicyUID || current.ServiceUID != live.ServiceUID ||
		current.SourceSHA256 != live.SourceSHA256 {
		return HandlerResult{MutationKind: "partial"}, errors.New("owned-client post-CAS authority not confirmed")
	}
	if e = litellmAwaitReadback(ctx, ec, current, req.OperationID); e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}
	receipt.Phase = "terminal-full"
	journal.Data["receipt"] = litellmReceiptRaw(receipt)
	if e = ec.Client.Update(ctx, journal); e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}
	return HandlerResult{MutationKind: "forward-only", Emitted: true,
		ObjectsTouched: []string{req.Namespace + "/" + litellmclient.PolicyConfigMapName, ec.JournalNamespace + "/" + journalName},
		Note:           fmt.Sprintf("owned LiteLLM client deny effective on both gateway Pods for operation %s", req.OperationID)}, nil
}

func init() { HandlerRegistry.Register(litellmClientRevokeHandler{}) }
