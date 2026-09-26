package actuator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/outputpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const (
	outputPolicyReadbackTimeout  = 4 * time.Second
	outputPolicyReadbackInterval = 100 * time.Millisecond
	outputPolicyMaxStateBytes    = 4096
)

type outputPolicyReceipt struct {
	Version                          int                     `json:"version"`
	Kind                             string                  `json:"kind"`
	Phase                            string                  `json:"phase"`
	PolicyNamespace                  string                  `json:"policyNamespace"`
	PolicyName                       string                  `json:"policyName"`
	PolicyUID                        string                  `json:"policyUID"`
	PolicyGeneration                 int64                   `json:"policyGeneration"`
	TickID                           string                  `json:"tickId"`
	SelectionDecisionID              string                  `json:"selectionDecisionId"`
	TargetName                       string                  `json:"targetName"`
	TargetUID                        string                  `json:"targetUID"`
	EventName                        string                  `json:"eventName"`
	EventUID                         string                  `json:"eventUID"`
	CreatorIdentity                  string                  `json:"creatorIdentity"`
	ConfigMapName                    string                  `json:"configMapName"`
	ConfigMapUID                     string                  `json:"configMapUID"`
	SelectedConfigMapResourceVersion string                  `json:"selectedConfigMapResourceVersion"`
	SelectedRevision                 uint64                  `json:"selectedRevision"`
	RuleSHA256                       string                  `json:"ruleSHA256"`
	ProxySourceSHA256                string                  `json:"proxySourceSHA256"`
	SupportSourceSHA256              string                  `json:"supportSourceSHA256"`
	ProxyImageID                     string                  `json:"proxyImageID"`
	SupportImageID                   string                  `json:"supportImageID"`
	PodIP                            string                  `json:"podIP"`
	Prior                            outputpolicy.Activation `json:"prior"`
	Desired                          outputpolicy.Activation `json:"desired"`
	OperationID                      string                  `json:"operationId"`
}

func (r outputPolicyReceipt) valid() bool {
	if r.Version != 1 || r.Kind != string(model.ActionSensitiveOutputPolicyActivate) ||
		(r.Phase != "prepared" && r.Phase != "terminal-full" && r.Phase != "rollback-intent" && r.Phase != "rolled-back") ||
		r.PolicyNamespace == "" || r.PolicyName == "" || r.PolicyUID == "" || r.PolicyGeneration < 1 || r.TickID == "" || len(r.TickID) > 253 || r.SelectionDecisionID == "" || len(r.SelectionDecisionID) > 253 || r.TargetName == "" || r.TargetUID == "" ||
		r.EventName == "" || r.EventUID == "" || r.CreatorIdentity == "" || r.ConfigMapName != "phorvex-output-policy-"+r.TargetName ||
		r.ConfigMapUID == "" || r.SelectedConfigMapResourceVersion == "" || len(r.SelectedConfigMapResourceVersion) > 253 || r.SelectedRevision != r.Prior.Revision || r.RuleSHA256 != outputpolicy.RuleSHA256(r.TargetUID) ||
		!outputpolicy.ValidSHA(r.ProxySourceSHA256) || !outputpolicy.ValidSHA(r.SupportSourceSHA256) ||
		r.ProxyImageID == "" || r.SupportImageID == "" || !outputpolicy.ValidOperationID(r.OperationID) ||
		r.OperationID != outputPolicyOperationID(r.PolicyUID, r.TargetUID, r.EventUID, r.TickID, r.SelectionDecisionID) ||
		r.Prior.Version != 1 || r.Prior.RuleID != outputpolicy.RuleID || r.Prior.ConfigMapUID != r.ConfigMapUID || r.Prior.Active ||
		r.Desired.Version != 1 || r.Desired.RuleID != outputpolicy.RuleID || r.Desired.ConfigMapUID != r.ConfigMapUID || !r.Desired.Active ||
		r.Prior.Revision > uint64(1<<63)-3 || r.Desired.Revision != r.Prior.Revision+1 || r.Desired.OperationID != r.OperationID {
		return false
	}
	if _, err := outputpolicy.ParseActivation(string(r.Prior.Bytes()), r.ConfigMapUID); err != nil {
		return false
	}
	if _, err := outputpolicy.ParseActivation(string(r.Desired.Bytes()), r.ConfigMapUID); err != nil {
		return false
	}
	_, err := netip.ParseAddr(r.PodIP)
	return err == nil
}

func outputPolicyOperationID(policyUID, podUID, eventUID, tickID, decisionID string) string {
	h := sha256.Sum256([]byte("phorvex-output-policy-v1\x00" + policyUID + "\x00" + podUID + "\x00" + eventUID + "\x00" + tickID + "\x00" + decisionID))
	return hex.EncodeToString(h[:])
}

// A retry may resume only the exact selection that first claimed this slot.
// A later decision about the same event is a different operation.
func outputPolicyReceiptMatchesRequest(r outputPolicyReceipt, req Request) bool {
	o := req.OutputPolicyObservation
	return o != nil && req.Action == model.ActionSensitiveOutputPolicyActivate &&
		r.PolicyNamespace == req.Namespace && r.PolicyName == req.PolicyName &&
		r.PolicyUID == req.PolicyUID && r.PolicyGeneration == req.PolicyGeneration &&
		r.TickID == req.TickID && r.SelectionDecisionID == req.OperationID &&
		r.TargetName == req.Pod && r.TargetUID == req.TargetUID &&
		r.EventName == o.EventName && r.EventUID == o.EventUID &&
		r.CreatorIdentity == o.CreatorIdentity && r.ConfigMapUID == o.ConfigMapUID &&
		r.SelectedConfigMapResourceVersion == o.SelectedConfigMapResourceVersion &&
		r.SelectedRevision == o.SelectedRevision && r.RuleSHA256 == o.RuleSHA256 &&
		r.ProxySourceSHA256 == o.ProxySourceSHA256 &&
		r.SupportSourceSHA256 == o.SupportSourceSHA256 &&
		r.ProxyImageID == o.ProxyImageID && r.SupportImageID == o.SupportImageID &&
		r.OperationID == outputPolicyOperationID(req.PolicyUID, req.TargetUID, o.EventUID, req.TickID, req.OperationID)
}

func outputPolicyImageID(p *corev1.Pod, name string) string {
	for _, s := range p.Status.ContainerStatuses {
		if s.Name == name {
			return s.ImageID
		}
	}
	return ""
}

func outputPolicyCapability(ctx context.Context, reader client.Reader, journalNS string, target Target) (bool, string) {
	if reader == nil || journalNS == "" || target.Namespace == "" || target.Pod == "" || target.UID == "" {
		return false, "output-policy-authority-unavailable"
	}
	probe, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	pod := &corev1.Pod{}
	if err := reader.Get(probe, client.ObjectKey{Namespace: target.Namespace, Name: target.Pod}, pod); err != nil {
		return false, "output-policy-pod-read-failed"
	}
	if string(pod.UID) != target.UID || pod.DeletionTimestamp != nil || pod.Annotations["phorvex.ai/output-event-creator"] == "" ||
		outputPolicyImageID(pod, "guardrail-proxy") == "" || outputPolicyImageID(pod, "support-app") == "" {
		return false, "output-policy-pod-source-unbound"
	}
	if _, err := netip.ParseAddr(pod.Status.PodIP); err != nil {
		return false, "output-policy-pod-address-invalid"
	}
	cm := &corev1.ConfigMap{}
	if err := reader.Get(probe, client.ObjectKey{Namespace: target.Namespace, Name: pod.Annotations[outputpolicy.PodConfigMapAnnotation]}, cm); err != nil {
		return false, "output-policy-configmap-read-failed"
	}
	a, err := outputpolicy.ValidateConfigMap(cm, pod)
	if err != nil || a.Active {
		return false, "output-policy-rule-or-activation-invalid"
	}
	journal := &corev1.ConfigMap{}
	if err := reader.Get(probe, client.ObjectKey{Namespace: journalNS, Name: outputpolicy.JournalName(target.UID)}, journal); err == nil {
		old, parseErr := outputPolicyParseJournal(EnactCtx{JournalNamespace: journalNS}, journal)
		prior := old.Prior
		prior.Revision = old.Desired.Revision + 1
		prior.OperationID = old.OperationID
		if parseErr != nil || old.Phase != "rolled-back" || old.TargetUID != target.UID || old.PolicyUID != target.PolicyUID || a != prior {
			return false, "output-policy-operation-pending"
		}
	} else if !apierrors.IsNotFound(err) {
		return false, "output-policy-journal-read-failed"
	}
	return true, ""
}

func outputPolicyStatePod(p *corev1.Pod, r outputPolicyReceipt) error {
	if p == nil || p.Name != r.TargetName || p.Namespace != r.PolicyNamespace || string(p.UID) != r.TargetUID ||
		p.DeletionTimestamp != nil || p.Status.PodIP != r.PodIP || p.ResourceVersion == "" ||
		p.Annotations[outputpolicy.PodConfigMapAnnotation] != r.ConfigMapName ||
		p.Annotations[outputpolicy.PodRuleSHAAnnotation] != r.RuleSHA256 ||
		p.Annotations[outputpolicy.PodProxySHAAnnotation] != r.ProxySourceSHA256 ||
		p.Annotations[outputpolicy.PodSupportSHAAnnotation] != r.SupportSourceSHA256 ||
		p.Annotations["phorvex.ai/output-event-creator"] != r.CreatorIdentity ||
		outputPolicyImageID(p, "guardrail-proxy") != r.ProxyImageID ||
		outputPolicyImageID(p, "support-app") != r.SupportImageID {
		return fmt.Errorf("output policy target Pod UID, source, image or address changed")
	}
	return nil
}

func outputPolicyAuthority(ctx context.Context, ec EnactCtx, r outputPolicyReceipt) (*corev1.Pod, *corev1.ConfigMap, outputpolicy.Activation, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || !r.valid() {
		return nil, nil, outputpolicy.Activation{}, fmt.Errorf("output policy authority unavailable")
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod); err != nil {
		return nil, nil, outputpolicy.Activation{}, err
	}
	if err := outputPolicyStatePod(pod, r); err != nil {
		return nil, nil, outputpolicy.Activation{}, err
	}
	authority := operationReceipt{PolicyNamespace: r.PolicyNamespace, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, TargetName: r.TargetName, TargetUID: r.TargetUID, TargetLabels: copyLabels(pod.Labels)}
	pol, err := receiptAuthority(ctx, ec.Reader, authority, model.ActionSensitiveOutputPolicyActivate)
	if err != nil {
		return nil, nil, outputpolicy.Activation{}, err
	}
	if pol.Generation != r.PolicyGeneration {
		return nil, nil, outputpolicy.Activation{}, fmt.Errorf("output policy generation changed")
	}
	sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || !sel.Matches(labels.Set(pod.Labels)) {
		return nil, nil, outputpolicy.Activation{}, fmt.Errorf("output policy target left policy selector")
	}
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.ConfigMapName}, cm); err != nil {
		return nil, nil, outputpolicy.Activation{}, err
	}
	a, err := outputpolicy.ValidateConfigMap(cm, pod)
	if err != nil || string(cm.UID) != r.ConfigMapUID {
		return nil, nil, outputpolicy.Activation{}, fmt.Errorf("output policy ConfigMap identity or rule changed: %w", err)
	}
	return pod, cm, a, nil
}

func outputPolicyObservation(req Request, pod *corev1.Pod, cm *corev1.ConfigMap, prior outputpolicy.Activation) (outputPolicyReceipt, error) {
	o := req.OutputPolicyObservation
	if o == nil || o.EventName == "" || o.EventUID == "" || o.CreatorIdentity == "" ||
		o.PolicyName != req.PolicyName || o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration || req.PolicyGeneration < 1 ||
		o.TargetPodUID != req.TargetUID || o.ConfigMapUID != string(cm.UID) || o.SelectedConfigMapResourceVersion != cm.ResourceVersion || o.SelectedRevision != prior.Revision || o.RuleSHA256 != outputpolicy.RuleSHA256(req.TargetUID) ||
		o.ProxySourceSHA256 != pod.Annotations[outputpolicy.PodProxySHAAnnotation] || o.SupportSourceSHA256 != pod.Annotations[outputpolicy.PodSupportSHAAnnotation] ||
		o.ProxyImageID == "" || o.SupportImageID == "" || o.ProxyImageID != outputPolicyImageID(pod, "guardrail-proxy") ||
		o.SupportImageID != outputPolicyImageID(pod, "support-app") || o.ObservedAt.IsZero() ||
		time.Since(o.ObservedAt) < 0 || time.Since(o.ObservedAt) > 60*time.Second {
		return outputPolicyReceipt{}, fmt.Errorf("output policy selection observation stale or changed")
	}
	if prior.Active || prior.Revision > uint64(1<<63)-3 {
		return outputPolicyReceipt{}, fmt.Errorf("output policy is already active or revision exhausted")
	}
	if req.TickID == "" || req.OperationID == "" || len(req.TickID) > 253 || len(req.OperationID) > 253 {
		return outputPolicyReceipt{}, fmt.Errorf("output policy selecting tick or decision identity absent")
	}
	id := outputPolicyOperationID(req.PolicyUID, req.TargetUID, o.EventUID, req.TickID, req.OperationID)
	r := outputPolicyReceipt{Version: 1, Kind: string(req.Action), Phase: "prepared", PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration, TickID: req.TickID, SelectionDecisionID: req.OperationID,
		TargetName: req.Pod, TargetUID: req.TargetUID, EventName: o.EventName, EventUID: o.EventUID, CreatorIdentity: o.CreatorIdentity,
		ConfigMapName: cm.Name, ConfigMapUID: string(cm.UID), SelectedConfigMapResourceVersion: o.SelectedConfigMapResourceVersion, SelectedRevision: o.SelectedRevision, RuleSHA256: o.RuleSHA256, ProxySourceSHA256: o.ProxySourceSHA256,
		SupportSourceSHA256: o.SupportSourceSHA256, ProxyImageID: o.ProxyImageID, SupportImageID: o.SupportImageID, PodIP: pod.Status.PodIP,
		Prior: prior, Desired: outputpolicy.Activation{Version: 1, RuleID: outputpolicy.RuleID, ConfigMapUID: string(cm.UID), Active: true, Revision: prior.Revision + 1, OperationID: id}, OperationID: id}
	if !r.valid() {
		return outputPolicyReceipt{}, fmt.Errorf("output policy selected receipt invalid")
	}
	return r, nil
}

func outputPolicyEvent(ctx context.Context, ec EnactCtx, r outputPolicyReceipt) error {
	event := &amtdv1beta1.SecurityEvent{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: r.EventName}, event); err != nil {
		return err
	}
	now := time.Now()
	if string(event.UID) != r.EventUID || event.DeletionTimestamp != nil || event.Annotations["phorvex.ai/creator-identity"] != r.CreatorIdentity ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != r.TargetUID || event.Spec.Rule.Type != model.AttackVectorSensitiveOutput ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != r.PolicyNamespace+"/"+r.TargetName ||
		event.CreationTimestamp.IsZero() || event.CreationTimestamp.Time.After(now) || now.Sub(event.CreationTimestamp.Time) > 60*time.Second {
		return fmt.Errorf("output policy event identity, target or freshness changed")
	}
	raw := event.Annotations[outputpolicy.EventAnnotation]
	if len(raw) == 0 || len(raw) > 2048 || outputPolicyExactObject([]byte(raw), "version", "ruleId", "ruleSHA256", "configMapUID", "podUID", "policyName", "policyUID", "policyGeneration", "requestPath", "observedAt") != nil {
		return fmt.Errorf("output policy event assertion absent")
	}
	var payload struct {
		Version          int       `json:"version"`
		RuleID           string    `json:"ruleId"`
		RuleSHA256       string    `json:"ruleSHA256"`
		ConfigMapUID     string    `json:"configMapUID"`
		PodUID           string    `json:"podUID"`
		PolicyName       string    `json:"policyName"`
		PolicyUID        string    `json:"policyUID"`
		PolicyGeneration int64     `json:"policyGeneration"`
		RequestPath      string    `json:"requestPath"`
		ObservedAt       time.Time `json:"observedAt"`
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF || payload.Version != 1 || payload.RuleID != outputpolicy.RuleID ||
		payload.RuleSHA256 != r.RuleSHA256 || payload.ConfigMapUID != r.ConfigMapUID || payload.PodUID != r.TargetUID || payload.PolicyName != r.PolicyName || payload.PolicyUID != r.PolicyUID || payload.PolicyGeneration != r.PolicyGeneration || payload.RequestPath != outputpolicy.Route ||
		payload.ObservedAt.IsZero() || !payload.ObservedAt.Before(event.CreationTimestamp.Time.Add(time.Second)) || payload.ObservedAt.After(now) ||
		event.CreationTimestamp.Time.Sub(payload.ObservedAt) > 60*time.Second || now.Sub(payload.ObservedAt) >= 60*time.Second {
		return fmt.Errorf("output policy event assertion changed")
	}
	return nil
}

func outputPolicyJournalGet(ctx context.Context, ec EnactCtx, uid string) (*corev1.ConfigMap, outputPolicyReceipt, error) {
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: outputpolicy.JournalName(uid)}, cm); err != nil {
		return nil, outputPolicyReceipt{}, err
	}
	r, err := outputPolicyParseJournal(ec, cm)
	return cm, r, err
}

func outputPolicyParseJournal(ec EnactCtx, cm *corev1.ConfigMap) (outputPolicyReceipt, error) {
	var r outputPolicyReceipt
	if cm == nil || cm.Namespace != ec.JournalNamespace || cm.UID == "" || cm.ResourceVersion == "" || cm.Labels[outputpolicy.JournalLabel] != "v1" ||
		len(cm.Data) != 1 || len(cm.Data["receipt"]) == 0 || len(cm.Data["receipt"]) > 8192 {
		return r, fmt.Errorf("output policy journal metadata invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(cm.Data["receipt"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return r, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return r, fmt.Errorf("output policy journal trailing bytes")
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal([]byte(cm.Data["receipt"]), canonical) || !r.valid() || cm.Name != outputpolicy.JournalName(r.TargetUID) {
		return r, fmt.Errorf("output policy journal content invalid")
	}
	return r, nil
}

func outputPolicyJournalAdvance(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r outputPolicyReceipt) error {
	if !r.valid() {
		return fmt.Errorf("output policy journal phase invalid")
	}
	copy := cm.DeepCopy()
	raw, _ := json.Marshal(r)
	copy.Data["receipt"] = string(raw)
	if err := ec.Client.Update(ctx, copy); err != nil {
		return err
	}
	*cm = *copy
	return nil
}

func outputPolicyJournalCreate(ctx context.Context, ec EnactCtx, r outputPolicyReceipt) (*corev1.ConfigMap, error) {
	raw, _ := json.Marshal(r)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: outputpolicy.JournalName(r.TargetUID), Namespace: ec.JournalNamespace, Labels: map[string]string{outputpolicy.JournalLabel: "v1"}}, Data: map[string]string{"receipt": string(raw)}}
	if err := ec.Client.Create(ctx, cm); err != nil {
		return nil, err
	}
	return cm, nil
}

const outputPolicyArchiveLabel = "phorvex.ai/output-policy-archive"
const outputPolicyArchiveTargetLabel = "phorvex.ai/output-policy-target"

func outputPolicyArchiveTarget(uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return hex.EncodeToString(sum[:10])
}

func outputPolicyArchiveName(r outputPolicyReceipt) string {
	return "phorvex-output-archive-" + outputPolicyArchiveTarget(r.TargetUID) + "-" + r.OperationID[:16]
}

// A completed rollback can relinquish the deterministic journal slot only after
// its exact receipt is retained in an immutable operator-namespace archive.
func outputPolicyArchive(ctx context.Context, ec EnactCtx, r outputPolicyReceipt) error {
	if r.Phase != "rolled-back" {
		return fmt.Errorf("output policy archive requires completed rollback")
	}
	selector := client.MatchingLabels{outputPolicyArchiveLabel: "v1", outputPolicyArchiveTargetLabel: outputPolicyArchiveTarget(r.TargetUID)}
	list := &corev1.ConfigMapList{}
	if err := ec.Reader.List(ctx, list, client.InNamespace(ec.JournalNamespace), selector, client.Limit(17)); err != nil {
		return err
	}
	if list.Continue != "" || len(list.Items) > 16 {
		return fmt.Errorf("output policy archive bound exhausted")
	}
	raw, _ := json.Marshal(r)
	name := outputPolicyArchiveName(r)
	for i := range list.Items {
		if list.Items[i].Name == name {
			item := &list.Items[i]
			if item.UID == "" || item.Immutable == nil || !*item.Immutable || len(item.Data) != 1 || item.Data["receipt"] != string(raw) {
				return fmt.Errorf("output policy archive collision")
			}
			return nil
		}
	}
	if len(list.Items) == 16 {
		return fmt.Errorf("output policy archive bound exhausted")
	}
	immutable := true
	archive := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ec.JournalNamespace, Labels: map[string]string{outputPolicyArchiveLabel: "v1", outputPolicyArchiveTargetLabel: outputPolicyArchiveTarget(r.TargetUID)}}, Immutable: &immutable, Data: map[string]string{"receipt": string(raw)}}
	if err := ec.Client.Create(ctx, archive); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		existing := &corev1.ConfigMap{}
		if getErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: name}, existing); getErr != nil {
			return getErr
		}
		if existing.UID == "" || existing.Immutable == nil || !*existing.Immutable || existing.Data["receipt"] != string(raw) || existing.Labels[outputPolicyArchiveLabel] != "v1" {
			return fmt.Errorf("output policy archive identity mismatch")
		}
	}
	return nil
}

type outputPolicyState struct {
	Version             int    `json:"version"`
	PodUID              string `json:"podUID"`
	ConfigMapUID        string `json:"configMapUID"`
	RuleID              string `json:"ruleId"`
	RuleSHA256          string `json:"ruleSHA256"`
	Active              bool   `json:"active"`
	Revision            uint64 `json:"revision"`
	OperationID         string `json:"operationId"`
	ProxySourceSHA256   string `json:"proxySourceSHA256"`
	SupportSourceSHA256 string `json:"supportSourceSHA256"`
	Ready               bool   `json:"ready"`
}

func outputPolicyExactObject(raw []byte, fields ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return fmt.Errorf("output policy JSON must be an object")
	}
	seen := map[string]bool{}
	allowed := map[string]bool{}
	for _, field := range fields {
		allowed[field] = true
	}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] || !allowed[name] {
			return fmt.Errorf("output policy JSON has duplicate or invalid member")
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return fmt.Errorf("output policy JSON object incomplete")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("output policy JSON trailing bytes")
	}
	if len(seen) != len(allowed) {
		return fmt.Errorf("output policy JSON fields incomplete")
	}
	return nil
}

// This is a read of the fixed proxy state route over internal Pod networking. The
// trust boundary is the independent Kubernetes Pod/ConfigMap/source read around it.
func outputPolicyReadback(ctx context.Context, ec EnactCtx, r outputPolicyReceipt, want outputpolicy.Activation) error {
	timeout, interval := ec.OutputPolicyReadbackTimeout, ec.OutputPolicyReadbackInterval
	if timeout <= 0 {
		timeout = outputPolicyReadbackTimeout
	}
	if interval <= 0 {
		interval = outputPolicyReadbackInterval
	}
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ip, err := netip.ParseAddr(r.PodIP)
	if err != nil {
		return err
	}
	url := "http://" + net.JoinHostPort(ip.String(), strconv.Itoa(8000)) + "/v1/output-policy/state"
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	var roundTripper http.RoundTripper = transport
	if ec.OutputPolicyTransport != nil {
		roundTripper = ec.OutputPolicyTransport
	}
	httpClient := &http.Client{Transport: roundTripper, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var last error
	for {
		if _, _, _, err := outputPolicyAuthority(deadline, ec, r); err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(deadline, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		response, err := httpClient.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, outputPolicyMaxStateBytes+1))
			closeErr := response.Body.Close()
			mediaType, _, mimeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
			if readErr != nil || closeErr != nil || len(body) > outputPolicyMaxStateBytes || response.StatusCode != http.StatusOK || mimeErr != nil || mediaType != "application/json" {
				last = fmt.Errorf("output policy state unavailable or oversized: status %d", response.StatusCode)
			} else {
				var state outputPolicyState
				decoder := json.NewDecoder(bytes.NewReader(body))
				decoder.DisallowUnknownFields()
				if outputPolicyExactObject(body, "version", "podUID", "configMapUID", "ruleId", "ruleSHA256", "active", "revision", "operationId", "proxySourceSHA256", "supportSourceSHA256", "ready") == nil && decoder.Decode(&state) == nil && decoder.Decode(new(any)) == io.EOF && state.Ready && state.Version == 1 &&
					state.PodUID == r.TargetUID && state.ConfigMapUID == r.ConfigMapUID && state.RuleID == outputpolicy.RuleID &&
					state.RuleSHA256 == r.RuleSHA256 && state.Active == want.Active && state.Revision == want.Revision &&
					state.OperationID == want.OperationID && state.ProxySourceSHA256 == r.ProxySourceSHA256 &&
					state.SupportSourceSHA256 == r.SupportSourceSHA256 {
					// A final API read detects UID/source replacement during the HTTP call.
					if _, cm, a, e := outputPolicyAuthority(deadline, ec, r); e == nil && cm.UID == types.UID(r.ConfigMapUID) && a == want {
						return nil
					}
					last = fmt.Errorf("output policy Kubernetes state changed during readback")
				} else {
					last = fmt.Errorf("output policy effective state did not match operation")
				}
			}
		} else {
			last = err
		}
		select {
		case <-deadline.Done():
			return fmt.Errorf("output policy effective readback unconfirmed: %w: %v", deadline.Err(), last)
		case <-time.After(interval):
		}
	}
}

func outputPolicyApply(ctx context.Context, ec EnactCtx, r outputPolicyReceipt, cm *corev1.ConfigMap, a outputpolicy.Activation) error {
	if a == r.Desired {
		return nil
	}
	if a != r.Prior {
		return fmt.Errorf("output policy activation superseded or changed")
	}
	copy := cm.DeepCopy()
	copy.Data[outputpolicy.ActivationKey] = string(r.Desired.Bytes())
	if err := ec.Client.Update(ctx, copy); err != nil {
		return err
	}
	return nil
}

func outputPolicyContinue(ctx context.Context, ec EnactCtx, journal *corev1.ConfigMap, r outputPolicyReceipt) (HandlerResult, error) {
	pod, cm, a, err := outputPolicyAuthority(ctx, ec, r)
	if err != nil {
		return HandlerResult{}, err
	}
	if r.Phase == "rollback-intent" || r.Phase == "rolled-back" {
		return HandlerResult{}, fmt.Errorf("output policy operation is rolling back")
	}
	if a != r.Prior && a != r.Desired {
		return HandlerResult{}, fmt.Errorf("output policy activation superseded")
	}
	if r.Phase == "prepared" {
		if err := outputPolicyApply(ctx, ec, r, cm, a); err != nil {
			return HandlerResult{}, err
		}
	}
	if err := outputPolicyReadback(ctx, ec, r, r.Desired); err != nil {
		return HandlerResult{MutationKind: "partial", ObjectsTouched: []string{r.PolicyNamespace + "/" + r.ConfigMapName}}, err
	}
	if r.Phase != "terminal-full" {
		r.Phase = "terminal-full"
		if err := outputPolicyJournalAdvance(ctx, ec, journal, r); err != nil {
			return HandlerResult{MutationKind: "partial"}, err
		}
	}
	return HandlerResult{ObjectsTouched: []string{r.PolicyNamespace + "/" + r.ConfigMapName}, RollbackRef: journal.Name + "/" + r.OperationID, MutationKind: "reversible", Emitted: true, Note: fmt.Sprintf("output policy operation %s terminal-full for Pod UID %s", r.OperationID, pod.UID)}, nil
}

type outputPolicyHandler struct{}

func (outputPolicyHandler) Name() string { return string(model.ActionSensitiveOutputPolicyActivate) }
func (outputPolicyHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	if req.Action != model.ActionSensitiveOutputPolicyActivate || req.TargetUID == "" || req.Namespace == "" || req.Pod == "" || req.PolicyName == "" || req.PolicyUID == "" || ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return HandlerResult{}, fmt.Errorf("output policy request authority incomplete")
	}
	var previousJournal *corev1.ConfigMap
	var previous outputPolicyReceipt
	if existing, r, err := outputPolicyJournalGet(ctx, ec, req.TargetUID); err == nil {
		if req.OutputPolicyObservation == nil || r.PolicyNamespace != req.Namespace || r.TargetName != req.Pod || r.TargetUID != req.TargetUID || r.PolicyUID != req.PolicyUID {
			return HandlerResult{}, fmt.Errorf("output policy journal occupied by another operation")
		}
		if outputPolicyReceiptMatchesRequest(r, req) {
			return outputPolicyContinue(ctx, ec, existing, r)
		}
		if r.EventUID == req.OutputPolicyObservation.EventUID {
			return HandlerResult{}, fmt.Errorf("output policy event already claimed by another selection")
		}
		if r.Phase != "rolled-back" {
			return HandlerResult{}, fmt.Errorf("output policy journal occupied by unfinished operation")
		}
		previousJournal, previous = existing, r
	} else if !apierrors.IsNotFound(err) {
		return HandlerResult{}, err
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		return HandlerResult{}, err
	}
	if string(pod.UID) != req.TargetUID || pod.DeletionTimestamp != nil {
		return HandlerResult{}, fmt.Errorf("output policy target UID changed")
	}
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: pod.Annotations[outputpolicy.PodConfigMapAnnotation]}, cm); err != nil {
		return HandlerResult{}, err
	}
	prior, err := outputpolicy.ValidateConfigMap(cm, pod)
	if err != nil {
		return HandlerResult{}, err
	}
	r, err := outputPolicyObservation(req, pod, cm, prior)
	if err != nil {
		return HandlerResult{}, err
	}
	if _, _, _, err := outputPolicyAuthority(ctx, ec, r); err != nil {
		return HandlerResult{}, err
	}
	if err := outputPolicyEvent(ctx, ec, r); err != nil {
		return HandlerResult{}, err
	}
	if previousJournal != nil {
		_, _, previousActivation, err := outputPolicyAuthority(ctx, ec, previous)
		if err != nil {
			return HandlerResult{}, err
		}
		restored := previous.Prior
		restored.Revision = previous.Desired.Revision + 1
		restored.OperationID = previous.OperationID
		if prior != restored || previousActivation != restored {
			return HandlerResult{}, fmt.Errorf("output policy prior rollback was superseded")
		}
		if err := outputPolicyReadback(ctx, ec, previous, restored); err != nil {
			return HandlerResult{}, err
		}
		if err := outputPolicyArchive(ctx, ec, previous); err != nil {
			return HandlerResult{}, err
		}
		if err := outputPolicyJournalAdvance(ctx, ec, previousJournal, r); err != nil {
			return HandlerResult{}, err
		}
		return outputPolicyContinue(ctx, ec, previousJournal, r)
	}
	journal, err := outputPolicyJournalCreate(ctx, ec, r)
	if apierrors.IsAlreadyExists(err) {
		var recorded outputPolicyReceipt
		var lookupErr error
		journal, recorded, lookupErr = outputPolicyJournalGet(ctx, ec, req.TargetUID)
		if lookupErr != nil {
			return HandlerResult{}, lookupErr
		}
		if !outputPolicyReceiptMatchesRequest(recorded, req) {
			err = fmt.Errorf("output policy journal occupied by another operation")
		} else {
			candidate := r
			candidate.Phase = recorded.Phase
			if candidate != recorded {
				err = fmt.Errorf("output policy journal changed selected intent")
			} else {
				r, err = recorded, nil
			}
		}
	}
	if err != nil {
		return HandlerResult{}, err
	}
	return outputPolicyContinue(ctx, ec, journal, r)
}
func (outputPolicyHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	if ec.DryRun {
		return errDryRunGuard
	}
	if req.Action != model.ActionSensitiveOutputPolicyActivate || req.TargetUID == "" || !strings.HasPrefix(ref, outputpolicy.JournalName(req.TargetUID)+"/") {
		return fmt.Errorf("output policy rollback reference invalid")
	}
	journal, r, err := outputPolicyJournalGet(ctx, ec, req.TargetUID)
	if err != nil {
		return err
	}
	if r.PolicyNamespace != req.Namespace || r.TargetName != req.Pod || r.PolicyUID != req.PolicyUID || ref != journal.Name+"/"+r.OperationID {
		return fmt.Errorf("output policy rollback identity mismatch")
	}
	return outputPolicyRollback(ctx, ec, journal, r)
}
func outputPolicyRollback(ctx context.Context, ec EnactCtx, journal *corev1.ConfigMap, r outputPolicyReceipt) error {
	_, cm, a, err := outputPolicyAuthority(ctx, ec, r)
	if err != nil {
		return err
	}
	restored := r.Prior
	restored.Revision = r.Desired.Revision + 1
	restored.OperationID = r.OperationID
	if r.Phase == "rolled-back" {
		if a != restored {
			return fmt.Errorf("output policy rollback superseded")
		}
		return outputPolicyReadback(ctx, ec, r, restored)
	}
	if a != r.Desired && a != restored {
		return fmt.Errorf("output policy rollback refuses superseding operation")
	}
	if r.Phase != "rollback-intent" {
		r.Phase = "rollback-intent"
		if err := outputPolicyJournalAdvance(ctx, ec, journal, r); err != nil {
			return err
		}
	}
	if a == r.Desired {
		copy := cm.DeepCopy()
		copy.Data[outputpolicy.ActivationKey] = string(restored.Bytes())
		if err := ec.Client.Update(ctx, copy); err != nil {
			return err
		}
	}
	if err := outputPolicyReadback(ctx, ec, r, restored); err != nil {
		return err
	}
	r.Phase = "rolled-back"
	return outputPolicyJournalAdvance(ctx, ec, journal, r)
}
func init() { HandlerRegistry.Register(outputPolicyHandler{}) }

func recoverOutputPolicyOperations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	list := &corev1.ConfigMapList{}
	if err := ec.Reader.List(ctx, list, client.InNamespace(ec.JournalNamespace), client.MatchingLabels{outputpolicy.JournalLabel: "v1"}, client.Limit(101)); err != nil {
		return nil, err
	}
	if list.Continue != "" || len(list.Items) > 100 {
		return nil, fmt.Errorf("output policy journal inventory exceeded recovery bound")
	}
	result := make([]RecoveryEvent, 0, len(list.Items))
	for i := range list.Items {
		journal := &list.Items[i]
		r, err := outputPolicyParseJournal(ec, journal)
		event := RecoveryEvent{Receipt: journal.Name, Kind: string(model.ActionSensitiveOutputPolicyActivate), Outcome: "refused"}
		if err != nil {
			event.Err = err
			result = append(result, event)
			continue
		}
		event.Phase = r.Phase
		event.PolicyNamespace = r.PolicyNamespace
		event.PolicyName = r.PolicyName
		event.PolicyUID = r.PolicyUID
		event.TargetName = r.TargetName
		event.TargetUID = r.TargetUID
		if allow != nil && !allow(model.ActionSensitiveOutputPolicyActivate) {
			event.Err = fmt.Errorf("output policy recovery routed away from native")
			result = append(result, event)
			continue
		}
		policy, policyErr := receiptAuthority(ctx, ec.Reader, operationReceipt{
			PolicyNamespace: r.PolicyNamespace, PolicyName: r.PolicyName,
			PolicyUID: r.PolicyUID, TargetName: r.TargetName, TargetUID: r.TargetUID,
		}, model.ActionSensitiveOutputPolicyActivate)
		if policyErr != nil {
			event.Err = policyErr
			result = append(result, event)
			continue
		}
		event.Tenant = policy.EffectiveTenant()
		switch r.Phase {
		case "rollback-intent", "rolled-back":
			event.Err = outputPolicyRollback(ctx, ec, journal, r)
			if event.Err == nil {
				event.Effect = "prior activation restored with higher revision"
			}
		default:
			_, event.Err = outputPolicyContinue(ctx, ec, journal, r)
			if event.Err == nil {
				event.Effect = "effective output policy state confirmed"
			}
		}
		if event.Err == nil {
			event.Outcome = "confirmed"
		} else if event.Effect != "" {
			event.Outcome = "partial"
		}
		result = append(result, event)
	}
	return result, nil
}

// PendingOutputPolicyOperation fences another action on the exact Pod while a
// policy projection or rollback remains unconfirmed. It does not scan or block
// unrelated Pods. A malformed occupied slot fails closed for its named Pod UID.
func PendingOutputPolicyOperation(ctx context.Context, reader client.Reader, operatorNamespace, namespace, podUID string) (bool, error) {
	if reader == nil || operatorNamespace == "" || namespace == "" || podUID == "" {
		return false, fmt.Errorf("output policy journal authority unavailable")
	}
	probe, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ec := EnactCtx{Reader: reader, JournalNamespace: operatorNamespace}
	_, r, err := outputPolicyJournalGet(probe, ec, podUID)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if r.PolicyNamespace != namespace || r.TargetUID != podUID {
		return false, fmt.Errorf("output policy journal scope mismatch")
	}
	return r.Phase == "prepared" || r.Phase == "rollback-intent", nil
}

func (n *NativeActuator) PendingOutputPolicyOperation(ctx context.Context, namespace, podUID string) (bool, error) {
	return PendingOutputPolicyOperation(ctx, n.Reader, n.JournalNamespace, namespace, podUID)
}
