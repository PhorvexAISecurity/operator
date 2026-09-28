package actuator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	"github.com/phorvex/phorvex/internal/voicerefundpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const (
	voiceRefundSecretName      = "voice-memory-state-token"
	voiceRefundEventAnnotation = "phorvex.ai/voice-refund-observation-v1"
	voiceRefundJournalLabel    = "phorvex.ai/voice-refund-journal"
)

type voiceRefundScope struct {
	pod        *corev1.Pod
	deployment *appsv1.Deployment
	policy     *v1alpha1.PhorvexPolicy
	cm         *corev1.ConfigMap
	rule       voicerefundpolicy.Rule
	secret     []byte
	pods       []corev1.Pod
}

func voiceRefundOwner(ctx context.Context, reader client.Reader, pod *corev1.Pod) (*appsv1.Deployment, error) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || len(pod.OwnerReferences) != 1 || owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" {
		return nil, fmt.Errorf("voice refund Pod owner invalid")
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, rs); err != nil {
		return nil, err
	}
	if rs.UID != owner.UID || len(rs.OwnerReferences) != 1 {
		return nil, fmt.Errorf("voice refund ReplicaSet identity changed")
	}
	parent := metav1.GetControllerOf(rs)
	if parent == nil || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" {
		return nil, fmt.Errorf("voice refund Deployment owner absent")
	}
	dep := &appsv1.Deployment{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: parent.Name}, dep); err != nil {
		return nil, err
	}
	if dep.UID != parent.UID || dep.DeletionTimestamp != nil {
		return nil, fmt.Errorf("voice refund Deployment identity changed")
	}
	return dep, nil
}

func voiceRefundMounts(pod *corev1.Pod) bool {
	var bot *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "bot" {
			bot = &pod.Spec.Containers[i]
		}
	}
	if bot == nil {
		return false
	}
	requiredMode := 0
	for _, variable := range bot.Env {
		if variable.Name == "VOICE_REFUND_POLICY_REQUIRED" {
			if variable.Value != "true" || variable.ValueFrom != nil {
				return false
			}
			requiredMode++
		}
	}
	if requiredMode != 1 {
		return false
	}
	paths := map[string]string{}
	for _, m := range bot.VolumeMounts {
		if m.ReadOnly && m.SubPath == "" {
			paths[m.MountPath] = m.Name
		}
	}
	policyVol, secretVol := paths["/etc/phorvex/voice-refund-policy"], paths["/etc/phorvex/voice-memory-state-token"]
	if policyVol == "" || secretVol == "" {
		return false
	}
	watermark := ""
	for _, m := range bot.VolumeMounts {
		if m.MountPath == "/var/lib/phorvex-voice-memory" && m.SubPath == "" {
			watermark = m.Name
		}
	}
	if watermark == "" {
		return false
	}
	valid := 0
	for _, v := range pod.Spec.Volumes {
		if v.Name == policyVol && v.ConfigMap != nil && v.ConfigMap.Name == voicerefundpolicy.ConfigMapName && (v.ConfigMap.Optional == nil || !*v.ConfigMap.Optional) {
			valid++
		}
		if v.Name == secretVol && v.Secret != nil && v.Secret.SecretName == voiceRefundSecretName {
			valid++
		}
		if v.Name == watermark && v.EmptyDir != nil {
			valid++
		}
	}
	return valid == 3
}

func voiceRefundReady(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil || p.Status.PodIP == "" || !voiceRefundMounts(p) {
		return false
	}
	if _, err := netip.ParseAddr(p.Status.PodIP); err != nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func voiceRefundScopeAt(ctx context.Context, reader client.Reader, target Target) (voiceRefundScope, error) {
	var s voiceRefundScope
	if reader == nil || target.Namespace != voicerefundpolicy.Namespace || target.Pod == "" || target.UID == "" || target.PolicyName == "" || target.PolicyUID == "" {
		return s, fmt.Errorf("voice refund target authority incomplete")
	}
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: target.Pod}, pod); err != nil {
		return s, err
	}
	if string(pod.UID) != target.UID || !voiceRefundReady(pod) || pod.Annotations["phorvex.ai/voice-refund-policy-configmap"] != voicerefundpolicy.ConfigMapName ||
		!voicerefundpolicy.ValidSHA(pod.Annotations["phorvex.ai/voice-refund-source-sha256"]) || pod.Annotations["phorvex.ai/voice-refund-event-creator"] == "" {
		return s, fmt.Errorf("voice refund target Pod source, mount or readiness unbound")
	}
	dep, err := voiceRefundOwner(ctx, reader, pod)
	if err != nil {
		return s, err
	}
	if voiceadmissionpolicy.HasWrapperAuthority(pod) {
		if _, err := voiceadmissionpolicy.VerifySource(ctx, reader, pod, dep); err != nil {
			return s, err
		}
	}
	pol, err := receiptAuthority(ctx, reader, operationReceipt{PolicyNamespace: target.Namespace, PolicyName: target.PolicyName, PolicyUID: target.PolicyUID,
		TargetName: target.Pod, TargetUID: target.UID, TargetLabels: pod.Labels}, model.ActionVoiceRefundPairDeny)
	if err != nil {
		return s, err
	}
	sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || sel.Empty() || !sel.Matches(labels.Set(pod.Labels)) {
		return s, fmt.Errorf("voice refund Pod outside policy selector")
	}
	cm := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: voicerefundpolicy.ConfigMapName}, cm); err != nil {
		return s, err
	}
	if cm.DeletionTimestamp != nil || len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Controller == nil || !*cm.OwnerReferences[0].Controller || cm.OwnerReferences[0].APIVersion != "apps/v1" || cm.OwnerReferences[0].Kind != "Deployment" || cm.OwnerReferences[0].UID != dep.UID || cm.OwnerReferences[0].Name != dep.Name || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return s, fmt.Errorf("voice refund ConfigMap owner or data invalid")
	}
	rule, err := voicerefundpolicy.Parse(cm.Data[voicerefundpolicy.RuleKey])
	if err != nil || rule.DeploymentUID != string(dep.UID) || rule.PolicyUID != string(pol.UID) || rule.SourceSHA256 != pod.Annotations["phorvex.ai/voice-refund-source-sha256"] {
		return s, fmt.Errorf("voice refund current rule identity invalid")
	}
	secret := &corev1.Secret{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: voiceRefundSecretName}, secret); err != nil {
		return s, err
	}
	token := secret.Data["token"]
	if len(token) < 32 || len(token) > 256 {
		return s, fmt.Errorf("voice refund private readback token invalid")
	}
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return s, fmt.Errorf("voice refund private readback token invalid")
		}
	}
	depSel, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || depSel.Empty() || !depSel.Matches(labels.Set(pod.Labels)) {
		return s, fmt.Errorf("voice refund Deployment selector invalid")
	}
	list := &corev1.PodList{}
	// Inventory all namespace Pods before filtering by the Deployment owner chain.
	// A serving child whose labels drifted must not escape the all-Pod readback.
	if err := reader.List(ctx, list, client.InNamespace(target.Namespace), client.Limit(129)); err != nil {
		return s, err
	}
	if list.Continue != "" || len(list.Items) == 0 || len(list.Items) > 128 {
		return s, fmt.Errorf("voice refund Pod inventory bound exceeded")
	}
	found := false
	for _, candidate := range list.Items {
		if candidate.DeletionTimestamp != nil {
			continue
		}
		owner, err := voiceRefundOwner(ctx, reader, &candidate)
		if err != nil {
			if depSel.Matches(labels.Set(candidate.Labels)) {
				return s, fmt.Errorf("voice refund labelled Pod owner chain invalid")
			}
			continue
		}
		if owner.UID != dep.UID {
			continue
		}
		if !voiceRefundReady(&candidate) ||
			!depSel.Matches(labels.Set(candidate.Labels)) ||
			!sel.Matches(labels.Set(candidate.Labels)) ||
			candidate.Annotations["phorvex.ai/voice-refund-policy-configmap"] != voicerefundpolicy.ConfigMapName ||
			candidate.Annotations["phorvex.ai/voice-refund-source-sha256"] != rule.SourceSHA256 ||
			candidate.Annotations["phorvex.ai/voice-refund-event-creator"] != pod.Annotations["phorvex.ai/voice-refund-event-creator"] {
			return s, fmt.Errorf("voice refund serving Pod scope incomplete")
		}
		if voiceadmissionpolicy.HasWrapperAuthority(pod) || voiceadmissionpolicy.HasWrapperAuthority(&candidate) {
			if _, err := voiceadmissionpolicy.VerifySource(ctx, reader, &candidate, dep); err != nil {
				return s, err
			}
		}
		if candidate.UID == pod.UID {
			found = true
		}
		s.pods = append(s.pods, candidate)
	}
	if !found || len(s.pods) == 0 {
		return s, fmt.Errorf("voice refund target absent from serving set")
	}
	s.pod, s.deployment, s.policy, s.cm, s.rule, s.secret = pod, dep, pol, cm, rule, append([]byte(nil), token...)
	return s, nil
}

type voiceRefundState struct {
	Version       int    `json:"version"`
	PodUID        string `json:"podUID"`
	DeploymentUID string `json:"deploymentUID"`
	PolicyUID     string `json:"policyUID"`
	SourceSHA256  string `json:"sourceSHA256"`
	RuleSHA256    string `json:"ruleSHA256"`
	Revision      uint64 `json:"revision"`
	OperationID   string `json:"operationId"`
	EntryCount    int    `json:"entryCount"`
	Ready         bool   `json:"ready"`
}

func voiceRefundReadback(ctx context.Context, s voiceRefundScope, rule voicerefundpolicy.Rule, transport http.RoundTripper) error {
	if len(s.pods) == 0 || !rule.Valid() {
		return fmt.Errorf("voice refund private readback scope empty or rule invalid")
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	}
	httpClient := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, pod := range s.pods {
		url := "http://" + net.JoinHostPort(pod.Status.PodIP, "8080") + voicerefundpolicy.StatePath
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+string(s.secret))
		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("voice refund private readback unavailable for Pod UID %s: %w", pod.UID, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
		resp.Body.Close()
		if readErr != nil || len(body) > 4096 || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
			return fmt.Errorf("voice refund private readback unready for Pod UID %s", pod.UID)
		}
		if outputPolicyExactObject(body, "version", "podUID", "deploymentUID", "policyUID", "sourceSHA256", "ruleSHA256", "revision", "operationId", "entryCount", "ready") != nil {
			return fmt.Errorf("voice refund private readback shape invalid")
		}
		var state voiceRefundState
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if dec.Decode(&state) != nil || !state.Ready || state.Version != 1 || state.PodUID != string(pod.UID) ||
			state.DeploymentUID != rule.DeploymentUID || state.PolicyUID != rule.PolicyUID || state.SourceSHA256 != rule.SourceSHA256 ||
			state.RuleSHA256 != rule.SHA256() || state.Revision != rule.Revision || state.OperationID != rule.OperationID || state.EntryCount != len(rule.Entries) {
			return fmt.Errorf("voice refund private readback identity or rule mismatch for Pod UID %s", pod.UID)
		}
		if _, err := dec.Token(); err != io.EOF {
			return fmt.Errorf("voice refund private readback trailing data")
		}
	}
	return nil
}

func voiceRefundJournalName(deploymentUID string, revision uint64) string {
	h := sha256.Sum256([]byte(deploymentUID))
	return "phorvex-voice-refund-" + hex.EncodeToString(h[:16]) + "-" + strconv.FormatUint(revision, 10)
}

type voiceRefundReceipt struct {
	Version             int                    `json:"version"`
	Phase               string                 `json:"phase"`
	PolicyName          string                 `json:"policyName"`
	PolicyUID           string                 `json:"policyUID"`
	PolicyGeneration    int64                  `json:"policyGeneration"`
	DeploymentUID       string                 `json:"deploymentUID"`
	TargetName          string                 `json:"targetName"`
	TargetPodUID        string                 `json:"targetPodUID"`
	EventName           string                 `json:"eventName"`
	EventUID            string                 `json:"eventUID"`
	CreatorIdentity     string                 `json:"creatorIdentity"`
	TickID              string                 `json:"tickId"`
	SelectionDecisionID string                 `json:"selectionDecisionId"`
	ConfigMapUID        string                 `json:"configMapUID"`
	Prior               voicerefundpolicy.Rule `json:"prior"`
	Desired             voicerefundpolicy.Rule `json:"desired"`
	OperationID         string                 `json:"operationId"`
}

func voiceRefundJournalGet(ctx context.Context, ec EnactCtx, name string) (*corev1.ConfigMap, voiceRefundReceipt, error) {
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: name}, cm); err != nil {
		return nil, voiceRefundReceipt{}, err
	}
	var r voiceRefundReceipt
	if cm.Labels[voiceRefundJournalLabel] != "v1" || len(cm.Data) != 1 || len(cm.Data["receipt.json"]) == 0 || len(cm.Data["receipt.json"]) > 150000 ||
		json.Unmarshal([]byte(cm.Data["receipt.json"]), &r) != nil ||
		r.Version != 1 || (r.Phase != "prepared" && r.Phase != "terminal-full") || !r.Prior.Valid() || !r.Desired.Valid() ||
		r.Desired.Revision != r.Prior.Revision+1 || r.Desired.OperationID != r.OperationID || !voicerefundpolicy.ValidSHA(r.OperationID) ||
		r.DeploymentUID != r.Prior.DeploymentUID || r.PolicyUID != r.Prior.PolicyUID || r.TargetName == "" || r.TargetPodUID == "" || r.EventUID == "" ||
		cm.Name != voiceRefundJournalName(r.DeploymentUID, r.Desired.Revision) {
		return nil, voiceRefundReceipt{}, fmt.Errorf("voice refund journal invalid")
	}
	canonical, _ := json.Marshal(r)
	if cm.Data["receipt.json"] != string(canonical) || r.PolicyName == "" || r.PolicyGeneration <= 0 || r.TickID == "" || r.SelectionDecisionID == "" ||
		len(r.TickID) > 253 || len(r.SelectionDecisionID) > 253 || r.ConfigMapUID == "" || r.CreatorIdentity == "" ||
		r.Prior.PolicyUID != r.Desired.PolicyUID || r.Prior.DeploymentUID != r.Desired.DeploymentUID || r.Prior.SourceSHA256 != r.Desired.SourceSHA256 ||
		len(r.Desired.Entries) != len(r.Prior.Entries)+1 ||
		r.OperationID != voiceRefundOperationID(Request{PolicyUID: r.PolicyUID, TickID: r.TickID, OperationID: r.SelectionDecisionID}, &model.VoiceRefundObservation{DeploymentUID: r.DeploymentUID, TargetPodUID: r.TargetPodUID, EventUID: r.EventUID}) {
		return nil, voiceRefundReceipt{}, fmt.Errorf("voice refund journal intent invalid")
	}
	var latest *voicerefundpolicy.Entry
	for i := range r.Desired.Entries {
		if r.Desired.Entries[i].OperationID == r.OperationID {
			latest = &r.Desired.Entries[i]
		}
	}
	if latest == nil {
		return nil, voiceRefundReceipt{}, fmt.Errorf("voice refund journal latest entry missing")
	}
	rebuilt, err := voicerefundpolicy.Append(r.Prior, voicerefundpolicy.Entry{AssertedCallerSHA256: latest.AssertedCallerSHA256, OrderSHA256: latest.OrderSHA256}, r.OperationID)
	if err != nil || rebuilt.SHA256() != r.Desired.SHA256() {
		return nil, voiceRefundReceipt{}, fmt.Errorf("voice refund journal erased prior entry")
	}
	return cm, r, nil
}

func voiceRefundCapability(ctx context.Context, reader client.Reader, journalNS string, target Target, transport http.RoundTripper) (bool, string) {
	if journalNS == "" {
		return false, "voice-refund-journal-unavailable"
	}
	probe, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	s, err := voiceRefundScopeAt(probe, reader, target)
	if err != nil {
		return false, "voice-refund-scope-unavailable: " + err.Error()
	}
	if len(s.rule.Entries) >= voicerefundpolicy.MaxEntries {
		return false, "voice-refund-quarantine-full"
	}
	ec := EnactCtx{Reader: reader, JournalNamespace: journalNS}
	if s.rule.Revision > 0 {
		_, r, err := voiceRefundJournalGet(probe, ec, voiceRefundJournalName(string(s.deployment.UID), s.rule.Revision))
		if err != nil || r.Phase != "terminal-full" || r.Desired.SHA256() != s.rule.SHA256() {
			return false, "voice-refund-prior-operation-unverified"
		}
	}
	if _, _, err := voiceRefundJournalGet(probe, ec, voiceRefundJournalName(string(s.deployment.UID), s.rule.Revision+1)); err == nil {
		return false, "voice-refund-operation-pending"
	} else if !apierrors.IsNotFound(err) {
		return false, "voice-refund-journal-read-failed"
	}
	if err := voiceRefundReadback(probe, s, s.rule, transport); err != nil {
		return false, "voice-refund-app-readback-unavailable"
	}
	return true, ""
}

func voiceRefundOperationID(req Request, o *model.VoiceRefundObservation) string {
	h := sha256.Sum256([]byte("phorvex-voice-refund-v1\x00" + req.PolicyUID + "\x00" + o.DeploymentUID + "\x00" + o.TargetPodUID + "\x00" + o.EventUID + "\x00" + req.TickID + "\x00" + req.OperationID))
	return hex.EncodeToString(h[:])
}

type voiceRefundHandler struct{}

func (voiceRefundHandler) Name() string { return string(model.ActionVoiceRefundPairDeny) }

func voiceRefundResume(ctx context.Context, ec EnactCtx, journal *corev1.ConfigMap, receipt voiceRefundReceipt) (HandlerResult, error) {
	target := Target{Namespace: voicerefundpolicy.Namespace, Pod: receipt.TargetName, UID: receipt.TargetPodUID, PolicyName: receipt.PolicyName, PolicyUID: receipt.PolicyUID}
	s, err := voiceRefundScopeAt(ctx, ec.Reader, target)
	if err != nil {
		return HandlerResult{MutationKind: "partial"}, err
	}
	if string(s.deployment.UID) != receipt.DeploymentUID || string(s.cm.UID) != receipt.ConfigMapUID || s.policy.Generation != receipt.PolicyGeneration ||
		s.rule.SourceSHA256 != receipt.Prior.SourceSHA256 {
		return HandlerResult{MutationKind: "partial"}, fmt.Errorf("voice refund recovery authority changed")
	}
	if s.rule.SHA256() == receipt.Prior.SHA256() {
		if err := voiceRefundReadback(ctx, s, receipt.Prior, ec.VoiceRefundTransport); err != nil {
			return HandlerResult{MutationKind: "partial"}, err
		}
		copy := s.cm.DeepCopy()
		copy.Data[voicerefundpolicy.RuleKey] = string(receipt.Desired.Bytes())
		if err := ec.Client.Update(ctx, copy); err != nil {
			return HandlerResult{MutationKind: "partial", Note: "voice refund prepared operation requires recovery"}, err
		}
	} else if s.rule.SHA256() != receipt.Desired.SHA256() {
		return HandlerResult{MutationKind: "partial"}, fmt.Errorf("voice refund rule superseded prepared operation")
	}
	deadline, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	for {
		current, scopeErr := voiceRefundScopeAt(deadline, ec.Reader, target)
		if scopeErr == nil {
			switch current.rule.SHA256() {
			case receipt.Desired.SHA256():
				scopeErr = voiceRefundReadback(deadline, current, receipt.Desired, ec.VoiceRefundTransport)
			case receipt.Prior.SHA256():
				// The boundary reader may still project the old rule after the CAS.
				// Wait for the desired bytes; an old read is not an effect.
				scopeErr = fmt.Errorf("voice refund desired rule not yet observed")
			default:
				return HandlerResult{MutationKind: "partial", Note: "voice refund prepared operation superseded after write"}, fmt.Errorf("voice refund rule superseded prepared operation")
			}
		}
		if scopeErr == nil {
			if receipt.Phase == "prepared" {
				copy := journal.DeepCopy()
				receipt.Phase = "terminal-full"
				encoded, _ := json.Marshal(receipt)
				copy.Data["receipt.json"] = string(encoded)
				if err := ec.Client.Update(ctx, copy); err != nil {
					return HandlerResult{MutationKind: "partial", Note: "voice refund effect observed but journal terminal write failed"}, err
				}
			}
			return HandlerResult{ObjectsTouched: []string{voicerefundpolicy.Namespace + "/" + voicerefundpolicy.ConfigMapName}, MutationKind: "forward-only", Emitted: true, Note: "voice refund pair denial confirmed on all serving Pods"}, nil
		}
		select {
		case <-deadline.Done():
			return HandlerResult{MutationKind: "partial", Note: "voice refund rule updated; complete per-Pod projection unverified"}, fmt.Errorf("voice refund projection readback timed out: %w", scopeErr)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (voiceRefundHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	o := req.VoiceRefundObservation
	if req.Action != model.ActionVoiceRefundPairDeny || ec.Client == nil || ec.Reader == nil || ec.JournalNamespace == "" ||
		o == nil || req.TickID == "" || req.OperationID == "" || len(req.TickID) > 253 || len(req.OperationID) > 253 ||
		req.Namespace != voicerefundpolicy.Namespace || o.TargetPodUID != req.TargetUID || o.PolicyName != req.PolicyName ||
		o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration || !voicerefundpolicy.ValidSHA(o.AssertedCallerSHA256) ||
		!voicerefundpolicy.ValidSHA(o.OrderSHA256) {
		return HandlerResult{}, fmt.Errorf("voice refund selection authority incomplete")
	}
	target := Target{Namespace: req.Namespace, Pod: req.Pod, UID: req.TargetUID, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID}
	s, err := voiceRefundScopeAt(ctx, ec.Reader, target)
	if err != nil {
		return HandlerResult{}, err
	}
	opID := voiceRefundOperationID(req, o)
	name := voiceRefundJournalName(o.DeploymentUID, o.SelectedRevision+1)
	if journal, recorded, err := voiceRefundJournalGet(ctx, ec, name); err == nil {
		if recorded.OperationID != opID || recorded.PolicyName != req.PolicyName || recorded.PolicyUID != req.PolicyUID ||
			recorded.PolicyGeneration != req.PolicyGeneration || recorded.DeploymentUID != o.DeploymentUID ||
			recorded.TargetName != req.Pod || recorded.TargetPodUID != req.TargetUID || recorded.EventName != o.EventName ||
			recorded.EventUID != o.EventUID || recorded.CreatorIdentity != o.CreatorIdentity ||
			recorded.TickID != req.TickID || recorded.SelectionDecisionID != req.OperationID || recorded.ConfigMapUID != o.ConfigMapUID ||
			recorded.Prior.SHA256() != o.RuleSHA256 || recorded.Desired.OperationID != opID {
			return HandlerResult{}, fmt.Errorf("voice refund journal occupied by another selection")
		}
		return voiceRefundResume(ctx, ec, journal, recorded)
	} else if !apierrors.IsNotFound(err) {
		return HandlerResult{}, err
	}
	if string(s.deployment.UID) != o.DeploymentUID || string(s.cm.UID) != o.ConfigMapUID ||
		s.cm.ResourceVersion != o.ConfigMapResourceVersion || s.rule.Revision != o.SelectedRevision || s.rule.SHA256() != o.RuleSHA256 ||
		s.rule.SourceSHA256 != o.SourceSHA256 || s.policy.Generation != o.PolicyGeneration {
		return HandlerResult{}, fmt.Errorf("voice refund selected source or rule changed")
	}
	event := &amtdv1beta1.SecurityEvent{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, event); err != nil {
		return HandlerResult{}, err
	}
	if string(event.UID) != o.EventUID || event.DeletionTimestamp != nil || event.Annotations["phorvex.ai/creator-identity"] != o.CreatorIdentity ||
		s.pod.Annotations["phorvex.ai/voice-refund-event-creator"] != o.CreatorIdentity ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != o.TargetPodUID || event.Spec.Rule.Type != model.AttackVectorVoiceRefund ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod ||
		event.CreationTimestamp.IsZero() || time.Since(event.CreationTimestamp.Time) < 0 || time.Since(event.CreationTimestamp.Time) >= time.Minute {
		return HandlerResult{}, fmt.Errorf("voice refund event identity or freshness changed")
	}
	raw := event.Annotations[voiceRefundEventAnnotation]
	if len(raw) == 0 || len(raw) > 2048 || outputPolicyExactObject([]byte(raw), "version", "scenarioId", "caseId", "assertedCallerSHA256", "orderSHA256", "deploymentUID", "podUID", "sourceSHA256", "policyName", "policyUID", "policyGeneration", "observedAt", "evidenceSource", "modelCallbackObserved", "crmSideEffectObserved") != nil {
		return HandlerResult{}, fmt.Errorf("voice refund event assertion invalid")
	}
	var assertion struct {
		Version               int       `json:"version"`
		ScenarioID            string    `json:"scenarioId"`
		CaseID                string    `json:"caseId"`
		AssertedCallerSHA256  string    `json:"assertedCallerSHA256"`
		OrderSHA256           string    `json:"orderSHA256"`
		DeploymentUID         string    `json:"deploymentUID"`
		PodUID                string    `json:"podUID"`
		SourceSHA256          string    `json:"sourceSHA256"`
		PolicyName            string    `json:"policyName"`
		PolicyUID             string    `json:"policyUID"`
		PolicyGeneration      int64     `json:"policyGeneration"`
		EvidenceSource        string    `json:"evidenceSource"`
		ModelCallbackObserved bool      `json:"modelCallbackObserved"`
		CRMSideEffectObserved bool      `json:"crmSideEffectObserved"`
		ObservedAt            time.Time `json:"observedAt"`
	}
	if json.Unmarshal([]byte(raw), &assertion) != nil || assertion.Version != 1 || assertion.ScenarioID == "" || assertion.CaseID == "" ||
		assertion.ScenarioID != o.ScenarioID || assertion.CaseID != o.CaseID || assertion.AssertedCallerSHA256 != o.AssertedCallerSHA256 || assertion.OrderSHA256 != o.OrderSHA256 ||
		assertion.DeploymentUID != o.DeploymentUID || assertion.PodUID != o.TargetPodUID || assertion.SourceSHA256 != o.SourceSHA256 ||
		assertion.PolicyName != req.PolicyName || assertion.PolicyUID != req.PolicyUID || assertion.PolicyGeneration != req.PolicyGeneration ||
		assertion.EvidenceSource != "TEST_INJECTED" || !assertion.ModelCallbackObserved || !assertion.CRMSideEffectObserved ||
		!assertion.ObservedAt.Equal(o.ObservedAt) || assertion.ObservedAt.IsZero() ||
		assertion.ObservedAt.After(time.Now()) || assertion.ObservedAt.After(event.CreationTimestamp.Time.Add(time.Second)) ||
		event.CreationTimestamp.Time.Sub(assertion.ObservedAt) > time.Minute {
		return HandlerResult{}, fmt.Errorf("voice refund event payload changed")
	}
	for _, entry := range s.rule.Entries {
		if entry.AssertedCallerSHA256 == o.AssertedCallerSHA256 && entry.OrderSHA256 == o.OrderSHA256 {
			return HandlerResult{}, fmt.Errorf("voice refund pair already quarantined")
		}
	}
	if s.rule.Revision > 0 {
		_, priorReceipt, err := voiceRefundJournalGet(ctx, ec, voiceRefundJournalName(o.DeploymentUID, s.rule.Revision))
		if err != nil || priorReceipt.Phase != "terminal-full" || priorReceipt.Desired.SHA256() != s.rule.SHA256() {
			return HandlerResult{}, fmt.Errorf("voice refund prior operation unverified")
		}
	}
	if err := voiceRefundReadback(ctx, s, s.rule, ec.VoiceRefundTransport); err != nil {
		return HandlerResult{}, err
	}
	desired, err := voicerefundpolicy.Append(s.rule, voicerefundpolicy.Entry{AssertedCallerSHA256: o.AssertedCallerSHA256, OrderSHA256: o.OrderSHA256}, opID)
	if err != nil {
		return HandlerResult{}, err
	}
	receipt := voiceRefundReceipt{Version: 1, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration,
		DeploymentUID: o.DeploymentUID, TargetName: req.Pod, TargetPodUID: req.TargetUID, EventName: o.EventName, EventUID: o.EventUID, CreatorIdentity: o.CreatorIdentity,
		TickID: req.TickID, SelectionDecisionID: req.OperationID, ConfigMapUID: o.ConfigMapUID, Prior: s.rule, Desired: desired, OperationID: opID}
	encoded, _ := json.Marshal(receipt)
	journal := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ec.JournalNamespace, Labels: map[string]string{voiceRefundJournalLabel: "v1"}}, Data: map[string]string{"receipt.json": string(encoded)}}
	if err := ec.Client.Create(ctx, journal); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return HandlerResult{}, err
		}
		journal, existing, readErr := voiceRefundJournalGet(ctx, ec, name)
		if readErr != nil || existing.OperationID != opID || existing.PolicyName != req.PolicyName || existing.PolicyUID != req.PolicyUID ||
			existing.PolicyGeneration != req.PolicyGeneration || existing.DeploymentUID != o.DeploymentUID ||
			existing.TargetName != req.Pod || existing.TargetPodUID != req.TargetUID || existing.EventName != o.EventName ||
			existing.EventUID != o.EventUID || existing.CreatorIdentity != o.CreatorIdentity || existing.TickID != req.TickID ||
			existing.SelectionDecisionID != req.OperationID || existing.ConfigMapUID != o.ConfigMapUID ||
			existing.Phase != "prepared" || existing.Prior.SHA256() != s.rule.SHA256() || existing.Desired.SHA256() != desired.SHA256() {
			return HandlerResult{}, fmt.Errorf("voice refund journal occupied by another selection")
		}
		return voiceRefundResume(ctx, ec, journal, existing)
	}
	return voiceRefundResume(ctx, ec, journal, receipt)
}

func init() { HandlerRegistry.Register(voiceRefundHandler{}) }

func recoverVoiceRefundOperations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	list := &corev1.ConfigMapList{}
	if err := ec.Reader.List(ctx, list, client.InNamespace(ec.JournalNamespace), client.MatchingLabels{voiceRefundJournalLabel: "v1"}, client.Limit(101)); err != nil {
		return nil, err
	}
	if list.Continue != "" || len(list.Items) > 100 {
		return nil, fmt.Errorf("voice refund journal inventory exceeded recovery bound")
	}
	events := make([]RecoveryEvent, 0, len(list.Items))
	for i := range list.Items {
		journal, r, err := voiceRefundJournalGet(ctx, ec, list.Items[i].Name)
		ev := RecoveryEvent{Receipt: list.Items[i].Name, Kind: string(model.ActionVoiceRefundPairDeny), Outcome: "refused"}
		if err != nil {
			ev.Err = err
			events = append(events, ev)
			continue
		}
		ev.Phase = r.Phase
		ev.PolicyNamespace = voicerefundpolicy.Namespace
		ev.PolicyName = r.PolicyName
		ev.PolicyUID = r.PolicyUID
		ev.TargetName = r.TargetName
		ev.TargetUID = r.TargetPodUID
		if policy, authorityErr := receiptAuthority(ctx, ec.Reader, operationReceipt{PolicyNamespace: voicerefundpolicy.Namespace,
			PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, TargetName: r.TargetName, TargetUID: r.TargetPodUID}, model.ActionVoiceRefundPairDeny); authorityErr == nil {
			ev.Tenant = policy.Spec.Tenant
			if ev.Tenant == "" {
				ev.Tenant = voicerefundpolicy.Namespace
			}
		}
		if allow != nil && !allow(model.ActionVoiceRefundPairDeny) {
			ev.Err = fmt.Errorf("voice refund recovery routed away from native")
			events = append(events, ev)
			continue
		}
		if r.Phase == "terminal-full" {
			ev.Outcome = "confirmed"
			ev.Effect = "previously confirmed per-Pod Voice refund rule"
			events = append(events, ev)
			continue
		}
		_, ev.Err = voiceRefundResume(ctx, ec, journal, r)
		if ev.Err == nil {
			ev.Outcome = "confirmed"
			ev.Effect = "Voice refund rule confirmed on current serving Pods"
		} else {
			ev.Outcome = "partial"
		}
		events = append(events, ev)
	}
	return events, nil
}
