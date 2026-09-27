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
	"github.com/phorvex/phorvex/internal/voicememorypolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const (
	voiceMemorySecretName      = "voice-memory-state-token"
	voiceMemoryEventAnnotation = "phorvex.ai/voice-memory-observation-v1"
	voiceMemoryJournalLabel    = "phorvex.ai/voice-memory-journal"
)

type voiceMemoryScope struct {
	pod        *corev1.Pod
	deployment *appsv1.Deployment
	policy     *v1alpha1.PhorvexPolicy
	cm         *corev1.ConfigMap
	rule       voicememorypolicy.Rule
	secret     []byte
	pods       []corev1.Pod
}

func voiceMemoryOwner(ctx context.Context, reader client.Reader, pod *corev1.Pod) (*appsv1.Deployment, error) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || len(pod.OwnerReferences) != 1 || owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" {
		return nil, fmt.Errorf("voice memory Pod owner invalid")
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, rs); err != nil {
		return nil, err
	}
	if rs.UID != owner.UID || len(rs.OwnerReferences) != 1 {
		return nil, fmt.Errorf("voice memory ReplicaSet identity changed")
	}
	parent := metav1.GetControllerOf(rs)
	if parent == nil || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" {
		return nil, fmt.Errorf("voice memory Deployment owner absent")
	}
	dep := &appsv1.Deployment{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: parent.Name}, dep); err != nil {
		return nil, err
	}
	if dep.UID != parent.UID || dep.DeletionTimestamp != nil {
		return nil, fmt.Errorf("voice memory Deployment identity changed")
	}
	return dep, nil
}

func voiceMemoryMounts(pod *corev1.Pod) bool {
	var bot *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "bot" {
			bot = &pod.Spec.Containers[i]
		}
	}
	if bot == nil {
		return false
	}
	paths := map[string]string{}
	for _, m := range bot.VolumeMounts {
		if m.ReadOnly && m.SubPath == "" {
			paths[m.MountPath] = m.Name
		}
	}
	policyVol, secretVol := paths["/etc/phorvex/voice-memory-policy"], paths["/etc/phorvex/voice-memory-state-token"]
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
		if v.Name == policyVol && v.ConfigMap != nil && v.ConfigMap.Name == voicememorypolicy.ConfigMapName && v.ConfigMap.Optional != nil && *v.ConfigMap.Optional {
			valid++
		}
		if v.Name == secretVol && v.Secret != nil && v.Secret.SecretName == voiceMemorySecretName {
			valid++
		}
		if v.Name == watermark && v.EmptyDir != nil {
			valid++
		}
	}
	return valid == 3
}

func voiceMemoryReady(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil || p.Status.PodIP == "" || !voiceMemoryMounts(p) {
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

func voiceMemoryScopeAt(ctx context.Context, reader client.Reader, target Target) (voiceMemoryScope, error) {
	var s voiceMemoryScope
	if reader == nil || target.Namespace != voicememorypolicy.Namespace || target.Pod == "" || target.UID == "" || target.PolicyName == "" || target.PolicyUID == "" {
		return s, fmt.Errorf("voice memory target authority incomplete")
	}
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: target.Pod}, pod); err != nil {
		return s, err
	}
	if string(pod.UID) != target.UID || !voiceMemoryReady(pod) || pod.Annotations["phorvex.ai/voice-memory-policy-configmap"] != voicememorypolicy.ConfigMapName ||
		!voicememorypolicy.ValidSHA(pod.Annotations["phorvex.ai/voice-memory-source-sha256"]) || pod.Annotations["phorvex.ai/voice-memory-event-creator"] == "" {
		return s, fmt.Errorf("voice memory target Pod source, mount or readiness unbound")
	}
	dep, err := voiceMemoryOwner(ctx, reader, pod)
	if err != nil {
		return s, err
	}
	pol, err := receiptAuthority(ctx, reader, operationReceipt{PolicyNamespace: target.Namespace, PolicyName: target.PolicyName, PolicyUID: target.PolicyUID,
		TargetName: target.Pod, TargetUID: target.UID, TargetLabels: pod.Labels}, model.ActionVoiceMemoryNoteRevoke)
	if err != nil {
		return s, err
	}
	sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || sel.Empty() || !sel.Matches(labels.Set(pod.Labels)) {
		return s, fmt.Errorf("voice memory Pod outside policy selector")
	}
	cm := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: voicememorypolicy.ConfigMapName}, cm); err != nil {
		return s, err
	}
	if cm.DeletionTimestamp != nil || len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Controller == nil || !*cm.OwnerReferences[0].Controller || cm.OwnerReferences[0].APIVersion != "apps/v1" || cm.OwnerReferences[0].Kind != "Deployment" || cm.OwnerReferences[0].UID != dep.UID || cm.OwnerReferences[0].Name != dep.Name || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return s, fmt.Errorf("voice memory ConfigMap owner or data invalid")
	}
	rule, err := voicememorypolicy.Parse(cm.Data[voicememorypolicy.RuleKey])
	if err != nil || rule.DeploymentUID != string(dep.UID) || rule.PolicyUID != string(pol.UID) || rule.SourceSHA256 != pod.Annotations["phorvex.ai/voice-memory-source-sha256"] {
		return s, fmt.Errorf("voice memory current rule identity invalid")
	}
	secret := &corev1.Secret{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: voiceMemorySecretName}, secret); err != nil {
		return s, err
	}
	token := secret.Data["token"]
	if len(token) < 32 || len(token) > 256 {
		return s, fmt.Errorf("voice memory private readback token invalid")
	}
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return s, fmt.Errorf("voice memory private readback token invalid")
		}
	}
	depSel, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || depSel.Empty() || !depSel.Matches(labels.Set(pod.Labels)) {
		return s, fmt.Errorf("voice memory Deployment selector invalid")
	}
	list := &corev1.PodList{}
	if err := reader.List(ctx, list, client.InNamespace(target.Namespace), client.MatchingLabelsSelector{Selector: depSel}, client.Limit(33)); err != nil {
		return s, err
	}
	if list.Continue != "" || len(list.Items) == 0 || len(list.Items) > 32 {
		return s, fmt.Errorf("voice memory Pod inventory bound exceeded")
	}
	found := false
	for _, candidate := range list.Items {
		if candidate.DeletionTimestamp != nil {
			continue
		}
		owner, err := voiceMemoryOwner(ctx, reader, &candidate)
		if err != nil || owner.UID != dep.UID || !voiceMemoryReady(&candidate) ||
			!sel.Matches(labels.Set(candidate.Labels)) ||
			candidate.Annotations["phorvex.ai/voice-memory-policy-configmap"] != voicememorypolicy.ConfigMapName ||
			candidate.Annotations["phorvex.ai/voice-memory-source-sha256"] != rule.SourceSHA256 ||
			candidate.Annotations["phorvex.ai/voice-memory-event-creator"] != pod.Annotations["phorvex.ai/voice-memory-event-creator"] {
			return s, fmt.Errorf("voice memory serving Pod scope incomplete")
		}
		if candidate.UID == pod.UID {
			found = true
		}
		s.pods = append(s.pods, candidate)
	}
	if !found || len(s.pods) == 0 {
		return s, fmt.Errorf("voice memory target absent from serving set")
	}
	s.pod, s.deployment, s.policy, s.cm, s.rule, s.secret = pod, dep, pol, cm, rule, append([]byte(nil), token...)
	return s, nil
}

type voiceMemoryState struct {
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

func voiceMemoryReadback(ctx context.Context, s voiceMemoryScope, rule voicememorypolicy.Rule, transport http.RoundTripper) error {
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	}
	httpClient := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, pod := range s.pods {
		url := "http://" + net.JoinHostPort(pod.Status.PodIP, "8080") + voicememorypolicy.StatePath
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+string(s.secret))
		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("voice memory private readback unavailable for Pod UID %s: %w", pod.UID, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
		resp.Body.Close()
		if readErr != nil || len(body) > 4096 || resp.StatusCode != http.StatusOK {
			return fmt.Errorf("voice memory private readback unready for Pod UID %s", pod.UID)
		}
		if outputPolicyExactObject(body, "version", "podUID", "deploymentUID", "policyUID", "sourceSHA256", "ruleSHA256", "revision", "operationId", "entryCount", "ready") != nil {
			return fmt.Errorf("voice memory private readback shape invalid")
		}
		var state voiceMemoryState
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if dec.Decode(&state) != nil || !state.Ready || state.Version != 1 || state.PodUID != string(pod.UID) ||
			state.DeploymentUID != rule.DeploymentUID || state.PolicyUID != rule.PolicyUID || state.SourceSHA256 != rule.SourceSHA256 ||
			state.RuleSHA256 != rule.SHA256() || state.Revision != rule.Revision || state.OperationID != rule.OperationID || state.EntryCount != len(rule.Entries) {
			return fmt.Errorf("voice memory private readback identity or rule mismatch for Pod UID %s", pod.UID)
		}
		if _, err := dec.Token(); err != io.EOF {
			return fmt.Errorf("voice memory private readback trailing data")
		}
	}
	return nil
}

func voiceMemoryJournalName(deploymentUID string, revision uint64) string {
	h := sha256.Sum256([]byte(deploymentUID))
	return "phorvex-voice-memory-" + hex.EncodeToString(h[:16]) + "-" + strconv.FormatUint(revision, 10)
}

type voiceMemoryReceipt struct {
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
	Prior               voicememorypolicy.Rule `json:"prior"`
	Desired             voicememorypolicy.Rule `json:"desired"`
	OperationID         string                 `json:"operationId"`
}

func voiceMemoryJournalGet(ctx context.Context, ec EnactCtx, name string) (*corev1.ConfigMap, voiceMemoryReceipt, error) {
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: name}, cm); err != nil {
		return nil, voiceMemoryReceipt{}, err
	}
	var r voiceMemoryReceipt
	if cm.Labels[voiceMemoryJournalLabel] != "v1" || len(cm.Data) != 1 || len(cm.Data["receipt.json"]) == 0 || len(cm.Data["receipt.json"]) > 25000 ||
		json.Unmarshal([]byte(cm.Data["receipt.json"]), &r) != nil ||
		r.Version != 1 || (r.Phase != "prepared" && r.Phase != "terminal-full") || !r.Prior.Valid() || !r.Desired.Valid() ||
		r.Desired.Revision != r.Prior.Revision+1 || r.Desired.OperationID != r.OperationID || !voicememorypolicy.ValidSHA(r.OperationID) ||
		r.DeploymentUID != r.Prior.DeploymentUID || r.PolicyUID != r.Prior.PolicyUID || r.TargetName == "" || r.TargetPodUID == "" || r.EventUID == "" ||
		cm.Name != voiceMemoryJournalName(r.DeploymentUID, r.Desired.Revision) {
		return nil, voiceMemoryReceipt{}, fmt.Errorf("voice memory journal invalid")
	}
	canonical, _ := json.Marshal(r)
	if cm.Data["receipt.json"] != string(canonical) || r.PolicyName == "" || r.PolicyGeneration <= 0 || r.TickID == "" || r.SelectionDecisionID == "" ||
		len(r.TickID) > 253 || len(r.SelectionDecisionID) > 253 || r.ConfigMapUID == "" || r.CreatorIdentity == "" ||
		r.Prior.PolicyUID != r.Desired.PolicyUID || r.Prior.DeploymentUID != r.Desired.DeploymentUID || r.Prior.SourceSHA256 != r.Desired.SourceSHA256 ||
		len(r.Desired.Entries) != len(r.Prior.Entries)+1 ||
		r.OperationID != voiceMemoryOperationID(Request{PolicyUID: r.PolicyUID, TickID: r.TickID, OperationID: r.SelectionDecisionID}, &model.VoiceMemoryObservation{DeploymentUID: r.DeploymentUID, EventUID: r.EventUID}) {
		return nil, voiceMemoryReceipt{}, fmt.Errorf("voice memory journal intent invalid")
	}
	var latest *voicememorypolicy.Entry
	for i := range r.Desired.Entries {
		if r.Desired.Entries[i].OperationID == r.OperationID {
			latest = &r.Desired.Entries[i]
		}
	}
	if latest == nil {
		return nil, voiceMemoryReceipt{}, fmt.Errorf("voice memory journal latest entry missing")
	}
	rebuilt, err := voicememorypolicy.Append(r.Prior, voicememorypolicy.Entry{CallerID: latest.CallerID, NoteSHA256: latest.NoteSHA256}, r.OperationID)
	if err != nil || rebuilt.SHA256() != r.Desired.SHA256() {
		return nil, voiceMemoryReceipt{}, fmt.Errorf("voice memory journal erased prior entry")
	}
	return cm, r, nil
}

func voiceMemoryCapability(ctx context.Context, reader client.Reader, journalNS string, target Target, transport http.RoundTripper) (bool, string) {
	if journalNS == "" {
		return false, "voice-memory-journal-unavailable"
	}
	probe, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	s, err := voiceMemoryScopeAt(probe, reader, target)
	if err != nil {
		return false, "voice-memory-scope-unavailable: " + err.Error()
	}
	if len(s.rule.Entries) >= voicememorypolicy.MaxEntries {
		return false, "voice-memory-quarantine-full"
	}
	ec := EnactCtx{Reader: reader, JournalNamespace: journalNS}
	if s.rule.Revision > 0 {
		_, r, err := voiceMemoryJournalGet(probe, ec, voiceMemoryJournalName(string(s.deployment.UID), s.rule.Revision))
		if err != nil || r.Phase != "terminal-full" || r.Desired.SHA256() != s.rule.SHA256() {
			return false, "voice-memory-prior-operation-unverified"
		}
	}
	if _, _, err := voiceMemoryJournalGet(probe, ec, voiceMemoryJournalName(string(s.deployment.UID), s.rule.Revision+1)); err == nil {
		return false, "voice-memory-operation-pending"
	} else if !apierrors.IsNotFound(err) {
		return false, "voice-memory-journal-read-failed"
	}
	if err := voiceMemoryReadback(probe, s, s.rule, transport); err != nil {
		return false, "voice-memory-app-readback-unavailable"
	}
	return true, ""
}

func voiceMemoryOperationID(req Request, o *model.VoiceMemoryObservation) string {
	h := sha256.Sum256([]byte("phorvex-voice-memory-v1\x00" + req.PolicyUID + "\x00" + o.DeploymentUID + "\x00" + o.EventUID + "\x00" + req.TickID + "\x00" + req.OperationID))
	return hex.EncodeToString(h[:])
}

type voiceMemoryHandler struct{}

func (voiceMemoryHandler) Name() string { return string(model.ActionVoiceMemoryNoteRevoke) }

func voiceMemoryResume(ctx context.Context, ec EnactCtx, journal *corev1.ConfigMap, receipt voiceMemoryReceipt) (HandlerResult, error) {
	target := Target{Namespace: voicememorypolicy.Namespace, Pod: receipt.TargetName, UID: receipt.TargetPodUID, PolicyName: receipt.PolicyName, PolicyUID: receipt.PolicyUID}
	s, err := voiceMemoryScopeAt(ctx, ec.Reader, target)
	if err != nil {
		return HandlerResult{MutationKind: "partial"}, err
	}
	if string(s.deployment.UID) != receipt.DeploymentUID || string(s.cm.UID) != receipt.ConfigMapUID || s.policy.Generation != receipt.PolicyGeneration ||
		s.rule.SourceSHA256 != receipt.Prior.SourceSHA256 {
		return HandlerResult{MutationKind: "partial"}, fmt.Errorf("voice memory recovery authority changed")
	}
	if s.rule.SHA256() == receipt.Prior.SHA256() {
		if err := voiceMemoryReadback(ctx, s, receipt.Prior, ec.VoiceMemoryTransport); err != nil {
			return HandlerResult{MutationKind: "partial"}, err
		}
		copy := s.cm.DeepCopy()
		copy.Data[voicememorypolicy.RuleKey] = string(receipt.Desired.Bytes())
		if err := ec.Client.Update(ctx, copy); err != nil {
			return HandlerResult{MutationKind: "partial", Note: "voice memory prepared operation requires recovery"}, err
		}
	} else if s.rule.SHA256() != receipt.Desired.SHA256() {
		return HandlerResult{MutationKind: "partial"}, fmt.Errorf("voice memory rule superseded prepared operation")
	}
	deadline, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	for {
		current, scopeErr := voiceMemoryScopeAt(deadline, ec.Reader, target)
		if scopeErr == nil && current.rule.SHA256() == receipt.Desired.SHA256() {
			scopeErr = voiceMemoryReadback(deadline, current, receipt.Desired, ec.VoiceMemoryTransport)
		}
		if scopeErr == nil {
			if receipt.Phase == "prepared" {
				copy := journal.DeepCopy()
				receipt.Phase = "terminal-full"
				encoded, _ := json.Marshal(receipt)
				copy.Data["receipt.json"] = string(encoded)
				if err := ec.Client.Update(ctx, copy); err != nil {
					return HandlerResult{MutationKind: "partial", Note: "voice memory effect observed but journal terminal write failed"}, err
				}
			}
			return HandlerResult{ObjectsTouched: []string{voicememorypolicy.Namespace + "/" + voicememorypolicy.ConfigMapName}, MutationKind: "forward-only", Emitted: true, Note: "voice memory note quarantine confirmed on all serving Pods"}, nil
		}
		select {
		case <-deadline.Done():
			return HandlerResult{MutationKind: "partial", Note: "voice memory rule updated; complete per-Pod projection unverified"}, fmt.Errorf("voice memory projection readback timed out: %w", scopeErr)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (voiceMemoryHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	o := req.VoiceMemoryObservation
	if req.Action != model.ActionVoiceMemoryNoteRevoke || ec.Client == nil || ec.Reader == nil || ec.JournalNamespace == "" ||
		o == nil || req.TickID == "" || req.OperationID == "" || len(req.TickID) > 253 || len(req.OperationID) > 253 ||
		req.Namespace != voicememorypolicy.Namespace || o.TargetPodUID != req.TargetUID || o.PolicyName != req.PolicyName ||
		o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration || !voicememorypolicy.ValidCaller(o.CallerID) ||
		!voicememorypolicy.ValidSHA(o.NoteSHA256) {
		return HandlerResult{}, fmt.Errorf("voice memory selection authority incomplete")
	}
	target := Target{Namespace: req.Namespace, Pod: req.Pod, UID: req.TargetUID, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID}
	s, err := voiceMemoryScopeAt(ctx, ec.Reader, target)
	if err != nil {
		return HandlerResult{}, err
	}
	opID := voiceMemoryOperationID(req, o)
	name := voiceMemoryJournalName(o.DeploymentUID, o.SelectedRevision+1)
	if journal, recorded, err := voiceMemoryJournalGet(ctx, ec, name); err == nil {
		if recorded.OperationID != opID || recorded.PolicyUID != req.PolicyUID || recorded.PolicyGeneration != req.PolicyGeneration ||
			recorded.TargetName != req.Pod || recorded.TargetPodUID != req.TargetUID || recorded.EventUID != o.EventUID ||
			recorded.TickID != req.TickID || recorded.SelectionDecisionID != req.OperationID || recorded.ConfigMapUID != o.ConfigMapUID ||
			recorded.Prior.SHA256() != o.RuleSHA256 || recorded.Desired.OperationID != opID {
			return HandlerResult{}, fmt.Errorf("voice memory journal occupied by another selection")
		}
		return voiceMemoryResume(ctx, ec, journal, recorded)
	} else if !apierrors.IsNotFound(err) {
		return HandlerResult{}, err
	}
	if string(s.deployment.UID) != o.DeploymentUID || string(s.cm.UID) != o.ConfigMapUID ||
		s.cm.ResourceVersion != o.ConfigMapResourceVersion || s.rule.Revision != o.SelectedRevision || s.rule.SHA256() != o.RuleSHA256 ||
		s.rule.SourceSHA256 != o.SourceSHA256 || s.policy.Generation != o.PolicyGeneration {
		return HandlerResult{}, fmt.Errorf("voice memory selected source or rule changed")
	}
	event := &amtdv1beta1.SecurityEvent{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, event); err != nil {
		return HandlerResult{}, err
	}
	if string(event.UID) != o.EventUID || event.DeletionTimestamp != nil || event.Annotations["phorvex.ai/creator-identity"] != o.CreatorIdentity ||
		s.pod.Annotations["phorvex.ai/voice-memory-event-creator"] != o.CreatorIdentity ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != o.TargetPodUID || event.Spec.Rule.Type != model.AttackVectorVoiceMemory ||
		len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod ||
		event.CreationTimestamp.IsZero() || time.Since(event.CreationTimestamp.Time) < 0 || time.Since(event.CreationTimestamp.Time) >= time.Minute {
		return HandlerResult{}, fmt.Errorf("voice memory event identity or freshness changed")
	}
	raw := event.Annotations[voiceMemoryEventAnnotation]
	if len(raw) == 0 || len(raw) > 2048 || outputPolicyExactObject([]byte(raw), "version", "scenarioId", "caseId", "callerId", "noteSHA256", "deploymentUID", "podUID", "sourceSHA256", "policyName", "policyUID", "policyGeneration", "observedAt", "evidenceSource", "observed") != nil {
		return HandlerResult{}, fmt.Errorf("voice memory event assertion invalid")
	}
	var assertion struct {
		Version          int       `json:"version"`
		ScenarioID       string    `json:"scenarioId"`
		CaseID           string    `json:"caseId"`
		CallerID         string    `json:"callerId"`
		NoteSHA256       string    `json:"noteSHA256"`
		DeploymentUID    string    `json:"deploymentUID"`
		PodUID           string    `json:"podUID"`
		SourceSHA256     string    `json:"sourceSHA256"`
		PolicyName       string    `json:"policyName"`
		PolicyUID        string    `json:"policyUID"`
		PolicyGeneration int64     `json:"policyGeneration"`
		EvidenceSource   string    `json:"evidenceSource"`
		Observed         bool      `json:"observed"`
		ObservedAt       time.Time `json:"observedAt"`
	}
	if json.Unmarshal([]byte(raw), &assertion) != nil || assertion.Version != 1 || assertion.ScenarioID == "" || assertion.CaseID == "" ||
		assertion.ScenarioID != o.ScenarioID || assertion.CaseID != o.CaseID || assertion.CallerID != o.CallerID || assertion.NoteSHA256 != o.NoteSHA256 ||
		assertion.DeploymentUID != o.DeploymentUID || assertion.PodUID != o.TargetPodUID || assertion.SourceSHA256 != o.SourceSHA256 ||
		assertion.PolicyName != req.PolicyName || assertion.PolicyUID != req.PolicyUID || assertion.PolicyGeneration != req.PolicyGeneration ||
		assertion.EvidenceSource != "TEST_INJECTED" || !assertion.Observed || !assertion.ObservedAt.Equal(o.ObservedAt) {
		return HandlerResult{}, fmt.Errorf("voice memory event payload changed")
	}
	for _, entry := range s.rule.Entries {
		if entry.CallerID == o.CallerID && entry.NoteSHA256 == o.NoteSHA256 {
			return HandlerResult{}, fmt.Errorf("voice memory pair already quarantined")
		}
	}
	if s.rule.Revision > 0 {
		_, priorReceipt, err := voiceMemoryJournalGet(ctx, ec, voiceMemoryJournalName(o.DeploymentUID, s.rule.Revision))
		if err != nil || priorReceipt.Phase != "terminal-full" || priorReceipt.Desired.SHA256() != s.rule.SHA256() {
			return HandlerResult{}, fmt.Errorf("voice memory prior operation unverified")
		}
	}
	if err := voiceMemoryReadback(ctx, s, s.rule, ec.VoiceMemoryTransport); err != nil {
		return HandlerResult{}, err
	}
	desired, err := voicememorypolicy.Append(s.rule, voicememorypolicy.Entry{CallerID: o.CallerID, NoteSHA256: o.NoteSHA256}, opID)
	if err != nil {
		return HandlerResult{}, err
	}
	receipt := voiceMemoryReceipt{Version: 1, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration,
		DeploymentUID: o.DeploymentUID, TargetName: req.Pod, TargetPodUID: req.TargetUID, EventName: o.EventName, EventUID: o.EventUID, CreatorIdentity: o.CreatorIdentity,
		TickID: req.TickID, SelectionDecisionID: req.OperationID, ConfigMapUID: o.ConfigMapUID, Prior: s.rule, Desired: desired, OperationID: opID}
	encoded, _ := json.Marshal(receipt)
	journal := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ec.JournalNamespace, Labels: map[string]string{voiceMemoryJournalLabel: "v1"}}, Data: map[string]string{"receipt.json": string(encoded)}}
	if err := ec.Client.Create(ctx, journal); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return HandlerResult{}, err
		}
		journal, existing, readErr := voiceMemoryJournalGet(ctx, ec, name)
		if readErr != nil || existing.OperationID != opID || existing.EventUID != o.EventUID || existing.Phase != "prepared" || existing.Prior.SHA256() != s.rule.SHA256() || existing.Desired.SHA256() != desired.SHA256() {
			return HandlerResult{}, fmt.Errorf("voice memory journal occupied by another selection")
		}
		return voiceMemoryResume(ctx, ec, journal, existing)
	}
	return voiceMemoryResume(ctx, ec, journal, receipt)
}

func init() { HandlerRegistry.Register(voiceMemoryHandler{}) }

func recoverVoiceMemoryOperations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	list := &corev1.ConfigMapList{}
	if err := ec.Reader.List(ctx, list, client.InNamespace(ec.JournalNamespace), client.MatchingLabels{voiceMemoryJournalLabel: "v1"}, client.Limit(101)); err != nil {
		return nil, err
	}
	if list.Continue != "" || len(list.Items) > 100 {
		return nil, fmt.Errorf("voice memory journal inventory exceeded recovery bound")
	}
	events := make([]RecoveryEvent, 0, len(list.Items))
	for i := range list.Items {
		journal, r, err := voiceMemoryJournalGet(ctx, ec, list.Items[i].Name)
		ev := RecoveryEvent{Receipt: list.Items[i].Name, Kind: string(model.ActionVoiceMemoryNoteRevoke), Outcome: "refused"}
		if err != nil {
			ev.Err = err
			events = append(events, ev)
			continue
		}
		ev.Phase = r.Phase
		ev.PolicyNamespace = voicememorypolicy.Namespace
		ev.PolicyName = r.PolicyName
		ev.PolicyUID = r.PolicyUID
		ev.TargetName = r.TargetName
		ev.TargetUID = r.TargetPodUID
		if allow != nil && !allow(model.ActionVoiceMemoryNoteRevoke) {
			ev.Err = fmt.Errorf("voice memory recovery routed away from native")
			events = append(events, ev)
			continue
		}
		if r.Phase == "terminal-full" {
			ev.Outcome = "confirmed"
			ev.Effect = "previously confirmed per-Pod Voice memory rule"
			events = append(events, ev)
			continue
		}
		_, ev.Err = voiceMemoryResume(ctx, ec, journal, r)
		if ev.Err == nil {
			ev.Outcome = "confirmed"
			ev.Effect = "Voice memory rule confirmed on current serving Pods"
		} else {
			ev.Outcome = "partial"
		}
		events = append(events, ev)
	}
	return events, nil
}
