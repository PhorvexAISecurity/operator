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
	"net/netip"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceoutputpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const (
	voiceOutputJournalName           = "phorvex-voice-output-journal"
	voiceOutputJournalLabel          = "phorvex.ai/voice-output-journal"
	voiceOutputObservationAnnotation = "phorvex.ai/voice-output-observation-v1"
	voiceOutputSecretName            = "voice-memory-state-token"
	voiceOutputTestSecretName        = "voice-output-test-token"
	voiceOutputCreator               = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
)

type voiceOutputScope struct {
	pod        *corev1.Pod
	deployment *appsv1.Deployment
	policy     *v1alpha1.PhorvexPolicy
	cm         *corev1.ConfigMap
	rule       voiceoutputpolicy.Rule
	token      []byte
	pods       []corev1.Pod
}

func voiceOutputReady(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil || p.Status.PodIP == "" || !voiceOutputRequiredMounts(p) {
		return false
	}
	if _, e := netip.ParseAddr(p.Status.PodIP); e != nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func voiceOutputRequiredMounts(p *corev1.Pod) bool {
	var bot *corev1.Container
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == "bot" {
			bot = &p.Spec.Containers[i]
		}
	}
	if bot == nil {
		return false
	}
	mode := 0
	for _, v := range bot.Env {
		if v.Name == "VOICE_OUTPUT_POLICY_REQUIRED" {
			if v.Value != "true" || v.ValueFrom != nil {
				return false
			}
			mode++
		}
	}
	if mode != 1 {
		return false
	}
	mounts := map[string]string{}
	watermark := ""
	for _, m := range bot.VolumeMounts {
		if m.ReadOnly && m.SubPath == "" {
			mounts[m.MountPath] = m.Name
		}
		if m.MountPath == "/var/lib/phorvex-voice-memory" && m.SubPath == "" {
			watermark = m.Name
		}
	}
	policyVol, tokenVol := mounts["/etc/phorvex/voice-output-policy"], mounts["/etc/phorvex/voice-memory-state-token"]
	testTokenVol := mounts["/etc/phorvex/voice-output-test-token"]
	if policyVol == "" || tokenVol == "" || testTokenVol == "" || watermark == "" {
		return false
	}
	count := 0
	for _, v := range p.Spec.Volumes {
		if v.Name == policyVol && v.ConfigMap != nil && v.ConfigMap.Name == voiceoutputpolicy.ConfigMapName && (v.ConfigMap.Optional == nil || !*v.ConfigMap.Optional) {
			count++
		}
		if v.Name == tokenVol && v.Secret != nil && v.Secret.SecretName == voiceOutputSecretName {
			count++
		}
		if v.Name == testTokenVol && v.Secret != nil && v.Secret.SecretName == voiceOutputTestSecretName {
			count++
		}
		if v.Name == watermark && v.EmptyDir != nil {
			count++
		}
	}
	return count == 4
}

func voiceOutputScopeAt(ctx context.Context, reader client.Reader, target Target) (voiceOutputScope, error) {
	var s voiceOutputScope
	if reader == nil || target.Namespace != voiceoutputpolicy.Namespace || target.Pod == "" || target.UID == "" || target.PolicyName == "" || target.PolicyUID == "" {
		return s, errors.New("Voice output target authority incomplete")
	}
	pod := &corev1.Pod{}
	if e := reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: target.Pod}, pod); e != nil {
		return s, e
	}
	if string(pod.UID) != target.UID || !voiceOutputReady(pod) || pod.Annotations["phorvex.ai/voice-output-policy-configmap"] != voiceoutputpolicy.ConfigMapName || !voiceoutputpolicy.ValidSHA(pod.Annotations["phorvex.ai/voice-output-source-sha256"]) || pod.Annotations["phorvex.ai/voice-output-event-creator"] == "" {
		return s, errors.New("Voice output target source, mount or readiness unbound")
	}
	dep, e := voiceRefundOwner(ctx, reader, pod)
	if e != nil {
		return s, e
	}
	pol, e := receiptAuthority(ctx, reader, operationReceipt{PolicyNamespace: target.Namespace, PolicyName: target.PolicyName, PolicyUID: target.PolicyUID, TargetName: target.Pod, TargetUID: target.UID, TargetLabels: pod.Labels}, model.ActionVoiceOutputPolicyActivate)
	if e != nil {
		return s, e
	}
	sel, e := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if e != nil || sel.Empty() || !sel.Matches(labels.Set(pod.Labels)) {
		return s, errors.New("Voice output target outside policy selector")
	}
	cm := &corev1.ConfigMap{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: voiceoutputpolicy.ConfigMapName}, cm); e != nil {
		return s, e
	}
	if cm.DeletionTimestamp != nil || !voiceOutputOwnedCM(cm, dep) || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return s, errors.New("Voice output ConfigMap owner or data invalid")
	}
	rule, e := voiceoutputpolicy.Parse(cm.Data[voiceoutputpolicy.RuleKey])
	if e != nil || rule.ConfigMapUID != string(cm.UID) || rule.DeploymentUID != string(dep.UID) || rule.PolicyUID != string(pol.UID) || rule.SourceSHA256 != pod.Annotations["phorvex.ai/voice-output-source-sha256"] {
		return s, errors.New("Voice output current rule identity invalid")
	}
	secret := &corev1.Secret{}
	if e = reader.Get(ctx, client.ObjectKey{Namespace: target.Namespace, Name: voiceOutputSecretName}, secret); e != nil {
		return s, e
	}
	token := secret.Data["token"]
	if len(token) < 32 || len(token) > 256 {
		return s, errors.New("Voice output private token invalid")
	}
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return s, errors.New("Voice output private token invalid")
		}
	}
	depSel, e := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if e != nil || depSel.Empty() || !depSel.Matches(labels.Set(pod.Labels)) {
		return s, errors.New("Voice output Deployment selector invalid")
	}
	list := &corev1.PodList{}
	if e = reader.List(ctx, list, client.InNamespace(target.Namespace), client.Limit(129)); e != nil {
		return s, e
	}
	if list.Continue != "" || len(list.Items) == 0 || len(list.Items) > 128 {
		return s, errors.New("Voice output Pod inventory bound exceeded")
	}
	found := false
	for _, candidate := range list.Items {
		if candidate.DeletionTimestamp != nil {
			continue
		}
		owner, oe := voiceRefundOwner(ctx, reader, &candidate)
		if oe != nil {
			if depSel.Matches(labels.Set(candidate.Labels)) {
				return s, errors.New("Voice output labelled Pod owner chain invalid")
			}
			continue
		}
		if owner.UID != dep.UID {
			continue
		}
		if !voiceOutputReady(&candidate) || !depSel.Matches(labels.Set(candidate.Labels)) || !sel.Matches(labels.Set(candidate.Labels)) || candidate.Annotations["phorvex.ai/voice-output-policy-configmap"] != voiceoutputpolicy.ConfigMapName || candidate.Annotations["phorvex.ai/voice-output-source-sha256"] != rule.SourceSHA256 || candidate.Annotations["phorvex.ai/voice-output-event-creator"] != pod.Annotations["phorvex.ai/voice-output-event-creator"] {
			return s, errors.New("Voice output serving Pod scope incomplete")
		}
		if candidate.UID == pod.UID {
			found = true
		}
		s.pods = append(s.pods, candidate)
	}
	if !found || len(s.pods) == 0 {
		return s, errors.New("Voice output target absent from serving set")
	}
	s.pod, s.deployment, s.policy, s.cm, s.rule, s.token = pod, dep, pol, cm, rule, append([]byte(nil), token...)
	return s, nil
}

func voiceOutputOwnedCM(cm *corev1.ConfigMap, dep *appsv1.Deployment) bool {
	if len(cm.OwnerReferences) != 1 {
		return false
	}
	o := cm.OwnerReferences[0]
	return o.Controller != nil && *o.Controller && o.APIVersion == "apps/v1" && o.Kind == "Deployment" && o.Name == dep.Name && o.UID == dep.UID
}

type voiceOutputState struct {
	Version            int    `json:"version"`
	PodUID             string `json:"podUID"`
	ConfigMapUID       string `json:"configMapUID"`
	DeploymentUID      string `json:"deploymentUID"`
	PolicyUID          string `json:"policyUID"`
	SourceSHA256       string `json:"sourceSHA256"`
	RuleSHA256         string `json:"ruleSHA256"`
	Revision           uint64 `json:"revision"`
	OperationID        string `json:"operationId"`
	EntryCount         int    `json:"entryCount"`
	MarkerSHA256       string `json:"markerSHA256"`
	Active             bool   `json:"active"`
	MatchedOperationID string `json:"matchedOperationId"`
	Ready              bool   `json:"ready"`
}

func voiceOutputReadback(ctx context.Context, s voiceOutputScope, rule voiceoutputpolicy.Rule, marker string, active bool, transport http.RoundTripper) error {
	if len(s.pods) == 0 || !rule.Valid() || !voiceoutputpolicy.ValidSHA(marker) {
		return errors.New("Voice output readback scope or marker invalid")
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	}
	httpClient := &http.Client{Transport: transport, Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, pod := range s.pods {
		url := "http://" + net.JoinHostPort(pod.Status.PodIP, "8080") + voiceoutputpolicy.StatePath + "?markerSHA256=" + marker
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+string(s.token))
		resp, e := httpClient.Do(req)
		if e != nil {
			return fmt.Errorf("Voice output private readback unavailable for Pod UID %s: %w", pod.UID, e)
		}
		body, re := io.ReadAll(io.LimitReader(resp.Body, 4097))
		resp.Body.Close()
		if re != nil || len(body) > 4096 || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
			return fmt.Errorf("Voice output private readback unready for Pod UID %s", pod.UID)
		}
		if outputPolicyExactObject(body, "version", "podUID", "configMapUID", "deploymentUID", "policyUID", "sourceSHA256", "ruleSHA256", "revision", "operationId", "entryCount", "markerSHA256", "active", "matchedOperationId", "ready") != nil {
			return errors.New("Voice output private readback shape invalid")
		}
		var state voiceOutputState
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		expectedOp := ""
		if active {
			for _, entry := range rule.Entries {
				if entry.MarkerSHA256 == marker {
					expectedOp = entry.OperationID
				}
			}
			if expectedOp == "" {
				return errors.New("Voice output desired marker absent from rule")
			}
		}
		if dec.Decode(&state) != nil || !state.Ready || state.Version != 1 || state.PodUID != string(pod.UID) || state.ConfigMapUID != rule.ConfigMapUID || state.DeploymentUID != rule.DeploymentUID || state.PolicyUID != rule.PolicyUID || state.SourceSHA256 != rule.SourceSHA256 || state.RuleSHA256 != rule.SHA256() || state.Revision != rule.Revision || state.OperationID != rule.OperationID || state.EntryCount != len(rule.Entries) || state.MarkerSHA256 != marker || state.Active != active || state.MatchedOperationID != expectedOp {
			return fmt.Errorf("Voice output private readback identity or rule mismatch for Pod UID %s", pod.UID)
		}
		if _, e = dec.Token(); e != io.EOF {
			return errors.New("Voice output private readback trailing data")
		}
	}
	return nil
}

type voiceOutputReceipt struct {
	Version             int    `json:"version"`
	Phase               string `json:"phase"`
	PolicyName          string `json:"policyName"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	DeploymentUID       string `json:"deploymentUID"`
	TargetName          string `json:"targetName"`
	TargetPodUID        string `json:"targetPodUID"`
	EventName           string `json:"eventName"`
	EventUID            string `json:"eventUID"`
	CreatorIdentity     string `json:"creatorIdentity"`
	TickID              string `json:"tickId"`
	SelectionDecisionID string `json:"selectionDecisionId"`
	ConfigMapUID        string `json:"configMapUID"`
	MarkerSHA256        string `json:"markerSHA256"`
	SourceSHA256        string `json:"sourceSHA256"`
	PriorRuleSHA256     string `json:"priorRuleSHA256"`
	DesiredRuleSHA256   string `json:"desiredRuleSHA256"`
	PriorRevision       uint64 `json:"priorRevision"`
	DesiredRevision     uint64 `json:"desiredRevision"`
	OperationID         string `json:"operationId"`
}

type voiceOutputJournal struct {
	Receipts []voiceOutputReceipt `json:"receipts"`
	Version  int                  `json:"version"`
}

func voiceOutputOperationID(policyUID, deploymentUID, podUID, eventUID, tickID, decisionID string) string {
	h := sha256.Sum256([]byte("phorvex-voice-output-v1\x00" + policyUID + "\x00" + deploymentUID + "\x00" + podUID + "\x00" + eventUID + "\x00" + tickID + "\x00" + decisionID))
	return hex.EncodeToString(h[:])
}

func voiceOutputJournalGet(ctx context.Context, reader client.Reader, ns string) (*corev1.ConfigMap, voiceOutputJournal, error) {
	cm := &corev1.ConfigMap{}
	if reader == nil || ns == "" {
		return nil, voiceOutputJournal{}, errors.New("Voice output protected journal unavailable")
	}
	if e := reader.Get(ctx, client.ObjectKey{Namespace: ns, Name: voiceOutputJournalName}, cm); e != nil {
		return nil, voiceOutputJournal{}, e
	}
	if cm.Labels[voiceOutputJournalLabel] != "v1" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || len(cm.Data["receipts.json"]) == 0 || len(cm.Data["receipts.json"]) > 262144 {
		return nil, voiceOutputJournal{}, errors.New("Voice output protected journal shape invalid")
	}
	var j voiceOutputJournal
	raw := cm.Data["receipts.json"]
	if json.Unmarshal([]byte(raw), &j) != nil || j.Version != 1 || j.Receipts == nil || len(j.Receipts) > voiceoutputpolicy.MaxEntries {
		return nil, voiceOutputJournal{}, errors.New("Voice output protected journal invalid")
	}
	canonical, _ := json.Marshal(j)
	if raw != string(canonical) {
		return nil, voiceOutputJournal{}, errors.New("Voice output protected journal noncanonical")
	}
	var prior voiceoutputpolicy.Rule
	for i, r := range j.Receipts {
		if r.Version != 1 || (r.Phase != "prepared" && r.Phase != "terminal-full") || (r.Phase == "prepared" && i != len(j.Receipts)-1) || r.PolicyName == "" || !voiceoutputpolicy.ValidUID(r.PolicyUID) || r.PolicyGeneration <= 0 || !voiceoutputpolicy.ValidUID(r.DeploymentUID) || r.TargetName == "" || !voiceoutputpolicy.ValidUID(r.TargetPodUID) || r.EventName == "" || !voiceoutputpolicy.ValidUID(r.EventUID) || r.CreatorIdentity == "" || r.TickID == "" || len(r.TickID) > 253 || r.SelectionDecisionID == "" || len(r.SelectionDecisionID) > 253 || !voiceoutputpolicy.ValidUID(r.ConfigMapUID) || !voiceoutputpolicy.ValidSHA(r.MarkerSHA256) || !voiceoutputpolicy.ValidSHA(r.SourceSHA256) || !voiceoutputpolicy.ValidSHA(r.PriorRuleSHA256) || !voiceoutputpolicy.ValidSHA(r.DesiredRuleSHA256) || r.PriorRevision != uint64(i) || r.DesiredRevision != uint64(i+1) || r.OperationID != voiceOutputOperationID(r.PolicyUID, r.DeploymentUID, r.TargetPodUID, r.EventUID, r.TickID, r.SelectionDecisionID) {
			return nil, voiceOutputJournal{}, errors.New("Voice output protected receipt invalid")
		}
		if i == 0 {
			prior = voiceoutputpolicy.Rule{Version: 1, ConfigMapUID: r.ConfigMapUID, DeploymentUID: r.DeploymentUID, PolicyUID: r.PolicyUID, SourceSHA256: r.SourceSHA256, Entries: []voiceoutputpolicy.Entry{}}
		}
		if prior.SHA256() != r.PriorRuleSHA256 || prior.ConfigMapUID != r.ConfigMapUID || prior.DeploymentUID != r.DeploymentUID || prior.PolicyUID != r.PolicyUID || prior.SourceSHA256 != r.SourceSHA256 {
			return nil, voiceOutputJournal{}, errors.New("Voice output protected history changed")
		}
		next, e := voiceoutputpolicy.Append(prior, r.MarkerSHA256, r.OperationID)
		if e != nil || next.SHA256() != r.DesiredRuleSHA256 {
			return nil, voiceOutputJournal{}, errors.New("Voice output protected append invalid")
		}
		prior = next
	}
	return cm, j, nil
}

func voiceOutputJournalMatchesRule(j voiceOutputJournal, rule voiceoutputpolicy.Rule) bool {
	if !rule.Valid() {
		return false
	}
	if len(j.Receipts) == 0 {
		return rule.Revision == 0
	}
	last := j.Receipts[len(j.Receipts)-1]
	if last.Phase == "prepared" {
		return rule.Revision == last.PriorRevision && rule.SHA256() == last.PriorRuleSHA256 || rule.Revision == last.DesiredRevision && rule.SHA256() == last.DesiredRuleSHA256
	}
	return rule.Revision == last.DesiredRevision && rule.SHA256() == last.DesiredRuleSHA256
}

func voiceOutputCapability(ctx context.Context, reader client.Reader, journalNS string, target Target, transport http.RoundTripper) (bool, string) {
	if journalNS == "" {
		return false, "voice-output-journal-unavailable"
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, e := voiceOutputScopeAt(probe, reader, target)
	if e != nil {
		return false, "voice-output-scope-unavailable: " + e.Error()
	}
	if len(s.rule.Entries) >= voiceoutputpolicy.MaxEntries {
		return false, "voice-output-policy-full"
	}
	_, j, e := voiceOutputJournalGet(probe, reader, journalNS)
	if e != nil || !voiceOutputJournalMatchesRule(j, s.rule) {
		return false, "voice-output-prior-history-unverified"
	}
	if len(j.Receipts) > 0 && j.Receipts[len(j.Receipts)-1].Phase == "prepared" {
		return false, "voice-output-operation-pending"
	}
	// An observation is only available in a decision snapshot; support checks the app
	// source and journal, while dispatch checks the exact marker readback.
	return true, ""
}

func PendingVoiceOutputOperation(ctx context.Context, reader client.Reader, journalNS, namespace, podName, podUID string) (bool, error) {
	if namespace != voiceoutputpolicy.Namespace || podUID == "" {
		return false, nil
	}
	_, j, e := voiceOutputJournalGet(ctx, reader, journalNS)
	if apierrors.IsNotFound(e) {
		policy := &corev1.ConfigMap{}
		probe := reader.Get(ctx, client.ObjectKey{Namespace: voiceoutputpolicy.Namespace, Name: voiceoutputpolicy.ConfigMapName}, policy)
		if apierrors.IsNotFound(probe) {
			return false, nil
		}
		if probe != nil {
			return true, probe
		}
		return true, errors.New("Voice output protected journal absent with installed policy")
	}
	if e != nil {
		return true, e
	}
	if len(j.Receipts) == 0 {
		return false, nil
	}
	r := j.Receipts[len(j.Receipts)-1]
	if r.Phase != "prepared" {
		return false, nil
	}
	if r.TargetPodUID == podUID {
		return true, nil
	}
	if podName == "" {
		return true, errors.New("Voice output pending operation cannot verify other Pod ownership")
	}
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: podName}, pod); err != nil {
		return true, err
	}
	if string(pod.UID) != podUID {
		return true, errors.New("Voice output pending operation target Pod changed")
	}
	dep, err := voiceRefundOwner(ctx, reader, pod)
	if err != nil {
		return true, err
	}
	return string(dep.UID) == r.DeploymentUID, nil
}

type voiceOutputHandler struct{}

func (voiceOutputHandler) Name() string { return string(model.ActionVoiceOutputPolicyActivate) }
func init()                             { HandlerRegistry.Register(voiceOutputHandler{}) }

func voiceOutputEvent(ctx context.Context, ec EnactCtx, req Request, o *model.VoiceOutputObservation, s voiceOutputScope) error {
	event := &amtdv1beta1.SecurityEvent{}
	if e := ec.Reader.Get(ctx, client.ObjectKey{Name: o.EventName}, event); e != nil {
		return e
	}
	if string(event.UID) != o.EventUID || event.DeletionTimestamp != nil || event.Annotations["phorvex.ai/creator-identity"] != o.CreatorIdentity || o.CreatorIdentity != voiceOutputCreator || s.pod.Annotations["phorvex.ai/voice-output-event-creator"] != o.CreatorIdentity || event.Annotations[model.ConsoleTargetPodUIDAnnotation] != o.TargetPodUID || event.Spec.Rule.Type != model.AttackVectorVoiceOutput || event.Spec.Rule.Source != "redteam" || len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != req.Namespace+"/"+req.Pod || event.CreationTimestamp.IsZero() || time.Since(event.CreationTimestamp.Time) < 0 || time.Since(event.CreationTimestamp.Time) >= time.Minute {
		return errors.New("Voice output SecurityEvent identity or freshness changed")
	}
	raw := event.Annotations[voiceOutputObservationAnnotation]
	if len(raw) == 0 || len(raw) > 2048 || outputPolicyExactObject([]byte(raw), "version", "scenarioId", "evidenceSource", "rawModelMarkerObserved", "assistantOutputMarkerObserved", "markerSHA256", "configMapUID", "deploymentUID", "sourceSHA256", "policyName", "policyUID", "policyGeneration", "podUID", "observedAt", "requestPath") != nil {
		return errors.New("Voice output event assertion malformed")
	}
	var a struct {
		Version                       int       `json:"version"`
		ScenarioID                    string    `json:"scenarioId"`
		EvidenceSource                string    `json:"evidenceSource"`
		RawModelMarkerObserved        bool      `json:"rawModelMarkerObserved"`
		AssistantOutputMarkerObserved bool      `json:"assistantOutputMarkerObserved"`
		MarkerSHA256                  string    `json:"markerSHA256"`
		ConfigMapUID                  string    `json:"configMapUID"`
		DeploymentUID                 string    `json:"deploymentUID"`
		SourceSHA256                  string    `json:"sourceSHA256"`
		PolicyName                    string    `json:"policyName"`
		PolicyUID                     string    `json:"policyUID"`
		PolicyGeneration              int64     `json:"policyGeneration"`
		PodUID                        string    `json:"podUID"`
		ObservedAt                    time.Time `json:"observedAt"`
		RequestPath                   string    `json:"requestPath"`
	}
	if json.Unmarshal([]byte(raw), &a) != nil || a.Version != 1 || a.ScenarioID != "ai2-system-prompt-leakage" || a.EvidenceSource != "TEST_INJECTED" || !a.RawModelMarkerObserved || !a.AssistantOutputMarkerObserved || a.MarkerSHA256 != o.MarkerSHA256 || a.ConfigMapUID != o.ConfigMapUID || a.DeploymentUID != o.DeploymentUID || a.SourceSHA256 != o.SourceSHA256 || a.PolicyName != req.PolicyName || a.PolicyUID != req.PolicyUID || a.PolicyGeneration != req.PolicyGeneration || a.PodUID != req.TargetUID || a.RequestPath != "/ws" || !a.ObservedAt.Equal(o.ObservedAt) || a.ObservedAt.IsZero() || a.ObservedAt.After(time.Now()) || a.ObservedAt.After(event.CreationTimestamp.Time.Add(time.Second)) || event.CreationTimestamp.Time.Sub(a.ObservedAt) > time.Minute {
		return errors.New("Voice output event assertion changed")
	}
	return nil
}

func voiceOutputResume(ctx context.Context, ec EnactCtx, jcm *corev1.ConfigMap, j voiceOutputJournal, r voiceOutputReceipt) (HandlerResult, error) {
	target := Target{Namespace: voiceoutputpolicy.Namespace, Pod: r.TargetName, UID: r.TargetPodUID, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID}
	s, e := voiceOutputScopeAt(ctx, ec.Reader, target)
	if e != nil {
		return HandlerResult{MutationKind: "partial"}, e
	}
	if string(s.deployment.UID) != r.DeploymentUID || string(s.cm.UID) != r.ConfigMapUID || s.policy.Generation != r.PolicyGeneration || s.rule.SourceSHA256 != r.SourceSHA256 {
		return HandlerResult{MutationKind: "partial"}, errors.New("Voice output recovery authority changed")
	}
	if s.rule.Revision == r.PriorRevision && s.rule.SHA256() == r.PriorRuleSHA256 {
		if e = voiceOutputReadback(ctx, s, s.rule, r.MarkerSHA256, false, ec.VoiceOutputTransport); e != nil {
			return HandlerResult{MutationKind: "partial"}, e
		}
		desired, ae := voiceoutputpolicy.Append(s.rule, r.MarkerSHA256, r.OperationID)
		if ae != nil || desired.SHA256() != r.DesiredRuleSHA256 {
			return HandlerResult{MutationKind: "partial"}, errors.New("Voice output prepared append changed")
		}
		copy := s.cm.DeepCopy()
		copy.Data[voiceoutputpolicy.RuleKey] = string(desired.Bytes())
		if e = ec.Client.Update(ctx, copy); e != nil {
			return HandlerResult{MutationKind: "partial", Note: "Voice output prepared operation awaits recovery"}, e
		}
	} else if s.rule.Revision != r.DesiredRevision || s.rule.SHA256() != r.DesiredRuleSHA256 {
		return HandlerResult{MutationKind: "partial"}, errors.New("Voice output protected rule superseded")
	}
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		current, se := voiceOutputScopeAt(deadline, ec.Reader, target)
		if se == nil {
			if current.rule.SHA256() == r.DesiredRuleSHA256 {
				se = voiceOutputReadback(deadline, current, current.rule, r.MarkerSHA256, true, ec.VoiceOutputTransport)
			} else if current.rule.SHA256() == r.PriorRuleSHA256 {
				se = errors.New("Voice output desired projection pending")
			} else {
				return HandlerResult{MutationKind: "partial"}, errors.New("Voice output rule changed after CAS")
			}
		}
		if se == nil {
			if r.Phase == "prepared" {
				copy := jcm.DeepCopy()
				j.Receipts[len(j.Receipts)-1].Phase = "terminal-full"
				raw, _ := json.Marshal(j)
				copy.Data["receipts.json"] = string(raw)
				if e = ec.Client.Update(ctx, copy); e != nil {
					return HandlerResult{MutationKind: "partial", Note: "Voice output effect seen but terminal journal write failed"}, e
				}
			}
			return HandlerResult{ObjectsTouched: []string{voiceoutputpolicy.Namespace + "/" + voiceoutputpolicy.ConfigMapName}, MutationKind: "forward-only", Emitted: true, Note: "Voice output rule projected to all current Ready Pods; speech outcome requires separate same-request proof"}, nil
		}
		select {
		case <-deadline.Done():
			return HandlerResult{MutationKind: "partial", Note: "Voice output rule update or projection unresolved"}, fmt.Errorf("Voice output readback timed out: %w", se)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (voiceOutputHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	o := req.VoiceOutputObservation
	if req.Action != model.ActionVoiceOutputPolicyActivate || ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || o == nil || req.Namespace != voiceoutputpolicy.Namespace || req.TickID == "" || req.OperationID == "" || len(req.TickID) > 253 || len(req.OperationID) > 253 || o.TargetPodUID != req.TargetUID || o.PolicyName != req.PolicyName || o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration || o.ScenarioID != "ai2-system-prompt-leakage" || o.EvidenceSource != "TEST_INJECTED" || o.CreatorIdentity != voiceOutputCreator || !o.RawModelMarkerObserved || !o.AssistantOutputMarkerObserved || !voiceoutputpolicy.ValidSHA(o.MarkerSHA256) {
		return HandlerResult{}, errors.New("Voice output selection authority incomplete")
	}
	target := Target{Namespace: req.Namespace, Pod: req.Pod, UID: req.TargetUID, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID}
	s, e := voiceOutputScopeAt(ctx, ec.Reader, target)
	if e != nil {
		return HandlerResult{}, e
	}
	jcm, j, e := voiceOutputJournalGet(ctx, ec.Reader, ec.JournalNamespace)
	if e != nil {
		return HandlerResult{}, e
	}
	if !voiceOutputJournalMatchesRule(j, s.rule) {
		return HandlerResult{}, errors.New("Voice output protected prior history differs from policy")
	}
	opID := voiceOutputOperationID(req.PolicyUID, o.DeploymentUID, req.TargetUID, o.EventUID, req.TickID, req.OperationID)
	if len(j.Receipts) > 0 && j.Receipts[len(j.Receipts)-1].Phase == "terminal-full" {
		r := j.Receipts[len(j.Receipts)-1]
		if r.OperationID == opID && r.EventUID == o.EventUID && r.MarkerSHA256 == o.MarkerSHA256 &&
			r.TargetPodUID == req.TargetUID && r.ConfigMapUID == o.ConfigMapUID && r.SourceSHA256 == o.SourceSHA256 &&
			r.PolicyName == req.PolicyName && r.PolicyUID == req.PolicyUID && r.PolicyGeneration == req.PolicyGeneration &&
			r.CreatorIdentity == o.CreatorIdentity && r.TickID == req.TickID && r.SelectionDecisionID == req.OperationID {
			return voiceOutputResume(ctx, ec, jcm, j, r)
		}
	}
	if len(j.Receipts) > 0 && j.Receipts[len(j.Receipts)-1].Phase == "prepared" {
		r := j.Receipts[len(j.Receipts)-1]
		if r.OperationID != opID || r.EventUID != o.EventUID || r.MarkerSHA256 != o.MarkerSHA256 || r.TargetPodUID != req.TargetUID || r.ConfigMapUID != o.ConfigMapUID || r.SourceSHA256 != o.SourceSHA256 {
			return HandlerResult{}, errors.New("Voice output protected journal occupied by another selection")
		}
		return voiceOutputResume(ctx, ec, jcm, j, r)
	}
	if string(s.deployment.UID) != o.DeploymentUID || string(s.cm.UID) != o.ConfigMapUID || s.cm.ResourceVersion != o.ConfigMapResourceVersion || s.rule.Revision != o.SelectedRevision || s.rule.SHA256() != o.RuleSHA256 || s.rule.SourceSHA256 != o.SourceSHA256 || s.policy.Generation != o.PolicyGeneration || s.pod.Annotations["phorvex.ai/voice-output-event-creator"] != o.CreatorIdentity {
		return HandlerResult{}, errors.New("Voice output selected source or rule changed")
	}
	if e = voiceOutputEvent(ctx, ec, req, o, s); e != nil {
		return HandlerResult{}, e
	}
	for _, entry := range s.rule.Entries {
		if entry.MarkerSHA256 == o.MarkerSHA256 {
			return HandlerResult{}, errors.New("Voice output marker already blocked")
		}
	}
	if e = voiceOutputReadback(ctx, s, s.rule, o.MarkerSHA256, false, ec.VoiceOutputTransport); e != nil {
		return HandlerResult{}, e
	}
	desired, e := voiceoutputpolicy.Append(s.rule, o.MarkerSHA256, opID)
	if e != nil {
		return HandlerResult{}, e
	}
	r := voiceOutputReceipt{Version: 1, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration, DeploymentUID: o.DeploymentUID, TargetName: req.Pod, TargetPodUID: req.TargetUID, EventName: o.EventName, EventUID: o.EventUID, CreatorIdentity: o.CreatorIdentity, TickID: req.TickID, SelectionDecisionID: req.OperationID, ConfigMapUID: o.ConfigMapUID, MarkerSHA256: o.MarkerSHA256, SourceSHA256: o.SourceSHA256, PriorRuleSHA256: s.rule.SHA256(), DesiredRuleSHA256: desired.SHA256(), PriorRevision: s.rule.Revision, DesiredRevision: desired.Revision, OperationID: opID}
	j.Receipts = append(j.Receipts, r)
	raw, _ := json.Marshal(j)
	if len(raw) > 262144 {
		return HandlerResult{}, errors.New("Voice output protected journal full")
	}
	copy := jcm.DeepCopy()
	copy.Data["receipts.json"] = string(raw)
	if e = ec.Client.Update(ctx, copy); e != nil {
		return HandlerResult{MutationKind: "partial", Note: "Voice output journal reservation outcome uncertain; policy not written"}, e
	}
	return voiceOutputResume(ctx, ec, copy, j, r)
}

func recoverVoiceOutputOperations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	cm, j, e := voiceOutputJournalGet(ctx, ec.Reader, ec.JournalNamespace)
	if apierrors.IsNotFound(e) {
		return nil, nil
	}
	if e != nil {
		return []RecoveryEvent{{Receipt: voiceOutputJournalName, Kind: string(model.ActionVoiceOutputPolicyActivate), Outcome: "refused", Err: e}}, nil
	}
	if len(j.Receipts) == 0 || j.Receipts[len(j.Receipts)-1].Phase != "prepared" {
		return nil, nil
	}
	r := j.Receipts[len(j.Receipts)-1]
	ev := RecoveryEvent{Receipt: voiceOutputJournalName, Kind: string(model.ActionVoiceOutputPolicyActivate), Phase: r.Phase, Tenant: voiceoutputpolicy.Namespace, PolicyNamespace: voiceoutputpolicy.Namespace, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, TargetName: r.TargetName, TargetUID: r.TargetPodUID, Outcome: "refused"}
	if allow != nil && !allow(model.ActionVoiceOutputPolicyActivate) {
		ev.Err = errors.New("Voice output recovery routed away from native")
	} else {
		_, ev.Err = voiceOutputResume(ctx, ec, cm, j, r)
	}
	if ev.Err == nil {
		ev.Outcome = "confirmed"
		ev.Effect = "Voice output rule confirmed on current serving Pods"
	} else {
		ev.Outcome = "partial"
	}
	return []RecoveryEvent{ev}, nil
}
