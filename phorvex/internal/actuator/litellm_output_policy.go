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
	"net/url"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/outputpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const liteOutputConsoleCreator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"

type liteOutputReceipt struct {
	Version                          int                   `json:"version"`
	Phase                            string                `json:"phase"`
	PolicyName                       string                `json:"policyName"`
	PolicyUID                        string                `json:"policyUID"`
	PolicyGeneration                 int64                 `json:"policyGeneration"`
	TargetName                       string                `json:"targetName"`
	TargetUID                        string                `json:"targetUID"`
	EventName                        string                `json:"eventName"`
	EventUID                         string                `json:"eventUID"`
	CreatorIdentity                  string                `json:"creatorIdentity"`
	TickID                           string                `json:"tickId"`
	SelectionDecisionID              string                `json:"selectionDecisionId"`
	OperationID                      string                `json:"operationId"`
	ConfigMapUID                     string                `json:"configMapUID"`
	SelectedConfigMapResourceVersion string                `json:"selectedConfigMapResourceVersion"`
	RuleConfigMapName                string                `json:"ruleConfigMapName"`
	RuleConfigMapUID                 string                `json:"ruleConfigMapUID"`
	RuleSHA256                       string                `json:"ruleSHA256"`
	Rule                             outputpolicy.LiteRule `json:"rule"`
	Prior                            string                `json:"prior"`
	Desired                          string                `json:"desired"`
	RequestSHA256                    string                `json:"requestSHA256"`
	OriginalCompletionSHA256         string                `json:"originalCompletionSHA256"`
	ObservedAt                       time.Time             `json:"observedAt"`
}

func liteOutputOperationID(policyUID, deploymentUID, eventUID, tickID, decisionID string) string {
	h := sha256.Sum256([]byte("phorvex-litellm-output-v2\x00" + policyUID + "\x00" + deploymentUID + "\x00" + eventUID + "\x00" + tickID + "\x00" + decisionID))
	return hex.EncodeToString(h[:])
}

func liteOutputJournalName(string) string { return outputpolicy.LiteJournalName }

func (r liteOutputReceipt) valid() bool {
	if r.Version != 2 || (r.Phase != "prepared" && r.Phase != "terminal-full" && r.Phase != "aborted-no-write") ||
		r.PolicyName != "litellm-defense" || r.PolicyUID == "" || r.PolicyGeneration < 1 ||
		r.TargetName == "" || r.TargetUID == "" || r.EventName == "" || r.EventUID == "" ||
		r.CreatorIdentity != liteOutputConsoleCreator || r.TickID == "" || r.SelectionDecisionID == "" ||
		r.ObservedAt.IsZero() ||
		r.ConfigMapUID == "" || r.SelectedConfigMapResourceVersion == "" || !outputpolicy.LiteValidRuleSlotName(r.RuleConfigMapName) || r.RuleConfigMapUID == "" ||
		r.Rule.SHA256() != r.RuleSHA256 || r.Rule.TargetPodUID != r.TargetUID ||
		!outputpolicy.ValidSHA(r.RequestSHA256) || !outputpolicy.ValidSHA(r.OriginalCompletionSHA256) ||
		r.OperationID != liteOutputOperationID(r.PolicyUID, r.Rule.DeploymentUID, r.EventUID, r.TickID, r.SelectionDecisionID) {
		return false
	}
	if _, err := outputpolicy.ParseLiteRule(string(r.Rule.Bytes())); err != nil {
		return false
	}
	prior, e1 := outputpolicy.ParseLiteState(r.Prior)
	desired, e2 := outputpolicy.ParseLiteState(r.Desired)
	if e1 != nil || e2 != nil || desired.Revision != prior.Revision+1 || len(desired.Entries) != len(prior.Entries)+1 {
		return false
	}
	entry := outputpolicy.LiteEntry{ObjectiveID: r.Rule.ObjectiveID, RunNonce: r.Rule.RunNonce, RuleSHA256: r.RuleSHA256,
		ProtectedSHA256: r.Rule.ProtectedSHA256, OperationID: r.OperationID, ServiceUID: r.Rule.ServiceUID,
		DeploymentUID: r.Rule.DeploymentUID, TargetPodUID: r.Rule.TargetPodUID, PeerPodUID: r.Rule.PeerPodUID,
		SourceSHA256: r.Rule.SourceSHA256, ContextSecretUID: r.Rule.ContextSecretUID, ContextSeedSHA256: r.Rule.ContextSeedSHA256}
	want, err := prior.Append(entry)
	return err == nil && r.Desired == string(want.Bytes())
}

func liteOutputCapability(ctx context.Context, reader client.Reader, journalNS string, target Target) (bool, string) {
	if reader == nil || journalNS == "" || target.UID == "" || target.Pod == "" {
		return false, "litellm-output: authority unavailable"
	}
	live, err := litellmclient.ValidateLive(ctx, reader, target.UID, "")
	if err != nil {
		return false, "litellm-output: Service gateway unavailable"
	}
	if len(live.Pods) != 2 {
		return false, "litellm-output: two gateway Pods required"
	}
	dep := &appsv1.Deployment{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: "litellm"}, dep); err != nil || dep.DeletionTimestamp != nil {
		return false, "litellm-output: Deployment unavailable"
	}
	cm := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: outputpolicy.LitePolicyConfigMap}, cm); err != nil ||
		!outputpolicy.LiteOwner(cm, string(dep.UID)) || len(cm.Data) != 1 {
		return false, "litellm-output: owned policy unavailable"
	}
	state, err := outputpolicy.ParseLiteState(cm.Data[outputpolicy.LitePolicyKey])
	if err != nil || len(state.Entries) >= outputpolicy.LiteMaxEntries {
		return false, "litellm-output: policy invalid or full"
	}
	_, history, err := liteOutputReadJournalDocument(ctx, EnactCtx{Reader: reader, JournalNamespace: journalNS})
	if err != nil || !liteOutputJournalMatchesState(history, state) {
		return false, "litellm-output: protected history differs from policy"
	}
	doc, prompt, err := liteOutputSecrets(ctx, reader, string(dep.UID))
	if err != nil {
		return false, "litellm-output: private context source unavailable"
	}
	for _, serving := range live.Pods {
		pod := &corev1.Pod{}
		if reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: serving.Name}, pod) != nil ||
			string(pod.UID) != serving.UID || !liteOutputPodHook(pod, string(cm.UID), live.ServiceUID, string(dep.UID), string(doc.UID), string(prompt.UID)) ||
			!liteOutputPodOwnedBy(ctx, reader, pod, string(dep.UID)) {
			return false, "litellm-output: serving gateway hook or owner unavailable"
		}
	}
	pending, err := pendingLiteOutputOperations(ctx, reader, journalNS, target.UID)
	if err != nil || pending {
		return false, "litellm-output: protected operation unresolved"
	}
	return true, ""
}

// liteOutputAuthority rechecks all live Kubernetes identities. On recovery it
// accepts only the protected prepared receipt, never another event assertion.
func liteOutputAuthority(ctx context.Context, ec EnactCtx, r liteOutputReceipt) (litellmclient.Live, *corev1.ConfigMap, outputpolicy.LiteState, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || !r.valid() {
		return litellmclient.Live{}, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output receipt authority unavailable")
	}
	probeUID, peerUID := r.TargetUID, r.Rule.PeerPodUID
	if r.Phase == "terminal-full" {
		// A completed earlier rule must survive an ordinary Deployment rollout.
		// Discover the current two Pod lifetimes, then authenticate both gateways.
		var pods corev1.PodList
		if err := ec.Reader.List(ctx, &pods, client.InNamespace(outputpolicy.LiteNamespace), client.MatchingLabels{"app": "litellm"}, client.Limit(3)); err != nil ||
			pods.Continue != "" || len(pods.Items) != 2 {
			return litellmclient.Live{}, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output current gateway inventory unavailable")
		}
		probeUID = string(pods.Items[0].UID)
		peerUID = ""
	}
	live, err := litellmclient.ValidateLive(ctx, ec.Reader, probeUID, peerUID)
	if err != nil {
		return live, nil, outputpolicy.LiteState{}, err
	}
	if live.ServiceUID != r.Rule.ServiceUID || live.SourceSHA256 != r.Rule.SourceSHA256 {
		return live, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output source or Service changed")
	}
	found := false
	for _, p := range live.Pods {
		if p.UID == r.TargetUID && p.Name == r.TargetName {
			found = true
		}
	}
	if r.Phase == "prepared" && !found {
		return live, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output selected Pod changed")
	}
	dep := &appsv1.Deployment{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: "litellm"}, dep); err != nil || dep.DeletionTimestamp != nil || string(dep.UID) != r.Rule.DeploymentUID {
		return live, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output Deployment changed")
	}
	doc, prompt, err := liteOutputSecrets(ctx, ec.Reader, r.Rule.DeploymentUID)
	if err != nil {
		return live, nil, outputpolicy.LiteState{}, err
	}
	selectedSecret := doc
	if r.Rule.ObjectiveID == outputpolicy.LitePromptObjective {
		selectedSecret = prompt
	}
	if string(selectedSecret.UID) != r.Rule.ContextSecretUID || outputpolicy.LiteSHA(selectedSecret.Data["seed"]) != r.Rule.ContextSeedSHA256 {
		return live, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output selected context source changed")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: r.PolicyName}, policy); err != nil ||
		policy.DeletionTimestamp != nil || string(policy.UID) != r.PolicyUID || policy.Generation != r.PolicyGeneration {
		return live, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output selecting policy changed")
	}
	authorized := false
	for _, action := range policy.Spec.Actions.Enabled {
		if string(action) == string(model.ActionSensitiveOutputPolicyActivate) {
			authorized = true
		}
	}
	sel, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || sel.Empty() || !authorized {
		return live, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output policy selector/action changed")
	}
	for _, selected := range live.Pods {
		pod := &corev1.Pod{}
		if ec.Reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: selected.Name}, pod) != nil ||
			string(pod.UID) != selected.UID || !sel.Matches(labels.Set(pod.Labels)) || !liteOutputPodOwnedBy(ctx, ec.Reader, pod, r.Rule.DeploymentUID) ||
			!liteOutputPodHook(pod, r.ConfigMapUID, live.ServiceUID, r.Rule.DeploymentUID, string(doc.UID), string(prompt.UID)) {
			return live, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output serving Pod owner or selector changed")
		}
	}
	ruleCM := &corev1.ConfigMap{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: r.RuleConfigMapName}, ruleCM); err != nil ||
		!outputpolicy.LiteOwner(ruleCM, r.Rule.DeploymentUID) || ruleCM.Immutable == nil || !*ruleCM.Immutable ||
		string(ruleCM.UID) != r.RuleConfigMapUID || len(ruleCM.Data) != 1 || ruleCM.Data[outputpolicy.LiteRuleKey] != string(r.Rule.Bytes()) {
		return live, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output immutable rule changed")
	}
	cm := &corev1.ConfigMap{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: outputpolicy.LitePolicyConfigMap}, cm); err != nil ||
		!outputpolicy.LiteOwner(cm, r.Rule.DeploymentUID) || string(cm.UID) != r.ConfigMapUID || len(cm.Data) != 1 {
		return live, nil, outputpolicy.LiteState{}, errors.New("LiteLLM output shared policy changed")
	}
	state, err := outputpolicy.ParseLiteState(cm.Data[outputpolicy.LitePolicyKey])
	return live, cm, state, err
}

func liteOutputPodOwnedBy(ctx context.Context, reader client.Reader, pod *corev1.Pod, deploymentUID string) bool {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" || owner.UID == "" {
		return false
	}
	rs := &appsv1.ReplicaSet{}
	if reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: owner.Name}, rs) != nil || rs.UID != owner.UID || rs.DeletionTimestamp != nil {
		return false
	}
	parent := metav1.GetControllerOf(rs)
	return parent != nil && parent.APIVersion == "apps/v1" && parent.Kind == "Deployment" && parent.Name == "litellm" && string(parent.UID) == deploymentUID
}

func liteOutputEvent(ctx context.Context, ec EnactCtx, r liteOutputReceipt) error {
	event := &amtdv1beta1.SecurityEvent{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: r.EventName}, event); err != nil {
		return err
	}
	if event.DeletionTimestamp != nil || string(event.UID) != r.EventUID || event.Spec.Rule.Type != model.AttackVectorSensitiveOutput ||
		event.Spec.Rule.Source != "redteam" || event.Annotations["phorvex.ai/creator-identity"] != r.CreatorIdentity ||
		event.Annotations[model.ConsoleTargetPodUIDAnnotation] != r.TargetUID || len(event.Spec.Targets) != 1 ||
		event.Spec.Targets[0] != outputpolicy.LiteNamespace+"/"+r.TargetName ||
		!litellmEventTimeMatches(event.CreationTimestamp.Time, r.ObservedAt, time.Now()) {
		return errors.New("LiteLLM output trusted event changed")
	}
	o, err := outputpolicy.ParseLiteObservation(event.Annotations[outputpolicy.LiteObservationAnnotation])
	if err != nil || o.ObjectiveID != r.Rule.ObjectiveID || o.RunNonce != r.Rule.RunNonce ||
		o.RuleSHA256 != r.RuleSHA256 || o.ProtectedSHA256 != r.Rule.ProtectedSHA256 || o.SourceSHA256 != r.Rule.SourceSHA256 ||
		o.RuleConfigMapName != r.RuleConfigMapName || o.RuleConfigMapUID != r.RuleConfigMapUID || o.PolicyConfigMapUID != r.ConfigMapUID || o.ServiceUID != r.Rule.ServiceUID ||
		o.DeploymentUID != r.Rule.DeploymentUID || o.TargetPodUID != r.TargetUID || o.PeerPodUID != r.Rule.PeerPodUID ||
		o.ContextSecretUID != r.Rule.ContextSecretUID || o.ContextSeedSHA256 != r.Rule.ContextSeedSHA256 ||
		o.PolicyName != r.PolicyName || o.PolicyUID != r.PolicyUID || o.PolicyGeneration != r.PolicyGeneration ||
		o.RequestSHA256 != r.RequestSHA256 || o.OriginalCompletionSHA256 != r.OriginalCompletionSHA256 || !o.ObservedAt.Equal(r.ObservedAt) ||
		!litellmEventTimeMatches(event.CreationTimestamp.Time, o.ObservedAt, time.Now()) {
		return errors.New("LiteLLM output event assertion changed")
	}
	return nil
}

type liteOutputJournalDocument struct {
	Receipts []liteOutputReceipt `json:"receipts"`
	Version  int                 `json:"version"`
}

func (d liteOutputJournalDocument) bytes() []byte { return outputpolicy.LiteCanonicalJSON(d) }

func liteOutputReadJournalDocument(ctx context.Context, ec EnactCtx) (*corev1.ConfigMap, liteOutputJournalDocument, error) {
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: outputpolicy.LiteJournalName}, cm); err != nil {
		return nil, liteOutputJournalDocument{}, err
	}
	if cm.DeletionTimestamp != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.Labels[outputpolicy.LiteJournalLabel] != "v2" ||
		len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return nil, liteOutputJournalDocument{}, errors.New("LiteLLM output protected journal shape changed")
	}
	raw := cm.Data[outputpolicy.LiteJournalKey]
	var doc liteOutputJournalDocument
	if len(raw) == 0 || len(raw) > outputpolicy.LiteMaxJournalBytes || json.Unmarshal([]byte(raw), &doc) != nil ||
		doc.Version != 2 || doc.Receipts == nil || len(doc.Receipts) > outputpolicy.LiteMaxEntries || raw != string(doc.bytes()) {
		return nil, liteOutputJournalDocument{}, errors.New("LiteLLM output protected journal invalid or noncanonical")
	}
	seenNonce, seenOp, seenEvent, seenSlot, seenRuleUID := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	pending := 0
	for _, row := range doc.Receipts {
		if !row.valid() || seenNonce[row.Rule.RunNonce] || seenOp[row.OperationID] || seenEvent[row.EventUID] ||
			seenSlot[row.RuleConfigMapName] || seenRuleUID[row.RuleConfigMapUID] {
			return nil, liteOutputJournalDocument{}, errors.New("LiteLLM output protected receipt repeated or invalid")
		}
		seenNonce[row.Rule.RunNonce], seenOp[row.OperationID], seenEvent[row.EventUID] = true, true, true
		seenSlot[row.RuleConfigMapName], seenRuleUID[row.RuleConfigMapUID] = true, true
		if row.Phase == "prepared" {
			pending++
		}
	}
	if pending > 1 {
		return nil, liteOutputJournalDocument{}, errors.New("LiteLLM output multiple operations pending")
	}
	return cm, doc, nil
}

func (d liteOutputJournalDocument) index(nonce string) int {
	for i, r := range d.Receipts {
		if r.Rule.RunNonce == nonce {
			return i
		}
	}
	return -1
}

func liteOutputReadJournal(ctx context.Context, ec EnactCtx, nonce string) (*corev1.ConfigMap, liteOutputReceipt, error) {
	cm, doc, err := liteOutputReadJournalDocument(ctx, ec)
	if err != nil {
		return nil, liteOutputReceipt{}, err
	}
	i := doc.index(nonce)
	if i < 0 {
		return nil, liteOutputReceipt{}, apierrors.NewNotFound(corev1.Resource("configmaps"), outputpolicy.LiteJournalName+"/"+nonce)
	}
	return cm, doc.Receipts[i], nil
}

func liteOutputCreateJournal(ctx context.Context, ec EnactCtx, r liteOutputReceipt) (*corev1.ConfigMap, error) {
	if !r.valid() || r.Phase != "prepared" {
		return nil, errors.New("LiteLLM output prepared journal intent invalid")
	}
	cm, doc, err := liteOutputReadJournalDocument(ctx, ec)
	if err != nil {
		return nil, err
	}
	if len(doc.Receipts) >= outputpolicy.LiteMaxEntries || doc.index(r.Rule.RunNonce) >= 0 {
		return nil, errors.New("LiteLLM output protected journal occupied or full")
	}
	for _, prior := range doc.Receipts {
		if prior.Phase == "prepared" {
			return nil, errors.New("LiteLLM output prior operation unresolved")
		}
		if prior.RuleConfigMapName == r.RuleConfigMapName || prior.RuleConfigMapUID == r.RuleConfigMapUID {
			return nil, errors.New("LiteLLM output immutable rule slot already used")
		}
	}
	state, err := outputpolicy.ParseLiteState(r.Prior)
	if err != nil || !liteOutputJournalMatchesState(doc, state) {
		return nil, errors.New("LiteLLM output protected history differs from policy")
	}
	doc.Receipts = append(doc.Receipts, r)
	next := doc.bytes()
	if len(next) > outputpolicy.LiteMaxJournalBytes {
		return nil, errors.New("LiteLLM output protected journal capacity exceeded")
	}
	cm.Data[outputpolicy.LiteJournalKey] = string(next)
	if err := ec.Client.Update(ctx, cm); err != nil {
		return nil, err
	}
	return cm, nil
}

func liteOutputJournalMatchesState(doc liteOutputJournalDocument, state outputpolicy.LiteState) bool {
	terminal := 0
	for _, row := range doc.Receipts {
		if row.Phase == "terminal-full" {
			terminal++
			found := false
			for _, entry := range state.Entries {
				if entry.RunNonce == row.Rule.RunNonce && entry.OperationID == row.OperationID && entry.Matches(row.Rule) {
					found = true
				}
			}
			if !found {
				return false
			}
		}
	}
	return terminal == len(state.Entries)
}

func liteOutputAdvanceJournal(ctx context.Context, ec EnactCtx, journal *corev1.ConfigMap, before, after liteOutputReceipt) error {
	if journal == nil || !before.valid() || !after.valid() || before.Phase != "prepared" || after.Phase != "terminal-full" {
		return errors.New("LiteLLM output journal transition invalid")
	}
	cm, doc, err := liteOutputReadJournalDocument(ctx, ec)
	if err != nil {
		return err
	}
	prior, priorErr := outputpolicy.ParseLiteState(before.Prior)
	if cm.UID != journal.UID || priorErr != nil || !liteOutputJournalMatchesState(doc, prior) {
		return errors.New("LiteLLM output protected journal identity or history changed")
	}
	i := doc.index(before.Rule.RunNonce)
	if i < 0 {
		return errors.New("LiteLLM output prepared journal missing")
	}
	currentRaw, _ := json.Marshal(doc.Receipts[i])
	beforeRaw, _ := json.Marshal(before)
	if !bytes.Equal(currentRaw, beforeRaw) {
		return errors.New("LiteLLM output prepared journal changed")
	}
	doc.Receipts[i] = after
	desired, desiredErr := outputpolicy.ParseLiteState(after.Desired)
	if desiredErr != nil || !liteOutputJournalMatchesState(doc, desired) {
		return errors.New("LiteLLM output terminal journal history differs from desired policy")
	}
	next := doc.bytes()
	if len(next) > outputpolicy.LiteMaxJournalBytes {
		return errors.New("LiteLLM output protected journal capacity exceeded")
	}
	cm.Data[outputpolicy.LiteJournalKey] = string(next)
	return ec.Client.Update(ctx, cm)
}

type liteOutputGatewayState struct {
	Version            int    `json:"version"`
	PodUID             string `json:"podUID"`
	SourceSHA256       string `json:"sourceSHA256"`
	PolicyConfigMapUID string `json:"policyConfigMapUID"`
	ObjectiveID        string `json:"objectiveId"`
	RunNonce           string `json:"runNonce"`
	RuleSHA256         string `json:"ruleSHA256"`
	ProtectedSHA256    string `json:"protectedSHA256"`
	ContextSecretUID   string `json:"contextSecretUID"`
	ContextSeedSHA256  string `json:"contextSeedSHA256"`
	Active             bool   `json:"active"`
	Revision           uint64 `json:"revision"`
	OperationID        string `json:"operationId"`
	Ready              bool   `json:"ready"`
	Counters           struct {
		ProviderCompletions uint64 `json:"providerCompletions"`
		Redactions          uint64 `json:"redactions"`
	} `json:"counters"`
}

func liteOutputReadbackOnce(ctx context.Context, ec EnactCtx, live litellmclient.Live, r liteOutputReceipt, want outputpolicy.LiteState) error {
	token := ec.LiteLLMStatusToken
	if token == "" {
		var err error
		token, err = litellmStatusToken()
		if err != nil {
			return errors.New("LiteLLM output private status credential unavailable")
		}
	}
	transport := ec.LiteLLMStatusTransport
	if transport == nil {
		transport = &http.Transport{Proxy: nil, MaxIdleConns: 0, DisableKeepAlives: true}
	}
	hc := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("LiteLLM output status redirect refused")
	}}
	for _, pod := range live.Pods {
		if net.ParseIP(pod.IP) == nil {
			return errors.New("LiteLLM output Pod IP invalid")
		}
		endpoint := "http://" + net.JoinHostPort(pod.IP, "4002") + "/v1/output-policy/state?objectiveId=" + url.QueryEscape(r.Rule.ObjectiveID) + "&runNonce=" + r.Rule.RunNonce
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || len(raw) > 8192 {
			return errors.New("LiteLLM output gateway status unavailable")
		}
		var object map[string]any
		if json.Unmarshal(raw, &object) != nil || len(object) != 15 {
			return errors.New("LiteLLM output gateway status malformed")
		}
		for _, key := range []string{"version", "podUID", "sourceSHA256", "policyConfigMapUID", "objectiveId", "runNonce", "ruleSHA256", "protectedSHA256", "contextSecretUID", "contextSeedSHA256", "active", "revision", "operationId", "ready", "counters"} {
			if _, ok := object[key]; !ok {
				return errors.New("LiteLLM output gateway status keyset differs")
			}
		}
		counter, ok := object["counters"].(map[string]any)
		if !ok || len(counter) != 2 {
			return errors.New("LiteLLM output gateway counter keyset differs")
		}
		for _, key := range []string{"providerCompletions", "redactions"} {
			if _, ok := counter[key]; !ok {
				return errors.New("LiteLLM output gateway counter keyset differs")
			}
		}
		canonical, _ := json.Marshal(object)
		if !bytes.Equal(raw, canonical) {
			return errors.New("LiteLLM output gateway status noncanonical")
		}
		var state liteOutputGatewayState
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&state) != nil || state.Version != 2 || !state.Ready || !state.Active ||
			state.PodUID != pod.UID || state.SourceSHA256 != r.Rule.SourceSHA256 || state.PolicyConfigMapUID != r.ConfigMapUID ||
			state.ObjectiveID != r.Rule.ObjectiveID || state.RunNonce != r.Rule.RunNonce || state.RuleSHA256 != r.RuleSHA256 ||
			state.ProtectedSHA256 != r.Rule.ProtectedSHA256 || state.ContextSecretUID != r.Rule.ContextSecretUID ||
			state.ContextSeedSHA256 != r.Rule.ContextSeedSHA256 || state.Revision != want.Revision || state.OperationID != r.OperationID {
			return errors.New("LiteLLM output gateway effective rule differs")
		}
	}
	return nil
}

func liteOutputAwaitReadback(ctx context.Context, ec EnactCtx, live litellmclient.Live, r liteOutputReceipt, want outputpolicy.LiteState) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := liteOutputReadbackOnce(ctx, ec, live, r, want); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("LiteLLM output gateway readback cancelled")
		case <-deadline.C:
			return errors.New("LiteLLM output both-gateway readback not confirmed")
		case <-ticker.C:
		}
	}
}

func liteOutputContinue(ctx context.Context, ec EnactCtx, journal *corev1.ConfigMap, r liteOutputReceipt) (HandlerResult, error) {
	if r.Phase == "aborted-no-write" {
		return HandlerResult{}, errors.New("LiteLLM output operation was definitively aborted")
	}
	live, cm, state, err := liteOutputAuthority(ctx, ec, r)
	if err != nil {
		return HandlerResult{MutationKind: "partial"}, err
	}
	prior, _ := outputpolicy.ParseLiteState(r.Prior)
	desired, _ := outputpolicy.ParseLiteState(r.Desired)
	current := string(state.Bytes())
	if r.Phase == "prepared" && current != r.Prior && current != r.Desired {
		return HandlerResult{MutationKind: "partial"}, errors.New("LiteLLM output policy superseded protected intent")
	}
	if r.Phase == "terminal-full" && !liteOutputContainsState(state, desired) {
		return HandlerResult{MutationKind: "partial"}, errors.New("LiteLLM output terminal entry removed or changed")
	}
	if r.Phase == "prepared" && current == r.Prior {
		if cm.ResourceVersion != r.SelectedConfigMapResourceVersion || state.Revision != prior.Revision {
			return HandlerResult{MutationKind: "partial"}, errors.New("LiteLLM output selected ConfigMap revision changed")
		}
		cm.Data[outputpolicy.LitePolicyKey] = r.Desired
		// One revision-checked write. A lost acknowledgement remains prepared and
		// recovery determines whether these exact desired bytes were installed.
		if err = ec.Client.Update(ctx, cm); err != nil {
			return HandlerResult{MutationKind: "partial"}, err
		}
	}
	live, _, state, err = liteOutputAuthority(ctx, ec, r)
	if err != nil || (r.Phase == "prepared" && (string(state.Bytes()) != r.Desired || state.Revision != desired.Revision)) ||
		(r.Phase == "terminal-full" && !liteOutputContainsState(state, desired)) {
		return HandlerResult{MutationKind: "partial"}, errors.New("LiteLLM output post-CAS policy/source not confirmed")
	}
	if err = liteOutputAwaitReadback(ctx, ec, live, r, state); err != nil {
		return HandlerResult{MutationKind: "partial"}, err
	}
	if r.Phase == "prepared" {
		after := r
		after.Phase = "terminal-full"
		if err = liteOutputAdvanceJournal(ctx, ec, journal, r, after); err != nil {
			return HandlerResult{MutationKind: "partial"}, err
		}
	}
	return HandlerResult{MutationKind: "forward-only", Emitted: true,
		ObjectsTouched: []string{outputpolicy.LiteNamespace + "/" + outputpolicy.LitePolicyConfigMap, ec.JournalNamespace + "/" + liteOutputJournalName(r.Rule.RunNonce)},
		Note:           fmt.Sprintf("LiteLLM exact output rule effective on both gateway Pods for operation %s", r.OperationID)}, nil
}

func liteOutputContainsState(current, earlier outputpolicy.LiteState) bool {
	if current.Version != 2 || current.Revision < earlier.Revision || len(current.Entries) < len(earlier.Entries) {
		return false
	}
	entries := make(map[string]outputpolicy.LiteEntry, len(current.Entries))
	for _, entry := range current.Entries {
		entries[entry.Key()] = entry
	}
	for _, entry := range earlier.Entries {
		if entries[entry.Key()] != entry {
			return false
		}
	}
	return true
}

func enactLiteOutputPolicy(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	o := req.OutputPolicyObservation
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || req.Action != model.ActionSensitiveOutputPolicyActivate ||
		req.Namespace != outputpolicy.LiteNamespace || req.Pod == "" || req.TargetUID == "" || req.PolicyName != "litellm-defense" ||
		req.PolicyUID == "" || req.PolicyGeneration < 1 || req.TickID == "" || req.OperationID == "" ||
		o == nil || o.Version != 2 || o.LiteLLM == nil || o.TargetPodUID != req.TargetUID ||
		o.PolicyName != req.PolicyName || o.PolicyUID != req.PolicyUID || o.PolicyGeneration != req.PolicyGeneration ||
		o.EventName == "" || o.EventUID == "" || o.CreatorIdentity != liteOutputConsoleCreator ||
		o.ObservedAt.IsZero() || time.Since(o.ObservedAt) < 0 || time.Since(o.ObservedAt) >= 60*time.Second {
		return HandlerResult{}, errors.New("LiteLLM output selection/observation incomplete")
	}
	v := o.LiteLLM
	ruleCM := &corev1.ConfigMap{}
	if !outputpolicy.LiteValidRuleSlotName(v.RuleConfigMapName) {
		return HandlerResult{}, errors.New("LiteLLM output rule slot invalid")
	}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: v.RuleConfigMapName}, ruleCM); err != nil {
		return HandlerResult{}, err
	}
	rule, err := outputpolicy.ParseLiteRule(ruleCM.Data[outputpolicy.LiteRuleKey])
	if err != nil || rule.SHA256() != o.RuleSHA256 || rule.SHA256() != v.RuleSHA256 ||
		rule.ObjectiveID != v.ObjectiveID || rule.RunNonce != v.RunNonce || rule.TargetPodUID != req.TargetUID ||
		rule.PeerPodUID != v.PeerPodUID || rule.ProtectedSHA256 != v.ProtectedSHA256 || rule.SourceSHA256 != v.SourceSHA256 ||
		rule.ServiceUID != v.ServiceUID || rule.DeploymentUID != v.DeploymentUID ||
		rule.ContextSecretUID != v.ContextSecretUID || rule.ContextSeedSHA256 != v.ContextSeedSHA256 ||
		string(ruleCM.UID) != v.RuleConfigMapUID || !outputpolicy.LiteOwner(ruleCM, rule.DeploymentUID) || ruleCM.Immutable == nil || !*ruleCM.Immutable ||
		len(ruleCM.Data) != 1 || ruleCM.Data[outputpolicy.LiteRuleKey] != string(rule.Bytes()) {
		return HandlerResult{}, errors.New("LiteLLM output selected immutable rule differs")
	}
	cm := &corev1.ConfigMap{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: outputpolicy.LitePolicyConfigMap}, cm); err != nil {
		return HandlerResult{}, err
	}
	if string(cm.UID) != o.ConfigMapUID || cm.ResourceVersion != o.SelectedConfigMapResourceVersion {
		return HandlerResult{}, errors.New("LiteLLM output selected policy ConfigMap changed")
	}
	prior, err := outputpolicy.ParseLiteState(cm.Data[outputpolicy.LitePolicyKey])
	if err != nil || prior.Revision != o.SelectedRevision {
		return HandlerResult{}, errors.New("LiteLLM output selected policy revision changed")
	}
	op := liteOutputOperationID(req.PolicyUID, rule.DeploymentUID, o.EventUID, req.TickID, req.OperationID)
	entry := outputpolicy.LiteEntry{ObjectiveID: rule.ObjectiveID, RunNonce: rule.RunNonce, RuleSHA256: rule.SHA256(),
		ProtectedSHA256: rule.ProtectedSHA256, OperationID: op, ServiceUID: rule.ServiceUID, DeploymentUID: rule.DeploymentUID,
		TargetPodUID: rule.TargetPodUID, PeerPodUID: rule.PeerPodUID, SourceSHA256: rule.SourceSHA256,
		ContextSecretUID: rule.ContextSecretUID, ContextSeedSHA256: rule.ContextSeedSHA256}
	desired, err := prior.Append(entry)
	if err != nil {
		return HandlerResult{}, err
	}
	r := liteOutputReceipt{Version: 2, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		PolicyGeneration: req.PolicyGeneration, TargetName: req.Pod, TargetUID: req.TargetUID, EventName: o.EventName, EventUID: o.EventUID,
		CreatorIdentity: o.CreatorIdentity, TickID: req.TickID, SelectionDecisionID: req.OperationID, OperationID: op,
		ConfigMapUID: o.ConfigMapUID, SelectedConfigMapResourceVersion: o.SelectedConfigMapResourceVersion,
		RuleConfigMapName: v.RuleConfigMapName, RuleConfigMapUID: v.RuleConfigMapUID, RuleSHA256: v.RuleSHA256, Rule: rule, Prior: string(prior.Bytes()), Desired: string(desired.Bytes()),
		RequestSHA256: v.RequestSHA256, OriginalCompletionSHA256: v.OriginalCompletionSHA256, ObservedAt: o.ObservedAt}
	if !r.valid() {
		return HandlerResult{}, errors.New("LiteLLM output prepared receipt invalid")
	}
	if _, _, state, err := liteOutputAuthority(ctx, ec, r); err != nil || string(state.Bytes()) != r.Prior {
		return HandlerResult{}, errors.New("LiteLLM output pre-write authority changed")
	}
	if err = liteOutputEvent(ctx, ec, r); err != nil {
		return HandlerResult{}, err
	}
	journal, err := liteOutputCreateJournal(ctx, ec, r)
	if err != nil {
		return HandlerResult{}, err
	}
	return liteOutputContinue(ctx, ec, journal, r)
}

func pendingLiteOutputOperations(ctx context.Context, reader client.Reader, journalNS, podUID string) (bool, error) {
	if podUID == "" {
		return false, errors.New("LiteLLM output target UID unavailable")
	}
	if reader == nil || journalNS == "" {
		return false, errors.New("LiteLLM output protected journal authority unavailable")
	}
	ec := EnactCtx{Reader: reader, JournalNamespace: journalNS}
	_, doc, err := liteOutputReadJournalDocument(ctx, ec)
	if err != nil {
		return false, err
	}
	for _, r := range doc.Receipts {
		// One installed LiteLLM Deployment: a pending append fences both current
		// and replacement Pods until its exact operation is recovered.
		if r.Phase == "prepared" {
			return true, nil
		}
	}
	return false, nil
}

func recoverLiteOutputOperations(ctx context.Context, ec EnactCtx, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.JournalNamespace == "" {
		return nil, nil
	}
	journal, doc, err := liteOutputReadJournalDocument(ctx, ec)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// The v2 fixture is opt-in. An installation without either owned
			// object must not interrupt recovery of unrelated actions. Once the
			// shared policy exists, its missing protected journal fails closed.
			policyCM := &corev1.ConfigMap{}
			policyErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: outputpolicy.LitePolicyConfigMap}, policyCM)
			if apierrors.IsNotFound(policyErr) {
				return nil, nil
			}
			if policyErr != nil {
				return nil, policyErr
			}
		}
		return nil, err
	}
	result := make([]RecoveryEvent, 0, len(doc.Receipts))
	for _, r := range doc.Receipts {
		event := RecoveryEvent{Receipt: outputpolicy.LiteJournalName + "/" + r.Rule.RunNonce, Kind: string(model.ActionSensitiveOutputPolicyActivate), Outcome: "refused"}
		event.Phase = r.Phase
		event.PolicyNamespace = outputpolicy.LiteNamespace
		event.PolicyName = r.PolicyName
		event.PolicyUID = r.PolicyUID
		event.TargetName = r.TargetName
		event.TargetUID = r.TargetUID
		if allow != nil && !allow(model.ActionSensitiveOutputPolicyActivate) {
			event.Err = errors.New("LiteLLM output recovery routed away from native")
			result = append(result, event)
			continue
		}
		policy := &v1alpha1.PhorvexPolicy{}
		if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: r.PolicyName}, policy); e != nil || string(policy.UID) != r.PolicyUID {
			event.Err = errors.New("LiteLLM output recovery policy unavailable")
			result = append(result, event)
			continue
		}
		event.Tenant = policy.EffectiveTenant()
		_, event.Err = liteOutputContinue(ctx, ec, journal, r)
		if event.Err == nil {
			event.Outcome = "confirmed"
			event.Effect = "exact output policy effective on both LiteLLM gateways"
		}
		result = append(result, event)
	}
	return result, nil
}
