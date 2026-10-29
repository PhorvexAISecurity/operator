package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/outputpolicy"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type supportCaseResponse struct {
	Diagnostics map[string]any `json:"diagnostics"`
}

type outputPolicyStateResponse struct {
	Ready       bool   `json:"ready"`
	Active      bool   `json:"active"`
	Revision    uint64 `json:"revision"`
	OperationID string `json:"operationId"`
}

func probeSensitiveOutput(ctx context.Context, p *servingCatalogueKubePreparation,
	profile servingCatalogueProfile) (outputPolicyStateResponse, supportCaseResponse, error) {
	var stateMap map[string]any
	if err := podProxyJSON(ctx, p.kube, profile.Namespace, p.target.Name, profile.Port,
		"GET", "/v1/output-policy/state", nil, &stateMap); err != nil {
		return outputPolicyStateResponse{}, supportCaseResponse{}, err
	}
	state := outputPolicyStateResponse{Ready: stateMap["ready"] == true, Active: stateMap["active"] == true}
	if revision, ok := stateMap["revision"].(float64); ok && revision >= 0 {
		state.Revision = uint64(revision)
	}
	state.OperationID, _ = stateMap["operationId"].(string)
	var responseMap map[string]any
	if err := podProxyJSON(ctx, p.kube, profile.Namespace, p.target.Name, profile.Port,
		"POST", profile.Route, map[string]string{"caseId": "CAT-001"}, &responseMap); err != nil {
		return state, supportCaseResponse{}, err
	}
	diagnostics, _ := responseMap["diagnostics"].(map[string]any)
	response := supportCaseResponse{Diagnostics: diagnostics}
	return state, response, nil
}

func sensitiveMarker(response supportCaseResponse) (string, bool) {
	if response.Diagnostics == nil {
		return "", false
	}
	marker, ok := response.Diagnostics["internalAuditMarker"].(string)
	return marker, ok
}

func preflightSensitiveOutput(ctx context.Context, profile servingCatalogueProfile, p *servingCatalogueKubePreparation) error {
	pod, err := p.kube.CoreV1().Pods(profile.Namespace).Get(ctx, profile.PodName, metav1.GetOptions{})
	if err != nil || pod.UID == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil ||
		pod.Status.Phase != corev1.PodRunning || !podReady(pod) || pod.Labels["app"] != "guardrail-fixture" {
		return errors.New("sensitive-output fixed fixture Pod is unavailable")
	}
	p.target = servingPodPin{Name: pod.Name, UID: string(pod.UID), ResourceVersion: pod.ResourceVersion,
		IP: pod.Status.PodIP, NodeName: pod.Spec.NodeName, RestartCount: servingPodRestartCount(pod)}
	cm, err := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, profile.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return errors.New("sensitive-output Pod-owned ConfigMap is unavailable")
	}
	activation, err := outputpolicy.ValidateConfigMap(cm, pod)
	if err != nil || activation.Active {
		return errors.New("sensitive-output exact rule is invalid or already active")
	}
	state, response, err := probeSensitiveOutput(ctx, p, profile)
	if err != nil || !state.Ready || state.Active || state.Revision != activation.Revision {
		return errors.New("sensitive-output proxy does not report the clean inactive baseline")
	}
	marker, present := sensitiveMarker(response)
	if !present || len(marker) < 32 || len(marker) > 128 || marker == "[REDACTED-BY-OUTPUT-POLICY]" {
		return errors.New("sensitive-output vulnerable baseline is not reproducible")
	}
	digest := sha256.Sum256([]byte(marker))
	p.sensitive = &sensitiveOutputPreparation{configMap: servingObjectPinFromMeta(cm),
		baselineActivation: cm.Data[outputpolicy.ActivationKey], markerSHA256: hex.EncodeToString(digest[:])}
	return nil
}

func sensitiveObservation(profile servingCatalogueProfile, p *servingCatalogueKubePreparation, observedAt time.Time) (string, error) {
	payload := struct {
		Version          int    `json:"version"`
		RuleID           string `json:"ruleId"`
		RuleSHA256       string `json:"ruleSHA256"`
		ConfigMapUID     string `json:"configMapUID"`
		PodUID           string `json:"podUID"`
		RequestPath      string `json:"requestPath"`
		PolicyName       string `json:"policyName"`
		PolicyUID        string `json:"policyUID"`
		PolicyGeneration int64  `json:"policyGeneration"`
		ObservedAt       string `json:"observedAt"`
	}{1, profile.RuleID, outputpolicy.RuleSHA256(p.target.UID), p.sensitive.configMap.UID, p.target.UID,
		profile.Route, profile.PolicyName, p.policy.UID, p.policy.Generation, observedAt.UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(payload)
	return string(raw), err
}

func (r *kubernetesServingCatalogueRuntime) executeSensitiveOutput(ctx context.Context, run AttackCatalogRunContext,
	profile servingCatalogueProfile, p *servingCatalogueKubePreparation) (servingCatalogueRuntimeObservation, error) {
	observation := servingCatalogueRuntimeObservation{Reason: "sensitive-output activation and redaction oracle did not complete"}
	if p.sensitive == nil {
		return observation, errors.New("sensitive-output preflight state is unavailable")
	}
	state, response, err := probeSensitiveOutput(ctx, p, profile)
	marker, leaked := sensitiveMarker(response)
	if err != nil || !state.Ready || state.Active || !leaked {
		return observation, errors.New("sensitive-output baseline changed after preflight")
	}
	digest := sha256.Sum256([]byte(marker))
	if hex.EncodeToString(digest[:]) != p.sensitive.markerSHA256 {
		return observation, errors.New("sensitive-output baseline marker identity changed after preflight")
	}
	payload, err := sensitiveObservation(profile, p, time.Now().UTC())
	if err != nil {
		return observation, err
	}
	signal, err := createServingSignal(ctx, p, run, profile, map[string]string{outputpolicy.EventAnnotation: payload})
	observation.MutationStarted = signal.Name != ""
	observation.Launched = signal.Created
	observation.Signal = signal
	if err != nil {
		return observation, err
	}
	ticker := time.NewTicker(r.pollInterval())
	defer ticker.Stop()
	var decision servingCatalogueDecision
	for {
		if matchedSignal, matchedDecision, ok := r.matchingDecision(ctx, profile, p, signal); ok {
			signal, decision = matchedSignal, matchedDecision
			p.signal, p.decision = signal, decision
		}
		pod, podErr := p.kube.CoreV1().Pods(profile.Namespace).Get(ctx, p.target.Name, metav1.GetOptions{})
		cm, cmErr := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, profile.ConfigMapName, metav1.GetOptions{})
		activation, activationErr := outputpolicy.ValidateConfigMap(cm, pod)
		if podErr == nil && cmErr == nil && activationErr == nil && activation.Active && decision.Actuated {
			proxyState, after, probeErr := probeSensitiveOutput(ctx, p, profile)
			afterMarker, afterPresent := sensitiveMarker(after)
			redacted := afterPresent && afterMarker == "[REDACTED-BY-OUTPUT-POLICY]"
			retained := string(pod.UID) == p.target.UID && pod.Status.Phase == corev1.PodRunning && podReady(pod) &&
				servingPodRestartCount(pod) == p.target.RestartCount
			if probeErr == nil && proxyState.Ready && proxyState.Active && proxyState.Revision == activation.Revision && redacted && retained {
				p.sensitive.operationID = activation.OperationID
				observation.Signal, observation.Decision = signal, decision
				observation.Sensitive = &sensitiveOutputPhysical{ConfigMapUID: string(cm.UID), PolicyUID: p.policy.UID,
					OperationID: activation.OperationID, MarkerSHA256: p.sensitive.markerSHA256,
					PolicyGeneration: p.policy.Generation, Revision: int64(activation.Revision), BaselineLeaked: true,
					ConfigMapActive: true, ProxyActive: true, Redacted: true, PodRetained: true}
				return observation, nil
			}
		}
		select {
		case <-ctx.Done():
			observation.Signal, observation.Decision = signal, decision
			return observation, nil
		case <-ticker.C:
		}
	}
}

type outputPolicyCleanupReceipt struct {
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

func readOutputPolicyCleanupJournal(ctx context.Context, profile servingCatalogueProfile,
	p *servingCatalogueKubePreparation) (*corev1.ConfigMap, outputPolicyCleanupReceipt, error) {
	name := outputpolicy.JournalName(p.target.UID)
	cm, err := p.kube.CoreV1().ConfigMaps(profile.OperatorNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, outputPolicyCleanupReceipt{}, err
	}
	var receipt outputPolicyCleanupReceipt
	if cm.UID == "" || cm.ResourceVersion == "" || cm.Labels[outputpolicy.JournalLabel] != "v1" ||
		json.Unmarshal([]byte(cm.Data["receipt"]), &receipt) != nil {
		return nil, receipt, errors.New("sensitive-output cleanup journal is malformed")
	}
	return cm, receipt, nil
}

func advanceOutputPolicyCleanupJournal(ctx context.Context, p *servingCatalogueKubePreparation,
	profile servingCatalogueProfile, cm *corev1.ConfigMap, receipt outputPolicyCleanupReceipt) (*corev1.ConfigMap, error) {
	raw, _ := json.Marshal(receipt)
	copy := cm.DeepCopy()
	copy.Data["receipt"] = string(raw)
	return p.kube.CoreV1().ConfigMaps(profile.OperatorNamespace).Update(ctx, copy, metav1.UpdateOptions{})
}

func rollbackSensitiveOutput(ctx context.Context, profile servingCatalogueProfile, p *servingCatalogueKubePreparation) error {
	if p.signal.UID == "" {
		cm, err := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, profile.ConfigMapName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		activation, err := outputpolicy.ParseActivation(cm.Data[outputpolicy.ActivationKey], string(cm.UID))
		if err != nil || activation.Active || string(cm.UID) != p.sensitive.configMap.UID ||
			cm.Data[outputpolicy.ActivationKey] != p.sensitive.baselineActivation {
			return errors.New("sensitive-output pre-signal baseline changed")
		}
		p.sensitive.restoredActivation = p.sensitive.baselineActivation
		return nil
	}
	journal, receipt, err := readOutputPolicyCleanupJournal(ctx, profile, p)
	if apierrors.IsNotFound(err) {
		cm, readErr := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, profile.ConfigMapName, metav1.GetOptions{})
		if readErr != nil || cm.Data[outputpolicy.ActivationKey] != p.sensitive.baselineActivation {
			return errors.New("sensitive-output activation changed without its exact journal")
		}
		p.sensitive.restoredActivation = p.sensitive.baselineActivation
		return nil
	}
	if err != nil {
		return err
	}
	if receipt.Version != 1 || receipt.Kind != profile.ExpectedAction || receipt.PolicyNamespace != profile.Namespace ||
		receipt.PolicyName != profile.PolicyName || receipt.PolicyUID != p.policy.UID ||
		receipt.PolicyGeneration != p.policy.Generation || receipt.TargetName != p.target.Name ||
		receipt.TargetUID != p.target.UID || receipt.EventName != p.signal.Name || receipt.EventUID != p.signal.UID ||
		receipt.CreatorIdentity != p.signal.Creator || p.decision.ID != "" && receipt.SelectionDecisionID != p.decision.ID ||
		receipt.ConfigMapName != profile.ConfigMapName || receipt.ConfigMapUID != p.sensitive.configMap.UID ||
		receipt.OperationID == "" || p.sensitive.operationID != "" && receipt.OperationID != p.sensitive.operationID ||
		string(receipt.Prior.Bytes()) != p.sensitive.baselineActivation || receipt.SelectedRevision != receipt.Prior.Revision ||
		receipt.Desired.ConfigMapUID != receipt.ConfigMapUID || !receipt.Desired.Active ||
		receipt.Desired.Revision != receipt.Prior.Revision+1 || receipt.Desired.OperationID != receipt.OperationID ||
		(receipt.Phase != "prepared" && receipt.Phase != "terminal-full" && receipt.Phase != "rollback-intent" && receipt.Phase != "rolled-back") {
		return errors.New("sensitive-output rollback receipt differs from the exact run")
	}
	cm, err := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, profile.ConfigMapName, metav1.GetOptions{})
	if err != nil || string(cm.UID) != receipt.ConfigMapUID {
		return errors.New("sensitive-output rollback ConfigMap identity changed")
	}
	activation, err := outputpolicy.ParseActivation(cm.Data[outputpolicy.ActivationKey], string(cm.UID))
	if err != nil {
		return err
	}
	restored := receipt.Prior
	restored.Revision = receipt.Desired.Revision + 1
	restored.OperationID = receipt.OperationID
	if activation != receipt.Prior && activation != receipt.Desired && activation != restored {
		return errors.New("sensitive-output rollback refuses a superseding activation")
	}
	if receipt.Phase != "rolled-back" {
		receipt.Phase = "rollback-intent"
		journal, err = advanceOutputPolicyCleanupJournal(ctx, p, profile, journal, receipt)
		if err != nil {
			return err
		}
		if activation == receipt.Prior || activation == receipt.Desired {
			copy := cm.DeepCopy()
			copy.Data[outputpolicy.ActivationKey] = string(restored.Bytes())
			if _, err = p.kube.CoreV1().ConfigMaps(profile.Namespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		cm, readErr := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, profile.ConfigMapName, metav1.GetOptions{})
		if readErr == nil {
			current, parseErr := outputpolicy.ParseActivation(cm.Data[outputpolicy.ActivationKey], string(cm.UID))
			if parseErr == nil && current == restored {
				state, _, probeErr := probeSensitiveOutput(ctx, p, profile)
				if probeErr == nil && state.Ready && !state.Active && state.Revision == restored.Revision {
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("sensitive-output rollback readback did not converge")
		case <-ticker.C:
		}
	}
	receipt.Phase = "rolled-back"
	_, err = advanceOutputPolicyCleanupJournal(ctx, p, profile, journal, receipt)
	if err == nil {
		p.sensitive.restoredActivation = string(restored.Bytes())
	}
	return err
}

func cleanupSensitiveOutput(ctx context.Context, _ AttackCatalogRunContext, profile servingCatalogueProfile,
	p *servingCatalogueKubePreparation) servingCatalogueRuntimeCleanup {
	result := servingCatalogueRuntimeCleanup{Attempted: true, MarkerDeleted: true}
	eventDeleted, err := deleteServingSignal(ctx, p)
	if err != nil || !eventDeleted {
		result.Reason = "sensitive-output exact event cleanup failed"
		return result
	}
	result.EventDeleted = true
	if err = rollbackSensitiveOutput(ctx, profile, p); err != nil {
		result.Reason = "sensitive-output exact activation rollback failed: " + err.Error()
		return result
	}
	cm, cmErr := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, profile.ConfigMapName, metav1.GetOptions{})
	pod, podErr := p.kube.CoreV1().Pods(profile.Namespace).Get(ctx, p.target.Name, metav1.GetOptions{})
	activation, activationErr := outputpolicy.ValidateConfigMap(cm, pod)
	result.Restored = cmErr == nil && podErr == nil && activationErr == nil && !activation.Active &&
		string(cm.UID) == p.sensitive.configMap.UID && string(pod.UID) == p.target.UID &&
		servingPodRestartCount(pod) == p.target.RestartCount &&
		p.sensitive.restoredActivation != "" && cm.Data[outputpolicy.ActivationKey] == p.sensitive.restoredActivation
	result.RetrySafe = result.Restored
	if result.Restored {
		result.Reason = "exact event deleted; inactive output policy and rolled-back operation verified without retaining response content"
	} else {
		result.Reason = "sensitive-output inactive baseline was not restored"
	}
	return result
}

type kvStateResponse struct {
	Pod            string   `json:"pod"`
	ImplantPresent bool     `json:"implant_present"`
	ImplantMarker  *string  `json:"implant_marker"`
	ValueSHA256    *string  `json:"value_sha256"`
	Keys           []string `json:"keys"`
	ResetCount     uint64   `json:"reset_count"`
}

func probeKV(ctx context.Context, p *servingCatalogueKubePreparation, profile servingCatalogueProfile,
	pod servingPodPin) (kvStateResponse, error) {
	var state kvStateResponse
	err := podProxyJSON(ctx, p.kube, profile.Namespace, pod.Name, profile.Port, "GET", "/kv", nil, &state)
	if err != nil || state.Pod != pod.Name {
		return state, errors.New("serving-kv exact Pod state is unavailable")
	}
	return state, nil
}

func preflightServingKV(ctx context.Context, profile servingCatalogueProfile, p *servingCatalogueKubePreparation) error {
	actuator, err := deploymentPin(ctx, p.kube, profile.OperatorNamespace, profile.Lane+"-actuator")
	if err != nil || len(actuator.Spec.Template.Spec.Containers) != 1 {
		return errors.New("serving-kv lane actuator is unavailable")
	}
	mode := false
	for _, arg := range actuator.Spec.Template.Spec.Containers[0].Args {
		if arg == "--serving-security-mode=legacy-plaintext" {
			mode = true
		}
	}
	if !mode {
		return errors.New("serving-kv reviewed fixture requires the preinstalled legacy-plaintext serving mode")
	}
	deployment, err := deploymentPin(ctx, p.kube, profile.Namespace, profile.Deployment)
	if err != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 2 ||
		deployment.Status.AvailableReplicas != 2 || deployment.Status.ReadyReplicas != 2 {
		return errors.New("serving-kv Deployment is not exactly two ready replicas")
	}
	service, err := p.kube.CoreV1().Services(profile.Namespace).Get(ctx, profile.Service, metav1.GetOptions{})
	if err != nil || service.UID == "" || service.DeletionTimestamp != nil {
		return errors.New("serving-kv fixed Service is unavailable")
	}
	pods, err := servingReadyPods(ctx, p.kube, profile.Namespace, profile.Selector, 3)
	if err != nil || len(pods) != 2 {
		return errors.New("serving-kv profile requires exactly two ready serving Pods")
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })
	p.target, p.bystander = pods[0], pods[1]
	for _, pod := range pods {
		object, readErr := p.kube.CoreV1().Pods(profile.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if readErr != nil || object.Annotations["phorvex.ai/serving-port"] != fmt.Sprint(profile.Port) ||
			object.Annotations["phorvex.ai/model-id"] == "" || !podDeclaresGPU(object) {
			return errors.New("serving-kv Pod lacks the reviewed serving and GPU binding")
		}
		state, probeErr := probeKV(ctx, p, profile, pod)
		if probeErr != nil || state.ImplantPresent {
			return errors.New("serving-kv fixture is not in a clean implant-free baseline")
		}
	}
	p.kv = &servingKVPreparation{}
	return nil
}

func podDeclaresGPU(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if quantity, ok := container.Resources.Limits[corev1.ResourceName("nvidia.com/gpu")]; ok && quantity.Sign() > 0 {
			return true
		}
	}
	return false
}

func seedKV(ctx context.Context, p *servingCatalogueKubePreparation, profile servingCatalogueProfile,
	pod servingPodPin, marker string) (kvStateResponse, error) {
	var state kvStateResponse
	body := map[string]string{"key": profile.ImplantKey, "marker": marker,
		"val": "controlled persistent context for catalogue run " + marker}
	err := podProxyJSON(ctx, p.kube, profile.Namespace, pod.Name, profile.Port, "POST", "/seed", body, &state)
	if err != nil || state.Pod != pod.Name || !state.ImplantPresent || state.ImplantMarker == nil || *state.ImplantMarker != marker {
		return state, errors.New("serving-kv implant seed did not bind to the exact Pod and run marker")
	}
	return state, nil
}

func resetKV(ctx context.Context, p *servingCatalogueKubePreparation, profile servingCatalogueProfile, pod servingPodPin) error {
	var response struct {
		Success bool `json:"success"`
	}
	if err := podProxyJSON(ctx, p.kube, profile.Namespace, pod.Name, profile.Port, "POST", "/reset_prefix_cache", nil, &response); err != nil || !response.Success {
		return errors.New("serving-kv exact cleanup reset was not acknowledged")
	}
	return nil
}

func (r *kubernetesServingCatalogueRuntime) executeServingKV(ctx context.Context, run AttackCatalogRunContext,
	profile servingCatalogueProfile, p *servingCatalogueKubePreparation) (servingCatalogueRuntimeObservation, error) {
	observation := servingCatalogueRuntimeObservation{Reason: "serving-kv decision and two-sided flush oracle did not complete"}
	if p.kv == nil {
		return observation, errors.New("serving-kv preflight state is unavailable")
	}
	suffix, err := servingRandomSuffix()
	if err != nil {
		return observation, err
	}
	p.kv.marker = profile.ImplantLabel + "-" + suffix
	targetState, err := seedKV(ctx, p, profile, p.target, p.kv.marker)
	if err != nil {
		return observation, err
	}
	p.kv.seededTarget, p.kv.baselineResetCount, observation.MutationStarted = true, targetState.ResetCount, true
	if _, err = seedKV(ctx, p, profile, p.bystander, p.kv.marker); err != nil {
		return observation, err
	}
	p.kv.seededBystander = true
	signal, err := createServingSignal(ctx, p, run, profile, nil)
	observation.Launched, observation.Signal = signal.Created, signal
	if err != nil {
		return observation, err
	}
	ticker := time.NewTicker(r.pollInterval())
	defer ticker.Stop()
	var decision servingCatalogueDecision
	for {
		if matchedSignal, matchedDecision, ok := r.matchingDecision(ctx, profile, p, signal); ok {
			signal, decision = matchedSignal, matchedDecision
			p.signal, p.decision = signal, decision
		}
		targetAfter, targetErr := probeKV(ctx, p, profile, p.target)
		bystanderAfter, bystanderErr := probeKV(ctx, p, profile, p.bystander)
		currentPods, podsErr := servingReadyPods(ctx, p.kube, profile.Namespace, profile.Selector, 3)
		deployment, deploymentErr := p.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
		identities := map[string]servingPodPin{}
		for _, current := range currentPods {
			identities[current.Name] = current
		}
		targetRetained := identities[p.target.Name].UID == p.target.UID && identities[p.target.Name].RestartCount == p.target.RestartCount
		bystanderRetained := identities[p.bystander.Name].UID == p.bystander.UID && identities[p.bystander.Name].RestartCount == p.bystander.RestartCount
		if decision.Actuated && targetErr == nil && bystanderErr == nil && podsErr == nil && deploymentErr == nil &&
			!targetAfter.ImplantPresent && targetAfter.ResetCount > p.kv.baselineResetCount &&
			bystanderAfter.ImplantPresent && bystanderAfter.ImplantMarker != nil && *bystanderAfter.ImplantMarker == p.kv.marker &&
			targetRetained && bystanderRetained && deployment.Spec.Replicas != nil && *deployment.Spec.Replicas >= 2 &&
			deployment.Status.AvailableReplicas == *deployment.Spec.Replicas {
			observation.Signal, observation.Decision = signal, decision
			observation.KV = &servingKVPhysical{BystanderUID: p.bystander.UID,
				BaselineResetCount: p.kv.baselineResetCount, AfterResetCount: targetAfter.ResetCount,
				TargetImplantBefore: true, TargetImplantAfter: false, TargetRetained: true,
				BystanderImplantRetained: true, BystanderRetained: true,
				AvailableReplicas: deployment.Status.AvailableReplicas, DesiredReplicas: *deployment.Spec.Replicas}
			return observation, nil
		}
		select {
		case <-ctx.Done():
			observation.Signal, observation.Decision = signal, decision
			return observation, nil
		case <-ticker.C:
		}
	}
}

func cleanupServingKV(ctx context.Context, _ AttackCatalogRunContext, profile servingCatalogueProfile,
	p *servingCatalogueKubePreparation) servingCatalogueRuntimeCleanup {
	result := servingCatalogueRuntimeCleanup{Attempted: true}
	eventDeleted, err := deleteServingSignal(ctx, p)
	if err != nil || !eventDeleted {
		result.Reason = "serving-kv exact event cleanup failed"
		return result
	}
	result.EventDeleted = true
	owned := []struct {
		pod    servingPodPin
		seeded bool
	}{{p.target, p.kv.seededTarget}, {p.bystander, p.kv.seededBystander}}
	for _, item := range owned {
		state, probeErr := probeKV(ctx, p, profile, item.pod)
		if probeErr != nil {
			result.Reason = "serving-kv cleanup state is unavailable"
			return result
		}
		if state.ImplantPresent {
			if !item.seeded || p.kv.marker == "" || state.ImplantMarker == nil || *state.ImplantMarker != p.kv.marker {
				result.Reason = "serving-kv cleanup refuses an implant not owned by this exact run"
				return result
			}
			if err = resetKV(ctx, p, profile, item.pod); err != nil {
				result.Reason = err.Error()
				return result
			}
		}
	}
	for _, item := range owned {
		state, probeErr := probeKV(ctx, p, profile, item.pod)
		current, podErr := p.kube.CoreV1().Pods(profile.Namespace).Get(ctx, item.pod.Name, metav1.GetOptions{})
		if probeErr != nil || podErr != nil || state.ImplantPresent || string(current.UID) != item.pod.UID ||
			!podReady(current) || servingPodRestartCount(current) != item.pod.RestartCount {
			result.Reason = "serving-kv implant absence and retained Pod cleanup could not be verified"
			return result
		}
	}
	result.MarkerDeleted = true
	deployment, err := p.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
	result.Restored = err == nil && deployment.Spec.Replicas != nil && *deployment.Spec.Replicas == 2 &&
		deployment.Status.AvailableReplicas == 2 && deployment.Status.ReadyReplicas == 2
	result.RetrySafe = result.Restored
	if result.Restored {
		result.Reason = "exact event deleted; both run-owned implants absent and both serving Pods retained"
	} else {
		result.Reason = "serving-kv availability baseline was not restored"
	}
	return result
}
