package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/servingbudget"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

const servingRateFloodImage = "docker.io/fortio/fortio@sha256:3dd31ddeb4f962a1dae8cc2a0bce62c408ac830c8435bbea51b1e0fd4c8f7181"

type servingRateStatusSnapshot struct {
	servingbudget.Status
}

type servingRateJournalReceipt struct {
	Request     servingRateJournalRequest `json:"request"`
	OperationID string                    `json:"operationID"`
	Namespace   string                    `json:"namespace"`
	PolicyUID   string                    `json:"policyUID"`
	ConfigUID   string                    `json:"configUID"`
	Phase       string                    `json:"phase"`
	Before      servingbudget.Contract    `json:"before"`
	After       servingbudget.Contract    `json:"after"`
}

type servingRateJournalRequest struct {
	OperationID                  string                         `json:"OperationID"`
	Namespace                    string                         `json:"Namespace"`
	Pod                          string                         `json:"Pod"`
	TargetUID                    string                         `json:"TargetUID"`
	PolicyName                   string                         `json:"PolicyName"`
	PolicyUID                    string                         `json:"PolicyUID"`
	PolicyGeneration             int64                          `json:"PolicyGeneration"`
	Action                       string                         `json:"Action"`
	ServingRateBudgetObservation *servingRateJournalObservation `json:"ServingRateBudgetObservation"`
}

type servingRateJournalObservation struct {
	EventName        string `json:"eventName"`
	EventUID         string `json:"eventUID"`
	CreatorIdentity  string `json:"creatorIdentity"`
	TargetPodUID     string `json:"targetPodUID"`
	PolicyName       string `json:"policyName"`
	PolicyUID        string `json:"policyUID"`
	PolicyGeneration int64  `json:"policyGeneration"`
}

func readServingRateStatus(ctx context.Context, p *servingCatalogueKubePreparation, profile servingCatalogueProfile) (servingRateStatusSnapshot, error) {
	cm, err := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, servingbudget.StatusName, metav1.GetOptions{})
	if err != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil {
		return servingRateStatusSnapshot{}, errors.New("serving-rate status is unavailable")
	}
	var status servingbudget.Status
	if raw := cm.Data[servingbudget.Key]; raw == "" || json.Unmarshal([]byte(raw), &status) != nil || !status.Fresh(time.Now()) {
		return servingRateStatusSnapshot{}, errors.New("serving-rate status is invalid or stale")
	}
	return servingRateStatusSnapshot{Status: status}, nil
}

func readServingRateJournal(ctx context.Context, p *servingCatalogueKubePreparation, profile servingCatalogueProfile) (*corev1.ConfigMap, servingRateJournalReceipt, error) {
	cm, err := p.kube.CoreV1().ConfigMaps(profile.OperatorNamespace).Get(ctx, servingbudget.JournalName, metav1.GetOptions{})
	if err != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil {
		return nil, servingRateJournalReceipt{}, errors.New("serving-rate journal is unavailable")
	}
	var receipt servingRateJournalReceipt
	raw := cm.Data[servingbudget.Key]
	if raw != "" && json.Unmarshal([]byte(raw), &receipt) != nil {
		return nil, receipt, errors.New("serving-rate journal is malformed")
	}
	return cm, receipt, nil
}

func preflightServingRate(ctx context.Context, profile servingCatalogueProfile, p *servingCatalogueKubePreparation) error {
	if err := noExistingServingJobs(ctx, p.kube, profile.Namespace); err != nil {
		return err
	}
	target, err := deploymentPin(ctx, p.kube, profile.Namespace, profile.Deployment)
	if err != nil || target.Status.AvailableReplicas != 1 || target.Status.ReadyReplicas != 1 {
		return errors.New("serving-rate target Deployment is not exactly one ready replica")
	}
	for _, name := range []string{"rate-admission", "rate-detector"} {
		deployment, readErr := deploymentPin(ctx, p.kube, profile.Namespace, name)
		if readErr != nil || deployment.Status.AvailableReplicas != 1 || deployment.Status.ReadyReplicas != 1 {
			return fmt.Errorf("serving-rate %s Deployment is not exactly one ready replica", name)
		}
	}
	pods, err := servingReadyPods(ctx, p.kube, profile.Namespace, profile.Selector, 2)
	if err != nil || len(pods) != 1 || pods[0].NodeName == "" {
		return errors.New("serving-rate profile requires exactly one ready pinned target Pod")
	}
	p.target = pods[0]
	for _, name := range []string{profile.Service, "rate-target-backend"} {
		service, serviceErr := p.kube.CoreV1().Services(profile.Namespace).Get(ctx, name, metav1.GetOptions{})
		if serviceErr != nil || service.UID == "" || service.DeletionTimestamp != nil {
			return errors.New("serving-rate fixed Service graph is unavailable")
		}
		selector, port, targetPort := "rate-admission", int32(80), int32(8080)
		if name == "rate-target-backend" {
			selector, port = "rate-target", 8080
		}
		if len(service.Spec.Selector) != 1 || service.Spec.Selector["app"] != selector ||
			len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != port || service.Spec.Ports[0].TargetPort.IntVal != targetPort {
			return errors.New("serving-rate fixed Service routing profile differs")
		}
	}
	for _, name := range []string{"rate-admission", "rate-detector", "rate-abusive", "rate-legit"} {
		account, accountErr := p.kube.CoreV1().ServiceAccounts(profile.Namespace).Get(ctx, name, metav1.GetOptions{})
		if accountErr != nil || account.UID == "" || account.DeletionTimestamp != nil {
			return errors.New("serving-rate fixed detector or load identity is unavailable")
		}
	}
	budget, err := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, servingbudget.ConfigName, metav1.GetOptions{})
	if err != nil || budget.UID == "" || budget.ResourceVersion == "" || budget.DeletionTimestamp != nil {
		return errors.New("serving-rate budget is unavailable")
	}
	contract, err := servingbudget.Parse(budget.Data[servingbudget.Key])
	if err != nil || contract.Enabled || contract.Calibrating || contract.Baseline <= 0 || contract.Reserved <= 0 {
		return errors.New("serving-rate budget is not armed and quiet")
	}
	statusCM, err := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, servingbudget.StatusName, metav1.GetOptions{})
	if err != nil || statusCM.UID == "" || statusCM.ResourceVersion == "" || statusCM.DeletionTimestamp != nil {
		return errors.New("serving-rate status ConfigMap is unavailable")
	}
	status, err := readServingRateStatus(ctx, p, profile)
	if err != nil || status.Contract != contract || status.ConfigUID != string(budget.UID) || status.CapActive {
		return errors.New("serving-rate proxy does not report the exact quiet budget")
	}
	journalCM, journal, err := readServingRateJournal(ctx, p, profile)
	if err != nil || journal.OperationID != "" && journal.Phase != "rolled-back" {
		return errors.New("serving-rate prior operation is unresolved")
	}
	detector, err := p.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, "rate-detector", metav1.GetOptions{})
	if err != nil || len(detector.Spec.Template.Spec.Containers) != 1 || detector.Spec.Template.Spec.Containers[0].Image == "" ||
		!strings.Contains(detector.Spec.Template.Spec.Containers[0].Image, "@sha256:") ||
		detector.Spec.Template.Spec.ServiceAccountName != "rate-detector" {
		return errors.New("serving-rate fixed load image is not digest-pinned")
	}
	detectorContainer := detector.Spec.Template.Spec.Containers[0]
	if len(detectorContainer.Command) != 1 || detectorContainer.Command[0] != "/cost-load-detector" {
		return errors.New("serving-rate detector executable differs from the reviewed p5 contract")
	}
	env := map[string]string{}
	for _, item := range detectorContainer.Env {
		if item.ValueFrom == nil {
			env[item.Name] = item.Value
		}
	}
	wantEnv := map[string]string{
		"PHORVEX_THROTTLE_NAMESPACE":         profile.Namespace,
		"PHORVEX_THROTTLE_POLICY":            profile.PolicyName,
		"PHORVEX_THROTTLE_DETECTOR_IDENTITY": "system:serviceaccount:" + profile.Namespace + ":rate-detector",
		"PHORVEX_THROTTLE_SOURCE":            "phorvex-rate-detector-" + profile.OperatorNamespace,
		"PHORVEX_THROTTLE_DEPLOYMENT":        "rate-admission",
		"PHORVEX_THROTTLE_SERVICE":           profile.Service,
		"PHORVEX_THROTTLE_BACKEND":           "rate-target-backend",
		"PHORVEX_THROTTLE_TARGET_APP":        "rate-target",
		"PHORVEX_THROTTLE_SOURCE_SHA256":     contract.SourceSHA256,
		"PHORVEX_THROTTLE_PROXY_IMAGE":       contract.ProxyImage,
	}
	for key, value := range wantEnv {
		if env[key] != value {
			return errors.New("serving-rate detector profile differs from the reviewed p5 contract")
		}
	}
	if contract.AbusiveAccount != "system:serviceaccount:"+profile.Namespace+":rate-abusive" ||
		contract.LegitimateAccount != "system:serviceaccount:"+profile.Namespace+":rate-legit" ||
		detectorContainer.Image != contract.ProxyImage {
		return errors.New("serving-rate budget identities or approved image differ from the reviewed p5 contract")
	}
	p.rate = &servingRatePreparation{statusBaseline: status,
		budget: servingObjectPinFromMeta(budget), status: servingObjectPinFromMeta(statusCM),
		journal: servingObjectPinFromMeta(journalCM), journalOperationID: journal.OperationID,
		loadImage: detector.Spec.Template.Spec.Containers[0].Image,
		nodeName:  p.target.NodeName}
	return nil
}

func servingRateJob(profile servingCatalogueProfile, runID, name, serviceAccount, image, node string, abusive bool) *batchv1.Job {
	labels := map[string]string{servingCatalogueRunLabel: runID, "phorvex.ai/fixture": "serving-rate-load"}
	backoff, parallelism, completions := int32(0), int32(1), int32(1)
	deadline, ttl := int64(210), int32(600)
	container := corev1.Container{Name: "client", Image: image,
		SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: servingBool(false), ReadOnlyRootFilesystem: servingBool(true),
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
		Resources: corev1.ResourceRequirements{},
	}
	if abusive {
		parallelism, completions = 3, 3
		container.Args = []string{"load", "-c", "50", "-qps", "0", "-t", "180s", "-quiet", "-allow-initial-errors",
			"http://" + profile.Service + "." + profile.Namespace + ".svc/"}
	} else {
		container.Command = []string{"/cost-client"}
		container.Args = []string{"--qps=3", "--duration=180s", "--url=http://" + profile.Service + "." + profile.Namespace + ".svc/"}
	}
	return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: profile.Namespace, Labels: labels},
		Spec: batchv1.JobSpec{Parallelism: &parallelism, Completions: &completions, BackoffLimit: &backoff,
			ActiveDeadlineSeconds: &deadline, TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{
				NodeSelector: map[string]string{"kubernetes.io/hostname": node}, ServiceAccountName: serviceAccount,
				AutomountServiceAccountToken: servingBool(false), RestartPolicy: corev1.RestartPolicyNever,
				SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: servingBool(true), RunAsUser: servingInt64(65532),
					SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
				Containers: []corev1.Container{container},
			}}}}
}

func servingBool(v bool) *bool    { return &v }
func servingInt64(v int64) *int64 { return &v }

func (r *kubernetesServingCatalogueRuntime) executeServingRate(ctx context.Context, run AttackCatalogRunContext,
	profile servingCatalogueProfile, p *servingCatalogueKubePreparation) (servingCatalogueRuntimeObservation, error) {
	observation := servingCatalogueRuntimeObservation{Reason: "serving-rate bounded load did not complete its exact decision and cap oracle"}
	if p.rate == nil {
		return observation, errors.New("serving-rate preflight state is unavailable")
	}
	current, err := readServingRateStatus(ctx, p, profile)
	if err != nil || current.ConfigUID != p.rate.statusBaseline.ConfigUID || current.PodUID != p.rate.statusBaseline.PodUID ||
		current.BootID != p.rate.statusBaseline.BootID || current.Contract != p.rate.statusBaseline.Contract || current.CapActive {
		return observation, errors.New("serving-rate quiet baseline changed after preflight")
	}
	suffix, err := servingRandomSuffix()
	if err != nil {
		return observation, err
	}
	legitName, abusiveName := "catalog-rate-legit-"+suffix, "catalog-rate-flood-"+suffix
	for _, job := range []*batchv1.Job{
		servingRateJob(profile, run.RunID, legitName, "rate-legit", p.rate.loadImage, p.rate.nodeName, false),
		servingRateJob(profile, run.RunID, abusiveName, "rate-abusive", servingRateFloodImage, p.rate.nodeName, true),
	} {
		created, createErr := p.kube.BatchV1().Jobs(profile.Namespace).Create(ctx, job, metav1.CreateOptions{})
		if createErr != nil || created.UID == "" {
			return observation, errors.New("serving-rate bounded load Job admission failed")
		}
		p.jobs = append(p.jobs, servingObjectPinFromMeta(created))
		observation.MutationStarted = true
	}
	observation.Launched = true
	ticker := time.NewTicker(r.pollInterval())
	defer ticker.Stop()
	var cap servingRateStatusSnapshot
	var capAt time.Time
	var signal servingCatalogueSignal
	var decision servingCatalogueDecision
	for {
		if matchedSignal, matchedDecision, ok := r.matchingDecision(ctx, profile, p, signal); ok {
			signal, decision = matchedSignal, matchedDecision
			p.signal, p.decision = signal, decision
		}
		status, statusErr := readServingRateStatus(ctx, p, profile)
		journalCM, journal, journalErr := readServingRateJournal(ctx, p, profile)
		if statusErr == nil && journalErr == nil && journalCM.UID == types.UID(p.rate.journal.UID) &&
			status.CapActive && status.Contract.Enabled && journal.Phase == "applied" &&
			status.Contract.OperationID != "" && status.Contract.OperationID == journal.OperationID &&
			journal.Namespace == profile.Namespace && journal.PolicyUID == p.policy.UID &&
			journal.ConfigUID == p.rate.budget.UID && signal.Observed && decision.Actuated {
			if capAt.IsZero() {
				cap, capAt = status, time.Now().UTC()
			}
			if time.Since(capAt) >= 10*time.Second {
				after, afterErr := readServingRateStatus(ctx, p, profile)
				if afterErr == nil && after.Contract.OperationID == journal.OperationID {
					elapsed := time.Since(capAt).Seconds()
					observation.Signal, observation.Decision = signal, decision
					observation.Rate = &servingRatePhysical{OperationID: journal.OperationID,
						Baseline: cap.Baseline, ElapsedSeconds: elapsed,
						AbusiveAttempted:       after.Abusive.Attempted - cap.Abusive.Attempted,
						AbusiveAdmitted:        after.Abusive.Admitted - cap.Abusive.Admitted,
						AbusiveRejected:        after.Abusive.Rejected - cap.Abusive.Rejected,
						LegitimateAttempted:    after.Legitimate.Attempted - cap.Legitimate.Attempted,
						LegitimateAdmitted:     after.Legitimate.Admitted - cap.Legitimate.Admitted,
						LegitimateRejected:     after.Legitimate.Rejected - cap.Legitimate.Rejected,
						CapApplied:             after.CapActive && after.Contract.Enabled,
						ProxyIdentityUnchanged: after.PodUID == cap.PodUID && after.BootID == cap.BootID && after.ConfigUID == cap.ConfigUID}
					return observation, nil
				}
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

func bindServingRateReceipt(ctx context.Context, profile servingCatalogueProfile, p *servingCatalogueKubePreparation,
	receipt servingRateJournalReceipt) error {
	request, observed := receipt.Request, receipt.Request.ServingRateBudgetObservation
	if observed == nil || receipt.OperationID == "" || request.OperationID != receipt.OperationID ||
		request.Namespace != profile.Namespace || request.Pod != p.target.Name || request.TargetUID != p.target.UID ||
		request.PolicyName != profile.PolicyName || request.PolicyUID != p.policy.UID ||
		request.PolicyGeneration != p.policy.Generation || request.Action != profile.ExpectedAction ||
		observed.PolicyName != profile.PolicyName || observed.PolicyUID != p.policy.UID ||
		observed.PolicyGeneration != p.policy.Generation || observed.TargetPodUID != p.target.UID ||
		observed.CreatorIdentity != "system:serviceaccount:"+profile.Namespace+":rate-detector" ||
		receipt.Namespace != profile.Namespace || receipt.PolicyUID != p.policy.UID ||
		receipt.ConfigUID != p.rate.budget.UID || receipt.Before != p.rate.statusBaseline.Contract ||
		!receipt.Before.Valid() || !receipt.After.Valid() || !receipt.After.Enabled ||
		receipt.After.OperationID != receipt.OperationID ||
		(p.decision.ID != "" && p.decision.ID != receipt.OperationID) {
		return errors.New("serving-rate rollback receipt is not bound to this exact run profile")
	}
	if p.signal.UID != "" && (p.signal.Name != observed.EventName || p.signal.UID != observed.EventUID ||
		p.signal.Creator != observed.CreatorIdentity || p.signal.TargetUID != observed.TargetPodUID) {
		return errors.New("serving-rate rollback receipt differs from the observed run signal")
	}
	event, err := p.dynamic.Resource(securityEventGVR).Get(ctx, observed.EventName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) && p.signal.Name == observed.EventName && p.signal.UID == observed.EventUID &&
		p.signal.Creator == observed.CreatorIdentity && p.signal.TargetUID == observed.TargetPodUID {
		return nil
	}
	if err != nil || string(event.GetUID()) != observed.EventUID || event.GetDeletionTimestamp() != nil ||
		event.GetCreationTimestamp().Time.IsZero() || event.GetCreationTimestamp().Time.Before(p.startedAt) ||
		event.GetAnnotations()["phorvex.ai/creator-identity"] != observed.CreatorIdentity ||
		event.GetAnnotations()["phorvex.ai/console-target-pod-uid"] != p.target.UID {
		return errors.New("serving-rate rollback detector event identity is unavailable or stale")
	}
	targets, _, _ := unstructured.NestedStringSlice(event.Object, "spec", "targets")
	eventType, _, _ := unstructured.NestedString(event.Object, "spec", "rule", "type")
	eventSource, _, _ := unstructured.NestedString(event.Object, "spec", "rule", "source")
	if len(targets) != 1 || targets[0] != profile.Namespace+"/"+p.target.Name ||
		eventType != profile.EventType || eventSource != "phorvex-rate-detector-"+profile.OperatorNamespace {
		return errors.New("serving-rate rollback detector event target or source changed")
	}
	p.signal = servingCatalogueSignal{Created: true, Observed: true, Name: observed.EventName,
		UID: observed.EventUID, Creator: observed.CreatorIdentity, TargetUID: observed.TargetPodUID}
	return nil
}

func rollbackServingRate(ctx context.Context, profile servingCatalogueProfile, p *servingCatalogueKubePreparation) error {
	journalCM, receipt, err := readServingRateJournal(ctx, p, profile)
	if err != nil {
		return err
	}
	if string(journalCM.UID) != p.rate.journal.UID ||
		(receipt.Phase != "prepared" && receipt.Phase != "applied" && receipt.Phase != "rollback-intent" && receipt.Phase != "rolled-back") {
		return errors.New("serving-rate rollback receipt does not belong to this exact profile")
	}
	if err = bindServingRateReceipt(ctx, profile, p, receipt); err != nil {
		return err
	}
	budget, err := p.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, servingbudget.ConfigName, metav1.GetOptions{})
	if err != nil || string(budget.UID) != receipt.ConfigUID {
		return errors.New("serving-rate rollback budget identity changed")
	}
	contract, err := servingbudget.Parse(budget.Data[servingbudget.Key])
	if err != nil {
		return err
	}
	restored := receipt.Before
	restored.Revision = receipt.After.Revision + 1
	restored.OperationID = "rollback:" + receipt.OperationID
	if contract != receipt.After && contract != restored && contract != receipt.Before {
		return errors.New("serving-rate rollback refuses a later writer")
	}
	if receipt.Phase != "rolled-back" {
		receipt.Phase = "rollback-intent"
		raw, _ := json.Marshal(receipt)
		journalCopy := journalCM.DeepCopy()
		journalCopy.Data[servingbudget.Key] = string(raw)
		if _, err = p.kube.CoreV1().ConfigMaps(profile.OperatorNamespace).Update(ctx, journalCopy, metav1.UpdateOptions{}); err != nil {
			return err
		}
		if contract != restored {
			budgetCopy := budget.DeepCopy()
			budgetCopy.Data[servingbudget.Key] = servingbudget.Encode(restored)
			if _, err = p.kube.CoreV1().ConfigMaps(profile.Namespace).Update(ctx, budgetCopy, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}
	deadline := time.NewTicker(250 * time.Millisecond)
	defer deadline.Stop()
	for {
		status, statusErr := readServingRateStatus(ctx, p, profile)
		if statusErr == nil && status.ConfigUID == receipt.ConfigUID && status.Contract == restored && !status.CapActive {
			break
		}
		select {
		case <-ctx.Done():
			return errors.New("serving-rate rollback proxy readback did not converge")
		case <-deadline.C:
		}
	}
	journalCM, receipt, err = readServingRateJournal(ctx, p, profile)
	if err != nil {
		return err
	}
	receipt.Phase = "rolled-back"
	raw, _ := json.Marshal(receipt)
	journalCopy := journalCM.DeepCopy()
	journalCopy.Data[servingbudget.Key] = string(raw)
	_, err = p.kube.CoreV1().ConfigMaps(profile.OperatorNamespace).Update(ctx, journalCopy, metav1.UpdateOptions{})
	return err
}

func cleanupServingRate(ctx context.Context, _ AttackCatalogRunContext, profile servingCatalogueProfile,
	p *servingCatalogueKubePreparation) servingCatalogueRuntimeCleanup {
	result := servingCatalogueRuntimeCleanup{Attempted: true}
	for _, job := range p.jobs {
		if err := exactDeleteJob(ctx, p.kube, profile.Namespace, job); err != nil {
			result.Reason = "serving-rate exact load cleanup failed"
			return result
		}
	}
	jobTicker := time.NewTicker(100 * time.Millisecond)
	defer jobTicker.Stop()
	for {
		remaining := false
		for _, job := range p.jobs {
			_, err := p.kube.BatchV1().Jobs(profile.Namespace).Get(ctx, job.Name, metav1.GetOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				result.Reason = "serving-rate load cleanup could not be verified"
				return result
			}
			remaining = remaining || err == nil
		}
		if !remaining {
			break
		}
		select {
		case <-ctx.Done():
			result.Reason = "serving-rate load Job absence did not converge"
			return result
		case <-jobTicker.C:
		}
	}
	result.MarkerDeleted = true
	_, receipt, err := readServingRateJournal(ctx, p, profile)
	if err != nil {
		result.Reason = "serving-rate journal unavailable during cleanup"
		return result
	}
	expectedContract := p.rate.statusBaseline.Contract
	runOperation := receipt.OperationID != "" && receipt.OperationID != p.rate.journalOperationID
	if runOperation {
		if err = rollbackServingRate(ctx, profile, p); err != nil {
			result.Reason = "serving-rate exact cap rollback failed: " + err.Error()
			return result
		}
		expectedContract = receipt.Before
		expectedContract.Revision = receipt.After.Revision + 1
		expectedContract.OperationID = "rollback:" + receipt.OperationID
	}
	eventDeleted, err := deleteServingSignal(ctx, p)
	if err != nil || !eventDeleted {
		result.Reason = "serving-rate detector event cleanup failed"
		return result
	}
	result.EventDeleted = true
	status, statusErr := readServingRateStatus(ctx, p, profile)
	_, finalReceipt, journalErr := readServingRateJournal(ctx, p, profile)
	result.Restored = statusErr == nil && !status.CapActive && !status.Contract.Enabled &&
		status.ConfigUID == p.rate.statusBaseline.ConfigUID && status.PodUID == p.rate.statusBaseline.PodUID &&
		status.BootID == p.rate.statusBaseline.BootID && status.Contract == expectedContract && journalErr == nil &&
		(!runOperation && finalReceipt.OperationID == p.rate.journalOperationID || runOperation && finalReceipt.Phase == "rolled-back")
	result.RetrySafe = result.Restored
	if !result.Restored {
		result.Reason = "serving-rate quiet baseline or rolled-back journal was not restored"
	} else {
		result.Reason = "exact load Jobs and detector event deleted; cap rollback and quiet baseline verified"
	}
	return result
}
