package defenders

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	installedControlPolicyName     = "harness-installed-manager-control"
	installedEligiblePolicyName    = "harness-installed-manager-eligible"
	installedEvictionRoleName      = "harness-installed-manager-eviction"
	installedControlWindow         = 12 * time.Second
	installedEligibleWindow        = 25 * time.Second
	installedCoordinationMinimum   = 70 * time.Second
	installedPolicyTick            = 5 * time.Second
	installedObserverMaxOutput     = 96 * 1024
	installedObserverBinaryMax     = 64 << 20
	installedObserverCredentialMax = 1 << 20
	installedCleanupWait           = 10 * time.Second
	installedPolicySchemaVersion   = "phorvex.installed-policy.v1"
	installedTargetMinimumAge      = 90 * time.Second
)

var phorvexPolicyGVK = schema.GroupVersionKind{Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicy"}
var phorvexPolicyListGVK = schema.GroupVersionKind{Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicyList"}
var phorvexPolicyCRDGVK = schema.GroupVersionKind{Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"}

func init() { core.RegisterDefender(&installedPhorvex{}) }

type installedPhorvex struct {
	mu               sync.Mutex
	skip             bool
	skipReason       string
	controlPolicyUID types.UID
	policyUID        types.UID
	policyGeneration int64
	roleUID          types.UID
	roleBindingUID   types.UID
	targetName       string
	targetUID        types.UID
	targetRV         string
	actionAt         time.Time
	actionCount      int
}

func (*installedPhorvex) Metadata() core.DefenderMeta {
	return core.DefenderMeta{Name: "d-phorvex-installed", Description: "Attach to one exactly pinned installed Phorvex manager; use sequential owned control/eligible policies plus one exact-target fixture eviction Role/RoleBinding, observe authenticated audit decisions, and coordinate one target without installing CRDs or starting controllers.", MeanRotationIntervalSeconds: 0}
}

func (p *installedPhorvex) Setup(ctx context.Context, env *core.Env) error {
	p.mu.Lock()
	p.skip, p.skipReason = false, ""
	p.controlPolicyUID, p.policyUID, p.policyGeneration, p.roleUID, p.roleBindingUID, p.targetName, p.targetUID, p.targetRV, p.actionAt, p.actionCount = "", "", 0, "", "", "", "", "", time.Time{}, 0
	if env.Config.InstalledManagerFixture == nil || env.ScenarioName != "c2-installed-manager-session" {
		p.skip = true
		p.skipReason = "installed-manager arm requires an explicit installedManagerFixture and c2-installed-manager-session"
	}
	skip := p.skip
	p.mu.Unlock()
	if skip {
		return nil
	}
	if env.Ctrl == nil {
		return errors.New("d-phorvex-installed is confined to the installed-manager session scenario with a controller-runtime client")
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	if err := validateInstalledManagerRuntime(ctx, env); err != nil {
		return err
	}
	if err := requireInstalledPolicyAbsent(ctx, env); err != nil {
		return err
	}
	return requireInstalledEvictionRBACAbsent(ctx, env)
}

func (p *installedPhorvex) SkipReason() (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.skip, p.skipReason
}

func (*installedPhorvex) Start(ctx context.Context, env *core.Env) error {
	return validateInstalledManagerRuntime(ctx, env)
}

func (p *installedPhorvex) CoordinateTargetedAction(ctx context.Context, env *core.Env, request core.TargetedActionRequest) (core.TargetedActionResult, error) {
	result := core.TargetedActionResult{SchemaVersion: "phorvex.targeted-action-result.v1", Coordinator: "d-phorvex-installed", StartedAtUTC: time.Now().UTC().Format(time.RFC3339Nano), Disposition: "unknown", TargetName: request.TargetName, TargetUID: request.TargetUID, TargetResourceVersion: request.TargetResourceVersion, RequestedGraceSeconds: request.RequestedGraceSeconds}
	finish := func(disposition string, complete bool) core.TargetedActionResult {
		result.Disposition, result.AttributionComplete, result.EndedAtUTC = disposition, complete, time.Now().UTC().Format(time.RFC3339Nano)
		return result
	}
	if err := validateInstalledTargetRequest(ctx, env, request); err != nil {
		return finish("invalid-request", false), err
	}
	if err := validateInstalledManagerRuntime(ctx, env); err != nil {
		return finish("refused", false), err
	}
	labelled, err := labelInstalledTarget(ctx, env, request)
	if labelled != nil && labelled.UID != "" {
		p.rememberTarget(labelled)
	}
	if err != nil {
		return finish("refused", false), err
	}
	result.TargetResourceVersion = labelled.ResourceVersion
	roleUID, bindingUID, err := createInstalledEvictionRBAC(ctx, env, request.TargetName, request.TargetUID)
	p.mu.Lock()
	p.roleUID, p.roleBindingUID = roleUID, bindingUID
	p.mu.Unlock()
	if err != nil {
		return finish("refused", false), err
	}
	if err := verifyInstalledEvictionRBAC(ctx, env, request.TargetName); err != nil {
		return finish("refused", false), err
	}
	result.AuthorizationReceiptJSON, err = installedAuthorizationReceipt(env, request, roleUID, bindingUID)
	if err != nil {
		return finish("unknown", false), err
	}
	cursor, err := runInstalledObserverCursor(ctx, env.Config.InstalledManagerFixture)
	if err != nil {
		return finish("unknown", false), err
	}
	controlStarted := time.Now().UTC()
	policy, err := createInstalledPolicy(ctx, env, installedControlPolicyName, 2)
	if policy != nil && policy.GetUID() != "" {
		p.rememberControlPolicy(policy, labelled)
	}
	if err != nil {
		return finish("refused", false), err
	}
	if _, err := waitInstalledPolicyTick(ctx, env, installedControlPolicyName, p.controlPolicyUID, policy.GetGeneration(), controlStarted, installedControlWindow); err != nil {
		return finish("unknown", false), err
	}
	if err := waitUntil(ctx, controlStarted.Add(installedControlWindow)); err != nil {
		return finish("unknown", false), err
	}
	control, err := runInstalledObserver(ctx, env.Config.InstalledManagerFixture, cursor, installedObserveRequest{Namespace: env.Config.Namespace, PolicyName: installedControlPolicyName, PolicyUID: string(p.controlPolicyUID), PolicyGeneration: policy.GetGeneration(), TargetName: request.TargetName, TargetUID: request.TargetUID, NotBefore: controlStarted, NotAfter: time.Now().UTC()})
	result.ControlReceiptJSON = control.raw
	if err != nil || !control.safeAvailabilityRefusal() {
		return finish("unknown", false), errors.Join(err, errors.New("installed manager did not produce an exact availability-floor refusal"))
	}
	if err := deleteInstalledPolicy(ctx, env, installedControlPolicyName, p.controlPolicyUID); err != nil {
		return finish("unknown", false), fmt.Errorf("retire exact control policy before eligible phase: %w", err)
	}
	pdbRV, err := transitionTargetAvailabilityGuard(ctx, env, request)
	if err != nil {
		return finish("refused", false), fmt.Errorf("transition exact native availability floor before eligible phase: %w", err)
	}
	result.AvailabilityPolicyResourceVersion = pdbRV
	eligibleCursor, err := runInstalledObserverCursor(ctx, env.Config.InstalledManagerFixture)
	if err != nil {
		return finish("unknown", false), err
	}
	eligibleStarted := time.Now().UTC()
	policy, err = createInstalledPolicy(ctx, env, installedEligiblePolicyName, 1)
	if policy != nil && policy.GetUID() != "" {
		p.mu.Lock()
		p.policyUID, p.policyGeneration = policy.GetUID(), policy.GetGeneration()
		p.mu.Unlock()
	}
	if err != nil {
		return finish("refused", false), err
	}
	if _, err := waitInstalledPolicyTick(ctx, env, installedEligiblePolicyName, p.policyUID, policy.GetGeneration(), eligibleStarted, installedEligibleWindow); err != nil {
		return finish("unknown", false), err
	}
	if err := waitUntil(ctx, eligibleStarted.Add(installedEligibleWindow)); err != nil {
		return finish("unknown", false), err
	}
	eligible, err := runInstalledObserver(ctx, env.Config.InstalledManagerFixture, eligibleCursor, installedObserveRequest{Namespace: env.Config.Namespace, PolicyName: installedEligiblePolicyName, PolicyUID: string(p.policyUID), PolicyGeneration: policy.GetGeneration(), TargetName: request.TargetName, TargetUID: request.TargetUID, TargetRV: labelled.ResourceVersion, ExpectedGrace: &request.RequestedGraceSeconds, AllowedObject: "Pod/" + env.Config.Namespace + "/" + request.TargetName, NotBefore: eligibleStarted, NotAfter: time.Now().UTC()})
	result.EligibleReceiptJSON = eligible.raw
	if err != nil || len(eligible.receipts) == 0 {
		return finish("unknown", false), errors.Join(err, errors.New("installed manager eligible observation has no attributed decision"))
	}
	disposition, actionAt, classifyErr := eligible.disposition()
	if classifyErr != nil {
		return finish("unknown", false), classifyErr
	}
	if actionAt != nil {
		result.ActionAtUTC = actionAt.UTC().Format(time.RFC3339Nano)
		p.mu.Lock()
		p.actionAt, p.actionCount = *actionAt, 1
		p.mu.Unlock()
	}
	if _, dryErr := updateInstalledPolicy(ctx, env, installedEligiblePolicyName, p.policyUID, policy.GetGeneration(), 1, "dryRun"); dryErr != nil {
		return finish("unknown", false), fmt.Errorf("set installed policy dry-run after observation: %w", dryErr)
	}
	return finish(disposition, true), nil
}

func (p *installedPhorvex) rememberTarget(target *corev1.Pod) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targetName, p.targetUID, p.targetRV = target.Name, target.UID, target.ResourceVersion
}

func (p *installedPhorvex) rememberControlPolicy(policy *unstructured.Unstructured, target *corev1.Pod) {
	p.rememberTarget(target)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.controlPolicyUID = policy.GetUID()
}

func (p *installedPhorvex) DefensiveActions(context.Context, *core.Env) (int, []float64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.actionCount == 0 {
		return 0, nil, nil
	}
	return 1, []float64{float64(p.actionAt.UnixNano()) / float64(time.Second)}, nil
}

func (p *installedPhorvex) Stop(ctx context.Context, env *core.Env) error {
	p.mu.Lock()
	uid, generation := p.policyUID, p.policyGeneration
	p.mu.Unlock()
	if uid == "" || env.Ctrl == nil {
		return nil
	}
	policy, err := getInstalledPolicy(ctx, env, installedEligiblePolicyName)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil || policy.GetUID() != uid {
		return errors.Join(err, errors.New("installed policy identity changed before stop"))
	}
	mode, _, _ := unstructured.NestedString(policy.Object, "spec", "mode")
	if mode == "dryRun" {
		return nil
	}
	_, err = updateInstalledPolicy(ctx, env, installedEligiblePolicyName, uid, generation, 1, "dryRun")
	return err
}

func (p *installedPhorvex) Teardown(ctx context.Context, env *core.Env) error {
	p.mu.Lock()
	skip := p.skip
	controlUID, uid, roleUID, roleBindingUID, targetName, targetUID := p.controlPolicyUID, p.policyUID, p.roleUID, p.roleBindingUID, p.targetName, p.targetUID
	p.mu.Unlock()
	if skip && controlUID == "" && uid == "" && roleUID == "" && roleBindingUID == "" && targetUID == "" {
		return nil
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	var problems []error
	if env.Ctrl != nil {
		for _, owned := range []struct {
			name string
			uid  types.UID
		}{{installedControlPolicyName, controlUID}, {installedEligiblePolicyName, uid}} {
			if owned.uid == "" {
				continue
			}
			if err := deleteInstalledPolicy(ctx, env, owned.name, owned.uid); err != nil {
				problems = append(problems, err)
			}
		}
	}
	// The fixture-only grant is retired after both policies, so no installed
	// manager reconciliation can race a new eviction authorization during
	// cleanup. UID preconditions refuse same-name replacements.
	for _, owned := range []struct {
		kind string
		name string
		uid  types.UID
	}{{"RoleBinding", installedEvictionRoleName, roleBindingUID}, {"Role", installedEvictionRoleName, roleUID}} {
		if owned.uid == "" {
			continue
		}
		options := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &owned.uid}}
		var err error
		if owned.kind == "RoleBinding" {
			err = env.Kube.RbacV1().RoleBindings(env.Config.Namespace).Delete(ctx, owned.name, options)
		} else {
			err = env.Kube.RbacV1().Roles(env.Config.Namespace).Delete(ctx, owned.name, options)
		}
		if err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, fmt.Errorf("delete installed fixture %s: %w", owned.kind, err))
			continue
		}
		if err := verifyInstalledRBACAbsent(ctx, env, owned.kind, owned.name, owned.uid); err != nil {
			problems = append(problems, err)
		}
	}
	if targetName != "" && targetUID != "" {
		pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, targetName, metav1.GetOptions{})
		if err == nil && pod.UID == targetUID && pod.Labels[RotationTargetLabel] == "true" {
			updated := pod.DeepCopy()
			delete(updated.Labels, RotationTargetLabel)
			updated, err = env.Kube.CoreV1().Pods(env.Config.Namespace).Update(ctx, updated, metav1.UpdateOptions{})
			if err != nil || updated == nil || updated.UID != targetUID || updated.Labels[RotationTargetLabel] != "" {
				problems = append(problems, errors.Join(err, errors.New("installed target-label cleanup returned a different identity")))
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			problems = append(problems, err)
		} else if err == nil && pod.UID != targetUID {
			problems = append(problems, errors.New("refusing target-label cleanup from replacement Pod UID"))
		}
	}
	return errors.Join(problems...)
}

func verifyInstalledRBACAbsent(ctx context.Context, env *core.Env, kind, name string, uid types.UID) error {
	var currentUID types.UID
	var err error
	if kind == "RoleBinding" {
		var current *rbacv1.RoleBinding
		current, err = env.Kube.RbacV1().RoleBindings(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
		if current != nil {
			currentUID = current.UID
		}
	} else {
		var current *rbacv1.Role
		current, err = env.Kube.RbacV1().Roles(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
		if current != nil {
			currentUID = current.UID
		}
	}
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("verify installed fixture %s absence: %w", kind, err)
	}
	if currentUID != uid {
		return fmt.Errorf("installed fixture %s name was reused before cleanup verified absence", kind)
	}
	return fmt.Errorf("installed fixture %s deletion accepted but object remains", kind)
}

func deleteInstalledPolicy(ctx context.Context, env *core.Env, name string, uid types.UID) error {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(phorvexPolicyGVK)
	policy.SetNamespace(env.Config.Namespace)
	policy.SetName(name)
	propagation := metav1.DeletePropagationBackground
	if err := env.Ctrl.Delete(ctx, policy, &client.DeleteOptions{Raw: &metav1.DeleteOptions{PropagationPolicy: &propagation, Preconditions: &metav1.Preconditions{UID: &uid}}}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return waitInstalledPolicyAbsent(ctx, env, name, uid, installedCleanupWait)
}

func waitInstalledPolicyAbsent(ctx context.Context, env *core.Env, name string, uid types.UID, bound time.Duration) error {
	deadline := time.Now().Add(bound)
	for {
		policy, err := getInstalledPolicy(ctx, env, name)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("verify installed policy absence: %w", err)
		}
		if policy.GetUID() != uid {
			return errors.New("installed policy name was reused before cleanup verified absence")
		}
		if time.Now().After(deadline) {
			return errors.New("installed policy deletion did not verify absence within bound")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func validateInstalledTargetRequest(ctx context.Context, env *core.Env, request core.TargetedActionRequest) error {
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineUTC)
	if err != nil || time.Until(deadline) < installedCoordinationMinimum {
		return errors.New("installed target request deadline cannot contain both fixed observation phases")
	}
	if request.Objective != "c2-installed-manager-session" || request.Namespace != env.Config.Namespace || request.TargetKind != "Pod" || request.TargetName == "" || request.TargetUID == "" || request.TargetResourceVersion == "" || request.OwnerKind != "ReplicaSet" || request.OwnerName == "" || request.OwnerUID == "" || request.TargetLabelKey != RotationTargetLabel || request.TargetLabelValue != "true" || request.RequestedGraceSeconds != 30 || request.AvailabilityPolicyName == "" || request.AvailabilityPolicyUID == "" || request.AvailabilityPolicyResourceVersion == "" || request.AvailabilitySelectorKey == "" || request.AvailabilitySelectorValue == "" || request.InitialMinAvailable != 2 || request.EligibleMinAvailable != 1 {
		return errors.New("installed target request identity differs")
	}
	pod, err := env.Kube.CoreV1().Pods(request.Namespace).Get(ctx, request.TargetName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != request.TargetUID || pod.ResourceVersion != request.TargetResourceVersion || pod.DeletionTimestamp != nil || pod.CreationTimestamp.IsZero() || time.Since(pod.CreationTimestamp.Time) < installedTargetMinimumAge || pod.Labels[RotationTargetLabel] != "" || !exactControllerOwner(pod.OwnerReferences, request.OwnerKind, request.OwnerName, types.UID(request.OwnerUID)) {
		return errors.Join(err, errors.New("installed target live identity differs before arming"))
	}
	return nil
}

func labelInstalledTarget(ctx context.Context, env *core.Env, request core.TargetedActionRequest) (*corev1.Pod, error) {
	if err := env.Guard.AssertMutationAllowed(request.Namespace); err != nil {
		return nil, err
	}
	pod, err := env.Kube.CoreV1().Pods(request.Namespace).Get(ctx, request.TargetName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != request.TargetUID || pod.ResourceVersion != request.TargetResourceVersion || pod.Labels[RotationTargetLabel] != "" {
		return nil, errors.Join(err, errors.New("installed target changed before exact label update"))
	}
	updated := pod.DeepCopy()
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	updated.Labels[RotationTargetLabel] = request.TargetLabelValue
	updated, err = env.Kube.CoreV1().Pods(request.Namespace).Update(ctx, updated, metav1.UpdateOptions{})
	if err == nil && updated != nil && updated.UID == pod.UID && updated.ResourceVersion != "" && updated.Labels[RotationTargetLabel] == request.TargetLabelValue {
		return updated, nil
	}
	observed, getErr := env.Kube.CoreV1().Pods(request.Namespace).Get(ctx, request.TargetName, metav1.GetOptions{})
	if getErr == nil && observed.UID == pod.UID && observed.ResourceVersion != "" && observed.DeletionTimestamp == nil && observed.Labels[RotationTargetLabel] == request.TargetLabelValue {
		return observed, errors.Join(err, errors.New("installed target label update outcome was ambiguous; exact Pod retained for cleanup"))
	}
	return updated, errors.Join(err, getErr, errors.New("installed target exact label update failed"))
}

func validateInstalledManagerRuntime(ctx context.Context, env *core.Env) error {
	f := env.Config.InstalledManagerFixture
	if f == nil {
		return errors.New("installed manager fixture absent")
	}
	if err := verifyInstalledObserverFiles(f); err != nil {
		return err
	}
	ns, err := env.Kube.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{})
	if err != nil || ns.DeletionTimestamp != nil {
		return errors.Join(err, errors.New("installed fixture namespace is absent or terminating"))
	}
	if value, present := ns.Annotations["phorvex.ai/dry-run"]; present && !installedFalse(value) {
		return errors.New("installed fixture namespace dry-run brake is engaged or malformed")
	}
	deployment, err := env.Kube.AppsV1().Deployments(f.ManagerNamespace).Get(ctx, f.DeploymentName, metav1.GetOptions{})
	if err != nil || string(deployment.UID) != f.DeploymentUID || deployment.DeletionTimestamp != nil || deployment.Status.ReadyReplicas < 1 || deployment.Status.AvailableReplicas < 1 {
		return errors.Join(err, errors.New("installed manager Deployment pin differs"))
	}
	rs, err := env.Kube.AppsV1().ReplicaSets(f.ManagerNamespace).Get(ctx, f.ReplicaSetName, metav1.GetOptions{})
	if err != nil || string(rs.UID) != f.ReplicaSetUID || !exactControllerOwner(rs.OwnerReferences, "Deployment", f.DeploymentName, types.UID(f.DeploymentUID)) || rs.DeletionTimestamp != nil {
		return errors.Join(err, errors.New("installed manager ReplicaSet pin differs"))
	}
	pod, err := env.Kube.CoreV1().Pods(f.ManagerNamespace).Get(ctx, f.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != f.PodUID || pod.DeletionTimestamp != nil || pod.Spec.ServiceAccountName != f.ManagerServiceAccount || !exactControllerOwner(pod.OwnerReferences, "ReplicaSet", f.ReplicaSetName, types.UID(f.ReplicaSetUID)) || !podIsReady(pod) {
		return errors.Join(err, errors.New("installed manager Pod pin differs"))
	}
	var spec *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == f.ContainerName {
			if spec != nil {
				return errors.New("installed manager Pod repeats the pinned container")
			}
			spec = &pod.Spec.Containers[i]
		}
	}
	var status *corev1.ContainerStatus
	for i := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[i].Name == f.ContainerName {
			status = &pod.Status.ContainerStatuses[i]
		}
	}
	startedAt, _ := time.Parse(time.RFC3339Nano, f.StartedAt)
	if spec == nil || status == nil || spec.Image != f.Image || status.ImageID != f.ImageID || status.RestartCount != f.RestartCount || status.State.Running == nil || !status.State.Running.StartedAt.Time.Equal(startedAt) {
		return errors.New("installed manager container incarnation pin differs")
	}
	crd := &unstructured.Unstructured{}
	crd.SetGroupVersionKind(phorvexPolicyCRDGVK)
	if err := env.Ctrl.Get(ctx, client.ObjectKey{Name: "phorvexpolicies.phorvex.ai"}, crd); err != nil || string(crd.GetUID()) != f.PolicyCRDUID || crd.GetResourceVersion() != f.PolicyCRDResourceVersion {
		return errors.Join(err, errors.New("installed PhorvexPolicy CRD pin differs"))
	}
	return nil
}

func podIsReady(pod *corev1.Pod) bool {
	if pod == nil || pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func installedFalse(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "false", "0", "no":
		return true
	default:
		return false
	}
}

func verifyInstalledObserverFiles(f *config.InstalledManagerFixtureConfig) error {
	info, err := os.Lstat(f.ObserverBinary)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > installedObserverBinaryMax || info.Mode().Perm()&0o111 == 0 {
		return errors.Join(err, errors.New("installed audit observer is not a bounded executable regular file"))
	}
	raw, err := os.ReadFile(f.ObserverBinary)
	if err != nil {
		return fmt.Errorf("read installed audit observer: %w", err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != f.ObserverBinarySHA256 {
		return errors.New("installed audit observer binary hash differs")
	}
	for label, path := range map[string]string{"CA": f.AuditCAFile, "client certificate": f.AuditClientCertFile, "client key": f.AuditClientKeyFile} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > installedObserverCredentialMax {
			return errors.Join(err, fmt.Errorf("installed audit %s is not a regular file", label))
		}
		if label == "client key" && info.Mode().Perm()&0o077 != 0 {
			return errors.New("installed audit client key permissions are not private")
		}
	}
	return nil
}

func requireInstalledPolicyAbsent(ctx context.Context, env *core.Env) error {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(phorvexPolicyListGVK)
	if err := env.Ctrl.List(ctx, list, client.InNamespace(env.Config.Namespace)); err != nil {
		return fmt.Errorf("list installed benchmark policies: %w", err)
	}
	if len(list.Items) != 0 {
		return errors.New("installed benchmark namespace already contains a PhorvexPolicy")
	}
	return nil
}

func requireInstalledEvictionRBACAbsent(ctx context.Context, env *core.Env) error {
	if _, err := env.Kube.RbacV1().Roles(env.Config.Namespace).Get(ctx, installedEvictionRoleName, metav1.GetOptions{}); err == nil || !apierrors.IsNotFound(err) {
		return errors.Join(err, errors.New("installed benchmark eviction Role already exists or absence is unknown"))
	}
	if _, err := env.Kube.RbacV1().RoleBindings(env.Config.Namespace).Get(ctx, installedEvictionRoleName, metav1.GetOptions{}); err == nil || !apierrors.IsNotFound(err) {
		return errors.Join(err, errors.New("installed benchmark eviction RoleBinding already exists or absence is unknown"))
	}
	return nil
}

func installedEvictionRBACLabels(env *core.Env, targetUID string) map[string]string {
	return env.OwnedLabels(map[string]string{
		"fixture.phorvex.ai/suite":      installedPolicySchemaVersion,
		"fixture.phorvex.ai/nonce":      env.Config.InstalledManagerFixture.FixtureNonce,
		"fixture.phorvex.ai/target-uid": targetUID,
	})
}

func createInstalledEvictionRBAC(ctx context.Context, env *core.Env, targetName, targetUID string) (types.UID, types.UID, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return "", "", err
	}
	if err := requireInstalledEvictionRBACAbsent(ctx, env); err != nil {
		return "", "", err
	}
	f := env.Config.InstalledManagerFixture
	labels := installedEvictionRBACLabels(env, targetUID)
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: installedEvictionRoleName, Namespace: env.Config.Namespace, Labels: labels}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/eviction"}, Verbs: []string{"create"}}}}
	createdRole, err := env.Kube.RbacV1().Roles(env.Config.Namespace).Create(ctx, role, metav1.CreateOptions{})
	if err != nil || createdRole == nil || createdRole.UID == "" || !exactInstalledEvictionRole(createdRole, env, targetName, targetUID) {
		if apierrors.IsAlreadyExists(err) {
			return "", "", errors.Join(err, errors.New("refusing to adopt preexisting installed fixture eviction Role"))
		}
		observed, getErr := env.Kube.RbacV1().Roles(env.Config.Namespace).Get(ctx, installedEvictionRoleName, metav1.GetOptions{})
		if getErr == nil && observed.UID != "" && exactInstalledEvictionRole(observed, env, targetName, targetUID) {
			return observed.UID, "", errors.Join(err, errors.New("installed fixture eviction Role create outcome was ambiguous; exact owned object retained for cleanup"))
		}
		return "", "", errors.Join(err, getErr, errors.New("create installed fixture eviction Role returned an invalid identity/shape"))
	}
	binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: installedEvictionRoleName, Namespace: env.Config.Namespace, Labels: cloneInstalledLabels(labels)}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: installedEvictionRoleName}, Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: f.ManagerServiceAccount, Namespace: f.ManagerNamespace}}}
	createdBinding, err := env.Kube.RbacV1().RoleBindings(env.Config.Namespace).Create(ctx, binding, metav1.CreateOptions{})
	if err != nil || createdBinding == nil || createdBinding.UID == "" || !exactInstalledEvictionRoleBinding(createdBinding, env, targetUID) {
		if apierrors.IsAlreadyExists(err) {
			return createdRole.UID, "", errors.Join(err, errors.New("refusing to adopt preexisting installed fixture eviction RoleBinding"))
		}
		observed, getErr := env.Kube.RbacV1().RoleBindings(env.Config.Namespace).Get(ctx, installedEvictionRoleName, metav1.GetOptions{})
		if getErr == nil && observed.UID != "" && exactInstalledEvictionRoleBinding(observed, env, targetUID) {
			return createdRole.UID, observed.UID, errors.Join(err, errors.New("installed fixture eviction RoleBinding create outcome was ambiguous; exact owned object retained for cleanup"))
		}
		return createdRole.UID, "", errors.Join(err, getErr, errors.New("create installed fixture eviction RoleBinding returned an invalid identity/shape"))
	}
	return createdRole.UID, createdBinding.UID, nil
}

func cloneInstalledLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func exactInstalledEvictionRole(role *rbacv1.Role, env *core.Env, targetName, targetUID string) bool {
	return role != nil && role.Name == installedEvictionRoleName && role.Namespace == env.Config.Namespace && role.DeletionTimestamp == nil && mapsEqualInstalled(role.Labels, installedEvictionRBACLabels(env, targetUID)) && len(role.Rules) == 1 && slicesEqualInstalled(role.Rules[0].APIGroups, []string{""}) && slicesEqualInstalled(role.Rules[0].Resources, []string{"pods/eviction"}) && len(role.Rules[0].ResourceNames) == 0 && slicesEqualInstalled(role.Rules[0].Verbs, []string{"create"})
}

func exactInstalledEvictionRoleBinding(binding *rbacv1.RoleBinding, env *core.Env, targetUID string) bool {
	f := env.Config.InstalledManagerFixture
	return binding != nil && binding.Name == installedEvictionRoleName && binding.Namespace == env.Config.Namespace && binding.DeletionTimestamp == nil && mapsEqualInstalled(binding.Labels, installedEvictionRBACLabels(env, targetUID)) && binding.RoleRef == (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: installedEvictionRoleName}) && len(binding.Subjects) == 1 && binding.Subjects[0] == (rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: f.ManagerServiceAccount, Namespace: f.ManagerNamespace})
}

func mapsEqualInstalled(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func slicesEqualInstalled(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func verifyInstalledEvictionRBAC(ctx context.Context, env *core.Env, targetName string) error {
	f := env.Config.InstalledManagerFixture
	user := "system:serviceaccount:" + f.ManagerNamespace + ":" + f.ManagerServiceAccount
	groups := []string{"system:serviceaccounts", "system:serviceaccounts:" + f.ManagerNamespace, "system:authenticated"}
	check := func(namespace, name string) (bool, error) {
		review, err := env.Kube.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: user, Groups: groups, ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: namespace, Verb: "create", Group: "", Version: "v1", Resource: "pods", Subresource: "eviction", Name: name}}}, metav1.CreateOptions{})
		if err != nil || review == nil {
			return false, errors.Join(err, errors.New("installed fixture eviction SubjectAccessReview unavailable"))
		}
		return review.Status.Allowed && !review.Status.Denied, nil
	}
	allowed, err := check(env.Config.Namespace, "")
	if err != nil || !allowed {
		return errors.Join(err, errors.New("installed manager is not authorized for the nameless fixture eviction capability gate"))
	}
	allowed, err = check(env.Config.Namespace, targetName)
	if err != nil || !allowed {
		return errors.Join(err, errors.New("installed manager is not authorized for the named fixture target eviction"))
	}
	allowed, err = check(f.AuthorizationDenyNamespace, "")
	if err != nil || allowed {
		return errors.Join(err, errors.New("installed manager fixture eviction grant reaches the unrelated deny namespace"))
	}
	return nil
}

func installedAuthorizationReceipt(env *core.Env, request core.TargetedActionRequest, roleUID, bindingUID types.UID) (string, error) {
	f := env.Config.InstalledManagerFixture
	receipt := struct {
		SchemaVersion              string   `json:"schemaVersion"`
		Namespace                  string   `json:"namespace"`
		RoleName                   string   `json:"roleName"`
		RoleUID                    string   `json:"roleUID"`
		RoleBindingName            string   `json:"roleBindingName"`
		RoleBindingUID             string   `json:"roleBindingUID"`
		ManagerServiceAccount      string   `json:"managerServiceAccount"`
		ManagerNamespace           string   `json:"managerNamespace"`
		TargetName                 string   `json:"targetName"`
		TargetUID                  string   `json:"targetUID"`
		FixtureNonce               string   `json:"fixtureNonce"`
		AuthorizationDenyNamespace string   `json:"authorizationDenyNamespace"`
		ManagerGroups              []string `json:"managerGroups"`
		NamelessFixtureAllowed     bool     `json:"namelessFixtureAllowed"`
		NamedTargetAllowed         bool     `json:"namedTargetAllowed"`
		UnrelatedNamespaceDenied   bool     `json:"unrelatedNamespaceDenied"`
		GateScope                  string   `json:"gateScope"`
	}{
		SchemaVersion: "phorvex.installed-fixture-authorization.v1", Namespace: env.Config.Namespace,
		RoleName: installedEvictionRoleName, RoleUID: string(roleUID), RoleBindingName: installedEvictionRoleName, RoleBindingUID: string(bindingUID),
		ManagerServiceAccount: f.ManagerServiceAccount, ManagerNamespace: f.ManagerNamespace,
		TargetName: request.TargetName, TargetUID: request.TargetUID, FixtureNonce: f.FixtureNonce,
		AuthorizationDenyNamespace: f.AuthorizationDenyNamespace,
		ManagerGroups:              []string{"system:serviceaccounts", "system:serviceaccounts:" + f.ManagerNamespace, "system:authenticated"},
		NamelessFixtureAllowed:     true, NamedTargetAllowed: true, UnrelatedNamespaceDenied: true,
		GateScope: "namespace-wide core pods/eviction:create is required because the installed capability witness checks the native rotate verb without a resource name; the unique non-inherited policy selector still binds one exact target",
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > 4096 {
		return "", errors.Join(err, errors.New("installed fixture authorization receipt exceeds bound"))
	}
	return string(raw), nil
}

func installedPolicyObject(env *core.Env, name string, minAvailable int, mode string) *unstructured.Unstructured {
	maxMoves := int64(1)
	grace := int64(30)
	policy := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy",
		"metadata": map[string]any{"name": name, "namespace": env.Config.Namespace, "labels": map[string]any{core.OwnedLabelKey: core.OwnedLabelValue, core.ScenarioLabelKey: "c2-installed-manager-session", core.TrialLabelKey: strconv.Itoa(env.Trial), "fixture.phorvex.ai/suite": installedPolicySchemaVersion, "fixture.phorvex.ai/nonce": env.Config.InstalledManagerFixture.FixtureNonce}},
		"spec": map[string]any{
			"tenant":     env.Config.Namespace,
			"selector":   map[string]any{"matchLabels": map[string]any{RotationTargetLabel: "true"}},
			"objective":  map[string]any{"disruptionAversion": "0.6", "costWeights": map[string]any{"normSparsity": "0.4", "flowDisruption": "0.6"}},
			"budget":     map[string]any{"maxMovesPerTick": maxMoves, "maxGracePeriodSeconds": grace, "tickInterval": installedPolicyTick.String(), "antiOverRotationWindow": "90s", "proactiveFloor": "1s"},
			"slo":        map[string]any{"minAvailableReplicas": int64(minAvailable)},
			"assetValue": map[string]any{"weightSecrets": "0.8", "blastRadiusFromGraph": false},
			"triggers":   map[string]any{"eventDriven": false, "reactiveOnly": false},
			"actions":    map[string]any{"enabled": []any{"rotate"}},
			"mode":       mode,
		},
	}}
	policy.SetGroupVersionKind(phorvexPolicyGVK)
	return policy
}

func createInstalledPolicy(ctx context.Context, env *core.Env, name string, minAvailable int) (*unstructured.Unstructured, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	if err := requireInstalledPolicyAbsent(ctx, env); err != nil {
		return nil, err
	}
	policy := installedPolicyObject(env, name, minAvailable, "active")
	err := env.Ctrl.Create(ctx, policy)
	if err == nil && exactInstalledPolicyIdentity(policy, installedPolicyObject(env, name, minAvailable, "active")) {
		return policy, nil
	}
	if apierrors.IsAlreadyExists(err) {
		return nil, errors.Join(err, errors.New("refusing to adopt preexisting installed benchmark policy"))
	}
	// A transport failure or incomplete create response can leave an object in
	// the API. Bind only the exact nonce-labelled request for cleanup and retain
	// the create as an error; it never becomes a successful phase.
	observed, getErr := getInstalledPolicy(ctx, env, name)
	if getErr == nil && exactInstalledPolicyIdentity(observed, installedPolicyObject(env, name, minAvailable, "active")) {
		return observed, errors.Join(err, errors.New("installed benchmark policy create outcome was ambiguous; exact owned object retained for cleanup"))
	}
	return policy, errors.Join(err, getErr, errors.New("create installed benchmark policy returned incomplete identity"))
}

func exactInstalledPolicyIdentity(observed, expected *unstructured.Unstructured) bool {
	if observed == nil || expected == nil || observed.GetName() != expected.GetName() || observed.GetNamespace() != expected.GetNamespace() || observed.GetUID() == "" || observed.GetGeneration() < 1 || observed.GetDeletionTimestamp() != nil || !mapsEqualInstalled(observed.GetLabels(), expected.GetLabels()) {
		return false
	}
	observedSpec, foundObserved, errObserved := unstructured.NestedMap(observed.Object, "spec")
	expectedSpec, foundExpected, errExpected := unstructured.NestedMap(expected.Object, "spec")
	if errObserved != nil || errExpected != nil || !foundObserved || !foundExpected {
		return false
	}
	if reflect.DeepEqual(observedSpec, expectedSpec) {
		return true
	}
	// The current CRD applies exactly these defaults inside objects which this
	// fixture already supplies. Accept their admitted representation, while
	// refusing any other default, pruning, or mutation of the requested spec.
	admitted := cloneInstalledAnyMap(expectedSpec)
	slo, ok := admitted["slo"].(map[string]any)
	if !ok {
		return false
	}
	slo["costCeiling"] = "1.2"
	triggers, ok := admitted["triggers"].(map[string]any)
	if !ok {
		return false
	}
	triggers["eventAgeHorizon"] = "1h"
	return reflect.DeepEqual(observedSpec, admitted)
}

func cloneInstalledAnyMap(in map[string]any) map[string]any {
	return runtime.DeepCopyJSONValue(in).(map[string]any)
}

func getInstalledPolicy(ctx context.Context, env *core.Env, name string) (*unstructured.Unstructured, error) {
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(phorvexPolicyGVK)
	err := env.Ctrl.Get(ctx, client.ObjectKey{Namespace: env.Config.Namespace, Name: name}, policy)
	return policy, err
}

func updateInstalledPolicy(ctx context.Context, env *core.Env, name string, uid types.UID, generation int64, minAvailable int, mode string) (*unstructured.Unstructured, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return nil, err
	}
	policy, err := getInstalledPolicy(ctx, env, name)
	if err != nil || policy.GetUID() != uid || policy.GetGeneration() != generation || policy.GetDeletionTimestamp() != nil {
		return nil, errors.Join(err, errors.New("installed policy identity/generation changed before update"))
	}
	if err := unstructured.SetNestedField(policy.Object, int64(minAvailable), "spec", "slo", "minAvailableReplicas"); err != nil {
		return nil, err
	}
	if err := unstructured.SetNestedField(policy.Object, mode, "spec", "mode"); err != nil {
		return nil, err
	}
	expected := installedPolicyObject(env, name, minAvailable, mode)
	if err := env.Ctrl.Update(ctx, policy); err != nil || policy.GetUID() != uid || policy.GetGeneration() <= generation || !exactInstalledPolicyIdentity(policy, expected) {
		return nil, errors.Join(err, errors.New("installed policy update did not advance exact generation"))
	}
	return policy, nil
}

func waitInstalledPolicyTick(ctx context.Context, env *core.Env, name string, uid types.UID, generation int64, after time.Time, bound time.Duration) (*unstructured.Unstructured, error) {
	deadline := time.Now().Add(bound)
	for {
		policy, err := getInstalledPolicy(ctx, env, name)
		if err == nil && policy.GetUID() == uid && policy.GetGeneration() == generation {
			observed, foundObserved, _ := unstructured.NestedInt64(policy.Object, "status", "observedGeneration")
			selected, foundSelected, _ := unstructured.NestedInt64(policy.Object, "status", "selectedPods")
			kill, foundKill, _ := unstructured.NestedBool(policy.Object, "status", "killSwitchEngaged")
			lastTick, foundTick, _ := unstructured.NestedString(policy.Object, "status", "lastTickTime")
			tickAt, tickErr := time.Parse(time.RFC3339Nano, lastTick)
			if foundObserved && observed == generation && foundSelected && selected == 1 && foundKill && !kill && foundTick && tickErr == nil && !tickAt.Before(after) {
				return policy, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, errors.New("installed policy did not report an exact healthy generation-bound tick")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func waitUntil(ctx context.Context, at time.Time) error {
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type installedAuditActionDisposition struct {
	Action              string                             `json:"action"`
	Status              string                             `json:"status"`
	ExclusionKind       string                             `json:"exclusionKind,omitempty"`
	AvailabilityRefusal *installedAuditAvailabilityRefusal `json:"availabilityRefusal,omitempty"`
}
type installedAuditAvailabilityRefusal struct {
	Ready        int `json:"ready"`
	Removed      int `json:"removed"`
	MinAvailable int `json:"minAvailable"`
}
type installedAuditGrace struct {
	PolicyGeneration            int64  `json:"policyGeneration"`
	PolicyGraceCapSeconds       int64  `json:"policyGraceCapSeconds"`
	WorkloadGraceSeconds        int64  `json:"workloadGraceSeconds"`
	WorkloadGraceExplicit       bool   `json:"workloadGraceExplicit"`
	EffectiveGracePeriodSeconds int64  `json:"effectiveGracePeriodSeconds"`
	PodResourceVersion          string `json:"podResourceVersion"`
	TerminationStatus           string `json:"terminationStatus"`
}
type installedAuditReceipt struct {
	SchemaVersion string    `json:"schemaVersion"`
	DecisionTime  time.Time `json:"decisionTime"`
	DecisionID    string    `json:"decisionID"`
	TickID        string    `json:"tickID"`
	Policy        struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		UID        string `json:"uid"`
		Generation int64  `json:"generation"`
	} `json:"policy"`
	Target struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		UID       string `json:"uid"`
	} `json:"target"`
	TraceSchema      string `json:"traceSchema"`
	BrainImageSHA256 string `json:"brainImageSHA256"`
	GitSHA           string `json:"gitSHA"`
	ParameterEpoch   struct {
		SchemaVersion       string `json:"schemaVersion"`
		ManifestID          string `json:"manifestID"`
		ManifestHash        string `json:"manifestHash"`
		PolicyOverridesID   string `json:"policyOverridesID"`
		PolicyOverridesHash string `json:"policyOverridesHash"`
	} `json:"parameterEpoch"`
	Action              string                           `json:"action"`
	Selected            bool                             `json:"selected"`
	Feasible            bool                             `json:"feasible"`
	DryRun              bool                             `json:"dryRun"`
	Actuated            bool                             `json:"actuated"`
	DispatchOutcome     string                           `json:"dispatchOutcome"`
	ActionDisposition   *installedAuditActionDisposition `json:"actionDisposition,omitempty"`
	Handler             string                           `json:"handler,omitempty"`
	MutationKind        string                           `json:"mutationKind,omitempty"`
	ObjectsTouched      []string                         `json:"objectsTouched,omitempty"`
	GracefulTermination *installedAuditGrace             `json:"gracefulTermination,omitempty"`
	RawSHA256           string                           `json:"rawSHA256"`
	SourceRanges        []struct {
		SegmentID  string `json:"segmentID"`
		Generation string `json:"generation"`
		Anchor     string `json:"anchor"`
		PinnedSize int64  `json:"pinnedSize"`
		Start      int64  `json:"start"`
		End        int64  `json:"end"`
		SHA256     string `json:"sha256"`
	} `json:"sourceRanges"`
}
type installedAuditSummary struct {
	SchemaVersion string    `json:"schemaVersion"`
	Status        string    `json:"status"`
	Attribution   string    `json:"attribution"`
	StartedAt     time.Time `json:"startedAt"`
	CompletedAt   time.Time `json:"completedAt"`
	NotBefore     time.Time `json:"notBefore"`
	NotAfter      time.Time `json:"notAfter"`
	BytesRead     int64     `json:"bytesRead"`
	RowsRead      int       `json:"rowsRead"`
	Receipts      int       `json:"receipts"`
	ErrorClass    string    `json:"errorClass,omitempty"`
}
type installedObservation struct {
	receipts []installedAuditReceipt
	summary  installedAuditSummary
	raw      string
}
type installedObserveRequest struct {
	Namespace, PolicyName, PolicyUID               string
	PolicyGeneration                               int64
	TargetName, TargetUID, TargetRV, AllowedObject string
	ExpectedGrace                                  *int64
	NotBefore, NotAfter                            time.Time
}

func observerTransportArgs(f *config.InstalledManagerFixtureConfig) []string {
	return []string{"--url=" + f.AuditURL, "--server-name=" + f.AuditServerName, "--ca-file=" + f.AuditCAFile, "--client-cert-file=" + f.AuditClientCertFile, "--client-key-file=" + f.AuditClientKeyFile, "--output=-", "--timeout=" + strconv.Itoa(f.ObservationTimeoutSeconds) + "s"}
}

func runInstalledObserverCursor(ctx context.Context, f *config.InstalledManagerFixtureConfig) ([]byte, error) {
	if err := verifyInstalledObserverFiles(f); err != nil {
		return nil, err
	}
	args := append([]string{"--mode=cursor"}, observerTransportArgs(f)...)
	out, errOut, err := runBoundedObserver(ctx, f.ObserverBinary, args)
	if err != nil {
		return nil, fmt.Errorf("capture installed audit cursor: %w (%s)", err, errOut)
	}
	if err := rejectDuplicateJSONKeys(out); err != nil {
		return nil, err
	}
	var cursor struct {
		SchemaVersion string    `json:"schemaVersion"`
		CapturedAt    time.Time `json:"capturedAt"`
		Segment       struct {
			ID, Generation, Anchor string
			Size                   int64
		} `json:"segment"`
		Offset int64 `json:"offset"`
	}
	if err := decodeStrictJSON(out, &cursor); err != nil || cursor.SchemaVersion != "phorvex.installed-audit-cursor.v1" || cursor.CapturedAt.IsZero() || cursor.Segment.ID != "live" || cursor.Segment.Generation == "" || cursor.Segment.Anchor == "" || cursor.Offset != cursor.Segment.Size || cursor.Offset < 0 {
		return nil, errors.Join(err, errors.New("installed audit cursor receipt invalid"))
	}
	return out, nil
}

func runInstalledObserver(ctx context.Context, f *config.InstalledManagerFixtureConfig, cursor []byte, request installedObserveRequest) (installedObservation, error) {
	var observation installedObservation
	dir, err := os.MkdirTemp("", "phorvex-installed-cursor-")
	if err != nil {
		return observation, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return observation, err
	}
	cursorPath := filepath.Join(dir, "cursor.json")
	if err := os.WriteFile(cursorPath, cursor, 0o600); err != nil {
		return observation, err
	}
	args := []string{"--mode=observe", "--cursor-file=" + cursorPath, "--policy-namespace=" + request.Namespace, "--policy-name=" + request.PolicyName, "--policy-uid=" + request.PolicyUID, "--policy-generation=" + strconv.FormatInt(request.PolicyGeneration, 10), "--target-namespace=" + request.Namespace, "--target-name=" + request.TargetName, "--target-uid=" + request.TargetUID, "--trace-schema=" + f.TraceSchema, "--brain-image=" + f.ExpectedBrainImage, "--git-sha=" + f.OCIRevision, "--parameter-manifest-id=" + f.ParameterManifestID, "--parameter-manifest-hash=" + f.ParameterManifestHash, "--not-before=" + request.NotBefore.Format(time.RFC3339Nano), "--not-after=" + request.NotAfter.Format(time.RFC3339Nano), "--max-bytes=" + strconv.FormatInt(f.ObservationMaxBytes, 10), "--max-rows=" + strconv.Itoa(f.ObservationMaxRows)}
	if request.ExpectedGrace != nil {
		args = append(args, "--target-resource-version="+request.TargetRV, "--expected-grace-seconds="+strconv.FormatInt(*request.ExpectedGrace, 10), "--allowed-object="+request.AllowedObject)
	}
	args = append(args, observerTransportArgs(f)...)
	out, errOut, runErr := runBoundedObserver(ctx, f.ObserverBinary, args)
	observation, parseErr := parseInstalledObservation(out)
	validationErr := validateInstalledObservation(f, request, observation)
	return observation, errors.Join(runErr, parseErr, validationErr, func() error {
		if runErr != nil {
			return fmt.Errorf("installed observer stderr: %s", errOut)
		}
		return nil
	}())
}

func validateInstalledObservation(f *config.InstalledManagerFixtureConfig, request installedObserveRequest, observation installedObservation) error {
	if observation.summary.SchemaVersion == "" {
		return nil // parsing already reports the missing summary while retaining any partial bytes
	}
	wantAttribution := "unavailable"
	if len(observation.receipts) > 0 {
		wantAttribution = "observed"
	}
	if observation.summary.NotBefore != request.NotBefore || observation.summary.NotAfter != request.NotAfter || observation.summary.Attribution != wantAttribution || observation.summary.BytesRead < 0 || observation.summary.RowsRead < len(observation.receipts) {
		return errors.New("installed observer summary window/count attribution differs")
	}
	imageSum := sha256.Sum256([]byte(f.ExpectedBrainImage))
	wantImageHash := "sha256:" + hex.EncodeToString(imageSum[:])
	wantOverridesID := fmt.Sprintf("%s/%s@%s:%d", request.Namespace, request.PolicyName, request.PolicyUID, request.PolicyGeneration)
	for _, receipt := range observation.receipts {
		if receipt.SchemaVersion != "phorvex.installed-audit-receipt.v1" || receipt.DecisionID == "" || receipt.TickID == "" || receipt.DecisionTime.Before(request.NotBefore) || receipt.DecisionTime.After(request.NotAfter) ||
			receipt.Policy.Namespace != request.Namespace || receipt.Policy.Name != request.PolicyName || receipt.Policy.UID != request.PolicyUID || receipt.Policy.Generation != request.PolicyGeneration ||
			receipt.Target.Namespace != request.Namespace || receipt.Target.Name != request.TargetName || receipt.Target.UID != request.TargetUID || receipt.TraceSchema != f.TraceSchema || receipt.BrainImageSHA256 != wantImageHash || receipt.GitSHA != f.OCIRevision ||
			receipt.ParameterEpoch.SchemaVersion != "phorvex.decision-parameter-set.v1" || receipt.ParameterEpoch.ManifestID != f.ParameterManifestID || receipt.ParameterEpoch.ManifestHash != f.ParameterManifestHash || receipt.ParameterEpoch.PolicyOverridesID != wantOverridesID || !installedDigest(receipt.ParameterEpoch.PolicyOverridesHash) || !installedDigest(receipt.RawSHA256) || len(receipt.SourceRanges) == 0 {
			return errors.New("installed observer receipt identity/source/parameter epoch differs")
		}
		for _, sourceRange := range receipt.SourceRanges {
			if sourceRange.SegmentID == "" || sourceRange.Generation == "" || sourceRange.Anchor == "" || sourceRange.Start < 0 || sourceRange.End <= sourceRange.Start || sourceRange.End > sourceRange.PinnedSize || !installedDigest(sourceRange.SHA256) {
				return errors.New("installed observer source range invalid")
			}
		}
		if receipt.DispatchOutcome == "emitted" {
			if request.ExpectedGrace == nil || receipt.GracefulTermination == nil || receipt.GracefulTermination.PolicyGeneration != request.PolicyGeneration || receipt.GracefulTermination.PodResourceVersion != request.TargetRV || receipt.GracefulTermination.EffectiveGracePeriodSeconds != *request.ExpectedGrace || receipt.GracefulTermination.TerminationStatus != "unconfirmed" || len(receipt.ObjectsTouched) != 1 || receipt.ObjectsTouched[0] != request.AllowedObject {
				return errors.New("installed emitted receipt target RV/grace/object differs")
			}
		}
	}
	return nil
}

func installedDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func runBoundedObserver(ctx context.Context, binary string, args []string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	stdout := &installedBoundedBuffer{limit: installedObserverMaxOutput}
	stderr := &installedBoundedBuffer{limit: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return nil, "output-bound-exceeded", errors.New("installed observer output exceeded bound")
	}
	return stdout.Bytes(), strings.TrimSpace(stderr.String()), err
}

// installedBoundedBuffer prevents an independently configured observer process
// from allocating unbounded harness memory before its output is validated. The
// first over-limit write is retained only up to the declared cap and refused.
type installedBoundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *installedBoundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return 0, errors.New("installed observer output bound exceeded")
	}
	if len(p) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		b.exceeded = true
		return remaining, errors.New("installed observer output bound exceeded")
	}
	return b.Buffer.Write(p)
}

func parseInstalledObservation(raw []byte) (installedObservation, error) {
	var out installedObservation
	if len(raw) == 0 || len(raw) > installedObserverMaxOutput {
		return out, errors.New("installed observer receipt size invalid")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 48*1024)
	var canonicalReceipts []installedAuditReceipt
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if err := rejectDuplicateJSONKeys(line); err != nil {
			return out, err
		}
		var head struct {
			SchemaVersion string `json:"schemaVersion"`
		}
		if err := json.Unmarshal(line, &head); err != nil {
			return out, err
		}
		switch head.SchemaVersion {
		case "phorvex.installed-audit-receipt.v1":
			var receipt installedAuditReceipt
			if err := decodeStrictJSON(line, &receipt); err != nil {
				return out, err
			}
			canonicalReceipts = append(canonicalReceipts, receipt)
		case "phorvex.installed-audit-summary.v1":
			if out.summary.SchemaVersion != "" {
				return out, errors.New("installed observer repeated summary")
			}
			if err := decodeStrictJSON(line, &out.summary); err != nil {
				return out, err
			}
		default:
			return out, errors.New("installed observer emitted unknown schema")
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	out.receipts = canonicalReceipts
	if out.summary.SchemaVersion == "" || out.summary.Receipts != len(out.receipts) {
		return out, errors.New("installed observer summary missing or contradictory")
	}
	wrapper, err := json.Marshal(struct {
		SchemaVersion string                  `json:"schemaVersion"`
		Receipts      []installedAuditReceipt `json:"receipts"`
		Summary       installedAuditSummary   `json:"summary"`
	}{"phorvex.installed-audit-phase.v1", out.receipts, out.summary})
	if err != nil || len(wrapper) > 32*1024 {
		return out, errors.Join(err, errors.New("installed audit phase receipt exceeds bound"))
	}
	out.raw = string(wrapper)
	if out.summary.Status != "complete" || out.summary.ErrorClass != "" {
		return out, errors.New("installed observer summary is not complete")
	}
	return out, nil
}

func (o installedObservation) safeAvailabilityRefusal() bool {
	if len(o.receipts) == 0 {
		return false
	}
	for _, receipt := range o.receipts {
		if receipt.Action != "noop" || receipt.DispatchOutcome != "not-attempted" || receipt.Actuated || receipt.ActionDisposition == nil || receipt.ActionDisposition.Action != "rotate" || receipt.ActionDisposition.Status != "infeasible" || receipt.ActionDisposition.ExclusionKind != "feasibility" || receipt.ActionDisposition.AvailabilityRefusal == nil || receipt.ActionDisposition.AvailabilityRefusal.Ready != 2 || receipt.ActionDisposition.AvailabilityRefusal.Removed != 1 || receipt.ActionDisposition.AvailabilityRefusal.MinAvailable != 2 {
			return false
		}
	}
	return true
}

func (o installedObservation) disposition() (string, *time.Time, error) {
	if len(o.receipts) == 0 {
		return "unknown", nil, errors.New("installed eligible phase contains no decisions")
	}
	var emitted *installedAuditReceipt
	refused := false
	noAction := false
	for i := range o.receipts {
		receipt := o.receipts[i]
		if receipt.DispatchOutcome == "emitted" || receipt.Actuated {
			if receipt.DispatchOutcome != "emitted" || receipt.Action != "rotate" || !receipt.Actuated || receipt.Handler != "rotate" || receipt.GracefulTermination == nil || len(receipt.ObjectsTouched) != 1 {
				return "unknown", nil, errors.New("installed eligible emitted decision is contradictory")
			}
			if emitted != nil {
				return "unknown", nil, errors.New("installed eligible phase emitted more than one target mutation")
			}
			emitted = &o.receipts[i]
			continue
		}
		if receipt.DispatchOutcome == "not-attempted" && receipt.Action == "noop" && !receipt.Actuated {
			noAction = true
			continue
		}
		if installedStringIn(receipt.DispatchOutcome, "refused-no-effect", "already-satisfied", "reconciled-no-new-mutation") && !receipt.Actuated {
			refused = true
			continue
		}
		return "unknown", nil, errors.New("installed eligible phase contains a failed, ambiguous, or unsupported dispatch attempt")
	}
	if emitted != nil {
		at := emitted.DecisionTime
		return "dispatched-unconfirmed", &at, nil
	}
	if refused {
		return "refused", nil, nil
	}
	if noAction {
		return "no-action", nil, nil
	}
	return "unknown", nil, errors.New("installed eligible decision disposition is contradictory or unsupported")
}

func installedStringIn(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func decodeStrictJSON(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("installed observer JSON has trailing data")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("installed observer JSON has duplicate object field")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return errors.New("installed observer JSON delimiter invalid")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("installed observer JSON trailing value")
	}
	return nil
}
