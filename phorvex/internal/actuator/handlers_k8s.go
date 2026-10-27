/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * The 7 native K8s ActionHandlers — Phorvex's own hands on a Kubernetes cluster, authored
 * from the published k8s.io API contract (clean-room, ZERO Phoenix imports). Each is one
 * struct + one init()->Register; the completeness invariant proves none is missing.
 */

package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/ownership"
)

var errPodTerminating = errors.New("actuator target Pod is terminating")

// getPod fetches a target that is still eligible for a new effect. It returns
// (nil,false,nil) if already gone, preserving callers' idempotent NotFound handling, but
// refuses an existing Pod whose deletion has started. The check prevents effects based on
// an object already committed to removal; callers must still use their existing identity
// and concurrency guards because deletion can begin after this read.
func getPod(ctx context.Context, c client.Reader, ns, name string) (*corev1.Pod, bool, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if pod.DeletionTimestamp != nil && !pod.DeletionTimestamp.IsZero() {
		return nil, false, fmt.Errorf("%w: %s/%s; refusing to start a new effect", errPodTerminating, ns, name)
	}
	return &pod, true, nil
}

func objRef(kind, ns, name string) string { return fmt.Sprintf("%s/%s/%s", kind, ns, name) }

// --- 1. rotate (native Eviction admission request; replacement unconfirmed) ----------------------

type rotateHandler struct{}

const defaultWorkloadGracePeriodSeconds int64 = 30

func (rotateHandler) Name() string { return string(model.ActionRotate) }

func (rotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	refuse := func(reason string) (HandlerResult, error) {
		disposition := NoEffectRefused
		if reason == "target-already-gone" {
			disposition = NoEffectSatisfied
		}
		return HandlerResult{NoEffect: disposition, Note: "Rotation not performed: " + reason}, nil
	}
	if ec.Reader == nil {
		return refuse("authoritative-reader-unavailable")
	}
	if ec.Client == nil {
		return refuse("mutation-client-unavailable")
	}
	if req.TargetUID == "" {
		return refuse("target-uid-unavailable")
	}
	if req.PolicyName == "" || req.PolicyUID == "" {
		return refuse("selecting-policy-identity-unavailable")
	}
	if req.MaxGracePeriodSeconds < 1 || req.MaxGracePeriodSeconds > 300 {
		return refuse("selecting-policy-grace-cap-invalid")
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return refuse("target-already-gone")
		}
		return refuse("target-unavailable")
	}
	if string(pod.UID) != req.TargetUID {
		return refuse("target-uid-mismatch")
	}
	verdict := ownership.Check(ctx, ec.Reader, pod)
	if !verdict.Eligible {
		return refuse(verdict.Reason)
	}
	uid, rv := pod.UID, pod.ResourceVersion
	if rv == "" {
		return refuse("target-version-unavailable")
	}
	workloadGrace, workloadGraceExplicit := defaultWorkloadGracePeriodSeconds, false
	if pod.Spec.TerminationGracePeriodSeconds != nil {
		workloadGrace, workloadGraceExplicit = *pod.Spec.TerminationGracePeriodSeconds, true
	}
	if workloadGrace < 0 {
		return refuse("target-grace-period-invalid")
	}

	// This is deliberately the final authoritative read before the Eviction. The
	// Pod's UID/resourceVersion preconditions close its mutation race; Kubernetes
	// offers no cross-object precondition, so the exact policy epoch is read and
	// bound as close to the request as the API permits.
	policy := &v1alpha1.PhorvexPolicy{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.PolicyName}, policy); err != nil {
		return refuse("selecting-policy-unavailable")
	}
	if string(policy.UID) != req.PolicyUID || policy.UID == "" {
		return refuse("selecting-policy-uid-mismatch")
	}
	if policy.Generation != req.PolicyGeneration {
		return refuse("selecting-policy-generation-mismatch")
	}
	if policy.DeletionTimestamp != nil || policy.Spec.IsDryRun() || !policy.Spec.ActionEnabled(v1alpha1.ActionRotate) {
		return refuse("selecting-policy-not-authorized")
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) {
		return refuse("selecting-policy-selector-mismatch")
	}
	policyCap, err := policy.Spec.EffectiveMaxGracePeriodSeconds()
	if err != nil {
		return refuse("selecting-policy-grace-cap-invalid")
	}
	if policyCap != req.MaxGracePeriodSeconds {
		return refuse("selecting-policy-grace-cap-mismatch")
	}
	effectiveGrace := workloadGrace
	if policyCap < effectiveGrace {
		effectiveGrace = policyCap
	}
	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{Namespace: req.Namespace, Name: req.Pod},
		DeleteOptions: &metav1.DeleteOptions{
			GracePeriodSeconds: &effectiveGrace,
			Preconditions:      &metav1.Preconditions{UID: &uid, ResourceVersion: &rv},
		},
	}
	if err := ec.Client.SubResource("eviction").Create(ctx, pod, eviction); err != nil {
		if apierrors.IsTooManyRequests(err) {
			return refuse("pdb-eviction-admission-refused")
		}
		if apierrors.IsForbidden(err) {
			return refuse("eviction-permission-denied")
		}
		if apierrors.IsConflict(err) {
			return refuse("target-changed-before-eviction")
		}
		if apierrors.IsNotFound(err) {
			return refuse("target-or-eviction-subresource-unavailable")
		}
		return HandlerResult{}, fmt.Errorf("rotate eviction %s/%s: %w", req.Namespace, req.Pod, err)
	}
	receipt := &model.GracefulTerminationReceipt{
		PolicyNamespace: req.Namespace, PolicyName: policy.Name, PolicyUID: string(policy.UID),
		PolicyGeneration: policy.Generation, PolicyGraceCapSeconds: policyCap,
		WorkloadGraceSeconds: workloadGrace, WorkloadGraceExplicit: workloadGraceExplicit,
		EffectiveGracePeriodSeconds: effectiveGrace, PodUID: string(uid), PodResourceVersion: rv,
		TerminationStatus: "unconfirmed",
	}
	return HandlerResult{
		Emitted: true, MutationKind: "forward-only",
		ObjectsTouched:      []string{objRef("Pod", req.Namespace, req.Pod)},
		GracefulTermination: receipt,
		Note:                fmt.Sprintf("Pod Eviction admission accepted with policy grace cap %ds and effective grace %ds; old-process termination and replacement unconfirmed", policyCap, effectiveGrace),
	}, nil
}

// Quarantine is implemented in quarantine.go and quarantine_plan.go.

// --- 3. debugger (= Phoenix Debugger: inject one ephemeral container) — IRREVERSIBLE -----

type debuggerHandler struct{}

func (debuggerHandler) Name() string { return string(model.ActionDebugger) }

func (debuggerHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return injectEphemeral(ctx, ec, req, debuggerEphemeralSpec())
}

// BusyBox's default sh exits on stdin EOF. This fixed command keeps a diagnostic process
// available for at most five minutes without accepting a user command or script.
func debuggerEphemeralSpec() corev1.EphemeralContainer {
	return ephemeralContainerSpec("phorvex-debugger", codeExecImage, []string{"sleep", "300"}, nil)
}

// --- 4. custom-inject (= Phoenix CustomAction) — fixed bounded marker profile — IRREVERSIBLE -

type customInjectHandler struct{}

func (customInjectHandler) Name() string { return string(model.ActionCustomInject) }

func (customInjectHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	// M-6: command/args are SPLIT to match the VAP allow-set exactly — command:["sh","-c"],
	// args:["echo phorvex-custom-action; sleep 1"]. Emitting the joined form (all in command)
	// would be DENIED by Phorvex's own admission policy.
	return injectEphemeral(ctx, ec, req, customInjectEphemeralSpec())
}

// customInjectEphemeralSpec is the exact phorvex-custom container the VAP allow-set validates
// (split command/args). Defined once so the handler and its test cannot drift.
func customInjectEphemeralSpec() corev1.EphemeralContainer {
	return ephemeralContainerSpec("phorvex-custom", codeExecImage,
		[]string{"sh", "-c"}, []string{"echo phorvex-custom-action; sleep 1"})
}

// codeExecImage is the pinned busybox digest (linux/amd64, busybox:1.36) the M-6 contract
// approves — identical to the value the VAP enforces. Pinning by digest (not the mutable
// :1.36 tag) means the injected image cannot drift out from under the admission allow-set.
const codeExecImage = "busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"

// hardenedEphemeralSecurityContext is the exact securityContext the M-6 VAP requires: a
// non-root, non-privileged, no-escalation, read-only-rootfs, all-capabilities-dropped,
// RuntimeDefault-seccomp container. The handler emits it so Phorvex's own injection passes
// its own admission policy; the VAP is the durable enforcement of the same profile.
func hardenedEphemeralSecurityContext() *corev1.SecurityContext {
	no, yes := false, true
	id := int64(65534)
	return &corev1.SecurityContext{
		Privileged:               &no,
		AllowPrivilegeEscalation: &no,
		RunAsNonRoot:             &yes,
		RunAsUser:                &id,
		RunAsGroup:               &id,
		ReadOnlyRootFilesystem:   &yes,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

// ephemeralContainerSpec builds ONE ephemeral container carrying the M-6 paired profile:
// the pinned digest, the exact hardened securityContext, no tty/stdin, and the given
// command/args. It is the SINGLE encoding of the VAP allow-set on the emit side, so the
// handler and the conformance test share exactly these bytes.
func ephemeralContainerSpec(name, image string, command, args []string) corev1.EphemeralContainer {
	return corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: name, Image: image, Command: command, Args: args,
			TTY: false, Stdin: false,
			SecurityContext: hardenedEphemeralSecurityContext(),
		},
	}
}

// injectEphemeral appends ONE prebuilt ephemeral container via the pods/ephemeralcontainers
// subresource. IRREVERSIBLE — K8s cannot remove
// an ephemeral container, so there is no rollback, only audit-flagging. The emitted request
// is the M-6 paired profile the VAP validates; see ephemeralContainerSpec.
func injectEphemeral(ctx context.Context, ec EnactCtx, req Request, spec corev1.EphemeralContainer) (HandlerResult, error) {
	if ec.Reader == nil {
		return HandlerResult{}, fmt.Errorf("inject: authoritative Pod reader unavailable")
	}
	pod, ok, err := getPod(ctx, ec.Reader, req.Namespace, req.Pod)
	if err != nil {
		return HandlerResult{}, err
	}
	if !ok {
		return HandlerResult{}, fmt.Errorf("inject: pod %s/%s gone", req.Namespace, req.Pod)
	}
	if req.TargetUID == "" || string(pod.UID) != req.TargetUID {
		return HandlerResult{}, fmt.Errorf("inject: target UID missing or changed for %s/%s", req.Namespace, req.Pod)
	}
	if pod.ResourceVersion == "" {
		return HandlerResult{}, fmt.Errorf("inject: target version unavailable for %s/%s", req.Namespace, req.Pod)
	}
	if spec.Name == "phorvex-debugger" {
		if len(pod.Spec.Containers) == 0 || pod.Spec.Containers[0].Name == "" {
			return HandlerResult{}, fmt.Errorf("debugger: target pod has no ordinary primary container")
		}
		spec.TargetContainerName = pod.Spec.Containers[0].Name
	}
	for _, ec2 := range pod.Spec.EphemeralContainers {
		if ec2.Name == spec.Name {
			if !sameEphemeralSpec(ec2, spec) {
				return HandlerResult{}, fmt.Errorf("inject: existing %s spec differs; immutable session requires a fresh Pod", spec.Name)
			}
			if spec.Name == "phorvex-debugger" {
				return debuggerObservedResult(pod, time.Now()), nil
			}
			return HandlerResult{Emitted: false, NoEffect: NoEffectReconciled, Note: "custom-inject spec already present; no new submission"}, nil
		}
	}
	pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, spec)
	if err := ec.Client.SubResource("ephemeralcontainers").Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("inject ephemeral container %s into %s/%s: %w", spec.Name, req.Namespace, req.Pod, err)
	}
	result := HandlerResult{
		Emitted: true, MutationKind: "irreversible",
		ObjectsTouched: []string{objRef("Pod/ephemeralcontainers", req.Namespace, req.Pod)},
		Note:           "ephemeral container " + spec.Name + " submitted; runtime state unobserved (irreversible spec)",
	}
	if spec.Name == "phorvex-debugger" {
		result.Note = "bounded debugger submitted for target " + spec.TargetContainerName + "; runtime state unobserved, inspect Pod status before use"
	}
	return result, nil
}

// The API server defaults these three ordinary fields on readback. Strip only their
// canonical defaults from the existing value; every unexpected value and every other
// field still participates in the exact comparison.
func sameEphemeralSpec(existing, desired corev1.EphemeralContainer) bool {
	normalized := *existing.DeepCopy()
	if normalized.ImagePullPolicy == corev1.PullIfNotPresent {
		normalized.ImagePullPolicy = ""
	}
	if normalized.TerminationMessagePath == corev1.TerminationMessagePathDefault {
		normalized.TerminationMessagePath = ""
	}
	if normalized.TerminationMessagePolicy == corev1.TerminationMessageReadFile {
		normalized.TerminationMessagePolicy = ""
	}
	return reflect.DeepEqual(normalized, desired)
}

func debuggerObservedResult(pod *corev1.Pod, now time.Time) HandlerResult {
	for _, st := range pod.Status.EphemeralContainerStatuses {
		if st.Name != "phorvex-debugger" {
			continue
		}
		switch {
		case st.State.Running != nil:
			started := st.State.Running.StartedAt.Time
			if started.IsZero() || started.After(now) {
				return HandlerResult{NoEffect: NoEffectReconciled, Note: "bounded debugger running status has invalid or missing start time; availability unobservable"}
			}
			if !now.Before(started.Add(5 * time.Minute)) {
				return HandlerResult{NoEffect: NoEffectReconciled, Note: "bounded debugger running status is past five-minute expiry; status may lag, use a fresh Pod for another session"}
			}
			return HandlerResult{NoEffect: NoEffectReconciled, Note: "bounded debugger observed running within five-minute window; no new submission; inspect runtime/PID support before use"}
		case st.State.Waiting != nil:
			return HandlerResult{NoEffect: NoEffectReconciled, Note: "bounded debugger observed waiting (" + st.State.Waiting.Reason + "); unavailable; no new submission"}
		case st.State.Terminated != nil:
			return HandlerResult{NoEffect: NoEffectReconciled, Note: "bounded debugger terminated; immutable session expired, use a fresh Pod for another session"}
		default:
			return HandlerResult{NoEffect: NoEffectReconciled, Note: "bounded debugger state unobservable; no new submission"}
		}
	}
	return HandlerResult{NoEffect: NoEffectReconciled, Note: "bounded debugger status missing; availability unobservable, no new submission"}
}

// --- 5. disable (= Phoenix DECLARATION) — declared-not-implemented ------------------------
//
// Matches Phoenix's own never-implemented posture. EXCLUDED from model.MutatingActions (so
// never generatable/selectable), but the handler EXISTS so the completeness enumeration is
// green and a policy that explicitly requests it fails LOUD rather than silently no-acting.

type disableHandler struct{}

func (disableHandler) Name() string { return string(model.ActionDisable) }

func (disableHandler) Enact(_ context.Context, _ EnactCtx, _ Request) (HandlerResult, error) {
	return HandlerResult{Emitted: false, NoEffect: NoEffectDeclared, MutationKind: "declared", Note: "disable is declared-not-implemented (matches Phoenix posture); no fabricated behaviour"}, nil
}

// --- 6. identity-rotate (LIGHT dedicated-SA credential invalidation) --------------------
//
// Genuine credential invalidation: on a trusted dedicated-SA external-theft observation
// (identityfixture.Observe, bound to a trusted pod-bound-api-auth detector event and the
// exact policy epoch) the handler deletes the ServiceAccount and recreates it with a new
// UID — so every bound token issued under the old UID, including a stolen pod-bound bearer,
// fails TokenReview — then removes legacy token Secrets, retaining the Pod. The full
// journaled forward-only state machine is in identity_rotation.go (enactIdentityRotation).
// It is forward-only: there is no credential un-rotation, so no Rollback is implemented.

type identityRotateHandler struct{}

func (identityRotateHandler) Name() string { return string(model.ActionIdentityRotate) }

func (identityRotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return enactIdentityRotation(ctx, ec, req)
}

// --- 7. route-rotate (advanced K8s; native-only) — protected reversible cutover -----------
//
// The shared route engine serializes by exact Service and target identity, records the
// owned fields in the protected journal, and confirms each selector transition through
// Service-owned EndpointSlices before advancing.

type routeRotateHandler struct{}

func (routeRotateHandler) Name() string { return string(model.ActionRouteRotate) }

func selectorMatchesPod(selector, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		actual, present := podLabels[key]
		if !present || actual != value {
			return false
		}
	}
	return true
}

func (routeRotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return enactRouteCutover(ctx, ec, req)
}

func (routeRotateHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	return rollbackRouteCutover(ctx, ec, req, ref)
}

// --- shared helpers ----------------------------------------------------------------------

func copyLabels(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func ensureMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func orGone(err error, ok bool, what string, req Request) error {
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s: pod %s/%s gone", what, req.Namespace, req.Pod)
	}
	return nil
}

func restoreLabels(ctx context.Context, ec EnactCtx, req Request, anno string) error {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return err
	}
	raw := pod.Annotations[anno]
	if raw == "" {
		return nil
	}
	var labels map[string]string
	if err := json.Unmarshal([]byte(raw), &labels); err != nil {
		return err
	}
	pod.Labels = labels
	delete(pod.Annotations, anno)
	return ec.Client.Update(ctx, pod)
}

func init() {
	HandlerRegistry.Register(rotateHandler{})
	HandlerRegistry.Register(quarantineHandler{})
	HandlerRegistry.Register(debuggerHandler{})
	HandlerRegistry.Register(customInjectHandler{})
	HandlerRegistry.Register(disableHandler{})
	HandlerRegistry.Register(identityRotateHandler{})
	HandlerRegistry.Register(routeRotateHandler{})
}
