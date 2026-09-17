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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

// --- 1. rotate (native delete request; replacement unconfirmed) ---------------------------------

type rotateHandler struct{}

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
	if req.TargetUID == "" {
		return refuse("target-uid-unavailable")
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
	if err := ec.Client.Delete(ctx, pod, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
			return refuse("target-changed-before-delete")
		}
		return HandlerResult{}, fmt.Errorf("rotate delete %s/%s: %w", req.Namespace, req.Pod, err)
	}
	return HandlerResult{Emitted: true, MutationKind: "forward-only", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "Pod deletion requested; replacement unconfirmed"}, nil
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

// --- 6. identity-rotate (declared-only; historical metadata rollback) ------------------
//
// The old handler only relabeled identity-epoch. No UID, IP, projected credential or
// EndpointSlice membership changed, so new dispatch refuses before any Pod access.
// Rollback remains registered solely to restore snapshots left by older builds.

type identityRotateHandler struct{}

func (identityRotateHandler) Name() string { return string(model.ActionIdentityRotate) }

const identitySnapAnno = "phorvex.ai/identity-snapshot"

func (identityRotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return HandlerResult{}, fmt.Errorf("%s", model.IdentityRotateUnsupportedReason)
}

func (identityRotateHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	return restoreLabels(ctx, ec, req, identitySnapAnno)
}

// --- 7. route-rotate (advanced K8s; native-only) — reversible ----------------------------
//
// Re-key the target pod and its declared fronting Service selector. Reversible: both
// the prior pod labels and the complete prior Service selector are snapshotted on the pod.
// The Service contract is explicit: the pod must name it with phorvex.ai/route-service,
// and the Service must select phorvex.ai/route-key.

type routeRotateHandler struct{}

func (routeRotateHandler) Name() string { return string(model.ActionRouteRotate) }

const routeSnapAnno = "phorvex.ai/route-snapshot"

type routeSnapshot struct {
	Labels          map[string]string `json:"labels"`
	ServiceName     string            `json:"serviceName"`
	ServiceSelector map[string]string `json:"serviceSelector"`
}

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
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "route-rotate", req)
	}
	svcName := pod.Annotations[annoRouteService]
	if svcName == "" {
		return HandlerResult{
			Emitted: false, NoEffect: NoEffectRefused, MutationKind: "none",
			Note: "route-rotate not emitted: pod has no " + annoRouteService + " annotation",
		}, nil
	}

	var svc corev1.Service
	if err := ec.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: svcName}, &svc); err != nil {
		return HandlerResult{}, fmt.Errorf("route-rotate get Service %s/%s: %w", req.Namespace, svcName, err)
	}
	if svc.Spec.Selector[labelRouteKey] == "" || !selectorMatchesPod(svc.Spec.Selector, pod.Labels) {
		return HandlerResult{}, fmt.Errorf("route-rotate refused: declared Service %s/%s does not select the target route-key", req.Namespace, svcName)
	}
	ready, err := readyPodsMatchingService(ctx, ec.Client, &svc)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("route-rotate count Ready backends for Service %s/%s: %w", req.Namespace, svcName, err)
	}
	if !podReady(pod) || ready < 2 {
		return HandlerResult{}, fmt.Errorf("route-rotate refused: Service %s/%s requires target Ready and at least two Ready backends (found %d)", req.Namespace, svcName, ready)
	}

	snap := routeSnapshot{
		Labels:          copyLabels(pod.Labels),
		ServiceName:     svcName,
		ServiceSelector: copyLabels(svc.Spec.Selector),
	}
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("route-rotate snapshot %s/%s: %w", req.Namespace, req.Pod, err)
	}
	pod.Labels = ensureMap(pod.Labels)
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[routeSnapAnno] = string(snapJSON)
	newKey := "route-" + pod.ResourceVersion
	pod.Labels[labelRouteKey] = newKey
	pod.Labels["phorvex.ai/route-epoch"] = pod.ResourceVersion
	if err := ec.Client.Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("route-rotate %s/%s: %w", req.Namespace, req.Pod, err)
	}

	svc.Spec.Selector = copyLabels(svc.Spec.Selector)
	svc.Spec.Selector[labelRouteKey] = newKey
	if err := ec.Client.Update(ctx, &svc); err != nil {
		// The pod re-key alone is inert and can temporarily remove it from the old
		// Service. Compensate before returning so a failed restitch earns no credit
		// and leaves no half-applied mutation behind.
		compensateErr := restoreRoutePodLabels(ctx, ec.Client, req.Namespace, req.Pod, snap.Labels)
		if compensateErr != nil {
			return HandlerResult{}, fmt.Errorf("route-rotate restitch Service %s/%s: %w; pod compensation also failed: %v", req.Namespace, svcName, err, compensateErr)
		}
		return HandlerResult{}, fmt.Errorf("route-rotate restitch Service %s/%s: %w (pod mutation compensated)", req.Namespace, svcName, err)
	}
	return HandlerResult{
		Emitted: true, MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod), objRef("Service", req.Namespace, svcName)},
		Note:           "route-key re-keyed and Service " + svcName + " selector restitched",
	}, nil
}

func (routeRotateHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return err
	}
	raw := pod.Annotations[routeSnapAnno]
	if raw == "" {
		return nil
	}

	var snap routeSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return fmt.Errorf("route-rotate rollback decode snapshot: %w", err)
	}
	// Backward compatibility for a snapshot written by the old label-only handler.
	if snap.Labels == nil {
		if err := json.Unmarshal([]byte(raw), &snap.Labels); err != nil {
			return fmt.Errorf("route-rotate rollback decode legacy snapshot: %w", err)
		}
	}

	// Restore the Service first. Its old selector still has at least one of the
	// Ready backends that made Enact safe, avoiding an empty selector transition.
	if snap.ServiceName != "" {
		var svc corev1.Service
		if err := ec.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: snap.ServiceName}, &svc); err != nil {
			return fmt.Errorf("route-rotate rollback get Service %s/%s: %w", req.Namespace, snap.ServiceName, err)
		}
		svc.Spec.Selector = copyLabels(snap.ServiceSelector)
		if err := ec.Client.Update(ctx, &svc); err != nil {
			return fmt.Errorf("route-rotate rollback Service %s/%s: %w", req.Namespace, snap.ServiceName, err)
		}
	}

	pod.Labels = snap.Labels
	delete(pod.Annotations, routeSnapAnno)
	if err := ec.Client.Update(ctx, pod); err != nil {
		return fmt.Errorf("route-rotate rollback pod %s/%s: %w", req.Namespace, req.Pod, err)
	}
	return nil
}

func readyPodsMatchingService(ctx context.Context, c client.Client, svc *corev1.Service) (int, error) {
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(svc.Namespace), client.MatchingLabels(svc.Spec.Selector)); err != nil {
		return 0, err
	}
	ready := 0
	for i := range pods.Items {
		for _, cond := range pods.Items[i].Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				ready++
				break
			}
		}
	}
	return ready, nil
}

func restoreRoutePodLabels(ctx context.Context, c client.Client, namespace, name string, labels map[string]string) error {
	var pod corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		return err
	}
	pod.Labels = labels
	delete(pod.Annotations, routeSnapAnno)
	return c.Update(ctx, &pod)
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
