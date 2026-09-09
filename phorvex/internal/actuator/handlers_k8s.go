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
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/ownership"
)

// getPod fetches the target pod; returns (nil,false,nil) if already gone (a NotFound is
// SUCCESS for an idempotent destructive move — the recon target is invalidated).
func getPod(ctx context.Context, c client.Client, ns, name string) (*corev1.Pod, bool, error) {
	var pod corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
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
		return HandlerResult{Note: "Rotation not performed: " + reason}, nil
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

// --- 2. quarantine (= Phoenix Quarantine: deny-all NP + detach) — THE LEAD DEMO ----------
//
// Isolation-before-detach, fidelity-critical: BOTH the deny-all NetworkPolicy AND the
// detach (relabel out of the owning controller's selector — ReplicaSet, StatefulSet,
// DaemonSet, Job, or the matching Services when no owner selector is readable — + strip
// the controller ownerRef) — or the owner re-adopts the frozen pod and the stateful job
// is destroyed. The pod is NOT
// killed, so its state survives. Reversible: a snapshot of prior labels+ownerRefs is
// stored on the pod (restart-safe rollback).

type quarantineHandler struct{}

func (quarantineHandler) Name() string { return string(model.ActionQuarantine) }

const (
	quarantineLabel      = "phorvex.ai/quarantined"
	quarantineSnapAnno   = "phorvex.ai/quarantine-snapshot"
	quarantineEpochLabel = "phorvex.ai/quarantine-epoch" // M-23 D2: event-valued clock for VarNetworkIdentity
)

type qtnSnapshot struct {
	Labels     map[string]string       `json:"labels"`
	OwnerRefs  []metav1.OwnerReference `json:"ownerRefs"`
	PolicyName string                  `json:"policyName"`
}

func (h quarantineHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil {
		return HandlerResult{}, err
	}
	if !ok {
		return HandlerResult{}, fmt.Errorf("quarantine: pod %s/%s gone", req.Namespace, req.Pod)
	}
	if pod.Labels[quarantineLabel] != "" {
		return HandlerResult{Emitted: true, MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod, Note: "already quarantined (idempotent)"}, nil
	}

	npName := "phorvex-quarantine-" + req.Pod
	snap := qtnSnapshot{Labels: copyLabels(pod.Labels), OwnerRefs: pod.OwnerReferences, PolicyName: npName}
	snapJSON, _ := json.Marshal(snap)

	// (a) deny-all NetworkPolicy keyed on a stable per-pod quarantine label.
	qid := string(pod.UID)
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: npName, Namespace: req.Namespace,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/quarantine-of": req.Pod},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{quarantineLabel: qid}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			// empty Ingress + Egress rule slices = DENY ALL.
		},
	}
	if err := ec.Client.Create(ctx, np); err != nil && !apierrors.IsAlreadyExists(err) {
		return HandlerResult{}, fmt.Errorf("quarantine NP %s: %w", npName, err)
	}

	// (b) DETACH: break the selector match of WHATEVER controller owns the pod (ReplicaSet,
	// StatefulSet, DaemonSet, Job, ...) + strip the controller ownerRef, so the owner spawns a
	// replacement and CANNOT re-adopt this frozen pod. When no owner selector can be
	// resolved (bare pod, or an owner kind the actuator cannot read), fall back to breaking
	// the keys every matching Service selects on, so the frozen pod at least leaves the
	// Service endpoints (PHORVEXSEC-169 / M-38). The Note reports exactly which path ran.
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[quarantineSnapAnno] = string(snapJSON)
	brk := ownerSelectorBreak(ctx, ec.Client, pod)
	if brk.empty() {
		brk = serviceSelectorBreak(ctx, ec.Client, pod)
	}
	brk.apply(pod.Labels)
	pod.Labels[quarantineLabel] = qid
	// M-23 D2: an event-valued epoch clock for VarNetworkIdentity. quarantineLabel is the pod
	// UID (state-valued: identical on every quarantine of the same pod, so it never resets), so
	// a re-quarantine could not be throttled. ResourceVersion differs each actuation. Stamped in
	// this same Update; NOT re-stamped on rollback — the snapshot-restore (taken above, before
	// this line) strips it, which correctly fail-OPENs the next quarantine after a re-admit.
	pod.Labels[quarantineEpochLabel] = pod.ResourceVersion
	pod.OwnerReferences = nil // detach from the controller owner
	if err := ec.Client.Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("quarantine detach %s/%s: %w", req.Namespace, req.Pod, err)
	}
	detachNote := "no owner or Service selector to break"
	if !brk.empty() {
		detachNote = "relabel-out-of-" + strings.Join(brk.Via, ",")
	}
	return HandlerResult{
		Emitted: true, MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("NetworkPolicy", req.Namespace, npName), objRef("Pod", req.Namespace, req.Pod)},
		Note:           "deny-all NP + " + detachNote + " + ownerRef-detach; pod ALIVE (state preserved)",
	}, nil
}

// Rollback restores the pod's labels+ownerRefs and deletes the deny-all NP.
func (h quarantineHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return err
	}
	raw := pod.Annotations[quarantineSnapAnno]
	if raw == "" {
		return nil
	}
	var snap qtnSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return err
	}
	pod.Labels = snap.Labels
	pod.OwnerReferences = snap.OwnerRefs
	delete(pod.Annotations, quarantineSnapAnno)
	if err := ec.Client.Update(ctx, pod); err != nil {
		return err
	}
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: snap.PolicyName, Namespace: req.Namespace}}
	if err := ec.Client.Delete(ctx, np); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// selectorBreak is the set of pod label keys quarantine mutates so that a selector stops
// matching the pod. Suffix keys get "-quarantined" appended to their value (breaks
// matchLabels and In expressions); Drop keys are removed (breaks Exists expressions).
// Via records, sorted, which owner/Service each key was taken from, for the Note.
type selectorBreak struct {
	Suffix map[string]bool
	Drop   map[string]bool
	Via    []string
}

func newSelectorBreak() selectorBreak {
	return selectorBreak{Suffix: map[string]bool{}, Drop: map[string]bool{}}
}

func (b selectorBreak) empty() bool { return len(b.Suffix) == 0 && len(b.Drop) == 0 }

func (b *selectorBreak) addSelector(sel *metav1.LabelSelector, via string) {
	if sel == nil {
		return
	}
	before := len(b.Suffix) + len(b.Drop)
	for k := range sel.MatchLabels {
		b.Suffix[k] = true
	}
	for _, expr := range sel.MatchExpressions {
		switch expr.Operator {
		case metav1.LabelSelectorOpIn:
			b.Suffix[expr.Key] = true
		case metav1.LabelSelectorOpExists:
			b.Drop[expr.Key] = true
		}
	}
	if len(b.Suffix)+len(b.Drop) > before {
		b.Via = append(b.Via, via)
		sort.Strings(b.Via)
	}
}

// apply mutates the pod labels so every recorded selector stops matching. Deterministic:
// keys are visited in sorted order.
func (b selectorBreak) apply(labels map[string]string) {
	keys := make([]string, 0, len(b.Suffix))
	for k := range b.Suffix {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if b.Drop[k] {
			continue
		}
		labels[k] = labels[k] + "-quarantined"
	}
	for k := range b.Drop {
		delete(labels, k)
	}
}

// ownerSelectorBreak resolves the selector of EVERY owner referenced by the pod through an
// unstructured Get (ReplicaSet, StatefulSet, DaemonSet, Job — any kind that carries
// spec.selector) and returns the keys quarantine must break. An owner that cannot be
// read (unknown kind, no RBAC, gone) contributes nothing; the caller falls back to the
// Service selectors in that case.
func ownerSelectorBreak(ctx context.Context, c client.Client, pod *corev1.Pod) selectorBreak {
	brk := newSelectorBreak()
	for _, o := range pod.OwnerReferences {
		owner := &unstructured.Unstructured{}
		owner.SetAPIVersion(o.APIVersion)
		owner.SetKind(o.Kind)
		if err := c.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: o.Name}, owner); err != nil {
			continue
		}
		raw, found, err := unstructured.NestedMap(owner.Object, "spec", "selector")
		if err != nil || !found {
			continue
		}
		var sel metav1.LabelSelector
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &sel); err != nil {
			continue
		}
		brk.addSelector(&sel, o.Kind+"/"+o.Name)
	}
	return brk
}

// serviceSelectorBreak returns the keys every Service in the pod's namespace whose
// selector currently matches the pod selects on. Services are visited in name order so
// the resulting Note is deterministic. The Services themselves are never mutated.
func serviceSelectorBreak(ctx context.Context, c client.Client, pod *corev1.Pod) selectorBreak {
	brk := newSelectorBreak()
	var svcs corev1.ServiceList
	if err := c.List(ctx, &svcs, client.InNamespace(pod.Namespace)); err != nil {
		return brk
	}
	sort.Slice(svcs.Items, func(i, j int) bool { return svcs.Items[i].Name < svcs.Items[j].Name })
	podLabels := labels.Set(pod.Labels)
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		if !labels.SelectorFromSet(svc.Spec.Selector).Matches(podLabels) {
			continue
		}
		brk.addSelector(&metav1.LabelSelector{MatchLabels: svc.Spec.Selector}, "Service/"+svc.Name)
	}
	return brk
}

// --- 3. debugger (= Phoenix Debugger: inject one ephemeral container) — IRREVERSIBLE -----

type debuggerHandler struct{}

func (debuggerHandler) Name() string { return string(model.ActionDebugger) }

func (debuggerHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return injectEphemeral(ctx, ec, req, "phorvex-debugger", "busybox:1.36", nil)
}

// --- 4. custom-inject (= Phoenix CustomAction) — also the KV-reset carrier — IRREVERSIBLE -

type customInjectHandler struct{}

func (customInjectHandler) Name() string { return string(model.ActionCustomInject) }

func (customInjectHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return injectEphemeral(ctx, ec, req, "phorvex-custom", "busybox:1.36", []string{"sh", "-c", "echo phorvex-custom-action; sleep 1"})
}

// injectEphemeral appends ONE named ephemeral container via the pods/ephemeralcontainers
// subresource. Name-keyed idempotent (skip if present). IRREVERSIBLE — K8s cannot remove
// an ephemeral container, so there is no rollback, only audit-flagging.
func injectEphemeral(ctx context.Context, ec EnactCtx, req Request, name, image string, cmd []string) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil {
		return HandlerResult{}, err
	}
	if !ok {
		return HandlerResult{}, fmt.Errorf("inject: pod %s/%s gone", req.Namespace, req.Pod)
	}
	for _, ec2 := range pod.Spec.EphemeralContainers {
		if ec2.Name == name {
			return HandlerResult{Emitted: true, MutationKind: "irreversible", Note: "ephemeral container already present (idempotent)"}, nil
		}
	}
	pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: name, Image: image, Command: cmd, TTY: false, Stdin: false},
	})
	if err := ec.Client.SubResource("ephemeralcontainers").Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("inject ephemeral container %s into %s/%s: %w", name, req.Namespace, req.Pod, err)
	}
	return HandlerResult{
		Emitted: true, MutationKind: "irreversible",
		ObjectsTouched: []string{objRef("Pod/ephemeralcontainers", req.Namespace, req.Pod)},
		Note:           "ephemeral container " + name + " injected (irreversible — audit-flagged)",
	}, nil
}

// --- 5. disable (= Phoenix DECLARATION) — declared-not-implemented ------------------------
//
// Matches Phoenix's own never-implemented posture. EXCLUDED from model.MutatingActions (so
// never generatable/selectable), but the handler EXISTS so the completeness enumeration is
// green and a policy that explicitly requests it fails LOUD rather than silently no-acting.

type disableHandler struct{}

func (disableHandler) Name() string { return string(model.ActionDisable) }

func (disableHandler) Enact(_ context.Context, _ EnactCtx, _ Request) (HandlerResult, error) {
	return HandlerResult{Emitted: false, MutationKind: "declared", Note: "disable is declared-not-implemented (matches Phoenix posture); no fabricated behaviour"}, nil
}

// --- 6. identity-rotate (advanced K8s; native-only) — reversible -------------------------
//
// Relabel the pod with a fresh identity epoch. Reversible (prior labels snapshotted).
//
// SCOPE — read before granting this action recon cover: it writes a `phorvex.ai/identity-epoch`
// LABEL. Projected tokens rotate on their own on modern K8s, and nothing selects on the label,
// so the pod's UID, SA token, IP and EndpointSlice
// membership are UNCHANGED. It does not invalidate the podIdentity recon fact — see
// recon/profile.go, where the cover grant was removed for exactly this reason.

type identityRotateHandler struct{}

func (identityRotateHandler) Name() string { return string(model.ActionIdentityRotate) }

const identitySnapAnno = "phorvex.ai/identity-snapshot"

func (identityRotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "identity-rotate", req)
	}
	snap, _ := json.Marshal(copyLabels(pod.Labels))
	pod.Labels = ensureMap(pod.Labels)
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[identitySnapAnno] = string(snap)
	epoch := pod.ResourceVersion // a fresh identity-epoch token each rotate
	pod.Labels["phorvex.ai/identity-epoch"] = epoch
	if err := ec.Client.Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("identity-rotate %s/%s: %w", req.Namespace, req.Pod, err)
	}
	return HandlerResult{
		Emitted: true, MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)},
		Note:           "identity-epoch relabel only; ServiceAccount token, pod UID and pod IP unchanged",
	}, nil
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

func (routeRotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "route-rotate", req)
	}
	svcName := pod.Annotations[annoRouteService]
	if svcName == "" {
		return HandlerResult{
			Emitted: false, MutationKind: "none",
			Note: "route-rotate not emitted: pod has no " + annoRouteService + " annotation",
		}, nil
	}

	var svc corev1.Service
	if err := ec.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: svcName}, &svc); err != nil {
		return HandlerResult{}, fmt.Errorf("route-rotate get Service %s/%s: %w", req.Namespace, svcName, err)
	}
	ready, err := readyPodsMatchingService(ctx, ec.Client, &svc)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("route-rotate count Ready backends for Service %s/%s: %w", req.Namespace, svcName, err)
	}
	if ready == 1 {
		return HandlerResult{}, fmt.Errorf("route-rotate refused: Service %s/%s has exactly one Ready backend", req.Namespace, svcName)
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
