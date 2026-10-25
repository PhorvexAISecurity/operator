/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * controller-stop: retire an attacker-created controller (Deployment/StatefulSet/ReplicaSet)
 * end-to-end. This split-stack handler is SYNCHRONOUS within one Actuate (the two-phase
 * begin/continuation seam the monolith used cannot cross the manager<->actuator gRPC boundary):
 *
 *   validate (trusted controller-UID-bound observation re-checked against the live cluster)
 *     -> scale the exact owner to zero via the scale subresource (UID+resourceVersion
 *        JSON-patch preconditions)
 *     -> wait for the scale to be acknowledged (owner desired==0, observedGeneration caught
 *        up, and for a Deployment every child ReplicaSet already at replicas==0 so the
 *        KCM cannot replace a Pod between our delete and the observation)
 *     -> delete the exact child Pods (UID preconditions; a 404 is absence, not our delete)
 *     -> observe a bounded no-recreation window inline (>= observationWindow of continuous
 *        absence, failing on any newly-UID'd child) -> receipt.
 *
 * It records only a bounded native absence window (ControllerStopReceipt), never permanent
 * erasure. Whole-owner removal is licensed ONLY by HasBoundPersistenceObservation (a fresh,
 * trusted, controller-UID-bound unauthorized-owner observation); generic Pod drift is never
 * authority to delete a whole owner. Forward-only (no Rollbacker).
 */

package actuator

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/persistence"
)

// Bounded observation knobs. The window is the continuous-absence proof; it is kept in
// lock-step with the audit/probe contract (>= 9s). The timeout bounds the whole synchronous
// enact (scale-ack wait + child deletion + observation); the actuator RPC deadline must
// exceed it. interval is the poll cadence.
const (
	controllerStopWindow   = 9 * time.Second
	controllerStopInterval = 1 * time.Second
	controllerStopTimeout  = 75 * time.Second
	controllerStopMaxGap   = 3 * controllerStopInterval // a missed sample discards the absence proof
)

var securityEventGVK = schema.GroupVersionKind{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "SecurityEvent"}

type controllerStopHandler struct{}

func (controllerStopHandler) Name() string { return string(model.ActionControllerStop) }

func init() { HandlerRegistry.Register(controllerStopHandler{}) }

// persistenceRequestValid is the exact-bound-request predicate: the observation must be the
// controller-UID-bound, policy-epoch-bound, falsifiable owner-removal authority, and it must
// agree with the dispatched Request's target and selecting policy identity. It never reads
// the cluster; it is the cheap gate the real re-validation (validateControllerStop) follows.
func persistenceRequestValid(req Request) bool {
	o := req.PersistenceObservation
	return o != nil && req.TargetUID != "" && req.Namespace != "" && req.Pod != "" &&
		o.TargetPodUID == req.TargetUID && o.Namespace == req.Namespace &&
		o.ControllerTargetUID != "" && o.ControllerName != "" && persistence.SupportedKind(o.OwnerKind) &&
		o.PolicyName == req.PolicyName && o.PolicyUID == req.PolicyUID && o.PolicyGeneration == req.PolicyGeneration &&
		o.PolicyUID != "" && o.PolicyGeneration > 0 && o.EventUID != "" && o.EventName != "" && o.CreatorIdentity != "" &&
		o.Unmanaged && o.NoLegitimateServiceRole && o.OwnerDeclaredMinAvailable == 0 && o.ObservedRecreation && o.Replicas > 0
}

// validateControllerStop re-authorizes the whole-owner removal against the LIVE cluster: the
// trusted observer identity still owns the fixture namespace, the observation and its admitted
// SecurityEvent are fresh and unchanged, the Pod/owner identities still match the bound UIDs,
// the removed->replacement recreation proof still holds, the selecting policy epoch is current
// and still enables controller-stop, no legitimate Service floor / PDB / HPA depends on the
// children (persistence.CheckSafety, which also re-proves attacker provenance + unmanaged), and
// the scale subresource still reflects the exact owner UID/resourceVersion/desired. It returns
// the resolved owner and its current children for the enact to mutate.
func validateControllerStop(ctx context.Context, ec EnactCtx, req Request, now time.Time) (persistence.Owner, []corev1.Pod, error) {
	var empty persistence.Owner
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || req.OperationID == "" {
		return empty, nil, fmt.Errorf("controller-stop: protected reader/client/operation unavailable")
	}
	if !persistenceRequestValid(req) {
		return empty, nil, fmt.Errorf("controller-stop: exact bound observation and policy required")
	}
	o := req.PersistenceObservation
	if !persistence.ObserverAllowed(o.CreatorIdentity, req.Namespace) {
		return empty, nil, fmt.Errorf("controller-stop: observation identity is not the authorized persistence observer for this namespace")
	}
	if !persistence.Fresh(o.ObservedAt, now) || !persistence.Fresh(o.CreatedAt, now) {
		return empty, nil, fmt.Errorf("controller-stop: persistence observation is stale")
	}

	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		return empty, nil, err
	}
	if string(pod.UID) != req.TargetUID || pod.DeletionTimestamp != nil {
		return empty, nil, fmt.Errorf("controller-stop: target Pod identity changed")
	}
	owner, err := persistence.ResolvePodOwner(ctx, ec.Reader, pod)
	if err != nil {
		return empty, nil, err
	}
	if string(owner.Object.GetUID()) != o.ControllerTargetUID || owner.Object.GetName() != o.ControllerName || owner.Kind != o.OwnerKind {
		return empty, nil, fmt.Errorf("controller-stop: resolved owner does not match the bound observation")
	}

	// Re-read the admitted observer SecurityEvent and prove it is byte-for-byte the one the
	// trusted observation was built from. A recreated same-name event has a new UID; an edited
	// assertion mismatches; a different rule type/source/target carries no removal authority.
	event := &unstructured.Unstructured{}
	event.SetGroupVersionKind(securityEventGVK)
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: o.EventName}, event); err != nil {
		return empty, nil, err
	}
	annotations := event.GetAnnotations()
	a, err := persistence.Decode(annotations[persistence.Annotation])
	if err != nil {
		return empty, nil, fmt.Errorf("controller-stop: admitted event assertion unreadable: %w", err)
	}
	rule, _, _ := unstructured.NestedStringMap(event.Object, "spec", "rule")
	targets, _, _ := unstructured.NestedStringSlice(event.Object, "spec", "targets")
	if string(event.GetUID()) != o.EventUID || !event.GetCreationTimestamp().Time.Equal(o.CreatedAt) || event.GetDeletionTimestamp() != nil || !persistence.Fresh(event.GetCreationTimestamp().Time, now) ||
		annotations["phorvex.ai/creator-identity"] != o.CreatorIdentity || annotations[model.ConsoleTargetControllerUIDAnnotation] != o.ControllerTargetUID || annotations["phorvex.ai/console-target-pod-uid"] != req.TargetUID ||
		rule["type"] != model.AttackVectorControllerPersistence || rule["source"] != persistence.Source || len(targets) != 1 || targets[0] != req.Namespace+"/"+req.Pod ||
		a.ControllerName != o.ControllerName || a.OwnerKind != o.OwnerKind || a.Namespace != req.Namespace || a.TargetPodUID != req.TargetUID || a.PolicyName != req.PolicyName || a.PolicyUID != req.PolicyUID || a.PolicyGeneration != req.PolicyGeneration ||
		a.RemovedPodUID != o.RemovedPodUID || a.ReplacementPodUID != o.ReplacementPodUID || !a.ObservedAt.Equal(o.ObservedAt) || a.ObservedAt.After(o.CreatedAt.Add(time.Second)) || a.Replicas > o.Replicas {
		return empty, nil, fmt.Errorf("controller-stop: admitted event or assertion changed")
	}

	children, err := persistence.Children(ctx, ec.Reader, owner)
	if err != nil {
		return empty, nil, err
	}
	// Recreation proof must still hold: the allegedly-removed child is gone, the replacement
	// is present, and no counts have grown beyond the observed authority bound.
	removedGone, replacementPresent := true, false
	for i := range children {
		switch string(children[i].UID) {
		case o.RemovedPodUID:
			removedGone = false
		case o.ReplacementPodUID:
			replacementPresent = true
		}
	}
	if !removedGone || !replacementPresent || len(children) > o.Replicas || int(owner.Desired) > o.Replicas || int(owner.Ready) > o.Replicas {
		return empty, nil, fmt.Errorf("controller-stop: recreation proof no longer holds")
	}

	if err := persistence.CurrentPolicy(ctx, ec.Reader, req.Namespace, req.PolicyName, req.PolicyUID, req.PolicyGeneration, children); err != nil {
		return empty, nil, err
	}
	if err := persistence.CheckSafety(ctx, ec.Reader, ec.JournalNamespace, owner, children, req.PolicyName); err != nil {
		return empty, nil, err
	}

	// The scale subresource is the exact object we will patch. Confirm it still reflects the
	// owner identity and desired replicas we validated, so the UID/resourceVersion test ops in
	// the patch cannot silently target a recreated owner.
	scale := &autoscalingv1.Scale{}
	if err := ec.Client.SubResource("scale").Get(ctx, owner.Object, scale); err != nil {
		return empty, nil, err
	}
	if scale.UID != owner.Object.GetUID() || scale.ResourceVersion != owner.Object.GetResourceVersion() || scale.Spec.Replicas != owner.Desired {
		return empty, nil, fmt.Errorf("controller-stop: scale subresource identity changed")
	}
	return owner, children, nil
}

func (controllerStopHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || req.OperationID == "" || req.TickID == "" {
		return HandlerResult{}, fmt.Errorf("controller-stop: protected reader/client/operation unavailable")
	}
	if !persistenceRequestValid(req) {
		return HandlerResult{}, fmt.Errorf("controller-stop: exact bound observation and policy required")
	}
	deadline := time.Now().Add(controllerStopTimeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	now := time.Now().UTC()

	// Namespace-level actuation brake (defense in depth; a brake engaged mid-tick refuses).
	ns := &corev1.Namespace{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: req.Namespace}, ns); err != nil {
		return HandlerResult{}, err
	}
	if ns.DeletionTimestamp != nil {
		return HandlerResult{}, fmt.Errorf("controller-stop: namespace terminating")
	}
	if brake := actuationbrake.Namespace(ns.Annotations); brake.Engaged {
		return HandlerResult{}, fmt.Errorf("controller-stop: namespace dry-run: %s", brake.Cause)
	}

	owner, children, err := validateControllerStop(ctx, ec, req, now)
	if err != nil {
		return HandlerResult{}, err
	}
	o := req.PersistenceObservation
	receipt := &model.ControllerStopReceipt{
		OperationID: req.OperationID, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration,
		EventUID: o.EventUID, Namespace: req.Namespace, OwnerKind: owner.Kind,
		OwnerName: owner.Object.GetName(), OwnerUID: string(owner.Object.GetUID()),
		StartedAt: time.Now().UTC(), ObservationWindow: 0,
	}

	// 1. Scale the exact owner to zero. UID + resourceVersion test ops make the write
	// impossible against a recreated owner; a transport error can hide a committed write, so
	// it is never reported as a no-effect refusal.
	patch, err := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": string(owner.Object.GetUID())},
		{"op": "test", "path": "/metadata/resourceVersion", "value": owner.Object.GetResourceVersion()},
		{"op": "replace", "path": "/spec/replicas", "value": 0},
	})
	if err != nil {
		return HandlerResult{}, err
	}
	scale := &autoscalingv1.Scale{}
	if err := ec.Client.SubResource("scale").Patch(ctx, owner.Object, client.RawPatch(types.JSONPatchType, patch), client.WithSubResourceBody(scale)); err != nil {
		return HandlerResult{ControllerStop: receipt, MutationKind: "partial", Note: "controller-stop scale write unconfirmed"}, fmt.Errorf("controller-stop scale write unconfirmed: %w", err)
	}
	receipt.ScaleAcknowledged = true
	objects := []string{owner.Kind + "/" + owner.Object.GetName()}

	// 2. Wait for the scale to be acknowledged before deleting any Pod: owner desired==0,
	// status caught up, and (Deployment) every owned ReplicaSet already at replicas==0 — so
	// the controller cannot replace a Pod in the gap between our delete and the observation.
	if err := waitScaleAcknowledged(ctx, ec, owner, deadline); err != nil {
		return HandlerResult{ControllerStop: receipt, MutationKind: "partial", Note: "controller-stop scale acknowledgement incomplete"}, err
	}

	// 3. Delete the exact children (UID preconditions). A 404 is absence, not our delete.
	// GracePeriodSeconds=0: the owner is already at desired==0 (step 2), so the controller will
	// not replace these Pods; a forced delete evicts them immediately instead of waiting out the
	// workload's termination grace. This bounds the whole SYNCHRONOUS Enact (delete -> 404 ->
	// >=9s no-recreation observation) well inside the actuator RPC deadline. The two-phase
	// reference observed out-of-band so it could tolerate a long grace; this port cannot.
	sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
	originals := map[string]bool{}
	for i := range children {
		p := children[i]
		originals[string(p.UID)] = true
		receipt.Children = append(receipt.Children, model.ControllerStopChild{Name: p.Name, UID: string(p.UID)})
	}
	zeroGrace := int64(0)
	for i := range children {
		p := children[i]
		uid := p.UID
		err := ec.Client.Delete(ctx, &p, &client.DeleteOptions{GracePeriodSeconds: &zeroGrace, Preconditions: &metav1.Preconditions{UID: &uid}})
		if err != nil && !apierrors.IsNotFound(err) {
			return HandlerResult{ControllerStop: receipt, MutationKind: "partial", Note: "controller-stop child deletion incomplete"}, fmt.Errorf("controller-stop child deletion incomplete: %w", err)
		}
		receipt.Children[i].DeleteAcknowledged = err == nil
		objects = append(objects, "Pod/"+p.Name)
	}

	// 4. Observe a bounded no-recreation window inline.
	if err := observeNoRecreation(ctx, ec, owner, originals, receipt, deadline); err != nil {
		return HandlerResult{ControllerStop: receipt, MutationKind: "forward-only", Emitted: true, ObjectsTouched: objects, Note: "controller-stop: owner scaled to zero and children removed, but bounded no-recreation window not met"}, err
	}
	return HandlerResult{
		Emitted: true, MutationKind: "forward-only", ObjectsTouched: objects, ControllerStop: receipt,
		Note: "exact controller scaled to zero; original children returned native 404; bounded no-recreation window observed",
	}, nil
}

// waitScaleAcknowledged blocks until the owner's desired replicas are zero and its status has
// observed that generation (and, for a Deployment, every owned ReplicaSet is at replicas==0),
// or the deadline passes. It re-resolves the owner each poll and fails if its UID changed.
func waitScaleAcknowledged(ctx context.Context, ec EnactCtx, owner persistence.Owner, deadline time.Time) error {
	ns := owner.Object.GetNamespace()
	ticker := time.NewTicker(controllerStopInterval)
	defer ticker.Stop()
	for {
		live, err := persistence.ReadOwner(ctx, ec.Reader, ns, owner.Kind, owner.Object.GetName())
		if err != nil {
			return err
		}
		if live.Object.GetUID() != owner.Object.GetUID() {
			return fmt.Errorf("controller-stop: owner UID changed during scale acknowledgement")
		}
		acknowledged := live.Desired == 0 && live.ObservedGeneration >= live.Object.GetGeneration()
		if acknowledged && owner.Kind == "Deployment" {
			var sets appsv1.ReplicaSetList
			if err := ec.Reader.List(ctx, &sets, client.InNamespace(ns)); err != nil {
				return err
			}
			for i := range sets.Items {
				rs := &sets.Items[i]
				if ref := metav1.GetControllerOf(rs); ref != nil && ref.UID == owner.Object.GetUID() {
					if rs.Spec.Replicas == nil || *rs.Spec.Replicas != 0 {
						acknowledged = false
					}
				}
			}
		}
		if acknowledged {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("controller-stop: scale to zero not acknowledged before deadline")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// observeNoRecreation accrues continuous child absence. It fails on any missed sample (an
// unobserved gap discards the proof), any owner UID change or non-zero desired, and any child
// whose UID is not one of the frozen originals (a recreation). When absence has held for
// controllerStopWindow it stamps the receipt and returns nil.
func observeNoRecreation(ctx context.Context, ec EnactCtx, owner persistence.Owner, originals map[string]bool, receipt *model.ControllerStopReceipt, deadline time.Time) error {
	ns := owner.Object.GetNamespace()
	ticker := time.NewTicker(controllerStopInterval)
	defer ticker.Stop()
	var absentSince, lastSample time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		now := time.Now().UTC()
		if !lastSample.IsZero() && now.Sub(lastSample) > controllerStopMaxGap {
			return fmt.Errorf("controller-stop: observation gap exceeded; bounded absence proof discarded")
		}
		lastSample = now
		receipt.Samples++
		receipt.LastObservedAt = now

		live, err := persistence.ReadOwner(ctx, ec.Reader, ns, owner.Kind, owner.Object.GetName())
		if err != nil {
			return err
		}
		if live.Object.GetUID() != owner.Object.GetUID() || live.Desired != 0 {
			return fmt.Errorf("controller-stop: owner reasserted desired replicas during the observation window")
		}
		children, err := persistence.Children(ctx, ec.Reader, live)
		if err != nil {
			return err
		}
		for i := range children {
			if !originals[string(children[i].UID)] {
				return fmt.Errorf("controller-stop: a newly-identified child appeared; owner is recreating")
			}
		}
		absent := len(children) == 0 && live.ObservedGeneration >= live.Object.GetGeneration()
		// Every frozen child must return a native 404 (or have a different UID under the name,
		// which is itself a recreation we refuse). A still-present child keeps absence false.
		for i := range receipt.Children {
			got := &corev1.Pod{}
			err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ns, Name: receipt.Children[i].Name}, got)
			switch {
			case apierrors.IsNotFound(err):
				receipt.Children[i].Absent404 = true
			case err != nil:
				return err
			case string(got.UID) != receipt.Children[i].UID:
				return fmt.Errorf("controller-stop: child name reused with a new UID; owner is recreating")
			default:
				receipt.Children[i].Absent404 = false
				absent = false
			}
		}
		if absent {
			if absentSince.IsZero() {
				absentSince = now
			}
			receipt.AbsentSince = absentSince
			if now.Sub(absentSince) >= controllerStopWindow {
				receipt.ObservationWindow = now.Sub(absentSince)
				receipt.NoRecreationObserved = true
				return nil
			}
		} else {
			absentSince = time.Time{}
			receipt.AbsentSince = time.Time{}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("controller-stop: bounded no-recreation window not reached before deadline")
		}
	}
}
