/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * k8s-object-revert — the native config-object remediation for AML.T0081 (Modify AI Agent
 * Configuration). A trusted detector flagged an operator-TRUSTED ConfigMap (the object an AI
 * agent re-reads for its instructions / tool descriptors / policy) as DRIFTED from its
 * operator-declared trusted snapshot (a tampered agent-config steering the agent). This handler
 * restores that ConfigMap's .data back to the OPERATOR-TRUSTED snapshot carried on the object's
 * own annotation (phorvex.ai/trusted-config-snapshot). It is the move that undoes the tamper at
 * the OBJECT itself: a generic rotate/quarantine churns the POD but the tampered ConfigMap
 * persists and re-serves the same bad config to every replacement. It targets only VOLUME-mounted
 * ConfigMaps (kubelet projects the restored data in place, so the agent re-reads the operator
 * instructions without a pod restart); env-materialized ConfigMaps are out of scope because a
 * .data revert would not reach a running process. It is forward-only and bounded: the only value
 * it can ever write is the operator's own snapshot — it NEVER trusts the event's bytes to choose
 * the data — so it cannot be weaponized into installing attacker-chosen config. It re-derives the
 * target from the LIVE pod's own mounted ConfigMap references (never the event), and acts only
 * when EXACTLY ONE carries a trusted snapshot AND has drifted; zero/multi/unparseable-on-drift
 * fails closed. Drift and restore are over .data (string data); binaryData is out of scope.
 * Idempotent: a ConfigMap already on its snapshot is a confirmed no-effect. Namespace-PARAMETRIC.
 * Clean-room k8s.io API only.
 */

package actuator

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

// TrustedConfigSnapshotAnnotation carries the OPERATOR-TRUSTED snapshot of a ConfigMap's .data as
// a JSON object (map[string]string). It is an operator declaration, never event-derived;
// k8s-object-revert restores exactly this value and nothing else.
const TrustedConfigSnapshotAnnotation = "phorvex.ai/trusted-config-snapshot"

type k8sObjectRevertHandler struct{}

func (k8sObjectRevertHandler) Name() string { return string(model.ActionK8sObjectRevert) }

// podMountedConfigMapRefs returns the sorted, de-duplicated set of ConfigMap names this Pod
// mounts as a VOLUME (direct or projected). It deliberately EXCLUDES envFrom / env valueFrom
// references: an env-materialized ConfigMap is copied into the container's environment at start,
// so a later .data revert would not reach the already-running process without a restart — the
// revert would be object-level only, not live-effective, which would make the "restores the
// config the agent re-reads" claim false. A volume-mounted ConfigMap is kubelet-projected and
// updated in place, so the agent re-reads the restored instructions without a pod restart. This
// is the live-state target derivation; the flagging event never chooses it.
func podMountedConfigMapRefs(pod *corev1.Pod) []string {
	seen := map[string]bool{}
	add := func(n string) {
		if n != "" {
			seen[n] = true
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.ConfigMap != nil {
			add(v.ConfigMap.Name)
		}
		if v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.ConfigMap != nil {
					add(s.ConfigMap.Name)
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (k8sObjectRevertHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	refuse := func(reason string) (HandlerResult, error) {
		disposition := NoEffectRefused
		if reason == "target-already-gone" {
			disposition = NoEffectSatisfied
		}
		return HandlerResult{NoEffect: disposition, MutationKind: "none", Note: "k8s-object-revert not performed: " + reason}, nil
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

	// Confirm the flagged Pod still exists with the exact selecting UID before acting.
	pod, present, err := getPod(ctx, ec.Reader, req.Namespace, req.Pod)
	if err != nil {
		return refuse("target-unavailable")
	}
	if !present {
		return refuse("target-already-gone")
	}
	if string(pod.UID) != req.TargetUID {
		return refuse("target-uid-mismatch")
	}

	// Derive the candidate set from the LIVE pod's own ConfigMap references, authoritatively — the
	// flagging event never chooses the write target. Scope to those carrying an operator-trusted
	// snapshot that has DRIFTED; exactly one is required.
	type candidate struct {
		cm       *corev1.ConfigMap
		snapshot map[string]string
	}
	var drifted []candidate
	malformedDrift := false // a drifted trusted object whose snapshot cannot be parsed: fail closed
	for _, name := range podMountedConfigMapRefs(pod) {
		var cm corev1.ConfigMap
		if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: name}, &cm); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return refuse("configmap-unavailable")
		}
		if cm.DeletionTimestamp != nil && !cm.DeletionTimestamp.IsZero() {
			continue // object is being deleted; do not start a restore effect on it
		}
		raw, ok := cm.Annotations[TrustedConfigSnapshotAnnotation]
		if !ok || raw == "" {
			continue // not an operator-trusted object; out of scope
		}
		live := cm.Data
		if live == nil {
			live = map[string]string{}
		}
		var snapshot map[string]string
		if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
			// A trusted object carrying an unparseable snapshot: only a concern if it has actually
			// drifted (its live .data cannot equal a snapshot we cannot read). Record it so we fail
			// closed rather than silently report "no drift" and mask an un-remediated tamper.
			malformedDrift = true
			continue
		}
		if reflect.DeepEqual(live, snapshot) {
			continue // already on its trusted snapshot; no drift
		}
		c := cm // capture
		drifted = append(drifted, candidate{cm: &c, snapshot: snapshot})
	}

	if len(drifted) == 0 {
		if malformedDrift {
			return refuse("drifted-trusted-configmap-has-unparseable-operator-snapshot")
		}
		// Either nothing referenced carries a trusted snapshot, or every snapshotted object is
		// already on its snapshot. Both are a confirmed no-effect (idempotent re-assertion).
		return HandlerResult{
			NoEffect:     NoEffectSatisfied,
			MutationKind: "none",
			Note:         "k8s-object-revert: no referenced operator-trusted ConfigMap is drifted from its snapshot; no new mitigation",
		}, nil
	}
	if len(drifted) > 1 {
		return refuse("multiple-referenced-configmaps-drifted")
	}

	target := drifted[0]
	objTarget := objRef("ConfigMap", target.cm.Namespace, target.cm.Name)

	// Restore .data to the operator-trusted snapshot and nothing else. Forward-only.
	before := target.cm.Data
	target.cm.Data = target.snapshot
	if err := ec.Client.Update(ctx, target.cm); err != nil {
		if apierrors.IsConflict(err) {
			return HandlerResult{MutationKind: "none", Note: "k8s-object-revert: ConfigMap changed under us; will retry next tick"}, nil
		}
		return HandlerResult{}, fmt.Errorf("k8s-object-revert patch configmap %s/%s: %w", target.cm.Namespace, target.cm.Name, err)
	}
	return HandlerResult{
		Emitted:        true,
		MutationKind:   "forward-only",
		ObjectsTouched: []string{objTarget},
		Note: fmt.Sprintf("k8s-object-revert: restored ConfigMap %s/%s .data from the tampered live state (%d keys) to the operator-trusted snapshot (%d keys)",
			target.cm.Namespace, target.cm.Name, len(before), len(target.snapshot)),
	}, nil
}

func init() { HandlerRegistry.Register(k8sObjectRevertHandler{}) }
