package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	kvEffectDomain        = "kv-session-v1"
	guardrailEffectDomain = "guardrail-variant-v1"
	annoKVLocalEffect     = "phorvex.ai/kv-local-effect-epoch"
	servingSlotMaxCount   = 1000
	servingSlotMaxBytes   = 16 << 20
	servingInventoryPage  = 64
	metadataPatchAttempts = 3
)

func effectDomain(action model.Action) string {
	switch action {
	case model.ActionKVReset, model.ActionKVMigrateInvalidate:
		return kvEffectDomain
	case model.ActionGuardrailRotate:
		return guardrailEffectDomain
	default:
		return ""
	}
}

func protectedServingAction(action model.Action) bool { return effectDomain(action) != "" }

func servingOperationID(req Request) (string, error) {
	if !protectedServingAction(req.Action) || req.TickID == "" || len(req.TickID) > 253 || req.PolicyUID == "" || req.Namespace == "" || req.TargetUID == "" {
		return "", fmt.Errorf("protected serving operation identity is incomplete")
	}
	return servingOperationDigest(req.TickID, req.PolicyUID, req.Namespace, req.TargetUID, req.Action), nil
}

func servingOperationDigest(tickID, policyUID, namespace, targetUID string, action model.Action) string {
	h := sha256.New()
	for _, value := range []string{"phorvex-serving-operation-v1", tickID, policyUID, namespace, targetUID, string(action)} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func epochToken(operationID, purpose string) string {
	sum := sha256.Sum256([]byte("phorvex-serving-epoch-v1\x00" + purpose + "\x00" + operationID))
	return hex.EncodeToString(sum[:20])
}

func selectedOwned(v model.OwnedValue) routeOwnedValue {
	return routeOwnedValue{Present: v.Present, Value: v.Value}
}

func podOwned(values map[string]string, key string) routeOwnedValue {
	value, present := values[key]
	return routeOwnedValue{Present: present, Value: value}
}

func requestObservation(req Request) (reset, migrate, local, guard routeOwnedValue, err error) {
	if req.ServingObservation == nil {
		return reset, migrate, local, guard, fmt.Errorf("protected serving selection observation is missing")
	}
	reset = selectedOwned(req.ServingObservation.KVReset)
	migrate = selectedOwned(req.ServingObservation.KVMigrate)
	local = selectedOwned(req.ServingObservation.KVLocalEffect)
	guard = selectedOwned(req.ServingObservation.Guardrail)
	for _, value := range []routeOwnedValue{reset, migrate, local, guard} {
		if !boundedOwnedValue(value) {
			return reset, migrate, local, guard, fmt.Errorf("protected serving selection observation exceeds %d bytes", servingEffectEpochMaxBytes)
		}
	}
	return reset, migrate, local, guard, nil
}

func kvObservationMatches(pod *corev1.Pod, r operationReceipt) bool {
	return podOwned(pod.Annotations, annoKVResetEpoch) == r.SelectedReset &&
		podOwned(pod.Annotations, annoKVEpoch) == r.SelectedMigrate &&
		podOwned(pod.Annotations, annoKVLocalEffect) == r.SelectedLocal
}

func guardrailObservationMatches(pod *corev1.Pod, r operationReceipt) bool {
	return podOwned(pod.Labels, "phorvex.ai/guardrail-epoch") == r.SelectedGuardrail
}

func servingObservationMatches(pod *corev1.Pod, r operationReceipt) bool {
	if r.EffectDomain == kvEffectDomain {
		return kvObservationMatches(pod, r)
	}
	return guardrailObservationMatches(pod, r)
}

func servingExpectedMatches(pod *corev1.Pod, r operationReceipt) bool {
	if r.EffectDomain == kvEffectDomain {
		return podOwned(pod.Annotations, annoKVResetEpoch) == r.ExpectedReset &&
			podOwned(pod.Annotations, annoKVEpoch) == r.ExpectedMigrate &&
			podOwned(pod.Annotations, annoKVLocalEffect) == r.ExpectedLocal
	}
	wantVariant := r.NextVariant
	wantSnapshot := routeOwnedValue{Present: true, Value: r.PriorVariant}
	if r.Phase == "rollback-confirmed" || r.Phase == "rolled-back" {
		wantVariant = r.PriorVariant
		wantSnapshot = r.PriorSnapshot
	}
	return podOwned(pod.Labels, "phorvex.ai/guardrail-epoch") == r.ExpectedGuardrail &&
		pod.Annotations[annoGuardrailVariant] == wantVariant && podOwned(pod.Annotations, annoGuardrailSnap) == wantSnapshot
}

func servingMetadataPreconditionMatches(pod *corev1.Pod, r operationReceipt) bool {
	if r.EffectDomain == kvEffectDomain {
		return kvObservationMatches(pod, r)
	}
	if r.Phase == "rollback-confirmed" {
		return pod.Annotations[annoGuardrailVariant] == r.NextVariant &&
			podOwned(pod.Annotations, annoGuardrailSnap) == (routeOwnedValue{Present: true, Value: r.PriorVariant}) &&
			podOwned(pod.Labels, "phorvex.ai/guardrail-epoch") == (routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "apply")})
	}
	return guardrailObservationMatches(pod, r) && pod.Annotations[annoGuardrailVariant] == r.PriorVariant &&
		podOwned(pod.Annotations, annoGuardrailSnap) == r.PriorSnapshot
}

func protectedEndpointConfigDigest(pod *corev1.Pod) string {
	ep := endpointForPod(pod)
	return digestJSON(struct {
		PodIP, ResetPath, GuardrailPath, KVPath string
		Port                                    int
	}{ep.podIP, ep.resetPath, ep.guardPath, ep.kvInvPath, ep.port})
}

func receiptSecurity(ec EnactCtx, pod *corev1.Pod) (digest, account string, legacy bool) {
	if ec.ServingAttempt != nil && !ec.ServingAttempt.legacy {
		return ec.ServingAttempt.digest, normalizeServiceAccount(pod.Spec.ServiceAccountName), false
	}
	return "", normalizeServiceAccount(pod.Spec.ServiceAccountName), true
}

func servingReceiptSecurityMatches(ec EnactCtx, pod *corev1.Pod, r operationReceipt) bool {
	digest, account, legacy := receiptSecurity(ec, pod)
	return digest == r.ServingBindingSHA256 && account == r.ServingServiceAccount && legacy == r.ServingLegacy && protectedEndpointConfigDigest(pod) == r.EndpointConfigSHA256
}

func servingReceiptRef(cm *corev1.ConfigMap, r operationReceipt) string {
	if cm == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s@%s#%d/%s", cm.Namespace, cm.Name, cm.UID, r.Generation, r.OperationID)
}

func servingPartial(cm *corev1.ConfigMap, r operationReceipt, emitted bool, cause error) (HandlerResult, error) {
	objects := []string(nil)
	if cm != nil {
		objects = []string{objRef("ConfigMap", cm.Namespace, cm.Name)}
	}
	return HandlerResult{Emitted: emitted, MutationKind: "partial", RollbackRef: servingReceiptRef(cm, r), ObjectsTouched: objects,
		Note: fmt.Sprintf("%s outcome retained in protected phase %s", r.Kind, r.Phase)}, cause
}

func servingReconciled(cm *corev1.ConfigMap, r operationReceipt, note string) HandlerResult {
	objects := []string(nil)
	if cm != nil {
		objects = []string{objRef("ConfigMap", cm.Namespace, cm.Name)}
	}
	return HandlerResult{NoEffect: NoEffectReconciled, MutationKind: "none", RollbackRef: servingReceiptRef(cm, r), ObjectsTouched: objects, Note: note}
}

func preparedServingResult(cm *corev1.ConfigMap, r operationReceipt, fresh bool, ready HandlerResult, err error) (HandlerResult, error, bool) {
	if ready.NoEffect != "" {
		return ready, nil, true
	}
	if err != nil {
		if cm == nil && IsNoEffectRefusal(err) {
			return ready, err, true
		}
		result, resultErr := servingPartial(cm, r, false, err)
		return result, resultErr, true
	}
	if !fresh {
		result, resultErr := servingPartial(cm, r, false, fmt.Errorf("protected serving operation remains in phase %s", r.Phase))
		return result, resultErr, true
	}
	return HandlerResult{}, nil, false
}

func protectedServingRefusal(ctx context.Context, ec EnactCtx, req Request, fallback HandlerResult, cause error) (HandlerResult, error) {
	cm, r, err := servingReceiptGet(ctx, ec, req.TargetUID, req.Action)
	if err == nil && !terminalServingPhase(r.Phase) {
		if cause == nil {
			cause = fmt.Errorf("%s", fallback.Note)
		}
		return servingPartial(cm, r, false, fmt.Errorf("protected serving operation remains pending; current validation failed: %w", cause))
	}
	if err != nil && !apierrors.IsNotFound(err) && ec.Reader != nil && ec.JournalNamespace != "" && req.TargetUID != "" {
		return HandlerResult{MutationKind: "partial", Note: "protected serving receipt state could not be classified; fallback is unsafe"}, errors.Join(cause, err)
	}
	return fallback, cause
}

func servingReceiptGet(ctx context.Context, ec EnactCtx, targetUID string, action model.Action) (*corev1.ConfigMap, operationReceipt, error) {
	probe := operationReceipt{Version: servingEffectReceiptVersion, EffectDomain: effectDomain(action), TargetUID: targetUID}
	if ec.Reader == nil || ec.JournalNamespace == "" || probe.EffectDomain == "" || targetUID == "" {
		return nil, operationReceipt{}, fmt.Errorf("protected serving journal identity unavailable")
	}
	cm := &corev1.ConfigMap{}
	err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: receiptName(probe)}, cm)
	if err != nil {
		return nil, operationReceipt{}, err
	}
	var recorded operationReceipt
	if err := json.Unmarshal([]byte(cm.Data["receipt"]), &recorded); err != nil || !recorded.valid() || cm.Name != receiptName(recorded) || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || recorded.TargetUID != targetUID || recorded.EffectDomain != probe.EffectDomain {
		return nil, operationReceipt{}, fmt.Errorf("protected serving receipt identity invalid")
	}
	return cm, recorded, nil
}

func pendingProtectedServingReceipt(ctx context.Context, ec EnactCtx, req Request) (bool, error) {
	if !protectedServingAction(req.Action) || req.TargetUID == "" || ec.Reader == nil || ec.JournalNamespace == "" {
		return false, nil
	}
	_, r, err := servingReceiptGet(ctx, ec, req.TargetUID, req.Action)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	return r.Phase != "terminal-full" && r.Phase != "terminal-partial" && r.Phase != "rolled-back", nil
}

func servingSlotAdmission(ctx context.Context, ec EnactCtx) error {
	count, bytes, err := servingSlotInventory(ctx, ec)
	if err != nil {
		return err
	}
	if count >= servingSlotMaxCount || bytes >= servingSlotMaxBytes {
		return fmt.Errorf("protected serving inventory admission threshold reached (%d records, %d bytes)", count, bytes)
	}
	return nil
}

func servingSlotInventory(ctx context.Context, ec EnactCtx) (count, bytes int, err error) {
	if ec.Reader == nil || ec.JournalNamespace == "" {
		return 0, 0, fmt.Errorf("protected serving inventory reader unavailable")
	}
	continuation := ""
	for pages := 0; pages <= servingSlotMaxCount/servingInventoryPage+2; pages++ {
		var list corev1.ConfigMapList
		opts := []client.ListOption{client.InNamespace(ec.JournalNamespace), client.MatchingLabels{servingJournalLabel: "v1"}, client.Limit(servingInventoryPage)}
		if continuation != "" {
			opts = append(opts, client.Continue(continuation))
		}
		if err := ec.Reader.List(ctx, &list, opts...); err != nil {
			return 0, 0, fmt.Errorf("protected serving inventory unavailable: %w", err)
		}
		for i := range list.Items {
			cm := &list.Items[i]
			encoded := cm.Data["receipt"]
			if len(encoded) == 0 || len(encoded) > servingEffectReceiptMaxBytes {
				return 0, 0, fmt.Errorf("protected serving inventory contains invalid-size receipt")
			}
			var r operationReceipt
			if json.Unmarshal([]byte(encoded), &r) != nil || !r.valid() || r.Version != servingEffectReceiptVersion || cm.Name != receiptName(r) || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil {
				return 0, 0, fmt.Errorf("protected serving inventory contains invalid receipt %s/%s", cm.Namespace, cm.Name)
			}
			count++
			bytes += len(encoded)
			if count > servingSlotMaxCount || bytes > servingSlotMaxBytes {
				return count, bytes, nil
			}
		}
		if list.Continue == "" {
			return count, bytes, nil
		}
		if list.Continue == continuation {
			return 0, 0, fmt.Errorf("protected serving inventory continuation made no progress")
		}
		continuation = list.Continue
	}
	return 0, 0, fmt.Errorf("protected serving inventory incomplete after bounded pagination")
}

func servingPostCreateAdmission(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap) error {
	count, bytes, err := servingSlotInventory(ctx, ec)
	if err != nil {
		return fmt.Errorf("protected serving post-create inventory unavailable: %w", err)
	}
	if count <= servingSlotMaxCount && bytes <= servingSlotMaxBytes {
		return nil
	}
	if err := journalFinish(ctx, ec, cm); err != nil {
		return fmt.Errorf("protected serving admission exceeded and prepared claim retirement was not acknowledged: %w", err)
	}
	return RefusedWithoutEffect(fmt.Errorf("protected serving inventory admission exceeded after concurrent create (%d records, %d bytes)", count, bytes))
}

func terminalServingPhase(phase string) bool {
	return phase == "terminal-full" || phase == "terminal-partial" || phase == "rolled-back"
}

func prepareServingReceipt(ctx context.Context, ec EnactCtx, req Request, pod *corev1.Pod, peers []string, priorVariant, nextVariant string) (*corev1.ConfigMap, operationReceipt, bool, HandlerResult, error) {
	opID, err := servingOperationID(req)
	if err != nil {
		if pending, pendingErr := pendingProtectedServingReceipt(ctx, ec, req); pending {
			return nil, operationReceipt{}, false, HandlerResult{MutationKind: "partial", Note: "protected serving identity invalid while a prior operation remains pending"}, errors.Join(err, pendingErr)
		}
		return nil, operationReceipt{}, false, HandlerResult{}, RefusedWithoutEffect(err)
	}
	reset, migrate, local, guard, err := requestObservation(req)
	if err != nil {
		if pending, pendingErr := pendingProtectedServingReceipt(ctx, ec, req); pending {
			return nil, operationReceipt{}, false, HandlerResult{MutationKind: "partial", Note: "protected serving observation invalid while a prior operation remains pending"}, errors.Join(err, pendingErr)
		}
		return nil, operationReceipt{}, false, HandlerResult{}, RefusedWithoutEffect(err)
	}
	digest, account, legacy := receiptSecurity(ec, pod)
	r := operationReceipt{Version: servingEffectReceiptVersion, Kind: string(req.Action), Phase: "prepared", EffectDomain: effectDomain(req.Action), OperationID: opID, TickID: req.TickID, Generation: 1,
		PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, TargetName: req.Pod, TargetUID: req.TargetUID, TargetLabels: copyLabels(pod.Labels),
		SelectedReset: reset, SelectedMigrate: migrate, SelectedLocal: local, SelectedGuardrail: guard,
		ExpectedReset: reset, ExpectedMigrate: migrate, ExpectedLocal: local, ExpectedGuardrail: guard,
		PriorVariant: priorVariant, NextVariant: nextVariant, PriorSnapshot: podOwned(pod.Annotations, annoGuardrailSnap), RemoteExpected: len(peers),
		DeclaredPeers:        append([]string(nil), peers...),
		ServingBindingSHA256: digest, ServingServiceAccount: account, ServingLegacy: legacy, EndpointConfigSHA256: protectedEndpointConfigDigest(pod)}
	token := routeOwnedValue{Present: true, Value: epochToken(opID, "apply")}
	switch req.Action {
	case model.ActionKVReset:
		r.ExpectedReset = token
	case model.ActionKVMigrateInvalidate:
		// Full versus local-only expected state is chosen after peer outcomes.
	case model.ActionGuardrailRotate:
		r.ExpectedGuardrail = token
	}
	if !r.valid() {
		if pending, pendingErr := pendingProtectedServingReceipt(ctx, ec, req); pending {
			return nil, operationReceipt{}, false, HandlerResult{MutationKind: "partial", Note: "protected serving request is invalid while a prior operation remains pending"}, errors.Join(fmt.Errorf("protected serving receipt is invalid"), pendingErr)
		}
		return nil, operationReceipt{}, false, HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("protected serving receipt is invalid"))
	}
	cm, old, getErr := servingReceiptGet(ctx, ec, req.TargetUID, req.Action)
	if getErr == nil {
		if old.PolicyNamespace != req.Namespace || old.TargetName != req.Pod || old.TargetUID != req.TargetUID {
			return cm, old, false, HandlerResult{}, fmt.Errorf("protected serving domain is occupied by a different target identity")
		}
		if !terminalServingPhase(old.Phase) {
			return cm, old, false, HandlerResult{}, nil
		}
		if _, err := receiptAuthority(ctx, ec.Reader, r, req.Action); err != nil {
			return cm, old, false, HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("protected serving policy authority: %w", err))
		}
		if old.OperationID == opID {
			if old.PolicyUID != req.PolicyUID || old.PolicyName != req.PolicyName || !servingReceiptSecurityMatches(ec, pod, old) || !servingExpectedMatches(pod, old) {
				return cm, old, false, HandlerResult{}, fmt.Errorf("terminal protected serving receipt no longer matches current authority or expected state")
			}
			note := "protected serving operation already reached a terminal state; no new effect credited"
			if old.Phase == "terminal-partial" {
				note = "protected serving operation already retained a confirmed local-only partial effect; no full-scope success or new effect credited"
			}
			return cm, old, false, servingReconciled(cm, old, note), nil
		}
		if !servingReceiptSecurityMatches(ec, pod, r) || !servingExpectedMatches(pod, old) || !servingObservationMatches(pod, r) || old.Generation == math.MaxUint64 {
			return cm, old, false, HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("stale selection cannot supersede protected serving terminal high-water"))
		}
		r.Generation = old.Generation + 1
		if err := journalAdvance(ctx, ec, cm, r); err != nil {
			return cm, old, false, HandlerResult{}, err
		}
		return cm, r, true, HandlerResult{}, nil
	}
	if !apierrors.IsNotFound(getErr) {
		return nil, r, false, HandlerResult{}, getErr
	}
	if !servingObservationMatches(pod, r) {
		return nil, r, false, HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("protected serving selection is stale"))
	}
	if _, err := receiptAuthority(ctx, ec.Reader, r, req.Action); err != nil {
		return nil, r, false, HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("protected serving policy authority: %w", err))
	}
	if err := servingSlotAdmission(ctx, ec); err != nil {
		return nil, r, false, HandlerResult{}, RefusedWithoutEffect(err)
	}
	cm, err = journalWrite(ctx, ec, r)
	if err != nil {
		// Create acknowledgement loss is never proof that the claim does not exist.
		observed, recorded, readErr := servingReceiptGet(ctx, ec, req.TargetUID, req.Action)
		if readErr == nil {
			return observed, recorded, false, HandlerResult{}, fmt.Errorf("protected serving claim create acknowledgement uncertain: %w", err)
		}
		return nil, r, false, HandlerResult{}, fmt.Errorf("protected serving claim create outcome unknown: %w", err)
	}
	if err := servingPostCreateAdmission(ctx, ec, cm); err != nil {
		if IsNoEffectRefusal(err) {
			return nil, r, false, HandlerResult{}, err
		}
		return cm, r, false, HandlerResult{}, err
	}
	return cm, r, true, HandlerResult{}, nil
}

func claimServingDispatch(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt, next string) error {
	if r.Phase != "prepared" && !(r.Phase == "effect-confirmed" && next == "remote-dispatching") {
		return fmt.Errorf("protected serving phase %q cannot claim %q", r.Phase, next)
	}
	r.Phase = next
	return journalAdvance(ctx, ec, cm, *r)
}

func currentServingPod(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	if ec.Reader == nil {
		return nil, fmt.Errorf("protected serving authoritative reader unavailable")
	}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod); err != nil {
		return nil, err
	}
	if string(pod.UID) != r.TargetUID || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil {
		return nil, fmt.Errorf("protected serving target identity unavailable or changed")
	}
	return pod, nil
}

func revalidateServingDispatch(ctx context.Context, ec EnactCtx, req Request, r operationReceipt, requireSelected bool) (EnactCtx, servingEndpoint, error) {
	freshEC := ec
	if err := prepareServingAttempt(ctx, &freshEC, req); err != nil {
		return freshEC, servingEndpoint{}, fmt.Errorf("post-claim serving security revalidation: %w", err)
	}
	pod, err := currentServingPod(ctx, freshEC, r)
	if err != nil {
		return freshEC, servingEndpoint{}, err
	}
	pol, err := receiptAuthority(ctx, freshEC.Reader, r, model.Action(r.Kind))
	if err != nil {
		return freshEC, servingEndpoint{}, err
	}
	selector, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) {
		return freshEC, servingEndpoint{}, fmt.Errorf("post-claim target left current policy selector")
	}
	if requireSelected && !servingObservationMatches(pod, r) {
		return freshEC, servingEndpoint{}, fmt.Errorf("post-claim selected observation changed")
	}
	if model.Action(r.Kind) == model.ActionGuardrailRotate {
		switch r.Phase {
		case "dispatching":
			if pod.Annotations[annoGuardrailVariant] != r.PriorVariant || podOwned(pod.Annotations, annoGuardrailSnap) != r.PriorSnapshot {
				return freshEC, servingEndpoint{}, fmt.Errorf("post-claim guardrail prior variant or snapshot changed")
			}
		case "rollback-dispatching":
			if !servingExpectedMatches(pod, r) || podOwned(pod.Annotations, annoGuardrailSnap) != (routeOwnedValue{Present: true, Value: r.PriorVariant}) {
				return freshEC, servingEndpoint{}, fmt.Errorf("post-claim guardrail applied state changed before rollback")
			}
		}
	}
	if !servingReceiptSecurityMatches(freshEC, pod, r) {
		return freshEC, servingEndpoint{}, fmt.Errorf("post-claim serving binding or endpoint changed")
	}
	ep, err := servingEndpointForPod(ctx, freshEC, req, pod)
	return freshEC, ep, err
}

func patchServingMetadata(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.Pod, error) {
	for attempt := 0; attempt < metadataPatchAttempts; attempt++ {
		pod, err := currentServingPod(ctx, ec, r)
		if err != nil {
			return nil, err
		}
		pol, err := receiptAuthority(ctx, ec.Reader, r, model.Action(r.Kind))
		if err != nil {
			return nil, fmt.Errorf("protected serving metadata policy authority changed: %w", err)
		}
		selector, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
		if err != nil || selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) {
			return nil, fmt.Errorf("protected serving metadata target left current policy selector")
		}
		if !servingReceiptSecurityMatches(ec, pod, r) {
			return nil, fmt.Errorf("protected serving metadata binding or endpoint changed")
		}
		if servingExpectedMatches(pod, r) {
			return pod, nil
		}
		if !servingMetadataPreconditionMatches(pod, r) {
			return nil, fmt.Errorf("protected serving owned metadata changed after effect confirmation")
		}
		before := pod.DeepCopy()
		pod.Annotations = ensureMap(pod.Annotations)
		pod.Labels = ensureMap(pod.Labels)
		switch model.Action(r.Kind) {
		case model.ActionKVReset:
			setOwned(pod.Annotations, annoKVResetEpoch, r.ExpectedReset)
		case model.ActionKVMigrateInvalidate:
			setOwned(pod.Annotations, annoKVEpoch, r.ExpectedMigrate)
			setOwned(pod.Annotations, annoKVLocalEffect, r.ExpectedLocal)
		case model.ActionGuardrailRotate:
			if r.Phase == "rollback-confirmed" || r.Phase == "rolled-back" {
				pod.Annotations[annoGuardrailVariant] = r.PriorVariant
				setOwned(pod.Annotations, annoGuardrailSnap, r.PriorSnapshot)
			} else {
				pod.Annotations[annoGuardrailVariant] = r.NextVariant
				setOwned(pod.Annotations, annoGuardrailSnap, routeOwnedValue{Present: true, Value: r.PriorVariant})
			}
			setOwned(pod.Labels, "phorvex.ai/guardrail-epoch", r.ExpectedGuardrail)
		}
		if err := ec.Client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return nil, err
		}
		// The optimistic-lock Patch acknowledgement binds these desired bytes to
		// the exact Pod RV checked above. Validate the server-returned identity and
		// owned state before returning it; otherwise a success on the final bounded
		// attempt is falsely reported as non-convergence merely because there is no
		// spare loop iteration to reread.
		if string(pod.UID) != r.TargetUID || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil || !servingExpectedMatches(pod, r) {
			return nil, fmt.Errorf("protected serving metadata Patch acknowledgement is incomplete or changed")
		}
		return pod, nil
	}
	return nil, fmt.Errorf("protected serving metadata did not converge after %d conflicts", metadataPatchAttempts)
}

func confirmServingEffect(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) error {
	r.Phase = "effect-confirmed"
	return journalAdvance(ctx, ec, cm, *r)
}

func finishServingEffect(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt, terminal string, emitted bool, note string, terminalErr error) (HandlerResult, error) {
	pod, err := patchServingMetadata(ctx, ec, *r)
	if err != nil {
		return servingPartial(cm, *r, emitted, fmt.Errorf("%s metadata convergence: %w", r.Kind, err))
	}
	r.Phase = terminal
	if err := journalAdvance(ctx, ec, cm, *r); err != nil {
		return servingPartial(cm, *r, emitted, fmt.Errorf("%s terminal receipt acknowledgement: %w", r.Kind, err))
	}
	objects := []string{objRef("ConfigMap", cm.Namespace, cm.Name), objRef("Pod", pod.Namespace, pod.Name)}
	kind := "forward-only"
	if !emitted || terminal == "terminal-partial" {
		kind = "partial"
	}
	return HandlerResult{Emitted: emitted, MutationKind: kind, RollbackRef: servingReceiptRef(cm, *r), ObjectsTouched: objects, Note: note}, terminalErr
}

func persistServingMetadataIntent(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt, partial bool) error {
	if partial {
		r.Phase = "metadata-ready-partial"
	} else {
		r.Phase = "metadata-ready-full"
	}
	return journalAdvance(ctx, ec, cm, *r)
}

func validatePeerOutcomes(peers []string, outcomes []kvPeerOutcome) (allConfirmed, finalPartial, unknown bool, err error) {
	if len(outcomes) != len(peers) {
		return false, false, false, fmt.Errorf("peer outcome count %d does not match declared %d", len(outcomes), len(peers))
	}
	want := make(map[string]bool, len(peers))
	for _, peer := range peers {
		want[peer] = true
	}
	seen, confirmed, partial := make(map[string]bool, len(peers)), 0, 0
	for _, outcome := range outcomes {
		if !outcome.valid() || !want[outcome.Peer] || seen[outcome.Peer] {
			return false, false, false, fmt.Errorf("peer outcome set is malformed")
		}
		seen[outcome.Peer] = true
		switch outcome.Disposition {
		case kvPeerConfirmed:
			confirmed++
		case kvPeerNotSentUnimplemented, kvPeerRefusedBeforeSend:
			partial++
		case kvPeerUnknownAfterDispatch:
			unknown = true
		}
	}
	return confirmed == len(peers), !unknown && partial > 0, unknown, nil
}

func peerOutcomeCounts(outcomes []kvPeerOutcome) (confirmed, notSent, refused, unknown int) {
	for _, outcome := range outcomes {
		switch outcome.Disposition {
		case kvPeerConfirmed:
			confirmed++
		case kvPeerNotSentUnimplemented:
			notSent++
		case kvPeerRefusedBeforeSend:
			refused++
		case kvPeerUnknownAfterDispatch:
			unknown++
		}
	}
	return
}

func enactProtectedKVReset(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, refusal, err := authoritativeRawKVPod(ctx, ec, req, "kv-reset")
	if pod == nil {
		return protectedServingRefusal(ctx, ec, req, refusal, err)
	}
	ep, reason := declaredKVEndpoint(ctx, ec, req, pod)
	if reason != "" {
		fallback, refusalErr := refuseAI("kv-reset", reason)
		return protectedServingRefusal(ctx, ec, req, fallback, refusalErr)
	}
	cm, r, fresh, ready, err := prepareServingReceipt(ctx, ec, req, pod, nil, "", "")
	if result, resultErr, done := preparedServingResult(cm, r, fresh, ready, err); done {
		return result, resultErr
	}
	if err := claimServingDispatch(ctx, ec, cm, &r, "dispatching"); err != nil {
		return servingPartial(cm, r, false, err)
	}
	ec, ep, err = revalidateServingDispatch(ctx, ec, req, r, true)
	if err != nil {
		return servingPartial(cm, r, false, err)
	}
	callErr := ec.vllm().ResetPrefixCache(ctx, ep)
	if callErr != nil {
		if errors.Is(callErr, errStackUnreachable) {
			if err := journalFinish(ctx, ec, cm); err == nil {
				return HandlerResult{NoEffect: NoEffectRefused, MutationKind: "none", Note: "kv-reset refused before the serving request was sent"}, nil
			}
		}
		return servingPartial(cm, r, false, fmt.Errorf("kv-reset dispatch outcome unresolved: %w", callErr))
	}
	if err := confirmServingEffect(ctx, ec, cm, &r); err != nil {
		return servingPartial(cm, r, true, err)
	}
	return finishServingEffect(ctx, ec, cm, &r, "terminal-full", true, "kv-reset confirmed; protected epoch converged", nil)
}

func enactProtectedGuardrail(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.Client == nil || ec.Reader == nil || ec.JournalNamespace == "" {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("guardrail-rotate requires authoritative client, reader, and protected journal"))
	}
	pod, ok, err := getPod(ctx, ec.Reader, req.Namespace, req.Pod)
	if err != nil || !ok {
		return protectedServingRefusal(ctx, ec, req, HandlerResult{}, orGone(err, ok, "guardrail-rotate", req))
	}
	if string(pod.UID) != req.TargetUID || pod.DeletionTimestamp != nil || pod.Labels[labelGuardrailTier] != "true" || pod.Annotations[annoGuardrailAlts] == "" {
		return protectedServingRefusal(ctx, ec, req, HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("guardrail-rotate target identity or declaration unavailable")))
	}
	cur, next := pod.Annotations[annoGuardrailVariant], ""
	for _, candidate := range strings.Split(pod.Annotations[annoGuardrailAlts], ",") {
		if candidate = strings.TrimSpace(candidate); candidate != "" && candidate != cur {
			next = candidate
			break
		}
	}
	if next == "" {
		return protectedServingRefusal(ctx, ec, req, HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("guardrail-rotate has no distinct alternate variant")))
	}
	ep, endpointErr := servingEndpointForPod(ctx, ec, req, pod)
	if endpointErr != nil {
		return protectedServingRefusal(ctx, ec, req, HandlerResult{}, RefusedWithoutEffect(endpointErr))
	}
	cm, r, fresh, ready, err := prepareServingReceipt(ctx, ec, req, pod, nil, cur, next)
	if result, resultErr, done := preparedServingResult(cm, r, fresh, ready, err); done {
		return result, resultErr
	}
	if err := claimServingDispatch(ctx, ec, cm, &r, "dispatching"); err != nil {
		return servingPartial(cm, r, false, err)
	}
	ec, ep, err = revalidateServingDispatch(ctx, ec, req, r, true)
	if err != nil {
		return servingPartial(cm, r, false, err)
	}
	callErr := ec.guardrail().ApplyVariant(ctx, ep, next)
	if callErr != nil {
		if errors.Is(callErr, errStackUnreachable) {
			if err := journalFinish(ctx, ec, cm); err == nil {
				return HandlerResult{NoEffect: NoEffectRefused, MutationKind: "none", Note: "guardrail rotate refused before send"}, nil
			}
		}
		return servingPartial(cm, r, false, fmt.Errorf("guardrail dispatch outcome unresolved: %w", callErr))
	}
	if err := confirmServingEffect(ctx, ec, cm, &r); err != nil {
		return servingPartial(cm, r, true, err)
	}
	result, err := finishServingEffect(ctx, ec, cm, &r, "terminal-full", true, "guardrail variant synchronously confirmed and metadata converged", nil)
	if err == nil {
		result.MutationKind = "reversible"
	}
	return result, err
}

func enactProtectedKVMigrate(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, refusal, err := authoritativeRawKVPod(ctx, ec, req, "kv-migrate-invalidate")
	if pod == nil {
		return protectedServingRefusal(ctx, ec, req, refusal, err)
	}
	peers, err := parseDisaggKVPeers(pod.Annotations[annoDisaggPeers])
	if err != nil {
		return protectedServingRefusal(ctx, ec, req, HandlerResult{}, RefusedWithoutEffect(err))
	}
	ep, reason := declaredKVEndpoint(ctx, ec, req, pod)
	if reason != "" {
		fallback, refusalErr := refuseAI("kv-migrate-invalidate", reason)
		return protectedServingRefusal(ctx, ec, req, fallback, refusalErr)
	}
	cm, r, fresh, ready, err := prepareServingReceipt(ctx, ec, req, pod, peers, "", "")
	if result, resultErr, done := preparedServingResult(cm, r, fresh, ready, err); done {
		return result, resultErr
	}
	if err := claimServingDispatch(ctx, ec, cm, &r, "dispatching"); err != nil {
		return servingPartial(cm, r, false, err)
	}
	ec, ep, err = revalidateServingDispatch(ctx, ec, req, r, true)
	if err != nil {
		return servingPartial(cm, r, false, err)
	}
	localErr := ec.kvxfer().InvalidateLocal(ctx, ep)
	if localErr != nil {
		if errors.Is(localErr, errStackUnreachable) {
			if err := journalFinish(ctx, ec, cm); err == nil {
				return HandlerResult{NoEffect: NoEffectRefused, MutationKind: "none", Note: "KV local invalidation refused before send"}, nil
			}
		}
		return servingPartial(cm, r, false, fmt.Errorf("KV local invalidation unresolved: %w", localErr))
	}
	if err := confirmServingEffect(ctx, ec, cm, &r); err != nil {
		return servingPartial(cm, r, true, err)
	}
	if len(peers) == 0 {
		r.ExpectedMigrate = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "apply")}
		if err := persistServingMetadataIntent(ctx, ec, cm, &r, false); err != nil {
			return servingPartial(cm, r, true, err)
		}
		return finishServingEffect(ctx, ec, cm, &r, "terminal-full", true, "local KV invalidation confirmed; no remote peers declared", nil)
	}
	if err := claimServingDispatch(ctx, ec, cm, &r, "remote-dispatching"); err != nil {
		return servingPartial(cm, r, true, err)
	}
	ec, ep, err = revalidateServingDispatch(ctx, ec, req, r, true)
	if err != nil {
		return servingPartial(cm, r, true, err)
	}
	outcomes, remoteErr := ec.kvxfer().MigrateRemote(ctx, ep, peers)
	all, partial, unknown, validationErr := validatePeerOutcomes(peers, outcomes)
	r.PeerOutcomes = append([]kvPeerOutcome(nil), outcomes...)
	if validationErr != nil || unknown || (!all && !partial) || (all && remoteErr != nil) {
		r.Phase = "remote-unknown"
		_ = journalAdvance(ctx, ec, cm, r)
		return servingPartial(cm, r, true, errors.Join(remoteErr, validationErr, fmt.Errorf("remote KV outcome unresolved")))
	}
	if all {
		r.ExpectedMigrate = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "apply")}
		if err := persistServingMetadataIntent(ctx, ec, cm, &r, false); err != nil {
			return servingPartial(cm, r, true, err)
		}
		return finishServingEffect(ctx, ec, cm, &r, "terminal-full", true, "local and all declared remote KV invalidations confirmed", remoteErr)
	}
	r.ExpectedLocal = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "local-only")}
	if err := persistServingMetadataIntent(ctx, ec, cm, &r, true); err != nil {
		return servingPartial(cm, r, true, err)
	}
	confirmed, notSent, refused, _ := peerOutcomeCounts(outcomes)
	return finishServingEffect(ctx, ec, cm, &r, "terminal-partial", true, fmt.Sprintf("local KV invalidation confirmed; peer outcomes: confirmed=%d not-sent-unimplemented=%d refused-before-send=%d", confirmed, notSent, refused), errors.Join(remoteErr, fmt.Errorf("distributed KV invalidation remains partial")))
}

func rollbackProtectedGuardrail(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	cm, r, err := servingReceiptGet(ctx, ec, req.TargetUID, model.ActionGuardrailRotate)
	if err != nil {
		return err
	}
	if ref != servingReceiptRef(cm, r) || r.Kind != string(model.ActionGuardrailRotate) || r.Phase != "terminal-full" ||
		r.PolicyNamespace != req.Namespace || r.PolicyName != req.PolicyName || r.PolicyUID != req.PolicyUID || r.TargetName != req.Pod || r.TargetUID != req.TargetUID {
		return fmt.Errorf("guardrail rollback reference is stale or not terminal")
	}
	if _, err := receiptAuthority(ctx, ec.Reader, r, model.ActionGuardrailRotate); err != nil {
		return err
	}
	pod, err := currentServingPod(ctx, ec, r)
	if err != nil {
		return err
	}
	if !servingExpectedMatches(pod, r) || !servingReceiptSecurityMatches(ec, pod, r) {
		return fmt.Errorf("guardrail rollback current binding, endpoint, or terminal metadata changed")
	}
	ep, err := servingEndpointForPod(ctx, ec, req, pod)
	if err != nil {
		return err
	}
	r.Phase = "rollback-dispatching"
	if err := journalAdvance(ctx, ec, cm, r); err != nil {
		return err
	}
	ec, ep, err = revalidateServingDispatch(ctx, ec, req, r, false)
	if err != nil {
		return err
	}
	if err := ec.guardrail().ApplyVariant(ctx, ep, r.PriorVariant); err != nil {
		return fmt.Errorf("guardrail rollback outcome unresolved; protected receipt retained: %w", err)
	}
	r.Phase = "rollback-confirmed"
	r.ExpectedGuardrail = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "rollback")}
	if err := journalAdvance(ctx, ec, cm, r); err != nil {
		return err
	}
	if _, err := patchServingMetadata(ctx, ec, r); err != nil {
		return err
	}
	r.Phase = "rolled-back"
	return journalAdvance(ctx, ec, cm, r)
}

func recoverProtectedServingEffect(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, error) {
	if r == nil || cm == nil || r.Version != servingEffectReceiptVersion {
		return "", fmt.Errorf("protected serving recovery receipt unavailable")
	}
	if terminalServingPhase(r.Phase) {
		return fmt.Sprintf("terminal protected %s receipt retained without a new effect", r.Kind), nil
	}
	current, currentErr := currentServingPod(ctx, ec, *r)
	if currentErr != nil || !servingReceiptSecurityMatches(ec, current, *r) {
		return "", errors.Join(currentErr, fmt.Errorf("protected serving recovery binding or endpoint changed"))
	}
	if ec.ServingAttempt == nil || ec.ServingAttempt.selector == nil || ec.ServingAttempt.selector.Empty() || !ec.ServingAttempt.selector.Matches(labels.Set(current.Labels)) {
		return "", fmt.Errorf("protected serving recovery target left current policy scope")
	}
	if r.Phase == "dispatching" || r.Phase == "remote-dispatching" || r.Phase == "remote-unknown" || r.Phase == "rollback-dispatching" {
		return "", fmt.Errorf("protected %s dispatch remains unresolved; recovery will not repeat it", r.Kind)
	}
	if r.Phase == "metadata-ready-full" || r.Phase == "metadata-ready-partial" {
		terminal := "terminal-full"
		if r.Phase == "metadata-ready-partial" {
			terminal = "terminal-partial"
		}
		if _, err := patchServingMetadata(ctx, ec, *r); err != nil {
			return "", err
		}
		r.Phase = terminal
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return "", err
		}
		return fmt.Sprintf("confirmed %s metadata converged without another serving request", r.Kind), nil
	}
	if r.Phase == "effect-confirmed" || r.Phase == "rollback-confirmed" {
		if r.Phase == "effect-confirmed" && r.Kind == string(model.ActionKVMigrateInvalidate) {
			if r.RemoteExpected > 0 {
				return recoverProtectedKVRemote(ctx, ec, cm, r)
			}
			r.ExpectedMigrate = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "apply")}
			if err := persistServingMetadataIntent(ctx, ec, cm, r, false); err != nil {
				return "local KV effect confirmed", err
			}
			return recoverProtectedServingEffect(ctx, ec, cm, r)
		}
		if _, err := patchServingMetadata(ctx, ec, *r); err != nil {
			return "", err
		}
		if r.Phase == "rollback-confirmed" {
			r.Phase = "rolled-back"
		} else {
			r.Phase = "terminal-full"
		}
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return "", err
		}
		return fmt.Sprintf("confirmed %s metadata converged without another serving request", r.Kind), nil
	}
	if r.Phase != "prepared" {
		return "", fmt.Errorf("unsupported protected serving recovery phase %q", r.Phase)
	}
	pod, err := currentServingPod(ctx, ec, *r)
	if err != nil || !servingObservationMatches(pod, *r) {
		return "", errors.Join(err, fmt.Errorf("protected serving selected observation changed before recovery dispatch"))
	}
	req := ec.ServingRequest
	ep, err := servingEndpointForPod(ctx, ec, req, pod)
	if err != nil {
		return "", err
	}
	if err := claimServingDispatch(ctx, ec, cm, r, "dispatching"); err != nil {
		return "", err
	}
	ec, ep, err = revalidateServingDispatch(ctx, ec, req, *r, true)
	if err != nil {
		return "", err
	}
	switch model.Action(r.Kind) {
	case model.ActionKVReset:
		err = ec.vllm().ResetPrefixCache(ctx, ep)
	case model.ActionKVMigrateInvalidate:
		err = ec.kvxfer().InvalidateLocal(ctx, ep)
	case model.ActionGuardrailRotate:
		err = ec.guardrail().ApplyVariant(ctx, ep, r.NextVariant)
	}
	if err != nil {
		return "", fmt.Errorf("protected %s recovery dispatch unresolved: %w", r.Kind, err)
	}
	if err := confirmServingEffect(ctx, ec, cm, r); err != nil {
		return fmt.Sprintf("%s synchronous effect confirmed; receipt acknowledgement failed", r.Kind), err
	}
	if r.Kind == string(model.ActionKVMigrateInvalidate) && r.RemoteExpected > 0 {
		return recoverProtectedKVRemote(ctx, ec, cm, r)
	}
	if r.Kind == string(model.ActionKVMigrateInvalidate) {
		r.ExpectedMigrate = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "apply")}
		if err := persistServingMetadataIntent(ctx, ec, cm, r, false); err != nil {
			return "local KV effect confirmed", err
		}
	}
	_, finishErr := finishServingEffect(ctx, ec, cm, r, "terminal-full", false, "protected serving operation recovered and reconciled", nil)
	return fmt.Sprintf("%s recovered; no new mitigation credit", r.Kind), finishErr
}

func recoverProtectedKVRemote(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, error) {
	pod, err := currentServingPod(ctx, ec, *r)
	if err != nil {
		return "", err
	}
	ep, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, pod)
	if err != nil {
		return "", err
	}
	if err := claimServingDispatch(ctx, ec, cm, r, "remote-dispatching"); err != nil {
		return "", err
	}
	ec, ep, err = revalidateServingDispatch(ctx, ec, ec.ServingRequest, *r, true)
	if err != nil {
		return "", err
	}
	outcomes, remoteErr := ec.kvxfer().MigrateRemote(ctx, ep, r.DeclaredPeers)
	all, partial, unknown, validationErr := validatePeerOutcomes(r.DeclaredPeers, outcomes)
	r.PeerOutcomes = append([]kvPeerOutcome(nil), outcomes...)
	if validationErr != nil || unknown || (!all && !partial) || (all && remoteErr != nil) {
		r.Phase = "remote-unknown"
		_ = journalAdvance(ctx, ec, cm, *r)
		return "local KV effect retained", errors.Join(remoteErr, validationErr, fmt.Errorf("remote KV recovery outcome unresolved"))
	}
	if all {
		r.ExpectedMigrate = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "apply")}
		if err := persistServingMetadataIntent(ctx, ec, cm, r, false); err != nil {
			return "local and remote KV effects confirmed", err
		}
		_, err = finishServingEffect(ctx, ec, cm, r, "terminal-full", false, "recovered all-peer KV confirmation", remoteErr)
		return "local and remote KV effects reconciled without new credit", err
	}
	r.ExpectedLocal = routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "local-only")}
	if err := persistServingMetadataIntent(ctx, ec, cm, r, true); err != nil {
		return "local-only KV effect confirmed", err
	}
	confirmed, notSent, refused, _ := peerOutcomeCounts(outcomes)
	note := fmt.Sprintf("recovered local-only KV partial outcome; peer outcomes: confirmed=%d not-sent-unimplemented=%d refused-before-send=%d", confirmed, notSent, refused)
	_, err = finishServingEffect(ctx, ec, cm, r, "terminal-partial", false, note, errors.Join(remoteErr, fmt.Errorf("distributed KV invalidation remains partial")))
	return "local-only KV effect reconciled without full-session credit", err
}
