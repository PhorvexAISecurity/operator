package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	adapterObservationTimeout  = 3 * time.Second
	adapterObservationInterval = 25 * time.Millisecond
)

func adapterTiming(ec EnactCtx) (time.Duration, time.Duration) {
	timeout, interval := ec.AdapterObservationTimeout, ec.AdapterObservationInterval
	if timeout <= 0 {
		timeout = adapterObservationTimeout
	}
	if interval <= 0 {
		interval = adapterObservationInterval
	}
	return timeout, interval
}

func adapterEndpointConfigDigest(pod *corev1.Pod) string {
	ep := endpointForPod(pod)
	token := sha256.Sum256([]byte(ep.token))
	return digestJSON(struct {
		PodIP, ModelsPath, UnloadPath, LoadPath, TokenSHA256 string
		Port                                                 int
	}{ep.podIP, ep.modelsPath, ep.unloadPath, ep.loadPath, hex.EncodeToString(token[:]), ep.port})
}

func waitAdapterMembership(ctx context.Context, ec EnactCtx, ep servingEndpoint, adapter string, want bool) error {
	timeout, interval := adapterTiming(ec)
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		loaded, err := ec.vllm().AdapterLoaded(waitCtx, ep, adapter)
		if err != nil {
			return err
		}
		if loaded == want {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("adapter membership did not converge to loaded=%t: %w", want, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func adapterReceiptObservation(r operationReceipt) *model.AdapterObservation {
	createdAt, _ := time.Parse(time.RFC3339Nano, r.AdapterEventCreatedAt)
	return &model.AdapterObservation{
		EventName: r.AdapterEventName, EventUID: r.AdapterEventUID, CreatorIdentity: r.AdapterCreator,
		TargetPodUID: r.TargetUID, AdapterName: r.AdapterName, CreatedAt: createdAt,
	}
}

func adapterAuthority(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.Pod, error) {
	pol, err := receiptAuthority(ctx, ec.Reader, r, model.ActionAdapterRotate)
	if err != nil {
		return nil, err
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod); err != nil {
		return nil, err
	}
	if string(pod.UID) != r.TargetUID || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil {
		return nil, fmt.Errorf("adapter-rotate target identity changed")
	}
	if _, err := validatedEndpointForPod(pod); err != nil {
		return nil, fmt.Errorf("adapter-rotate serving endpoint configuration: %w", err)
	}
	sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || !sel.Matches(labels.Set(pod.Labels)) {
		return nil, fmt.Errorf("adapter-rotate target left current policy selector")
	}
	if adapterEndpointConfigDigest(pod) != r.AdapterEndpointSHA256 {
		return nil, fmt.Errorf("adapter-rotate serving endpoint configuration changed")
	}
	if _, err := validateAdapterDispatch(ctx, ec, Request{
		Namespace: r.PolicyNamespace, Pod: r.TargetName, TargetUID: r.TargetUID,
		Action: model.ActionAdapterRotate, AdapterObservation: adapterReceiptObservation(r),
	}, r.TargetUID); err != nil {
		return nil, err
	}
	source, present := ec.AdapterSources.source(r.PolicyNamespace, r.AdapterName)
	if present != r.AdapterSourcePresent || source != r.AdapterSource {
		return nil, fmt.Errorf("adapter-rotate approved source mapping changed")
	}
	return pod, nil
}

func adapterResult(cm *corev1.ConfigMap, emitted bool, kind, note string, pod *corev1.Pod) HandlerResult {
	objects := make([]string, 0, 2)
	rollback := ""
	if cm != nil {
		objects = append(objects, objRef("ConfigMap", cm.Namespace, cm.Name))
		rollback = cm.Namespace + "/" + cm.Name + "@" + string(cm.UID)
	}
	if pod != nil {
		objects = append(objects, objRef("Pod", pod.Namespace, pod.Name))
	}
	return HandlerResult{Emitted: emitted, MutationKind: kind, RollbackRef: rollback, ObjectsTouched: objects, Note: note}
}

func adapterPartial(cm *corev1.ConfigMap, cause error) (HandlerResult, error) {
	return adapterResult(cm, true, "partial", "adapter-rotate outcome partial or unknown; protected recovery receipt retained", nil), cause
}

func writeAdapterCompletion(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (*corev1.Pod, error) {
	pod, err := adapterAuthority(ctx, ec, *r)
	if err != nil {
		return nil, err
	}
	snap, _ := json.Marshal(map[string]string{"adapter": r.AdapterName, "eventUID": r.AdapterEventUID})
	before := pod.DeepCopy()
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Labels = ensureMap(pod.Labels)
	pod.Annotations[annoAdapterSnapshot] = string(snap)
	pod.Annotations["phorvex.ai/adapter-epoch"] = r.AdapterEventUID
	pod.Labels["phorvex.ai/adapter-epoch"] = r.AdapterEventUID
	if err := ec.Client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		return nil, err
	}
	fresh := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, fresh); err != nil {
		return nil, err
	}
	if string(fresh.UID) != r.TargetUID || fresh.Annotations["phorvex.ai/adapter-epoch"] != r.AdapterEventUID {
		return nil, fmt.Errorf("adapter-rotate completion epoch was not confirmed")
	}
	r.Phase = "completed"
	if err := journalAdvance(ctx, ec, cm, *r); err != nil {
		return fresh, err
	}
	return fresh, nil
}

func adapterEventStillCurrent(ctx context.Context, ec EnactCtx, r operationReceipt) (bool, error) {
	if ec.Reader == nil {
		return false, fmt.Errorf("authoritative reader unavailable")
	}
	se := &unstructured.Unstructured{}
	se.SetAPIVersion("amtd.r6security.com/v1beta1")
	se.SetKind("SecurityEvent")
	err := ec.Reader.Get(ctx, client.ObjectKey{Name: r.AdapterEventName}, se)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	created := se.GetCreationTimestamp()
	age := time.Since(created.Time)
	return string(se.GetUID()) == r.AdapterEventUID && created.Time.UTC().Format(time.RFC3339Nano) == r.AdapterEventCreatedAt && se.GetDeletionTimestamp() == nil && !created.IsZero() && age >= 0 && age < adapterHorizon, nil
}

func continueAdapterOperation(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt, newAttempt bool) (HandlerResult, error) {
	if r.Phase == "completed" {
		current, err := adapterEventStillCurrent(ctx, ec, *r)
		if err != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate completed receipt revalidation: %w", err))
		}
		if current {
			result := adapterResult(cm, false, "none", "adapter-rotate already completed for the current trusted detector event; no new mitigation credited", nil)
			result.NoEffect = NoEffectReconciled
			return result, nil
		}
		if err := journalFinish(ctx, ec, cm); err != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate retire completed receipt: %w", err))
		}
		return HandlerResult{Emitted: false, NoEffect: NoEffectReconciled, MutationKind: "none", Note: "adapter-rotate retired completed receipt after detector authority ended"}, nil
	}
	pod, err := adapterAuthority(ctx, ec, *r)
	if err != nil {
		return adapterPartial(cm, fmt.Errorf("adapter-rotate recovery authority: %w", err))
	}
	ep, endpointErr := validatedEndpointForPod(pod)
	if endpointErr != nil {
		return adapterPartial(cm, fmt.Errorf("adapter-rotate serving endpoint configuration: %w", endpointErr))
	}
	if r.Phase == "prepared" {
		if err := journalFinish(ctx, ec, cm); err != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate finish unclaimed intent: %w", err))
		}
		return HandlerResult{Emitted: false, NoEffect: NoEffectReconciled, MutationKind: "none", Note: "adapter-rotate prepared intent retired before serving dispatch"}, nil
	}
	if r.Phase == "unload-dispatching" {
		loaded, observeErr := ec.vllm().AdapterLoaded(ctx, ep, r.AdapterName)
		if observeErr != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate pre-retry inventory unavailable: %w", observeErr))
		}
		if !loaded {
			// A prior POST may have completed while its acknowledgement or phase CAS was
			// lost. Inventory is the terminal authority; resume clean reload without a
			// duplicate unload.
			r.Phase = "absent-confirmed"
			if err := journalAdvance(ctx, ec, cm, *r); err != nil {
				return adapterPartial(cm, fmt.Errorf("adapter-rotate record recovered absence: %w", err))
			}
		} else {
			uerr := ec.vllm().UnloadAdapter(ctx, ep, r.AdapterName)
			if uerr != nil && !errors.Is(uerr, errAdapterAbsent) {
				return adapterPartial(cm, fmt.Errorf("adapter-rotate unload dispatch outcome unknown: %w", uerr))
			}
			r.Phase = "unload-acknowledged"
			if err := journalAdvance(ctx, ec, cm, *r); err != nil {
				return adapterPartial(cm, fmt.Errorf("adapter-rotate record unload acknowledgement: %w", err))
			}
			if errors.Is(uerr, errAdapterAbsent) {
				loaded, observeErr = ec.vllm().AdapterLoaded(ctx, ep, r.AdapterName)
				if observeErr != nil {
					return adapterPartial(cm, fmt.Errorf("adapter-rotate 404 inventory unavailable: %w", observeErr))
				}
				if loaded {
					return adapterPartial(cm, fmt.Errorf("adapter-rotate 404 contradicted by current inventory"))
				}
				r.Phase = "absent-confirmed"
				if err := journalAdvance(ctx, ec, cm, *r); err != nil {
					return adapterPartial(cm, fmt.Errorf("adapter-rotate record 404-confirmed inventory absence: %w", err))
				}
			}
		}
	}
	if r.Phase == "unload-acknowledged" {
		if err := waitAdapterMembership(ctx, ec, ep, r.AdapterName, false); err != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate unload unconfirmed: %w", err))
		}
		r.Phase = "absent-confirmed"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate record confirmed absence: %w", err))
		}
	}
	if r.Phase == "absent-confirmed" && r.AdapterSourcePresent {
		r.Phase = "load-dispatching"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate claim clean reload: %w", err))
		}
	}
	if r.Phase == "load-dispatching" {
		loaded, observeErr := ec.vllm().AdapterLoaded(ctx, ep, r.AdapterName)
		if observeErr != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate pre-retry clean-load inventory unavailable: %w", observeErr))
		}
		if loaded {
			r.Phase = "loaded-confirmed"
			if err := journalAdvance(ctx, ec, cm, *r); err != nil {
				return adapterPartial(cm, fmt.Errorf("adapter-rotate record recovered loaded membership: %w", err))
			}
		} else {
			if err := ec.vllm().LoadAdapter(ctx, ep, r.AdapterName, r.AdapterSource); err != nil {
				return adapterPartial(cm, fmt.Errorf("adapter-rotate configured clean reload outcome unknown: %w", err))
			}
			r.Phase = "load-acknowledged"
			if err := journalAdvance(ctx, ec, cm, *r); err != nil {
				return adapterPartial(cm, fmt.Errorf("adapter-rotate record load acknowledgement: %w", err))
			}
		}
	}
	if r.Phase == "load-acknowledged" {
		if err := waitAdapterMembership(ctx, ec, ep, r.AdapterName, true); err != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate clean reload unconfirmed: %w", err))
		}
		r.Phase = "loaded-confirmed"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return adapterPartial(cm, fmt.Errorf("adapter-rotate record confirmed load: %w", err))
		}
	}
	if r.Phase != "absent-confirmed" && r.Phase != "loaded-confirmed" {
		return adapterPartial(cm, fmt.Errorf("adapter-rotate unsupported recovery phase %q", r.Phase))
	}
	loaded, observeErr := ec.vllm().AdapterLoaded(ctx, ep, r.AdapterName)
	if observeErr != nil {
		return adapterPartial(cm, fmt.Errorf("adapter-rotate final inventory unavailable: %w", observeErr))
	}
	if loaded != r.AdapterSourcePresent {
		return adapterPartial(cm, fmt.Errorf("adapter-rotate terminal membership drifted before completion: loaded=%t want=%t", loaded, r.AdapterSourcePresent))
	}
	completedPod, err := writeAdapterCompletion(ctx, ec, cm, r)
	if err != nil {
		return adapterPartial(cm, fmt.Errorf("adapter-rotate completion: %w", err))
	}
	if !newAttempt {
		result := adapterResult(cm, false, "none", "adapter-rotate reconciled a prior protected operation; no new mitigation credited", completedPod)
		result.NoEffect = NoEffectReconciled
		return result, nil
	}
	note := "adapter " + r.AdapterName + " absence confirmed from serving inventory; degraded to base model"
	if r.AdapterSourcePresent {
		note = "adapter " + r.AdapterName + " absence confirmed; exact membership restored after the configured recovery path; artifact bytes and source provenance not attested"
	}
	return adapterResult(cm, true, "forward-only", "adapter-rotate: "+note, completedPod), nil
}

func enactAdapterRotate(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.Client == nil || ec.Reader == nil {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate requires a Kubernetes client and authoritative reader"))
	}
	pod, ok, err := getPod(ctx, ec.Reader, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "adapter-rotate", req)
	}
	adapter, err := validateAdapterDispatch(ctx, ec, req, string(pod.UID))
	if err != nil {
		return HandlerResult{Emitted: false, NoEffect: NoEffectRefused, MutationKind: "none", Note: err.Error()}, nil
	}
	if pod.Labels[labelLoRAEnabled] != "true" {
		return HandlerResult{Emitted: false, NoEffect: NoEffectRefused, MutationKind: "none", Note: "adapter-rotate unsupported: LoRA capability unavailable"}, nil
	}
	if ec.JournalNamespace == "" || req.PolicyName == "" || req.PolicyUID == "" || req.TargetUID == "" {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate requires authoritative reader, protected journal, policy and target identity"))
	}
	ep, endpointErr := validatedEndpointForPod(pod)
	if endpointErr != nil {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate serving endpoint configuration: %w", endpointErr))
	}
	source, sourcePresent := ec.AdapterSources.source(req.Namespace, adapter)
	r := operationReceipt{
		Version: adapterRotateReceiptVersion, Kind: "adapter-rotate", Phase: "prepared",
		PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		TargetName: pod.Name, TargetUID: string(pod.UID), TargetLabels: copyLabels(pod.Labels),
		AdapterName: adapter, AdapterSource: source, AdapterSourcePresent: sourcePresent,
		AdapterEventName: req.AdapterObservation.EventName, AdapterEventUID: req.AdapterObservation.EventUID,
		AdapterEventCreatedAt: req.AdapterObservation.CreatedAt.UTC().Format(time.RFC3339Nano),
		AdapterCreator:        req.AdapterObservation.CreatorIdentity, AdapterEndpointSHA256: adapterEndpointConfigDigest(pod),
	}
	if !r.valid() {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate bounded receipt preconditions are invalid"))
	}
	if _, err := receiptAuthority(ctx, ec.Reader, r, model.ActionAdapterRotate); err != nil {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate policy authority: %w", err))
	}
	var replaceCompleted *corev1.ConfigMap
	if cm, recorded, requireErr := journalRequire(ctx, ec, r); requireErr == nil {
		if recorded.Kind != r.Kind || recorded.AdapterName != r.AdapterName {
			return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate pending protected operation conflicts with current request"))
		}
		if recorded.AdapterEventUID == r.AdapterEventUID {
			return continueAdapterOperation(ctx, ec, cm, &recorded, false)
		}
		oldCreatedAt, oldErr := time.Parse(time.RFC3339Nano, recorded.AdapterEventCreatedAt)
		newCreatedAt, newErr := time.Parse(time.RFC3339Nano, r.AdapterEventCreatedAt)
		if recorded.Phase != "completed" || oldErr != nil || newErr != nil || !newCreatedAt.After(oldCreatedAt) {
			return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate pending protected operation conflicts with current request"))
		}
		replaceCompleted = cm
	} else if !apierrors.IsNotFound(requireErr) {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate protected operation lookup: %w", requireErr))
	}
	loaded, err := ec.vllm().AdapterLoaded(ctx, ep, adapter)
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate pre-dispatch inventory unavailable: %w", err))
	}
	if !loaded {
		return HandlerResult{Emitted: false, NoEffect: NoEffectSatisfied, MutationKind: "none", Note: "adapter-rotate inventory confirms adapter already absent before operation; no new mitigation credited"}, nil
	}
	cm := replaceCompleted
	if cm != nil {
		if err := journalAdvance(ctx, ec, cm, r); err != nil {
			return adapterResult(cm, false, "none", "adapter-rotate could not claim a newer trusted event", nil), RefusedWithoutEffect(err)
		}
	} else {
		cm, err = journalWrite(ctx, ec, r)
	}
	if apierrors.IsAlreadyExists(err) {
		cm, recorded, requireErr := journalRequire(ctx, ec, r)
		if requireErr != nil || recorded.Kind != r.Kind || recorded.AdapterEventUID != r.AdapterEventUID || recorded.AdapterName != r.AdapterName {
			return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("adapter-rotate pending protected operation conflicts with current request: %w", requireErr))
		}
		return continueAdapterOperation(ctx, ec, cm, &recorded, false)
	}
	if err != nil {
		return HandlerResult{}, fmt.Errorf("adapter-rotate prepare receipt: %w", err)
	}
	if _, err := adapterAuthority(ctx, ec, r); err != nil {
		finishErr := journalFinish(ctx, ec, cm)
		return adapterResult(cm, false, "none", "adapter-rotate refused before serving dispatch", nil), fmt.Errorf("adapter-rotate authority changed after preparation: %w", errors.Join(err, finishErr))
	}
	r.Phase = "unload-dispatching"
	if err := journalAdvance(ctx, ec, cm, r); err != nil {
		return adapterPartial(cm, fmt.Errorf("adapter-rotate claim unload dispatch: %w", err))
	}
	return continueAdapterOperation(ctx, ec, cm, &r, true)
}

func recoverAdapterRotate(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, error) {
	result, err := continueAdapterOperation(ctx, ec, cm, r, false)
	return result.Note, err
}
