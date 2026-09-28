package actuator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	requestDrainObservationTimeout  = 3 * time.Second
	requestDrainObservationInterval = 25 * time.Millisecond
)

func newRequestDrainToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("request-drain operation token: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func requestDrainTiming(ec EnactCtx) (time.Duration, time.Duration) {
	timeout, interval := ec.DrainObservationTimeout, ec.DrainObservationInterval
	if timeout <= 0 {
		timeout = requestDrainObservationTimeout
	}
	if interval <= 0 {
		interval = requestDrainObservationInterval
	}
	return timeout, interval
}

func drainEndpointConfigDigest(pod *corev1.Pod) string {
	ep := endpointForPod(pod)
	tokenDigest := sha256.Sum256([]byte(ep.token))
	return digestJSON(struct {
		PodIP       string `json:"podIP"`
		Port        int    `json:"port"`
		DrainPath   string `json:"drainPath"`
		TokenSHA256 string `json:"tokenSHA256"`
	}{PodIP: ep.podIP, Port: ep.port, DrainPath: ep.drainPath, TokenSHA256: hex.EncodeToString(tokenDigest[:])})
}

func secureDrainEndpointConfigDigest(pod *corev1.Pod) string {
	ep := endpointForPod(pod)
	return digestJSON(struct {
		PodIP     string `json:"podIP"`
		Port      int    `json:"port"`
		DrainPath string `json:"drainPath"`
	}{PodIP: ep.podIP, Port: ep.port, DrainPath: ep.drainPath})
}

func drainReceiptEndpointConfigDigest(pod *corev1.Pod, version int) string {
	if version == requestDrainSecureReceiptVersion || version == operationDrainReceiptVersion {
		return secureDrainEndpointConfigDigest(pod)
	}
	return drainEndpointConfigDigest(pod)
}

func authoritativeDrainPod(ctx context.Context, ec EnactCtx, req Request) (*corev1.Pod, error) {
	if ec.Reader == nil || req.TargetUID == "" {
		return nil, RefusedWithoutEffect(fmt.Errorf("request-drain requires authoritative reader and selected target UID"))
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		return nil, RefusedWithoutEffect(fmt.Errorf("request-drain target read: %w", err))
	}
	if string(pod.UID) != req.TargetUID || pod.UID == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil {
		return nil, RefusedWithoutEffect(fmt.Errorf("request-drain target identity changed or is terminating"))
	}
	ep, endpointErr := servingEndpointForPod(ctx, ec, req, pod)
	if endpointErr != nil {
		return nil, RefusedWithoutEffect(fmt.Errorf("request-drain target serving endpoint configuration: %w", endpointErr))
	}
	if pod.Status.PodIP == "" || !ep.reachable() {
		return nil, RefusedWithoutEffect(fmt.Errorf("request-drain target serving endpoint is unavailable"))
	}
	return pod, nil
}

func serviceSelectsDrainTarget(svc *corev1.Service, pod *corev1.Pod) bool {
	if svc == nil || pod == nil || svc.Namespace != pod.Namespace || svc.UID == "" || svc.ResourceVersion == "" || svc.DeletionTimestamp != nil || len(svc.Spec.Selector) == 0 {
		return false
	}
	if _, ok := svc.Spec.Selector[labelServing]; !ok {
		return false
	}
	return labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(pod.Labels))
}

func bindDrainService(ctx context.Context, reader client.Reader, pod *corev1.Pod) (*corev1.Service, error) {
	if reader == nil || pod == nil {
		return nil, fmt.Errorf("request-drain Service authority unavailable")
	}
	declared := pod.Annotations[annoRouteService]
	if declared != "" {
		svc := &corev1.Service{}
		if err := reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: declared}, svc); err != nil {
			return nil, fmt.Errorf("request-drain declared Service %s/%s: %w", pod.Namespace, declared, err)
		}
		if !serviceSelectsDrainTarget(svc, pod) {
			return nil, fmt.Errorf("request-drain declared Service no longer selects the target through %s", labelServing)
		}
		return svc, nil
	}
	var services corev1.ServiceList
	if err := reader.List(ctx, &services, client.InNamespace(pod.Namespace)); err != nil {
		return nil, fmt.Errorf("request-drain Service inventory: %w", err)
	}
	valid := make([]*corev1.Service, 0, len(services.Items))
	for i := range services.Items {
		if serviceSelectsDrainTarget(&services.Items[i], pod) {
			valid = append(valid, &services.Items[i])
		}
	}
	if len(valid) == 0 {
		return nil, fmt.Errorf("request-drain has no current selecting Service")
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].Name < valid[j].Name })
	return valid[0].DeepCopy(), nil
}

func endpointActive(e discoveryv1.Endpoint) bool {
	return (e.Conditions.Ready == nil || *e.Conditions.Ready) && (e.Conditions.Serving == nil || *e.Conditions.Serving) && (e.Conditions.Terminating == nil || !*e.Conditions.Terminating)
}

func endpointSliceOwnedByService(slice *discoveryv1.EndpointSlice, service *corev1.Service) bool {
	if slice == nil || service == nil {
		return false
	}
	for _, owner := range slice.OwnerReferences {
		if owner.APIVersion == "v1" && owner.Kind == "Service" && owner.Name == service.Name && owner.UID == service.UID {
			return true
		}
	}
	return false
}

func drainEndpointAddresses(ctx context.Context, reader client.Reader, service *corev1.Service, pod *corev1.Pod) ([]string, error) {
	if reader == nil || service == nil || pod == nil {
		return nil, fmt.Errorf("request-drain EndpointSlice authority unavailable")
	}
	var slices discoveryv1.EndpointSliceList
	if err := reader.List(ctx, &slices, client.InNamespace(service.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: service.Name}); err != nil {
		return nil, fmt.Errorf("request-drain EndpointSlice inventory: %w", err)
	}
	addresses := map[string]bool{}
	for i := range slices.Items {
		slice := &slices.Items[i]
		// The service-name label is not ownership. Ignore a stale slice left by a
		// same-name Service incarnation; it can neither prove withdrawal nor return.
		if !endpointSliceOwnedByService(slice, service) {
			continue
		}
		if slice.UID == "" || slice.ResourceVersion == "" || slice.DeletionTimestamp != nil {
			return nil, fmt.Errorf("request-drain EndpointSlice identity incomplete")
		}
		for _, endpoint := range slice.Endpoints {
			ref := endpoint.TargetRef
			if ref == nil || ref.Kind != "Pod" || ref.Namespace != pod.Namespace || ref.Name != pod.Name || ref.UID != pod.UID || !endpointActive(endpoint) {
				continue
			}
			for _, address := range endpoint.Addresses {
				if address == pod.Status.PodIP {
					addresses[address] = true
				}
			}
		}
	}
	out := make([]string, 0, len(addresses))
	for address := range addresses {
		out = append(out, address)
	}
	sort.Strings(out)
	if len(out) > requestDrainMaxAddresses {
		return nil, fmt.Errorf("request-drain endpoint address set exceeds %d", requestDrainMaxAddresses)
	}
	return out, nil
}

func readBoundDrainService(ctx context.Context, reader client.Reader, r operationReceipt) (*corev1.Service, error) {
	svc := &corev1.Service{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.ServiceName}, svc); err != nil {
		return nil, err
	}
	if string(svc.UID) != r.ServiceUID || svc.UID == "" || svc.ResourceVersion == "" || svc.DeletionTimestamp != nil || !reflect.DeepEqual(svc.Spec.Selector, r.ServiceSelector) {
		return nil, fmt.Errorf("request-drain bound Service identity or selector changed")
	}
	return svc, nil
}

func sameAddressSet(got, want []string) bool {
	for _, expected := range want {
		for _, observed := range got {
			if observed == expected {
				return true
			}
		}
	}
	return false
}

func waitDrainEndpointState(ctx context.Context, ec EnactCtx, r operationReceipt, wantPresent bool) error {
	timeout, interval := requestDrainTiming(ec)
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		svc, err := readBoundDrainService(waitCtx, ec.Reader, r)
		if err != nil {
			return fmt.Errorf("request-drain bound Service revalidation: %w", err)
		}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: r.PolicyNamespace, Name: r.TargetName, UID: types.UID(r.TargetUID)}, Status: corev1.PodStatus{PodIP: r.EndpointAddresses[0]}}
		addresses, err := drainEndpointAddresses(waitCtx, ec.Reader, svc, pod)
		if err != nil {
			return err
		}
		present := sameAddressSet(addresses, r.EndpointAddresses)
		if present == wantPresent {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("request-drain EndpointSlice observation timed out waiting present=%t: %w", wantPresent, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func requestDrainResult(cm *corev1.ConfigMap, pod *corev1.Pod, emitted bool, note string, terminal ...*operationReceipt) HandlerResult {
	objects := make([]string, 0, 2)
	rollback := ""
	if pod != nil {
		objects = append(objects, objRef("Pod", pod.Namespace, pod.Name))
	}
	if cm != nil {
		objects = append(objects, objRef("ConfigMap", cm.Namespace, cm.Name))
		rollback = cm.Namespace + "/" + cm.Name + "@" + string(cm.UID)
	}
	result := HandlerResult{Emitted: emitted, MutationKind: "reversible", RollbackRef: rollback, ObjectsTouched: objects, Note: note}
	if len(terminal) == 1 && terminal[0] != nil {
		r := terminal[0]
		if r.Version == operationDrainReceiptVersion && r.Kind == "request-drain" &&
			r.Phase == "restored" && r.DrainV11 != nil && r.DrainV11.reopened() {
			result.DrainOperation = &model.DrainOperationEvidence{
				OperationID: r.DrainV11.OperationID, Generation: r.DrainV11.OperationGeneration,
				PolicyUID: r.PolicyUID, TargetUID: r.TargetUID, ServiceUID: r.ServiceUID,
				BackendIncarnation: r.DrainV11.BackendIncarnation, ReceiptSHA256: r.DrainV11.ReceiptSHA256,
				ProxyActive: r.DrainV11.ProxyActive, SnapshotRunning: r.DrainV11.SnapshotRunning,
				Aborted: r.DrainV11.Aborted, CompletedBefore: r.DrainV11.CompletedBeforeAbort,
				SnapshotRequests: append([]string(nil), r.DrainV11.SnapshotDigests...),
				Dispositions:     append([]model.DrainRequestDisposition(nil), r.DrainV11.TerminalDigests...),
				Reopened:         true, Restored: true,
			}
		}
	}
	return result
}

func drainPodWithReceipt(ctx context.Context, ec EnactCtx, pod *corev1.Pod, r operationReceipt) (*corev1.Pod, bool, error) {
	before := pod.DeepCopy()
	pod.Labels = ensureMap(pod.Labels)
	pod.Labels[labelServing] = "drained"
	pod.Labels[labelDrainEpoch] = r.OperationToken
	if err := ec.Client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		return nil, false, err
	}
	fresh := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, fresh); err != nil {
		return nil, true, err
	}
	if string(fresh.UID) != r.TargetUID || fresh.Labels[labelServing] != "drained" || fresh.Labels[labelDrainEpoch] != r.OperationToken {
		return nil, true, fmt.Errorf("request-drain stop-admit write not confirmed")
	}
	return fresh, true, nil
}

func revalidateDrainDispatch(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.Pod, error) {
	fresh := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, fresh); err != nil {
		return nil, err
	}
	if string(fresh.UID) != r.TargetUID || fresh.UID == "" || fresh.ResourceVersion == "" || fresh.DeletionTimestamp != nil || fresh.Labels[labelServing] != "drained" || fresh.Labels[labelDrainEpoch] != r.OperationToken {
		return nil, fmt.Errorf("request-drain target identity or operation state changed before abort")
	}
	if _, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, fresh); err != nil {
		return nil, fmt.Errorf("request-drain target serving endpoint configuration: %w", err)
	}
	if drainReceiptEndpointConfigDigest(fresh, r.Version) != r.EndpointConfigSHA256 || fresh.Status.PodIP != r.EndpointAddresses[0] {
		return nil, fmt.Errorf("request-drain serving endpoint configuration changed before abort")
	}
	svc, err := readBoundDrainService(ctx, ec.Reader, r)
	if err != nil {
		return nil, err
	}
	addresses, err := drainEndpointAddresses(ctx, ec.Reader, svc, fresh)
	if err != nil {
		return nil, err
	}
	if sameAddressSet(addresses, r.EndpointAddresses) {
		return nil, fmt.Errorf("request-drain endpoint returned before abort dispatch")
	}
	return fresh, nil
}

func servingRestored(pod *corev1.Pod, r operationReceipt) bool {
	value, present := pod.Labels[labelServing]
	return present == r.PriorServingPresent && (!present || value == r.PriorServingValue)
}

func restoreDrainPod(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod); err != nil {
		return nil, err
	}
	if string(pod.UID) != r.TargetUID || pod.UID == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil {
		return nil, fmt.Errorf("request-drain restore target identity changed")
	}
	if pod.Labels[labelDrainEpoch] != r.OperationToken {
		return nil, fmt.Errorf("request-drain restore token changed")
	}
	if !servingRestored(pod, r) {
		if pod.Labels[labelServing] != "drained" {
			return nil, fmt.Errorf("request-drain serving state changed outside the operation")
		}
		before := pod.DeepCopy()
		pod.Labels = ensureMap(pod.Labels)
		if r.PriorServingPresent {
			pod.Labels[labelServing] = r.PriorServingValue
		} else {
			delete(pod.Labels, labelServing)
		}
		if err := ec.Client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return nil, err
		}
	}
	fresh := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, fresh); err != nil {
		return nil, err
	}
	if string(fresh.UID) != r.TargetUID || fresh.Labels[labelDrainEpoch] != r.OperationToken || !servingRestored(fresh, r) {
		return nil, fmt.Errorf("request-drain exact restoration not confirmed")
	}
	return fresh, nil
}

func recoverRequestDrain(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, bool, error) {
	if cm == nil || r == nil || r.Kind != "request-drain" || !r.valid() {
		return "", false, fmt.Errorf("request-drain recovery receipt invalid")
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return "original Pod absent; receipt retained without mutating a replacement", requestDrainWriteConfirmed(*r, nil), err
		}
		return "authoritative Pod outcome unreadable; receipt retained", requestDrainWriteConfirmed(*r, nil), err
	}
	if string(pod.UID) != r.TargetUID {
		return "same-name replacement left untouched; receipt retained", requestDrainWriteConfirmed(*r, pod), fmt.Errorf("request-drain target UID changed")
	}
	if r.Phase == "prepared" && pod.Labels[labelDrainEpoch] != r.OperationToken && servingRestored(pod, *r) {
		if _, err := readBoundDrainService(ctx, ec.Reader, *r); err != nil {
			return "prepared operation made no confirmed Pod mutation; receipt retained", false, err
		}
		if err := waitDrainEndpointState(ctx, ec, *r, true); err != nil {
			return "prepared operation made no confirmed Pod mutation; endpoint membership unresolved; receipt retained", false, err
		}
		if err := journalFinish(ctx, ec, cm); err != nil {
			return "prepared operation made no confirmed Pod mutation", false, err
		}
		return "prepared operation made no confirmed Pod mutation; receipt finished", false, nil
	}
	confirmedWrite := requestDrainWriteConfirmed(*r, pod)
	// The receipt binds restoration authority to the exact Service identity and
	// selector observed before the stop-admit write. A replacement or selector edit
	// is user-owned state; detect it before writing the Pod and retain the receipt.
	if _, err := readBoundDrainService(ctx, ec.Reader, *r); err != nil {
		return "request-drain Service authority changed; Pod left untouched and receipt retained", confirmedWrite, err
	}
	if r.DrainV11 != nil && r.DrainV11.CreateRejection != nil {
		if drainReceiptEndpointConfigDigest(pod, r.Version) != r.EndpointConfigSHA256 || pod.Status.PodIP != r.EndpointAddresses[0] {
			return "request-drain rejection endpoint authority changed; receipt retained", confirmedWrite, fmt.Errorf("request-drain rejection endpoint configuration changed")
		}
		if _, err := receiptAuthority(ctx, ec.Reader, *r, model.ActionRequestDrain); err != nil {
			return "request-drain rejection policy authority changed; receipt retained", confirmedWrite, err
		}
		ep, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, pod)
		if err == nil {
			_, err = drainV11UnadvancedCapability(ctx, ec, ep, r.DrainV11)
		}
		if err != nil {
			return "request-drain rejected create OPEN authority unresolved; receipt retained", confirmedWrite, err
		}
	}
	if r.Version == operationDrainReceiptVersion && r.Phase == "drain-dispatching-v11" {
		ep, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, pod)
		if err != nil {
			return "request-drain operation status pending", confirmedWrite, err
		}
		if err := recoverDrainV11(ctx, ec, ep, r, func() error {
			return journalAdvance(ctx, ec, cm, *r)
		}); errors.Is(err, errDrainV11CancellationRequired) {
			if cancelErr := recoverDrainV11Cancellation(ctx, ec, ep, r, func() error {
				return journalAdvance(ctx, ec, cm, *r)
			}); !errors.Is(cancelErr, errDrainV11Cancelled) {
				return "request-drain cancellation retained for GET-only recovery", confirmedWrite, cancelErr
			}
		} else if err != nil {
			return "request-drain operation status retained for GET-only recovery", confirmedWrite, err
		}
		if r.Phase != "drain-cancelled-v11" {
			r.Aborted = r.DrainV11.Aborted
			r.Phase = "drain-confirmed-v11"
			if err := journalAdvance(ctx, ec, cm, *r); err != nil {
				return "request-drain operation confirmed; receipt phase unresolved", confirmedWrite, err
			}
		}
	}
	if r.Version == operationDrainReceiptVersion && r.Phase == "drain-cancel-dispatching-v11" {
		ep, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, pod)
		if err != nil {
			return "request-drain cancellation pending", confirmedWrite, err
		}
		if cancelErr := recoverDrainV11Cancellation(ctx, ec, ep, r, func() error {
			return journalAdvance(ctx, ec, cm, *r)
		}); !errors.Is(cancelErr, errDrainV11Cancelled) {
			return "request-drain cancellation retained for GET-only recovery", confirmedWrite, cancelErr
		}
	}
	if r.Version == operationDrainReceiptVersion && r.Phase == "drain-confirmed-v11" {
		// An engine process restart need not change the Pod/container tuple. Refresh
		// the exact backend operation before claiming reopen so an internally stale
		// receipt is superseded rather than trusted.
		ep, endpointErr := servingEndpointForPod(ctx, ec, ec.ServingRequest, pod)
		if endpointErr != nil {
			return "request-drain quiesced; backend incarnation changed before reopen", confirmedWrite, endpointErr
		}
		if recoveryErr := recoverDrainV11(ctx, ec, ep, r, func() error {
			return journalAdvance(ctx, ec, cm, *r)
		}); recoveryErr != nil {
			return "request-drain quiesced; backend incarnation changed before reopen", confirmedWrite, recoveryErr
		}
		r.Aborted = r.DrainV11.Aborted
		r.Phase = "drain-confirmed-v11"
		if journalErr := journalAdvance(ctx, ec, cm, *r); journalErr != nil {
			return "replacement request-drain confirmed; receipt phase pending", confirmedWrite, journalErr
		}
		r.DrainV11.ReopenRequests = 1
		r.Phase = "reopen-dispatching-v11"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return "request-drain quiesced; backend reopen claim unconfirmed", confirmedWrite, err
		}
	}
	if r.Version == operationDrainReceiptVersion && r.Phase == "drain-cancelled-v11" {
		if err := drainV11Authority(ctx, ec, r.DrainV11); err != nil {
			return "request-drain cancelled; backend reopen authority unavailable", confirmedWrite, err
		}
		r.DrainV11.ReopenRequests = 1
		r.Phase = "reopen-dispatching-v11"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return "request-drain cancelled; backend reopen claim unconfirmed", confirmedWrite, err
		}
	}
	if r.Version == operationDrainReceiptVersion && r.Phase == "reopen-dispatching-v11" {
		ep, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, pod)
		if err != nil {
			return "request-drain quiesced; backend reopen pending", confirmedWrite, err
		}
		cancelled := r.DrainV11.cancelled()
		if err := drainV11Authority(ctx, ec, r.DrainV11); err != nil && cancelled {
			return "request-drain cancelled; backend reopen authority changed", confirmedWrite, err
		} else if err != nil {
			if recoveryErr := recoverDrainV11(ctx, ec, ep, r, func() error {
				return journalAdvance(ctx, ec, cm, *r)
			}); recoveryErr != nil {
				return "request-drain quiesced; backend incarnation changed during reopen", confirmedWrite, recoveryErr
			}
			r.Aborted = r.DrainV11.Aborted
			r.Phase = "drain-confirmed-v11"
			if journalErr := journalAdvance(ctx, ec, cm, *r); journalErr != nil {
				return "replacement request-drain confirmed; receipt phase pending", confirmedWrite, journalErr
			}
			return recoverRequestDrain(ctx, ec, cm, r)
		}
		if err := reopenDrainV11(ctx, ec, ep, r.DrainV11); errors.Is(err, errDrainV11Stale) && cancelled {
			return "request-drain cancelled; backend became stale before reopen", confirmedWrite, err
		} else if errors.Is(err, errDrainV11Stale) {
			if recoveryErr := recoverDrainV11(ctx, ec, ep, r, func() error {
				return journalAdvance(ctx, ec, cm, *r)
			}); recoveryErr != nil {
				return "request-drain quiesced; backend incarnation changed during reopen", confirmedWrite, recoveryErr
			}
			r.Aborted = r.DrainV11.Aborted
			r.Phase = "drain-confirmed-v11"
			if journalErr := journalAdvance(ctx, ec, cm, *r); journalErr != nil {
				return "replacement request-drain confirmed; receipt phase pending", confirmedWrite, journalErr
			}
			return recoverRequestDrain(ctx, ec, cm, r)
		} else if err != nil {
			return "request-drain quiesced; backend reopen unconfirmed", confirmedWrite, err
		}
		r.Phase = "backend-reopened-v11"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return "request-drain backend reopened; receipt phase unresolved", confirmedWrite, err
		}
	}
	if r.Version == operationDrainReceiptVersion && r.Phase != "stopped" && r.Phase != "withdrawn" &&
		r.Phase != "claimed" && r.Phase != "drain-unsent" && r.Phase != "drain-rejected-v11" && r.Phase != "backend-reopened-v11" && r.Phase != "restored" {
		return "request-drain v11 is not ready for route restoration", confirmedWrite,
			fmt.Errorf("request-drain v11 phase %q is not restorable", r.Phase)
	}
	restored, err := restoreDrainPod(ctx, ec, *r)
	if err != nil {
		return "request-drain restoration unresolved; receipt retained", confirmedWrite, err
	}
	if r.DrainV11 != nil && r.DrainV11.CreateRejection != nil {
		// The protected journal serializes normal native choices, but a runtime
		// read and a Kubernetes CAS are not one atomic cross-plane transaction.
		// Recheck after the owned route write before claiming completion or
		// retiring the only recovery authority.
		ep, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, restored)
		if err == nil {
			_, err = drainV11UnadvancedCapability(ctx, ec, ep, r.DrainV11)
		}
		if err != nil {
			return "serving label write observed; rejected create OPEN authority changed before restoration confirmation; receipt retained", confirmedWrite, err
		}
	}
	if r.Phase != "restored" {
		r.Phase = "restored"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return "serving label restored; receipt phase unresolved", confirmedWrite, err
		}
	}
	if err := waitDrainEndpointState(ctx, ec, *r, true); err != nil {
		return "serving label restored; endpoint return unresolved; receipt retained", confirmedWrite, err
	}
	if err := journalFinish(ctx, ec, cm); err != nil {
		return "serving label and endpoint return confirmed; receipt cleanup unresolved", confirmedWrite, err
	}
	if r.Aborted > 0 {
		return fmt.Sprintf("%d in-flight requests confirmed aborted; exact serving state and endpoint membership restored; receipt finished", r.Aborted), confirmedWrite, nil
	}
	if r.DrainV11 != nil && r.DrainV11.CreateRejection != nil {
		return "create definitively rejected for ledger capacity; no backend drain or abort; exact serving state and endpoint membership restored; receipt finished", confirmedWrite, nil
	}
	return "exact serving state and endpoint membership restored; receipt finished", confirmedWrite, nil
}

func requestDrainWriteConfirmed(r operationReceipt, pod *corev1.Pod) bool {
	if pod != nil && string(pod.UID) == r.TargetUID && pod.Labels[labelDrainEpoch] == r.OperationToken {
		return true
	}
	switch r.Phase {
	case "stopped", "withdrawn", "drain-dispatching-v11", "drain-unsent", "drain-rejected-v11", "drain-cancel-dispatching-v11", "drain-cancelled-v11", "drain-confirmed-v11", "reopen-dispatching-v11", "backend-reopened-v11", "restored":
		return true
	default:
		return false
	}
}

func finishDefinitelyRejectedDrainClaim(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r operationReceipt) error {
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod); err != nil {
		return err
	}
	if string(pod.UID) != r.TargetUID || pod.Labels[labelDrainEpoch] == r.OperationToken || !servingRestored(pod, r) {
		return fmt.Errorf("request-drain rejected Patch outcome is not an authoritative no-effect state")
	}
	if _, err := readBoundDrainService(ctx, ec.Reader, r); err != nil {
		return err
	}
	if err := waitDrainEndpointState(ctx, ec, r, true); err != nil {
		return err
	}
	return journalFinish(ctx, ec, cm)
}

func definitelyRejectedDrainPatch(err error) bool {
	return apierrors.IsConflict(err) || apierrors.IsForbidden(err) || apierrors.IsInvalid(err) || apierrors.IsUnauthorized(err)
}

func requestDrainFailure(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt, pod *corev1.Pod, cause error) (HandlerResult, error) {
	effect, confirmedWrite, restoreErr := recoverRequestDrain(ctx, ec, cm, r)
	note := "request-drain outcome unknown: " + effect
	if confirmedWrite {
		note = "request-drain partial confirmed mutation: " + effect
	}
	touchedPod := pod
	if !confirmedWrite && restoreErr == nil {
		touchedPod = nil
	}
	return requestDrainResult(cm, touchedPod, confirmedWrite, note), fmt.Errorf("request-drain incomplete: %w", errors.Join(cause, restoreErr))
}

func enactRequestDrain(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	req.Action = model.ActionRequestDrain
	ec.ServingRequest = req
	if ec.Client == nil || ec.Reader == nil || ec.JournalNamespace == "" || req.PolicyName == "" || req.PolicyUID == "" {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("request-drain requires authoritative client, protected journal and policy identity"))
	}
	pod, err := authoritativeDrainPod(ctx, ec, req)
	if err != nil {
		return HandlerResult{}, err
	}
	service, err := bindDrainService(ctx, ec.Reader, pod)
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(err)
	}
	addresses, err := drainEndpointAddresses(ctx, ec.Reader, service, pod)
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(err)
	}
	if len(addresses) == 0 {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("request-drain target has no confirmed active membership in the bound Service EndpointSlices"))
	}
	token, err := newRequestDrainToken()
	if err != nil {
		return HandlerResult{}, err
	}
	priorValue, priorPresent := pod.Labels[labelServing]
	injected := ec.ServingSecurity == nil && ec.VLLM != nil
	if !injected && (ec.ServingSecurity == nil || ec.ServingSecurity.Mode() != ServingSecuritySecureRequired) {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("request-drain operation-bound v11 requires secure serving credentials"))
	}
	drainReceipt, _, err := prepareDrainV11(ctx, ec, req, pod, string(service.UID), 3*time.Minute)
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("request-drain operation-bound capability: %w", err))
	}
	r := operationReceipt{
		Version: operationDrainReceiptVersion, Kind: "request-drain", Phase: "prepared",
		PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		TargetName: pod.Name, TargetUID: string(pod.UID), TargetLabels: copyLabels(pod.Labels),
		OperationToken: token, ServiceName: service.Name, ServiceUID: string(service.UID), ServiceSelector: copyLabels(service.Spec.Selector),
		PriorServingPresent: priorPresent, PriorServingValue: priorValue, EndpointAddresses: append([]string(nil), addresses...), EndpointConfigSHA256: drainEndpointConfigDigest(pod),
		DrainV11: drainReceipt,
	}
	r.EndpointConfigSHA256 = secureDrainEndpointConfigDigest(pod)
	if !injected {
		r.ServingBindingSHA256 = ec.ServingAttempt.digest
	}
	r.ServingServiceAccount = normalizeServiceAccount(pod.Spec.ServiceAccountName)
	r.ServingLegacy = injected
	if !r.valid() {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("request-drain bounded receipt preconditions are invalid"))
	}
	if _, err := receiptAuthority(ctx, ec.Reader, r, model.ActionRequestDrain); err != nil {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("request-drain policy authority: %w", err))
	}
	cm, err := journalWrite(ctx, ec, r)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("request-drain already has a pending protected receipt"))
		}
		return HandlerResult{}, fmt.Errorf("request-drain prepare receipt: %w", err)
	}

	// Re-read all selection authority after the receipt write and before the first tenant mutation.
	fresh, err := authoritativeDrainPod(ctx, ec, req)
	if err == nil && fresh.ResourceVersion != pod.ResourceVersion {
		err = fmt.Errorf("request-drain target changed after preparation")
	}
	if err == nil {
		_, err = readBoundDrainService(ctx, ec.Reader, r)
	}
	if err == nil {
		var current []string
		current, err = drainEndpointAddresses(ctx, ec.Reader, service, fresh)
		if err == nil && !sameAddressSet(current, r.EndpointAddresses) {
			err = fmt.Errorf("request-drain endpoint membership changed after preparation")
		}
	}
	if err != nil {
		finishErr := journalFinish(ctx, ec, cm)
		return requestDrainResult(cm, nil, false, "request-drain refused before target mutation"), fmt.Errorf("request-drain authority changed before mutation: %w", errors.Join(err, finishErr))
	}
	r.Phase = "claimed"
	if err := journalAdvance(ctx, ec, cm, r); err != nil {
		// The CAS may have been accepted despite a lost response. No Pod write follows an
		// unacknowledged claim; leave the receipt for authoritative recovery.
		return requestDrainResult(cm, nil, false, "request-drain outcome unknown: pre-write claim unconfirmed; receipt retained"), fmt.Errorf("request-drain pre-write claim: %w", err)
	}
	// The claim CAS closes the prepared-recovery race. Re-read the external
	// authorities once more after that write so the Pod Patch uses current state.
	claimedFresh, claimErr := authoritativeDrainPod(ctx, ec, req)
	if claimErr == nil && claimedFresh.ResourceVersion != fresh.ResourceVersion {
		claimErr = fmt.Errorf("request-drain target changed after pre-write claim")
	}
	if claimErr == nil && drainReceiptEndpointConfigDigest(claimedFresh, r.Version) != r.EndpointConfigSHA256 {
		claimErr = fmt.Errorf("request-drain serving endpoint configuration changed after pre-write claim")
	}
	if claimErr == nil {
		_, claimErr = readBoundDrainService(ctx, ec.Reader, r)
	}
	if claimErr == nil {
		var current []string
		current, claimErr = drainEndpointAddresses(ctx, ec.Reader, service, claimedFresh)
		if claimErr == nil && !sameAddressSet(current, r.EndpointAddresses) {
			claimErr = fmt.Errorf("request-drain endpoint membership changed after pre-write claim")
		}
	}
	if claimErr != nil {
		finishErr := finishDefinitelyRejectedDrainClaim(ctx, ec, cm, r)
		return requestDrainResult(cm, nil, false, "request-drain refused after pre-write claim; no target mutation confirmed"), fmt.Errorf("request-drain authority changed before Pod Patch: %w", errors.Join(claimErr, finishErr))
	}

	stopped, patchAccepted, err := drainPodWithReceipt(ctx, ec, claimedFresh, r)
	if err != nil {
		// A Patch or read-back error is ambiguous: the apiserver may have accepted the
		// stop-admit write. Recovery must inspect the exact token and retain the receipt
		// when that inspection is unavailable; never delete the only restoration authority.
		if !patchAccepted && definitelyRejectedDrainPatch(err) {
			finishErr := finishDefinitelyRejectedDrainClaim(ctx, ec, cm, r)
			return requestDrainResult(cm, nil, false, "request-drain Pod Patch was definitely rejected; no confirmed Pod mutation"), fmt.Errorf("request-drain stop-admit: %w", errors.Join(err, finishErr))
		}
		return requestDrainFailure(ctx, ec, cm, &r, pod, fmt.Errorf("request-drain stop-admit: %w", err))
	}
	r.Phase = "stopped"
	if err := journalAdvance(ctx, ec, cm, r); err != nil {
		return requestDrainFailure(ctx, ec, cm, &r, stopped, fmt.Errorf("record stopped phase: %w", err))
	}
	if err := waitDrainEndpointState(ctx, ec, r, false); err != nil {
		return requestDrainFailure(ctx, ec, cm, &r, stopped, err)
	}
	r.Phase = "withdrawn"
	if err := journalAdvance(ctx, ec, cm, r); err != nil {
		return requestDrainFailure(ctx, ec, cm, &r, stopped, fmt.Errorf("record withdrawn phase: %w", err))
	}

	confirmedTarget, err := revalidateDrainDispatch(ctx, ec, r)
	if err != nil {
		return requestDrainFailure(ctx, ec, cm, &r, stopped, fmt.Errorf("request-drain pre-abort revalidation: %w", err))
	}
	r.Phase = "drain-dispatching-v11"
	r.DrainV11.CreateRequests = 1
	if err := journalAdvance(ctx, ec, cm, r); err != nil {
		return requestDrainFailure(ctx, ec, cm, &r, stopped,
			fmt.Errorf("request-drain v11 dispatch claim was not acknowledged: %w", err))
	}
	confirmedTarget, err = revalidateDrainDispatch(ctx, ec, r)
	if err != nil {
		return requestDrainFailure(ctx, ec, cm, &r, stopped,
			fmt.Errorf("request-drain authority changed after dispatch claim: %w", err))
	}
	ep, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, confirmedTarget)
	if err != nil {
		return requestDrainFailure(ctx, ec, cm, &r, stopped, err)
	}
	create := drainV11CreateFromReceipt(r.DrainV11)
	if err := completeDrainV11(ctx, ec, ep, r.DrainV11, &create); err != nil {
		var rejected *drainV11CreateRejectedError
		if errors.As(err, &rejected) {
			if proofErr := bindDrainV11CreateRejection(ctx, ec, ep, r.DrainV11, rejected); proofErr != nil {
				return requestDrainFailure(ctx, ec, cm, &r, stopped, errors.Join(err, proofErr))
			}
			r.Phase = "drain-rejected-v11"
			if journalErr := journalAdvance(ctx, ec, cm, r); journalErr != nil {
				// Do not restore from an unacknowledged durable proof. Recovery may
				// consume the protected rejection only if the CAS actually landed.
				return requestDrainResult(cm, stopped, true, "request-drain create rejection receipt unconfirmed; owned routing and protected receipt retained"), journalErr
			}
			return requestDrainFailure(ctx, ec, cm, &r, stopped, err)
		}
		var unreachable *definiteServingUnreachableError
		if errors.As(err, &unreachable) {
			r.Phase = "drain-unsent"
			if journalErr := journalAdvance(ctx, ec, cm, r); journalErr != nil {
				return requestDrainFailure(ctx, ec, cm, &r, stopped,
					fmt.Errorf("request-drain definitely-unsent evidence was not acknowledged: %w", journalErr))
			}
			return requestDrainFailure(ctx, ec, cm, &r, stopped,
				fmt.Errorf("request-drain v11 create was definitely unsent: %w", err))
		}
		return requestDrainFailure(ctx, ec, cm, &r, stopped,
			fmt.Errorf("request-drain v11 outcome retained for GET-only recovery: %w", err))
	}
	r.Aborted = r.DrainV11.Aborted
	r.Phase = "drain-confirmed-v11"
	if err := journalAdvance(ctx, ec, cm, r); err != nil {
		return requestDrainFailure(ctx, ec, cm, &r, stopped, fmt.Errorf("record confirmed stack effect: %w", err))
	}
	effect, _, err := recoverRequestDrain(ctx, ec, cm, &r)
	if err != nil {
		return requestDrainResult(cm, stopped, true, "request-drain partial confirmed mutation: "+effect), fmt.Errorf("request-drain restoration after confirmed abort: %w", err)
	}
	if r.Aborted == 0 {
		return requestDrainResult(cm, stopped, true, "request-drain v11 quiesced and reopened without aborting active work; exact serving state restored", &r),
			fmt.Errorf("request-drain v11 confirmed zero aborted requests")
	}
	metrics.RecordRequestDrainAborted(req.Tenant, req.Namespace, req.Pod, r.Aborted)
	return requestDrainResult(cm, stopped, true, fmt.Sprintf("request-drain: %d in-flight aborted; operation-bound backend reopened; exact serving state restored; does not block re-entry — pair with quarantine/route-rotate", r.Aborted), &r), nil
}

func rollbackRequestDrain(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || req.PolicyName == "" || req.PolicyUID == "" || req.TargetUID == "" {
		return fmt.Errorf("request-drain rollback refused: protected operation identity is incomplete")
	}
	parts := strings.Split(ref, "@")
	if len(parts) != 2 || parts[1] == "" {
		return fmt.Errorf("request-drain rollback refused: protected receipt reference is invalid")
	}
	keyParts := strings.Split(parts[0], "/")
	if len(keyParts) != 2 || keyParts[0] != ec.JournalNamespace {
		return fmt.Errorf("request-drain rollback refused: protected receipt scope is invalid")
	}
	expectedName := receiptName(operationReceipt{Kind: "request-drain", PolicyUID: req.PolicyUID, TargetUID: req.TargetUID})
	if keyParts[1] != expectedName {
		return fmt.Errorf("request-drain rollback refused: protected receipt name is unbound")
	}
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: expectedName}, cm); err != nil {
		return err
	}
	r, err := validateProtectedReceipt(cm, ec.JournalNamespace)
	if err != nil || string(cm.UID) != parts[1] || r.Kind != "request-drain" || r.PolicyNamespace != req.Namespace || r.PolicyName != req.PolicyName || r.PolicyUID != req.PolicyUID || r.TargetName != req.Pod || r.TargetUID != req.TargetUID {
		return fmt.Errorf("request-drain rollback refused: protected receipt identity changed")
	}
	if _, err := receiptAuthority(ctx, ec.Reader, r, model.ActionRequestDrain); err != nil {
		return fmt.Errorf("request-drain rollback refused: %w", err)
	}
	_, _, err = recoverRequestDrain(ctx, ec, cm, &r)
	return err
}
