package actuator

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errDrainV11Stale = errors.New("drain v11 backend incarnation is stale")
var errDrainV11CancellationRequired = errors.New("drain v11 cancellation is required")
var errDrainV11Cancelled = errors.New("drain v11 operation was cancelled")

type drainV11ContainerBinding struct {
	Name         string `json:"name"`
	ContainerID  string `json:"container_id"`
	RestartCount int32  `json:"restart_count"`
}

func drainV11OperatorBinding(pod *corev1.Pod, capabilitySHA, backendDigest string) (string, error) {
	if pod == nil || pod.UID == "" || pod.DeletionTimestamp != nil ||
		!validDrainV11Hex(capabilitySHA, 32) || !validDrainV11Hex(backendDigest, 32) {
		return "", fmt.Errorf("drain v11 Kubernetes binding is incomplete")
	}
	containers := make([]drainV11ContainerBinding, 0, len(pod.Status.ContainerStatuses))
	for _, status := range pod.Status.ContainerStatuses {
		if status.ContainerID == "" || status.RestartCount != 0 {
			return "", fmt.Errorf("drain v11 participant container identity is unavailable or restarted")
		}
		containers = append(containers, drainV11ContainerBinding{Name: status.Name,
			ContainerID: status.ContainerID, RestartCount: status.RestartCount})
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })
	if len(containers) != 2 || containers[0].Name != "guardrail" || containers[1].Name != "vllm" {
		return "", fmt.Errorf("drain v11 requires exact guardrail and vllm containers")
	}
	ready := false
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready {
		return "", fmt.Errorf("drain v11 participant is not Ready")
	}
	return drainV11Digest("phorvex-drain-operator-binding-v1", map[string]any{
		"backend_incarnation_digest": backendDigest,
		"capability_sha256":          capabilitySHA,
		"containers":                 containers,
		"pod_uid":                    string(pod.UID),
	})
}

func drainV11SourceBinding(pod *corev1.Pod, proxySource, engineSource string) error {
	if pod == nil || pod.Annotations[annoDrainProxySource] != proxySource ||
		pod.Annotations[annoDrainEngineSource] != engineSource ||
		!validDrainV11Source(proxySource) || !validDrainV11Source(engineSource) {
		return fmt.Errorf("drain v11 source annotations do not match capability")
	}
	return nil
}

func drainV11Authority(ctx context.Context, ec EnactCtx, receipt *drainV11Receipt) error {
	binding, err := drainV11ObservedBinding(ctx, ec, receipt)
	if err != nil {
		return err
	}
	if binding != receipt.OperatorBinding {
		return fmt.Errorf("drain v11 operator incarnation binding changed")
	}
	return nil
}

func drainV11InjectedBinding(ec EnactCtx, pod *corev1.Pod, capabilitySHA, backendDigest string) (string, bool, error) {
	if ec.ServingSecurity != nil || ec.VLLM == nil {
		return "", false, nil
	}
	if pod != nil && pod.Annotations[annoDrainProxySource] != "" && pod.Annotations[annoDrainEngineSource] != "" {
		return "", false, nil
	}
	if pod == nil || pod.UID == "" || pod.DeletionTimestamp != nil ||
		!validDrainV11Hex(capabilitySHA, sha256.Size) || !validDrainV11Hex(backendDigest, sha256.Size) {
		return "", true, fmt.Errorf("injected drain v11 binding is incomplete")
	}
	digest, err := drainV11Digest("phorvex-drain-injected-binding-v1", map[string]string{
		"backend_incarnation_digest": backendDigest,
		"capability_sha256":          capabilitySHA,
		"pod_uid":                    string(pod.UID),
	})
	return digest, true, err
}

func drainV11ObservedBinding(ctx context.Context, ec EnactCtx, receipt *drainV11Receipt) (string, error) {
	if receipt == nil || ec.Reader == nil {
		return "", fmt.Errorf("drain v11 authority is unavailable")
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: receipt.TargetNamespace, Name: receipt.TargetName}, pod); err != nil {
		return "", fmt.Errorf("drain v11 participant read: %w", err)
	}
	if string(pod.UID) != receipt.Owner.PodUID {
		return "", fmt.Errorf("drain v11 participant UID changed")
	}
	if binding, injected, err := drainV11InjectedBinding(ec, pod, receipt.CapabilitySHA256, receipt.ExpectedIncarnation); injected {
		return binding, err
	}
	if err := drainV11SourceBinding(pod, receipt.ProxySource, receipt.EngineSource); err != nil {
		return "", err
	}
	binding, err := drainV11OperatorBinding(pod, receipt.CapabilitySHA256, receipt.ExpectedIncarnation)
	if err != nil {
		return "", err
	}
	return binding, nil
}

func drainV11Client(ec EnactCtx) (vLLMDrainV11Client, error) {
	client, ok := ec.vllm().(vLLMDrainV11Client)
	if !ok {
		return nil, fmt.Errorf("serving backend does not implement operation-bound drain v11")
	}
	return client, nil
}

func prepareDrainV11(ctx context.Context, ec EnactCtx, req Request, pod *corev1.Pod,
	serviceUID string, timeout time.Duration) (*drainV11Receipt, drainV11CreateRequest, error) {
	backend, err := drainV11Client(ec)
	if err != nil {
		return nil, drainV11CreateRequest{}, err
	}
	ep, err := servingEndpointForPod(ctx, ec, req, pod)
	if err != nil {
		return nil, drainV11CreateRequest{}, err
	}
	capability, err := backend.DrainV11Capability(ctx, ep)
	if err != nil {
		return nil, drainV11CreateRequest{}, err
	}
	injectedClient := ec.ServingSecurity == nil && ec.VLLM != nil
	if capability.PodUID != string(pod.UID) && !(injectedClient && capability.PodUID == "") {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 capability Pod UID mismatch")
	}
	if capability.Admission != "OPEN" || capability.NextOperationGeneration == "" {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 capability does not admit a new operation")
	}
	if !validDrainV11Hex(capability.RawSHA256, 32) {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 raw capability hash unavailable")
	}
	fresh := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKeyFromObject(pod), fresh); err != nil || fresh.UID != pod.UID {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 participant identity changed after capability")
	}
	operatorBinding, injected, err := drainV11InjectedBinding(ec, fresh, capability.RawSHA256, capability.IncarnationDigest)
	if err != nil {
		return nil, drainV11CreateRequest{}, err
	}
	if !injected {
		if err := drainV11SourceBinding(fresh, capability.ProxySource, capability.EngineSource); err != nil {
			return nil, drainV11CreateRequest{}, err
		}
		operatorBinding, err = drainV11OperatorBinding(fresh, capability.RawSHA256, capability.IncarnationDigest)
		if err != nil {
			return nil, drainV11CreateRequest{}, err
		}
	}
	namespace := &corev1.Namespace{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: pod.Namespace}, namespace); err != nil {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 namespace authority: %w", err)
	}
	namespaceUID := string(namespace.UID)
	if injectedClient && namespaceUID == "" {
		namespaceUID = namespace.Name
	}
	if namespaceUID == "" || (!injectedClient && namespace.ResourceVersion == "") || namespace.DeletionTimestamp != nil {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 namespace authority is incomplete")
	}
	operationID, err := newDrainV11ID()
	if err != nil {
		return nil, drainV11CreateRequest{}, err
	}
	deadline, cancelAt, grace := drainV11CancellationTimes(timeout)
	owner := drainV11Owner{Tenant: req.Tenant, NamespaceUID: namespaceUID,
		PolicyUID: req.PolicyUID, PodUID: string(pod.UID), ServiceUID: serviceUID}
	create := drainV11CreateRequest{Schema: drainV11Schema, OperationID: operationID,
		OperationGeneration: capability.NextOperationGeneration, Attempt: 1, Owner: owner,
		ExpectedIncarnationDigest: capability.IncarnationDigest, Deadline: deadline,
		Mode: "abort-and-quiesce"}
	receipt := &drainV11Receipt{OperationID: operationID, Attempt: 1,
		OperationGeneration: capability.NextOperationGeneration,
		ExpectedIncarnation: capability.IncarnationDigest, LedgerID: capability.LedgerID,
		ProxyBootID: capability.ProxyBootID, EngineBootID: capability.EngineBootID,
		Deadline: deadline, CancelNotBefore: cancelAt, CancellationGraceDeadline: grace,
		TransitionReason: "none", CancelBoundaryRevision: "0",
		Owner: owner, TargetNamespace: fresh.Namespace, TargetName: fresh.Name,
		CapabilitySHA256: capability.RawSHA256, ProxySource: capability.ProxySource,
		EngineSource: capability.EngineSource, OperatorBinding: operatorBinding}
	if !receipt.prepared() {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 prepared receipt is invalid")
	}
	return receipt, create, nil
}

func drainV11CreateFromReceipt(receipt *drainV11Receipt) drainV11CreateRequest {
	return drainV11CreateRequest{Schema: drainV11Schema, OperationID: receipt.OperationID,
		OperationGeneration: receipt.OperationGeneration, Attempt: receipt.Attempt, Owner: receipt.Owner,
		ExpectedIncarnationDigest: receipt.ExpectedIncarnation, Deadline: receipt.Deadline,
		Mode: "abort-and-quiesce", Supersedes: receipt.Supersedes}
}

func prepareDrainV11Supersession(ctx context.Context, ec EnactCtx, ep servingEndpoint,
	stale *drainV11Receipt, timeout time.Duration) (*drainV11Receipt, drainV11CreateRequest, error) {
	if stale == nil || stale.Attempt != 1 || stale.State != "STALE" ||
		!validDrainV11Decimal(stale.Revision, true) {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 supersession requires the exact stale attempt-1 receipt")
	}
	backend, err := drainV11Client(ec)
	if err != nil {
		return nil, drainV11CreateRequest{}, err
	}
	capability, err := backend.DrainV11Capability(ctx, ep)
	if err != nil {
		return nil, drainV11CreateRequest{}, err
	}
	if capability.Admission != "CLOSED" || capability.NextOperationGeneration == "" ||
		capability.PodUID != stale.Owner.PodUID || capability.LedgerID != stale.LedgerID ||
		capability.IncarnationDigest == stale.ExpectedIncarnation ||
		capability.ProxySource != stale.ProxySource || capability.EngineSource != stale.EngineSource ||
		!validDrainV11Hex(capability.RawSHA256, sha256.Size) {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 stale backend capability is not an exact supersession target")
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: stale.TargetNamespace, Name: stale.TargetName}, pod); err != nil {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 supersession participant read: %w", err)
	}
	if string(pod.UID) != stale.Owner.PodUID {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 supersession participant UID changed")
	}
	binding, injected, err := drainV11InjectedBinding(ec, pod, capability.RawSHA256, capability.IncarnationDigest)
	if err != nil {
		return nil, drainV11CreateRequest{}, err
	}
	if !injected {
		if err := drainV11SourceBinding(pod, capability.ProxySource, capability.EngineSource); err != nil {
			return nil, drainV11CreateRequest{}, err
		}
		binding, err = drainV11OperatorBinding(pod, capability.RawSHA256, capability.IncarnationDigest)
		if err != nil {
			return nil, drainV11CreateRequest{}, err
		}
	}
	operationID, err := newDrainV11ID()
	if err != nil {
		return nil, drainV11CreateRequest{}, err
	}
	supersedes := &drainV11Supersedes{OperationGeneration: stale.OperationGeneration,
		OperationID: stale.OperationID, Revision: stale.Revision}
	deadline, cancelAt, grace := drainV11CancellationTimes(timeout)
	next := &drainV11Receipt{OperationID: operationID,
		OperationGeneration: capability.NextOperationGeneration, Attempt: 2, Supersedes: supersedes,
		ExpectedIncarnation: capability.IncarnationDigest, LedgerID: capability.LedgerID,
		ProxyBootID: capability.ProxyBootID, EngineBootID: capability.EngineBootID,
		Deadline: deadline, CancelNotBefore: cancelAt, CancellationGraceDeadline: grace,
		TransitionReason: "none", CancelBoundaryRevision: "0", Owner: stale.Owner,
		TargetNamespace: stale.TargetNamespace, TargetName: stale.TargetName,
		CapabilitySHA256: capability.RawSHA256, ProxySource: capability.ProxySource,
		EngineSource: capability.EngineSource, OperatorBinding: binding, CreateRequests: 1}
	if !next.prepared() {
		return nil, drainV11CreateRequest{}, fmt.Errorf("drain v11 supersession receipt is invalid")
	}
	create := drainV11CreateFromReceipt(next)
	return next, create, nil
}

func completeDrainV11(ctx context.Context, ec EnactCtx, ep servingEndpoint,
	receipt *drainV11Receipt, create *drainV11CreateRequest) error {
	backend, err := drainV11Client(ec)
	if err != nil {
		return err
	}
	var status drainV11StatusResponse
	var expectedNonce *string
	staleLookup := false
	var observedBinding string
	if err := drainV11Authority(ctx, ec, receipt); err != nil {
		if create != nil {
			return err
		}
		// A same-Pod process/container restart changes the operator binding. It
		// may authorize only an authenticated GET whose bound response is STALE;
		// it can never authorize effect completion under the old incarnation.
		observedBinding, err = drainV11ObservedBinding(ctx, ec, receipt)
		if err != nil {
			return err
		}
		staleLookup = true
	}
	if create != nil {
		if receipt.CreateRequests != 1 {
			return fmt.Errorf("drain v11 create was not durably claimed exactly once")
		}
		status, err = backend.DrainV11Create(ctx, ep, *create)
	} else {
		nonce, nonceErr := newDrainV11Nonce()
		if nonceErr != nil {
			return nonceErr
		}
		receipt.StatusRequests++
		status, err = backend.DrainV11Status(ctx, ep, receipt.OperationGeneration,
			receipt.OperationID, nonce)
		expectedNonce = &nonce
	}
	if err != nil {
		return err
	}
	if staleLookup {
		afterBinding, authorityErr := drainV11ObservedBinding(ctx, ec, receipt)
		if authorityErr != nil || afterBinding != observedBinding || status.State != "STALE" {
			return fmt.Errorf("drain v11 changed-incarnation lookup did not return stable STALE authority")
		}
	} else if err := drainV11Authority(ctx, ec, receipt); err != nil {
		return err
	}
	if err := bindDrainV11Status(receipt, status, expectedNonce); err != nil {
		return err
	}
	cancelAt, err := time.Parse(time.RFC3339Nano, receipt.CancelNotBefore)
	if err != nil {
		return fmt.Errorf("drain v11 cancellation threshold is invalid")
	}
	for status.State == "DRAINING" {
		if !time.Now().Before(cancelAt) {
			return errDrainV11CancellationRequired
		}
		nonce, nonceErr := newDrainV11Nonce()
		if nonceErr != nil {
			return nonceErr
		}
		if err := drainV11Authority(ctx, ec, receipt); err != nil {
			return err
		}
		receipt.StatusRequests++
		status, err = backend.DrainV11Status(ctx, ep, receipt.OperationGeneration,
			receipt.OperationID, nonce)
		if err != nil {
			return err
		}
		if err := drainV11Authority(ctx, ec, receipt); err != nil {
			return err
		}
		if err := bindDrainV11Status(receipt, status, &nonce); err != nil {
			return err
		}
		if status.State == "DRAINING" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	if status.State == "CANCEL_REQUESTED" || status.State == "CANCELLED" {
		return errDrainV11CancellationRequired
	}
	if !receipt.confirmed() {
		return fmt.Errorf("drain v11 terminal state %q is not quiescence", receipt.State)
	}
	return nil
}

// recoverDrainV11Cancellation persists the one possible cancel dispatch before
// sending it. Every later pass is GET-only, including a lost cancel response.
func recoverDrainV11Cancellation(ctx context.Context, ec EnactCtx, ep servingEndpoint,
	operation *operationReceipt, persist func() error) error {
	if operation == nil || operation.DrainV11 == nil || persist == nil {
		return fmt.Errorf("drain v11 cancellation identity is incomplete")
	}
	receipt := operation.DrainV11
	dispatch := false
	if operation.Phase == "drain-dispatching-v11" {
		if receipt.CancelRequests != 0 || receipt.Revision == "" {
			return fmt.Errorf("drain v11 cancellation is not claimable")
		}
		receipt.CancelRequests = 1
		operation.Phase = "drain-cancel-dispatching-v11"
		if err := persist(); err != nil {
			return fmt.Errorf("drain v11 cancellation journal CAS was not acknowledged: %w", err)
		}
		dispatch = receipt.State != "CANCEL_REQUESTED" && receipt.State != "CANCELLED"
	} else if operation.Phase != "drain-cancel-dispatching-v11" {
		return fmt.Errorf("drain v11 cancellation phase %q is invalid", operation.Phase)
	}
	backend, err := drainV11Client(ec)
	if err != nil {
		return err
	}
	if dispatch {
		if err := drainV11Authority(ctx, ec, receipt); err != nil {
			return err
		}
		status, callErr := backend.DrainV11Cancel(ctx, ep, receipt.OperationGeneration,
			receipt.OperationID, drainV11IntentRequest{OwnerDigest: receipt.OwnerDigest,
				ExpectedIncarnationDigest: receipt.BackendIncarnation,
				ExpectedRevision:          receipt.Revision})
		if callErr != nil {
			return fmt.Errorf("drain v11 cancel outcome retained for GET-only recovery: %w", callErr)
		}
		if err := drainV11Authority(ctx, ec, receipt); err != nil {
			return err
		}
		if err := bindDrainV11Status(receipt, status, nil); err != nil {
			return fmt.Errorf("drain v11 cancel response binding changed: %w", err)
		}
		if err := persist(); err != nil {
			return fmt.Errorf("drain v11 cancellation response was not journaled: %w", err)
		}
	}
	grace, err := time.Parse(time.RFC3339Nano, receipt.CancellationGraceDeadline)
	if err != nil {
		return fmt.Errorf("drain v11 cancellation grace is invalid")
	}
	for receipt.State != "CANCELLED" {
		if receipt.State == "FAILED" || receipt.State == "STALE" || receipt.State == "OPENED" || receipt.State == "QUIESCENT" {
			return fmt.Errorf("drain v11 cancellation reached invalid state %q", receipt.State)
		}
		if !time.Now().Before(grace) {
			return fmt.Errorf("drain v11 cancellation grace expired")
		}
		nonce, nonceErr := newDrainV11Nonce()
		if nonceErr != nil {
			return nonceErr
		}
		if err := drainV11Authority(ctx, ec, receipt); err != nil {
			return err
		}
		receipt.StatusRequests++
		status, callErr := backend.DrainV11Status(ctx, ep, receipt.OperationGeneration,
			receipt.OperationID, nonce)
		if callErr != nil {
			return callErr
		}
		if err := drainV11Authority(ctx, ec, receipt); err != nil {
			return err
		}
		if err := bindDrainV11Status(receipt, status, &nonce); err != nil {
			return err
		}
		if err := persist(); err != nil {
			return fmt.Errorf("drain v11 cancellation observation was not journaled: %w", err)
		}
		if receipt.State == "CANCEL_REQUESTED" || receipt.State == "DRAINING" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	if !receipt.cancelled() {
		return fmt.Errorf("drain v11 cancellation lacks terminal quiescence proof")
	}
	operation.Phase = "drain-cancelled-v11"
	if err := persist(); err != nil {
		return fmt.Errorf("drain v11 cancelled phase was not journaled: %w", err)
	}
	return errDrainV11Cancelled
}

// recoverDrainV11 resolves a possible-send by GET only. If that exact GET
// proves the retained attempt became STALE after a same-Pod backend restart,
// it prepares the one allowed attempt-2 supersession, persists its complete
// identity through the caller's journal CAS, and only then sends create.
func recoverDrainV11(ctx context.Context, ec EnactCtx, ep servingEndpoint,
	operation *operationReceipt, persist func() error) error {
	if operation == nil || operation.DrainV11 == nil || persist == nil {
		return fmt.Errorf("drain v11 recovery identity is incomplete")
	}
	probe := cloneDrainV11Receipt(operation.DrainV11)
	err := completeDrainV11(ctx, ec, ep, probe, nil)
	if err == nil {
		operation.DrainV11 = probe
		return nil
	}
	if errors.Is(err, errDrainV11CancellationRequired) {
		// completeDrainV11 returns this sentinel only after it has strictly
		// validated and bound the exact operation response (or a bound DRAINING
		// response reached the fixed cancel threshold). Carry that evidence into
		// the caller's cancellation-intent CAS so an already-requested or
		// completed cancellation never triggers another POST.
		operation.DrainV11 = probe
		return err
	}
	if probe.State != "STALE" {
		return err
	}
	if probe.Attempt != 1 {
		return fmt.Errorf("drain v11 attempt-2 became stale; automatic retry exhausted: %w", err)
	}
	next, create, prepareErr := prepareDrainV11Supersession(ctx, ec, ep, probe, 3*time.Minute)
	if prepareErr != nil {
		return fmt.Errorf("drain v11 stale supersession preparation: %w", prepareErr)
	}
	operation.DrainV11 = next
	operation.DrainAttempts = 2
	operation.Phase = "drain-dispatching-v11"
	if persistErr := persist(); persistErr != nil {
		return fmt.Errorf("drain v11 stale supersession journal CAS was not acknowledged: %w", persistErr)
	}
	if completeErr := completeDrainV11(ctx, ec, ep, operation.DrainV11, &create); completeErr != nil {
		return fmt.Errorf("drain v11 attempt-2 outcome retained for GET-only recovery: %w", completeErr)
	}
	return nil
}

func cloneDrainV11Receipt(receipt *drainV11Receipt) *drainV11Receipt {
	if receipt == nil {
		return nil
	}
	clone := *receipt
	if receipt.Supersedes != nil {
		value := *receipt.Supersedes
		clone.Supersedes = &value
	}
	clone.ObservationNonces = append([]string(nil), receipt.ObservationNonces...)
	clone.ObservationSequences = append([]string(nil), receipt.ObservationSequences...)
	clone.ObservationHashes = append([]string(nil), receipt.ObservationHashes...)
	return &clone
}

func reopenDrainV11(ctx context.Context, ec EnactCtx, ep servingEndpoint,
	receipt *drainV11Receipt) error {
	if receipt == nil || (!receipt.confirmed() && !receipt.cancelled()) {
		return fmt.Errorf("drain v11 reopen requires a confirmed receipt")
	}
	if receipt.ReopenRequests != 1 {
		return fmt.Errorf("drain v11 reopen was not durably claimed exactly once")
	}
	backend, err := drainV11Client(ec)
	if err != nil {
		return err
	}
	// A prior reopen response may have been lost. Resolve that state with GET;
	// never replay the POST after the backend has durably opened admission.
	nonce, err := newDrainV11Nonce()
	if err != nil {
		return err
	}
	if err := drainV11Authority(ctx, ec, receipt); err != nil {
		return err
	}
	receipt.StatusRequests++
	observed, err := backend.DrainV11Status(ctx, ep, receipt.OperationGeneration,
		receipt.OperationID, nonce)
	if err != nil {
		return err
	}
	if err := drainV11Authority(ctx, ec, receipt); err != nil {
		return err
	}
	probe := *receipt
	if err := bindDrainV11Status(&probe, observed, &nonce); err != nil {
		return fmt.Errorf("drain v11 reopen observation binding changed: %w", err)
	}
	if observed.State == "STALE" {
		return errDrainV11Stale
	}
	if observed.State == "OPENED" && observed.Admission == "OPEN" {
		*receipt = probe
		return nil
	}
	if (observed.State != "QUIESCENT" && observed.State != "CANCELLED") || observed.Admission != "CLOSED" ||
		observed.Revision != receipt.Revision {
		return fmt.Errorf("drain v11 reopen requires unchanged quiescence")
	}
	reopened, err := backend.DrainV11Reopen(ctx, ep, receipt.OperationGeneration,
		receipt.OperationID, drainV11IntentRequest{OwnerDigest: receipt.OwnerDigest,
			ExpectedIncarnationDigest: receipt.BackendIncarnation,
			ExpectedRevision:          receipt.Revision})
	if err != nil {
		return err
	}
	if err := drainV11Authority(ctx, ec, receipt); err != nil {
		return err
	}
	reopenProbe := *receipt
	if err := bindDrainV11Status(&reopenProbe, reopened, nil); err != nil {
		return fmt.Errorf("drain v11 reopen response binding changed: %w", err)
	}
	if reopened.State != "OPENED" || reopened.Admission != "OPEN" {
		return fmt.Errorf("drain v11 reopen was not confirmed")
	}
	*receipt = reopenProbe
	return nil
}
