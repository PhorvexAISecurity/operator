package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	routeBridgeLabel         = "phorvex.ai/route-bridge"
	routeTargetGuardLabel    = "phorvex.ai/route-target-guard"
	routeTargetGuardVersion  = 1
	routeObservationTimeout  = 3 * time.Second
	routeObservationInterval = 25 * time.Millisecond
)

var errRouteRestoreRequired = errors.New("route cutover restoration required")
var errRouteWriteRejected = errors.New("route cutover write rejected before effect")

type routeTargetGuard struct {
	Version         int    `json:"version"`
	ReceiptName     string `json:"receiptName"`
	ReceiptID       string `json:"receiptID"`
	PolicyNamespace string `json:"policyNamespace"`
	PolicyUID       string `json:"policyUID"`
	ServiceUID      string `json:"serviceUID"`
	TargetUID       string `json:"targetUID"`
	Action          string `json:"action"`
	OperationID     string `json:"operationID"`
	ReceiptUID      string `json:"receiptUID,omitempty"`
}

func routeReceiptID(policyUID, targetUID string, action model.Action, operationID string) string {
	h := sha256.Sum256([]byte("route-cutover/v1/" + policyUID + "/" + targetUID + "/" + string(action) + "/" + operationID))
	return hex.EncodeToString(h[:20])
}

func routeToken(prefix, policyUID, targetUID string, action model.Action, operationID string) string {
	h := sha256.Sum256([]byte(prefix + "/" + policyUID + "/" + targetUID + "/" + string(action) + "/" + operationID))
	return prefix[:1] + "-" + hex.EncodeToString(h[:20])
}

func routeGuardName(targetUID string) string {
	h := sha256.Sum256([]byte("route-target/" + targetUID))
	return fmt.Sprintf("phorvex-route-target-%x", h[:20])
}

func routeGuardFor(r operationReceipt) routeTargetGuard {
	return routeTargetGuard{
		Version: routeTargetGuardVersion, ReceiptName: receiptName(r), ReceiptID: r.ReceiptID,
		PolicyNamespace: r.PolicyNamespace, PolicyUID: r.PolicyUID, ServiceUID: r.ServiceUID,
		TargetUID: r.TargetUID, Action: r.Kind, OperationID: r.OperationToken,
	}
}

func (g routeTargetGuard) valid() bool {
	if g.Version != routeTargetGuardVersion || g.ReceiptName == "" || g.ReceiptID == "" || len(g.ReceiptID) != 40 ||
		g.PolicyNamespace == "" || g.PolicyUID == "" || g.ServiceUID == "" || g.TargetUID == "" ||
		(g.Action != string(model.ActionRouteRotate) && g.Action != string(model.ActionEndpointRotate)) ||
		g.OperationID == "" || len(g.OperationID) > 253 || len(g.ReceiptUID) > 253 || g.ReceiptName != receiptName(operationReceipt{Kind: g.Action, ServiceUID: g.ServiceUID}) ||
		g.ReceiptID != routeReceiptID(g.PolicyUID, g.TargetUID, model.Action(g.Action), g.OperationID) {
		return false
	}
	_, err := hex.DecodeString(g.ReceiptID)
	return err == nil
}

func readRouteGuard(cm *corev1.ConfigMap) (routeTargetGuard, error) {
	if cm == nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Labels[routeTargetGuardLabel] != "v1" || len(cm.Data) != 1 {
		return routeTargetGuard{}, fmt.Errorf("route target guard identity invalid")
	}
	var g routeTargetGuard
	if err := json.Unmarshal([]byte(cm.Data["guard"]), &g); err != nil || !g.valid() || cm.Name != routeGuardName(g.TargetUID) {
		return routeTargetGuard{}, fmt.Errorf("route target guard content invalid")
	}
	return g, nil
}

func routeGuardTupleEqual(a, b routeTargetGuard) bool {
	a.ReceiptUID, b.ReceiptUID = "", ""
	return reflect.DeepEqual(a, b)
}

func acquireRouteGuard(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.ConfigMap, error) {
	if ec.Client == nil || ec.Reader == nil || ec.JournalNamespace == "" || ec.JournalNamespace == r.PolicyNamespace {
		return nil, fmt.Errorf("route target guard unavailable")
	}
	want := routeGuardFor(r)
	b, _ := json.Marshal(want)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ec.JournalNamespace, Name: routeGuardName(r.TargetUID), Labels: map[string]string{routeTargetGuardLabel: "v1"}}, Data: map[string]string{"guard": string(b)}}
	createErr := ec.Client.Create(ctx, cm)
	if createErr == nil && cm.UID != "" && cm.ResourceVersion != "" {
		return cm, nil
	}
	observed := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKeyFromObject(cm), observed); err != nil {
		if createErr != nil {
			return nil, fmt.Errorf("route target guard create outcome unresolved: %w", errors.Join(createErr, err))
		}
		return nil, fmt.Errorf("route target guard create acknowledgement missing: %w", err)
	}
	got, err := readRouteGuard(observed)
	if err != nil {
		return nil, err
	}
	if !routeGuardTupleEqual(got, want) {
		return nil, fmt.Errorf("route target is owned by another unresolved operation")
	}
	return observed, nil
}

func bindRouteGuard(ctx context.Context, ec EnactCtx, guard, receipt *corev1.ConfigMap, r operationReceipt) error {
	if guard == nil || receipt == nil || receipt.UID == "" {
		return fmt.Errorf("route target guard binding unavailable")
	}
	fresh := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKeyFromObject(guard), fresh); err != nil {
		return err
	}
	got, err := readRouteGuard(fresh)
	if err != nil || fresh.UID != guard.UID || !routeGuardTupleEqual(got, routeGuardFor(r)) {
		return errors.Join(err, fmt.Errorf("route target guard changed before Service receipt binding"))
	}
	if got.ReceiptUID == string(receipt.UID) {
		*guard = *fresh
		return nil
	}
	if got.ReceiptUID != "" {
		return fmt.Errorf("route target guard is bound to a different Service receipt")
	}
	got.ReceiptUID = string(receipt.UID)
	b, _ := json.Marshal(got)
	fresh.Data = map[string]string{"guard": string(b)}
	writeErr := ec.Client.Update(ctx, fresh)
	observed := &corev1.ConfigMap{}
	readErr := ec.Reader.Get(ctx, client.ObjectKeyFromObject(fresh), observed)
	if readErr == nil {
		bound, decodeErr := readRouteGuard(observed)
		if decodeErr == nil && observed.UID == guard.UID && routeGuardTupleEqual(bound, routeGuardFor(r)) && bound.ReceiptUID == string(receipt.UID) {
			*guard = *observed
			return nil
		}
		readErr = errors.Join(readErr, decodeErr, fmt.Errorf("route target guard binding not observed"))
	}
	return fmt.Errorf("route target guard binding outcome unresolved: %w", errors.Join(writeErr, readErr))
}

func requireRouteGuard(ctx context.Context, ec EnactCtx, guard, receipt *corev1.ConfigMap, r operationReceipt) error {
	if guard == nil || receipt == nil || receipt.UID == "" {
		return fmt.Errorf("route target guard missing")
	}
	fresh := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKeyFromObject(guard), fresh); err != nil {
		return err
	}
	got, err := readRouteGuard(fresh)
	if err != nil {
		return err
	}
	if fresh.UID != guard.UID || !routeGuardTupleEqual(got, routeGuardFor(r)) || got.ReceiptUID != string(receipt.UID) {
		return fmt.Errorf("route target guard changed")
	}
	*guard = *fresh
	return nil
}

func finishRouteGuard(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap) error {
	if cm == nil || cm.UID == "" || cm.ResourceVersion == "" {
		return fmt.Errorf("route target guard finish identity invalid")
	}
	uid, rv := cm.UID, cm.ResourceVersion
	err := ec.Client.Delete(ctx, cm, client.Preconditions{UID: &uid, ResourceVersion: &rv})
	if err == nil || apierrors.IsNotFound(err) {
		return nil
	}
	fresh := &corev1.ConfigMap{}
	readErr := ec.Reader.Get(ctx, client.ObjectKeyFromObject(cm), fresh)
	if apierrors.IsNotFound(readErr) {
		return nil
	}
	if readErr != nil {
		return errors.Join(err, readErr)
	}
	if fresh.UID != uid {
		return fmt.Errorf("route target guard replaced after delete outcome: %w", err)
	}
	return fmt.Errorf("route target guard retained after delete outcome: %w", err)
}

func ownedValue(values map[string]string, key string) routeOwnedValue {
	value, present := values[key]
	return routeOwnedValue{Present: present, Value: value}
}

func ownedMatches(values map[string]string, key string, want routeOwnedValue) bool {
	value, present := values[key]
	return present == want.Present && (!present || value == want.Value)
}

func setOwned(values map[string]string, key string, want routeOwnedValue) {
	if want.Present {
		values[key] = want.Value
	} else {
		delete(values, key)
	}
}

func routeAppliedValue(value string) routeOwnedValue {
	return routeOwnedValue{Present: true, Value: value}
}

func routeEpochKey(action model.Action) string {
	if action == model.ActionEndpointRotate {
		return "phorvex.ai/endpoint-epoch"
	}
	return "phorvex.ai/route-epoch"
}

func routeTiming(ec EnactCtx) (time.Duration, time.Duration) {
	timeout, interval := ec.RouteObservationTimeout, ec.RouteObservationInterval
	if timeout <= 0 {
		timeout = routeObservationTimeout
	}
	if interval <= 0 {
		interval = routeObservationInterval
	}
	return timeout, interval
}

func routePolicySelector(pol *v1alpha1.PhorvexPolicy) (labels.Selector, error) {
	if pol == nil || len(pol.Spec.Selector.MatchLabels)+len(pol.Spec.Selector.MatchExpressions) == 0 {
		return nil, fmt.Errorf("current policy selector empty")
	}
	return metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
}

func routeActionEnabled(pol *v1alpha1.PhorvexPolicy, action model.Action) bool {
	return pol != nil && pol.Spec.ActionEnabled(v1alpha1.ActionType(action))
}

func routeReady(pod *corev1.Pod) bool {
	return pod != nil && pod.UID != "" && pod.ResourceVersion != "" && pod.DeletionTimestamp == nil && podReady(pod)
}

func routeServiceSelectsPod(svc *corev1.Service, pod *corev1.Pod) bool {
	return svc != nil && pod != nil && svc.Namespace == pod.Namespace && svc.UID != "" && svc.ResourceVersion != "" &&
		svc.DeletionTimestamp == nil && selectorMatchesPod(svc.Spec.Selector, pod.Labels)
}

func routeSelectingServices(ctx context.Context, reader client.Reader, pod *corev1.Pod) ([]corev1.Service, error) {
	var services corev1.ServiceList
	if err := reader.List(ctx, &services, client.InNamespace(pod.Namespace)); err != nil {
		return nil, err
	}
	out := make([]corev1.Service, 0, len(services.Items))
	for i := range services.Items {
		if routeServiceSelectsPod(&services.Items[i], pod) {
			out = append(out, *services.Items[i].DeepCopy())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func requireOnlyRouteService(ctx context.Context, reader client.Reader, pod *corev1.Pod, serviceUID string) error {
	services, err := routeSelectingServices(ctx, reader, pod)
	if err != nil {
		return fmt.Errorf("route Service inventory: %w", err)
	}
	if len(services) != 1 || string(services[0].UID) != serviceUID {
		return fmt.Errorf("target must be selected by exactly the declared Service (found %d)", len(services))
	}
	return nil
}

func routeEndpointMembers(ctx context.Context, reader client.Reader, svc *corev1.Service) ([]string, error) {
	if reader == nil || svc == nil || svc.UID == "" {
		return nil, fmt.Errorf("route EndpointSlice authority unavailable")
	}
	var slices discoveryv1.EndpointSliceList
	if err := reader.List(ctx, &slices, client.InNamespace(svc.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: svc.Name}); err != nil {
		return nil, fmt.Errorf("route EndpointSlice inventory: %w", err)
	}
	owned := 0
	members := map[string]bool{}
	for i := range slices.Items {
		slice := &slices.Items[i]
		if !endpointSliceOwnedByService(slice, svc) {
			continue
		}
		owned++
		if slice.UID == "" || slice.ResourceVersion == "" || slice.DeletionTimestamp != nil {
			return nil, fmt.Errorf("route EndpointSlice identity incomplete")
		}
		for _, endpoint := range slice.Endpoints {
			if !endpointActive(endpoint) {
				continue
			}
			ref := endpoint.TargetRef
			if ref == nil || ref.Kind != "Pod" || ref.Namespace != svc.Namespace || ref.Name == "" || ref.UID == "" {
				return nil, fmt.Errorf("route EndpointSlice active target identity incomplete")
			}
			if members[string(ref.UID)] {
				return nil, fmt.Errorf("route EndpointSlice repeats active Pod UID %s", ref.UID)
			}
			members[string(ref.UID)] = true
		}
	}
	if owned == 0 {
		return nil, fmt.Errorf("route has no EndpointSlice owned by the exact Service UID")
	}
	out := make([]string, 0, len(members))
	for uid := range members {
		out = append(out, uid)
	}
	sort.Strings(out)
	return out, nil
}

func containsUID(values []string, uid string) bool {
	for _, value := range values {
		if value == uid {
			return true
		}
	}
	return false
}

func routeMembershipFloor(ctx context.Context, ec EnactCtx, r operationReceipt) (int, error) {
	floor := r.AdmittedFloor
	policy := &v1alpha1.PhorvexPolicy{}
	err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.PolicyName}, policy)
	if apierrors.IsNotFound(err) {
		return floor, nil
	}
	if err != nil {
		return 0, fmt.Errorf("current route availability floor unreadable: %w", err)
	}
	if string(policy.UID) == r.PolicyUID && policy.Spec.EffectiveMinAvailableReplicas() > floor {
		floor = policy.Spec.EffectiveMinAvailableReplicas()
	}
	return floor, nil
}

func waitRouteMembership(ctx context.Context, ec EnactCtx, r operationReceipt, exactTarget bool) error {
	timeout, interval := routeTiming(ec)
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	confirmedOnce := false
	for {
		floor, floorErr := r.AdmittedFloor, error(nil)
		if !exactTarget {
			floor, floorErr = routeMembershipFloor(waitCtx, ec, r)
		}
		svc := &corev1.Service{}
		err := floorErr
		if err == nil {
			err = ec.Reader.Get(waitCtx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.ServiceName}, svc)
		}
		if err == nil && string(svc.UID) != r.ServiceUID {
			err = fmt.Errorf("bound Service UID changed")
		}
		if err == nil {
			var members []string
			members, err = routeEndpointMembers(waitCtx, ec.Reader, svc)
			if err == nil {
				matches := false
				if exactTarget {
					if len(members) == 1 && members[0] == r.TargetUID && len(members) >= floor {
						matches = true
					}
				} else if len(members) >= floor {
					matches = true
				}
				if matches {
					if confirmedOnce {
						return nil
					}
					confirmedOnce = true
				} else {
					confirmedOnce = false
					err = fmt.Errorf("EndpointSlice membership %v does not meet floor %d", members, floor)
				}
			}
		}
		if err != nil {
			confirmedOnce = false
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("route EndpointSlice convergence timed out: %w", errors.Join(err, waitCtx.Err()))
		case <-ticker.C:
		}
	}
}

func routeInitialReceipt(ctx context.Context, ec EnactCtx, req Request) (operationReceipt, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || ec.JournalNamespace == req.Namespace {
		return operationReceipt{}, fmt.Errorf("authoritative reader, writer and separate protected journal namespace are required")
	}
	if req.Action != model.ActionRouteRotate && req.Action != model.ActionEndpointRotate {
		return operationReceipt{}, fmt.Errorf("unsupported route action")
	}
	if req.TargetUID == "" || req.PolicyName == "" || req.PolicyUID == "" || req.OperationID == "" || len(req.OperationID) > 253 {
		return operationReceipt{}, fmt.Errorf("target, policy and stable operation identity are required")
	}
	ns := &corev1.Namespace{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: req.Namespace}, ns); err != nil || ns.UID == "" || ns.DeletionTimestamp != nil {
		return operationReceipt{}, fmt.Errorf("namespace authority unavailable: %w", err)
	}
	if observation := actuationbrake.Namespace(ns.Annotations); observation.Engaged {
		return operationReceipt{}, fmt.Errorf("namespace dry-run: %s", observation.Cause)
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.PolicyName}, pol); err != nil {
		return operationReceipt{}, fmt.Errorf("policy authority unavailable: %w", err)
	}
	if string(pol.UID) != req.PolicyUID || pol.DeletionTimestamp != nil || pol.Spec.IsDryRun() || !routeActionEnabled(pol, req.Action) {
		return operationReceipt{}, fmt.Errorf("policy identity, mode or enabled action changed")
	}
	if pol.Spec.EffectiveMinAvailableReplicas() != 1 {
		return operationReceipt{}, fmt.Errorf("route cutover supports effective minAvailableReplicas=1 only (got %d)", pol.Spec.EffectiveMinAvailableReplicas())
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		return operationReceipt{}, fmt.Errorf("target Pod read: %w", err)
	}
	if string(pod.UID) != req.TargetUID || !routeReady(pod) {
		return operationReceipt{}, fmt.Errorf("target Pod identity is changed, terminating or not Ready")
	}
	if len(pod.Labels) == 0 || len(pod.Labels) > requestDrainMaxLabels {
		return operationReceipt{}, fmt.Errorf("target label set is empty or exceeds %d", requestDrainMaxLabels)
	}
	svcName := pod.Annotations[annoRouteService]
	if svcName == "" {
		return operationReceipt{}, fmt.Errorf("target declares no %s", annoRouteService)
	}
	svc := &corev1.Service{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: svcName}, svc); err != nil {
		return operationReceipt{}, fmt.Errorf("declared Service read: %w", err)
	}
	if !routeServiceSelectsPod(svc, pod) || len(svc.Spec.Selector) > requestDrainMaxLabels {
		return operationReceipt{}, fmt.Errorf("declared Service identity/selector is unsupported or does not select target")
	}
	podRoute := ownedValue(pod.Labels, labelRouteKey)
	serviceRoute := ownedValue(svc.Spec.Selector, labelRouteKey)
	if !podRoute.Present || podRoute != serviceRoute || ownedValue(pod.Labels, routeBridgeLabel).Present || ownedValue(svc.Spec.Selector, routeBridgeLabel).Present {
		return operationReceipt{}, fmt.Errorf("route-key is absent/mismatched or bridge key collides")
	}
	if err := requireOnlyRouteService(ctx, ec.Reader, pod, string(svc.UID)); err != nil {
		return operationReceipt{}, err
	}
	members, err := routeEndpointMembers(ctx, ec.Reader, svc)
	if err != nil || len(members) < 1 || !containsUID(members, req.TargetUID) {
		return operationReceipt{}, fmt.Errorf("initial EndpointSlice membership incomplete: %w", err)
	}
	epochKey := routeEpochKey(req.Action)
	routeValue := routeToken("route", req.PolicyUID, req.TargetUID, req.Action, req.OperationID)
	bridgeValue := routeToken("bridge", req.PolicyUID, req.TargetUID, req.Action, req.OperationID)
	projected := copyLabels(pod.Labels)
	projected[labelRouteKey] = routeValue
	bridgeInitial := copyLabels(pod.Labels)
	bridgeInitial[routeBridgeLabel] = bridgeValue
	bridgeFinal := copyLabels(projected)
	bridgeFinal[routeBridgeLabel] = bridgeValue
	sel, err := routePolicySelector(pol)
	if err != nil || !sel.Matches(labels.Set(pod.Labels)) || !sel.Matches(labels.Set(projected)) || !sel.Matches(labels.Set(bridgeInitial)) || !sel.Matches(labels.Set(bridgeFinal)) {
		return operationReceipt{}, fmt.Errorf("policy selector does not authorize every cutover label state: %w", err)
	}
	r := operationReceipt{
		Version: routeCutoverReceiptVersion, Kind: string(req.Action), Phase: "prepared",
		PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		NamespaceUID: string(ns.UID), TargetName: req.Pod, TargetUID: req.TargetUID, TargetLabels: copyLabels(pod.Labels),
		OperationToken: req.OperationID, ServiceName: svc.Name, ServiceUID: string(svc.UID),
		ReceiptID: routeReceiptID(req.PolicyUID, req.TargetUID, req.Action, req.OperationID), AdmittedFloor: 1,
		RouteEpochKey: epochKey, RouteValue: routeValue, BridgeValue: bridgeValue,
		OriginalServiceSelector: copyLabels(svc.Spec.Selector),
		BeforePodRoute:          podRoute, BeforePodEpoch: ownedValue(pod.Annotations, epochKey), BeforePodBridge: ownedValue(pod.Labels, routeBridgeLabel),
		BeforeServiceRoute: serviceRoute, BeforeServiceBridge: ownedValue(svc.Spec.Selector, routeBridgeLabel),
	}
	return r, nil
}

func readRouteReceipt(cm *corev1.ConfigMap) (operationReceipt, error) {
	if cm == nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Labels[journalLabel] != "v1" || len(cm.Data) != 1 {
		return operationReceipt{}, fmt.Errorf("route Service receipt identity invalid")
	}
	var r operationReceipt
	if err := json.Unmarshal([]byte(cm.Data["receipt"]), &r); err != nil || !r.valid() || cm.Name != receiptName(r) {
		return operationReceipt{}, fmt.Errorf("route Service receipt content invalid")
	}
	return r, nil
}

func routeReceiptEqual(a, b operationReceipt) bool {
	return reflect.DeepEqual(a, b)
}

func routeTerminalExact(ctx context.Context, ec EnactCtx, r operationReceipt) error {
	pod, svc, stage, err := readRouteStage(ctx, ec.Reader, r)
	if err != nil {
		return err
	}
	if stage != "applied" || pod == nil || svc == nil {
		return fmt.Errorf("prior terminal route receipt no longer matches exact applied state")
	}
	return waitRouteMembership(ctx, ec, r, true)
}

func acquireRouteReceipt(ctx context.Context, ec EnactCtx, candidate operationReceipt, guard *corev1.ConfigMap) (*corev1.ConfigMap, operationReceipt, error) {
	name := receiptName(candidate)
	key := client.ObjectKey{Namespace: ec.JournalNamespace, Name: name}
	existing := &corev1.ConfigMap{}
	err := ec.Reader.Get(ctx, key, existing)
	if apierrors.IsNotFound(err) {
		candidate.TargetGuardUID = string(guard.UID)
		created, createErr := journalWrite(ctx, ec, candidate)
		if createErr == nil {
			return created, candidate, nil
		}
		observed := &corev1.ConfigMap{}
		if readErr := ec.Reader.Get(ctx, key, observed); readErr != nil {
			return nil, operationReceipt{}, fmt.Errorf("route Service receipt create outcome unresolved: %w", errors.Join(createErr, readErr))
		}
		got, readErr := readRouteReceipt(observed)
		if readErr != nil || got.ReceiptID != candidate.ReceiptID || got.TargetGuardUID != string(guard.UID) {
			return nil, operationReceipt{}, fmt.Errorf("route Service receipt create not owned: %w", errors.Join(createErr, readErr))
		}
		return observed, got, nil
	}
	if err != nil {
		return nil, operationReceipt{}, err
	}
	current, err := readRouteReceipt(existing)
	if err != nil {
		return nil, operationReceipt{}, err
	}
	if current.ReceiptID == candidate.ReceiptID {
		if current.TargetGuardUID != string(guard.UID) {
			return nil, operationReceipt{}, fmt.Errorf("same route operation has a different target guard incarnation")
		}
		return existing, current, nil
	}
	if current.Phase != "applied" {
		return nil, operationReceipt{}, fmt.Errorf("declared Service is owned by unresolved route operation %s", current.ReceiptID)
	}
	if err := routeTerminalExact(ctx, ec, current); err != nil {
		return nil, operationReceipt{}, err
	}
	candidate.TargetGuardUID = string(guard.UID)
	if err := journalAdvance(ctx, ec, existing, candidate); err != nil {
		observed := &corev1.ConfigMap{}
		if readErr := ec.Reader.Get(ctx, key, observed); readErr != nil {
			return nil, operationReceipt{}, errors.Join(err, readErr)
		}
		got, readErr := readRouteReceipt(observed)
		if readErr != nil || got.ReceiptID != candidate.ReceiptID || got.TargetGuardUID != string(guard.UID) {
			return nil, operationReceipt{}, fmt.Errorf("route terminal receipt supersession unresolved: %w", errors.Join(err, readErr))
		}
		return observed, got, nil
	}
	return existing, candidate, nil
}

func routeUnrelatedSelectorExact(svc *corev1.Service, r operationReceipt) bool {
	if svc == nil {
		return false
	}
	for key, want := range r.OriginalServiceSelector {
		if key == labelRouteKey || key == routeBridgeLabel {
			continue
		}
		if got, ok := svc.Spec.Selector[key]; !ok || got != want {
			return false
		}
	}
	for key := range svc.Spec.Selector {
		if key == labelRouteKey || key == routeBridgeLabel {
			continue
		}
		if _, ok := r.OriginalServiceSelector[key]; !ok {
			return false
		}
	}
	return true
}

func routePodState(pod *corev1.Pod, r operationReceipt, route, epoch, bridge routeOwnedValue) bool {
	return pod != nil && string(pod.UID) == r.TargetUID && pod.UID != "" && pod.ResourceVersion != "" &&
		ownedMatches(pod.Labels, labelRouteKey, route) && ownedMatches(pod.Annotations, r.RouteEpochKey, epoch) &&
		ownedMatches(pod.Labels, routeBridgeLabel, bridge)
}

func routeServiceState(svc *corev1.Service, r operationReceipt, route, bridge routeOwnedValue) bool {
	return svc != nil && string(svc.UID) == r.ServiceUID && svc.UID != "" && svc.ResourceVersion != "" &&
		svc.DeletionTimestamp == nil && routeUnrelatedSelectorExact(svc, r) &&
		ownedMatches(svc.Spec.Selector, labelRouteKey, route) && ownedMatches(svc.Spec.Selector, routeBridgeLabel, bridge)
}

func readRouteStage(ctx context.Context, reader client.Reader, r operationReceipt) (*corev1.Pod, *corev1.Service, string, error) {
	svc := &corev1.Service{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.ServiceName}, svc); err != nil {
		return nil, nil, "", err
	}
	if string(svc.UID) != r.ServiceUID {
		return nil, svc, "", fmt.Errorf("bound Service UID changed")
	}
	pod := &corev1.Pod{}
	podErr := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod)
	if podErr != nil {
		if apierrors.IsNotFound(podErr) {
			return nil, svc, "target-missing", nil
		}
		return nil, svc, "", podErr
	}
	if string(pod.UID) != r.TargetUID {
		return nil, svc, "target-replaced", nil
	}
	beforeRoute, beforeEpoch, absentBridge := r.BeforePodRoute, r.BeforePodEpoch, r.BeforePodBridge
	appliedRoute, appliedEpoch, appliedBridge := routeAppliedValue(r.RouteValue), routeAppliedValue(r.RouteValue), routeAppliedValue(r.BridgeValue)
	svcBeforeRoute, svcBeforeBridge := r.BeforeServiceRoute, r.BeforeServiceBridge
	svcBridgeRoute := routeOwnedValue{}
	svcBridge := appliedBridge
	svcFinalRoute := appliedRoute
	svcFinalBridge := routeOwnedValue{}
	switch {
	case routePodState(pod, r, beforeRoute, beforeEpoch, absentBridge) && routeServiceState(svc, r, svcBeforeRoute, svcBeforeBridge):
		return pod, svc, "prepared", nil
	case routePodState(pod, r, beforeRoute, beforeEpoch, appliedBridge) && routeServiceState(svc, r, svcBeforeRoute, svcBeforeBridge):
		return pod, svc, "pod-bridged", nil
	case routePodState(pod, r, beforeRoute, beforeEpoch, appliedBridge) && routeServiceState(svc, r, svcBridgeRoute, svcBridge):
		return pod, svc, "service-bridged", nil
	case routePodState(pod, r, appliedRoute, appliedEpoch, appliedBridge) && routeServiceState(svc, r, svcBridgeRoute, svcBridge):
		return pod, svc, "target-rekeyed", nil
	case routePodState(pod, r, appliedRoute, appliedEpoch, appliedBridge) && routeServiceState(svc, r, svcFinalRoute, svcFinalBridge):
		return pod, svc, "service-final", nil
	case routePodState(pod, r, appliedRoute, appliedEpoch, absentBridge) && routeServiceState(svc, r, svcFinalRoute, svcFinalBridge):
		return pod, svc, "applied", nil
	default:
		return pod, svc, "", fmt.Errorf("route owned fields do not match a recoverable phase")
	}
}

func routeAdvance(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt, phase string) error {
	if r.Phase == phase {
		return nil
	}
	next := *r
	next.Phase = phase
	if err := journalAdvance(ctx, ec, cm, next); err != nil {
		fresh := &corev1.ConfigMap{}
		if readErr := ec.Reader.Get(ctx, client.ObjectKeyFromObject(cm), fresh); readErr != nil {
			return errors.Join(err, readErr)
		}
		observed, readErr := readRouteReceipt(fresh)
		if readErr != nil || observed.ReceiptID != r.ReceiptID || observed.Phase != phase {
			return errors.Join(err, readErr)
		}
		*cm, *r = *fresh, observed
		return nil
	}
	*r = next
	return nil
}

func restoreRequired(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errRouteRestoreRequired, fmt.Sprintf(format, args...))
}

func routeForwardAuthority(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.Pod, *corev1.Service, error) {
	ns := &corev1.Namespace{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: r.PolicyNamespace}, ns); err != nil {
		return nil, nil, err
	}
	if string(ns.UID) != r.NamespaceUID || ns.DeletionTimestamp != nil {
		return nil, nil, fmt.Errorf("recorded namespace incarnation changed")
	}
	if observation := actuationbrake.Namespace(ns.Annotations); observation.Engaged {
		return nil, nil, restoreRequired("namespace dry-run: %s", observation.Cause)
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.PolicyName}, pol); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, restoreRequired("recorded policy is absent")
		}
		return nil, nil, err
	}
	action := model.Action(r.Kind)
	if string(pol.UID) != r.PolicyUID || pol.DeletionTimestamp != nil || pol.Spec.IsDryRun() || !routeActionEnabled(pol, action) {
		return nil, nil, restoreRequired("policy identity, mode or action authority changed")
	}
	if pol.Spec.EffectiveMinAvailableReplicas() > r.AdmittedFloor || pol.Spec.EffectiveMinAvailableReplicas() != 1 {
		return nil, nil, restoreRequired("current availability floor %d exceeds bounded route contract", pol.Spec.EffectiveMinAvailableReplicas())
	}
	sel, err := routePolicySelector(pol)
	if err != nil {
		return nil, nil, restoreRequired("current policy selector invalid: %v", err)
	}
	before := copyLabels(r.TargetLabels)
	projected := copyLabels(r.TargetLabels)
	projected[labelRouteKey] = r.RouteValue
	bridgeBefore := copyLabels(before)
	bridgeBefore[routeBridgeLabel] = r.BridgeValue
	bridgeFinal := copyLabels(projected)
	bridgeFinal[routeBridgeLabel] = r.BridgeValue
	for _, state := range []map[string]string{before, projected, bridgeBefore, bridgeFinal} {
		if !sel.Matches(labels.Set(state)) {
			return nil, nil, restoreRequired("current policy selector no longer admits every recorded phase")
		}
	}
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, restoreRequired("target Pod is absent")
		}
		return nil, nil, err
	}
	if string(pod.UID) != r.TargetUID {
		return nil, nil, restoreRequired("target Pod was replaced")
	}
	if !routeReady(pod) {
		return nil, nil, restoreRequired("target Pod is terminating or not Ready")
	}
	if pod.Annotations[annoRouteService] != r.ServiceName || !sel.Matches(labels.Set(pod.Labels)) {
		return nil, nil, restoreRequired("target declaration or current policy scope changed")
	}
	svc := &corev1.Service{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.ServiceName}, svc); err != nil {
		return nil, nil, err
	}
	if string(svc.UID) != r.ServiceUID || !routeServiceSelectsPod(svc, pod) {
		return nil, nil, fmt.Errorf("bound Service identity changed or no longer selects target")
	}
	if !routeUnrelatedSelectorExact(svc, r) {
		return nil, nil, fmt.Errorf("bound Service unrelated selector predicates changed")
	}
	if err := requireOnlyRouteService(ctx, ec.Reader, pod, r.ServiceUID); err != nil {
		return nil, nil, restoreRequired("%v", err)
	}
	return pod, svc, nil
}

func patchRoutePod(ctx context.Context, ec EnactCtx, r operationReceipt, pod *corev1.Pod, route, epoch, bridge routeOwnedValue) error {
	if pod == nil || string(pod.UID) != r.TargetUID || pod.ResourceVersion == "" {
		return fmt.Errorf("route Pod write identity invalid")
	}
	before := pod.DeepCopy()
	pod.Labels = ensureMap(pod.Labels)
	pod.Annotations = ensureMap(pod.Annotations)
	setOwned(pod.Labels, labelRouteKey, route)
	setOwned(pod.Annotations, r.RouteEpochKey, epoch)
	setOwned(pod.Labels, routeBridgeLabel, bridge)
	writeErr := ec.Client.Patch(ctx, pod, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
	fresh := &corev1.Pod{}
	readErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, fresh)
	if readErr == nil && routePodState(fresh, r, route, epoch, bridge) {
		return nil
	}
	if writeErr != nil {
		if apierrors.IsConflict(writeErr) || apierrors.IsNotFound(writeErr) || apierrors.IsForbidden(writeErr) || apierrors.IsUnauthorized(writeErr) || apierrors.IsInvalid(writeErr) {
			return fmt.Errorf("%w: %v", errRouteWriteRejected, writeErr)
		}
		return fmt.Errorf("route Pod patch outcome unresolved: %w", errors.Join(writeErr, readErr))
	}
	return fmt.Errorf("route Pod patch postcondition unconfirmed: %w", readErr)
}

func updateRouteService(ctx context.Context, ec EnactCtx, r operationReceipt, svc *corev1.Service, route, bridge routeOwnedValue) error {
	if svc == nil || string(svc.UID) != r.ServiceUID || svc.ResourceVersion == "" || !routeUnrelatedSelectorExact(svc, r) {
		return fmt.Errorf("route Service write identity invalid")
	}
	svc.Spec.Selector = copyLabels(svc.Spec.Selector)
	setOwned(svc.Spec.Selector, labelRouteKey, route)
	setOwned(svc.Spec.Selector, routeBridgeLabel, bridge)
	writeErr := ec.Client.Update(ctx, svc)
	fresh := &corev1.Service{}
	readErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.ServiceName}, fresh)
	if readErr == nil && routeServiceState(fresh, r, route, bridge) {
		return nil
	}
	if writeErr != nil {
		return fmt.Errorf("route Service update outcome unresolved: %w", errors.Join(writeErr, readErr))
	}
	return fmt.Errorf("route Service update postcondition unconfirmed: %w", readErr)
}

func routePartialResult(ec EnactCtx, cm *corev1.ConfigMap, r operationReceipt, note string) HandlerResult {
	objects := []string{objRef("Pod", r.PolicyNamespace, r.TargetName), objRef("Service", r.PolicyNamespace, r.ServiceName)}
	rollback := ""
	if cm != nil {
		objects = append(objects, objRef("ConfigMap", cm.Namespace, cm.Name))
		rollback = cm.Namespace + "/" + cm.Name + "@" + string(cm.UID) + "#" + r.ReceiptID
	}
	return HandlerResult{Emitted: true, MutationKind: "partial", RollbackRef: rollback, ObjectsTouched: objects, Note: note}
}

func routeCompleteResult(cm *corev1.ConfigMap, r operationReceipt) HandlerResult {
	return HandlerResult{
		Emitted: true, MutationKind: "reversible",
		RollbackRef:    cm.Namespace + "/" + cm.Name + "@" + string(cm.UID) + "#" + r.ReceiptID,
		ObjectsTouched: []string{objRef("Pod", r.PolicyNamespace, r.TargetName), objRef("Service", r.PolicyNamespace, r.ServiceName), objRef("ConfigMap", cm.Namespace, cm.Name)},
		Note:           string(model.Action(r.Kind)) + ": exact Pod/Service route cutover confirmed through Service-owned EndpointSlices; network data plane and bounded outage unverified",
	}
}

func routeLocksOnlyResult(guard *corev1.ConfigMap, cm *corev1.ConfigMap, note string) HandlerResult {
	objects := []string{}
	if guard != nil {
		objects = append(objects, objRef("ConfigMap", guard.Namespace, guard.Name))
	}
	if cm != nil {
		objects = append(objects, objRef("ConfigMap", cm.Namespace, cm.Name))
	}
	return HandlerResult{MutationKind: "partial", ObjectsTouched: objects, Note: note}
}

func runRouteForward(ctx context.Context, ec EnactCtx, cm, guard *corev1.ConfigMap, r operationReceipt) (HandlerResult, error) {
	for attempt := 0; attempt < 10; attempt++ {
		pod, svc, stage, err := readRouteStage(ctx, ec.Reader, r)
		if err != nil {
			return routePartialResult(ec, cm, r, "route owned state unreadable or foreign; receipt retained"), err
		}
		if err := requireRouteGuard(ctx, ec, guard, cm, r); err != nil {
			if stage == "prepared" {
				return routeLocksOnlyResult(guard, cm, "route target guard unresolved before any confirmed tenant write"), err
			}
			return routePartialResult(ec, cm, r, "route target guard unresolved; no further tenant write allowed"), err
		}
		if stage == "target-missing" || stage == "target-replaced" {
			return restoreRouteCutover(ctx, ec, cm, guard, &r, restoreRequired("%s", stage))
		}
		pod, svc, authErr := routeForwardAuthority(ctx, ec, r)
		if authErr != nil {
			if errors.Is(authErr, errRouteRestoreRequired) {
				return restoreRouteCutover(ctx, ec, cm, guard, &r, authErr)
			}
			return routePartialResult(ec, cm, r, "route authority read unresolved; receipt retained"), authErr
		}
		if stage == "applied" {
			if err := waitRouteMembership(ctx, ec, r, true); err != nil {
				return routePartialResult(ec, cm, r, "final Service membership unconfirmed; receipt retained"), err
			}
			if _, _, finalAuthErr := routeForwardAuthority(ctx, ec, r); finalAuthErr != nil {
				if errors.Is(finalAuthErr, errRouteRestoreRequired) {
					return restoreRouteCutover(ctx, ec, cm, guard, &r, finalAuthErr)
				}
				return routePartialResult(ec, cm, r, "final route authority changed during observation; receipt retained"), finalAuthErr
			}
			if err := routeAdvance(ctx, ec, cm, &r, "applied"); err != nil {
				return routePartialResult(ec, cm, r, "final route state confirmed but terminal receipt acknowledgement failed"), err
			}
			if err := finishRouteGuard(ctx, ec, guard); err != nil {
				return routePartialResult(ec, cm, r, "final route state confirmed but target guard cleanup unresolved"), err
			}
			return routeCompleteResult(cm, r), nil
		}
		switch stage {
		case "prepared":
			if !routePodState(pod, r, r.BeforePodRoute, r.BeforePodEpoch, r.BeforePodBridge) || !routeServiceState(svc, r, r.BeforeServiceRoute, r.BeforeServiceBridge) {
				return routePartialResult(ec, cm, r, "route owned state raced before bridge patch; receipt retained"), fmt.Errorf("route prepared state changed")
			}
			if err := patchRoutePod(ctx, ec, r, pod, r.BeforePodRoute, r.BeforePodEpoch, routeAppliedValue(r.BridgeValue)); err != nil {
				if errors.Is(err, errRouteWriteRejected) {
					return routeLocksOnlyResult(guard, cm, "first tenant patch was rejected; protected intent retained for reconciliation"), err
				}
				return routePartialResult(ec, cm, r, "bridge-label patch outcome unresolved; receipt retained"), err
			}
			if err := routeAdvance(ctx, ec, cm, &r, "pod-bridged"); err != nil {
				return routePartialResult(ec, cm, r, "bridge-label applied; receipt phase unresolved"), err
			}
		case "pod-bridged":
			if !routePodState(pod, r, r.BeforePodRoute, r.BeforePodEpoch, routeAppliedValue(r.BridgeValue)) || !routeServiceState(svc, r, r.BeforeServiceRoute, r.BeforeServiceBridge) {
				return routePartialResult(ec, cm, r, "route owned state raced before Service bridge; receipt retained"), fmt.Errorf("route pod-bridged state changed")
			}
			if err := updateRouteService(ctx, ec, r, svc, routeOwnedValue{}, routeAppliedValue(r.BridgeValue)); err != nil {
				return routePartialResult(ec, cm, r, "Service bridge update outcome unresolved; receipt retained"), err
			}
			if err := waitRouteMembership(ctx, ec, r, true); err != nil {
				return restoreRouteCutover(ctx, ec, cm, guard, &r, restoreRequired("bridge membership unconfirmed: %v", err))
			}
			if err := routeAdvance(ctx, ec, cm, &r, "service-bridged"); err != nil {
				return routePartialResult(ec, cm, r, "Service bridge confirmed; receipt phase unresolved"), err
			}
		case "service-bridged":
			if !routePodState(pod, r, r.BeforePodRoute, r.BeforePodEpoch, routeAppliedValue(r.BridgeValue)) || !routeServiceState(svc, r, routeOwnedValue{}, routeAppliedValue(r.BridgeValue)) {
				return routePartialResult(ec, cm, r, "route owned state raced before target re-key; receipt retained"), fmt.Errorf("route service-bridged state changed")
			}
			if err := waitRouteMembership(ctx, ec, r, true); err != nil {
				return restoreRouteCutover(ctx, ec, cm, guard, &r, restoreRequired("bridge membership changed: %v", err))
			}
			if err := patchRoutePod(ctx, ec, r, pod, routeAppliedValue(r.RouteValue), routeAppliedValue(r.RouteValue), routeAppliedValue(r.BridgeValue)); err != nil {
				return routePartialResult(ec, cm, r, "target re-key patch outcome unresolved; receipt retained"), err
			}
			if err := routeAdvance(ctx, ec, cm, &r, "target-rekeyed"); err != nil {
				return routePartialResult(ec, cm, r, "target re-keyed; receipt phase unresolved"), err
			}
		case "target-rekeyed":
			if !routePodState(pod, r, routeAppliedValue(r.RouteValue), routeAppliedValue(r.RouteValue), routeAppliedValue(r.BridgeValue)) || !routeServiceState(svc, r, routeOwnedValue{}, routeAppliedValue(r.BridgeValue)) {
				return routePartialResult(ec, cm, r, "route owned state raced before final Service selector; receipt retained"), fmt.Errorf("route target-rekeyed state changed")
			}
			if err := waitRouteMembership(ctx, ec, r, true); err != nil {
				return restoreRouteCutover(ctx, ec, cm, guard, &r, restoreRequired("bridge membership changed before final selector: %v", err))
			}
			if err := updateRouteService(ctx, ec, r, svc, routeAppliedValue(r.RouteValue), routeOwnedValue{}); err != nil {
				return routePartialResult(ec, cm, r, "final Service update outcome unresolved; receipt retained"), err
			}
			if err := waitRouteMembership(ctx, ec, r, true); err != nil {
				return restoreRouteCutover(ctx, ec, cm, guard, &r, restoreRequired("final membership unconfirmed: %v", err))
			}
			if err := routeAdvance(ctx, ec, cm, &r, "service-final"); err != nil {
				return routePartialResult(ec, cm, r, "final Service membership confirmed; receipt phase unresolved"), err
			}
		case "service-final":
			if !routePodState(pod, r, routeAppliedValue(r.RouteValue), routeAppliedValue(r.RouteValue), routeAppliedValue(r.BridgeValue)) || !routeServiceState(svc, r, routeAppliedValue(r.RouteValue), routeOwnedValue{}) {
				return routePartialResult(ec, cm, r, "route owned state raced before bridge cleanup; receipt retained"), fmt.Errorf("route service-final state changed")
			}
			if err := patchRoutePod(ctx, ec, r, pod, routeAppliedValue(r.RouteValue), routeAppliedValue(r.RouteValue), r.BeforePodBridge); err != nil {
				return routePartialResult(ec, cm, r, "bridge cleanup patch outcome unresolved; receipt retained"), err
			}
			if err := waitRouteMembership(ctx, ec, r, true); err != nil {
				return routePartialResult(ec, cm, r, "bridge removed but final membership unconfirmed; receipt retained"), err
			}
		default:
			return routePartialResult(ec, cm, r, "route phase is not forward-recoverable; receipt retained"), fmt.Errorf("unexpected route stage %q", stage)
		}
	}
	return routePartialResult(ec, cm, r, "route state machine exceeded bounded steps; receipt retained"), fmt.Errorf("route cutover did not converge")
}

func ensureRouteGuardForReceipt(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (*corev1.ConfigMap, error) {
	guard, err := acquireRouteGuard(ctx, ec, *r)
	if err == nil && string(guard.UID) == r.TargetGuardUID {
		if bindErr := bindRouteGuard(ctx, ec, guard, cm, *r); bindErr != nil {
			return nil, bindErr
		}
		return guard, nil
	}
	if err == nil && string(guard.UID) != r.TargetGuardUID {
		next := *r
		next.TargetGuardUID = string(guard.UID)
		if advanceErr := journalAdvance(ctx, ec, cm, next); advanceErr != nil {
			_ = finishRouteGuard(ctx, ec, guard)
			return nil, advanceErr
		}
		*r = next
		if bindErr := bindRouteGuard(ctx, ec, guard, cm, *r); bindErr != nil {
			return nil, bindErr
		}
		return guard, nil
	}
	return nil, err
}

func routePodOwnedRecoverable(pod *corev1.Pod, r operationReceipt) bool {
	appliedRoute := routeAppliedValue(r.RouteValue)
	appliedBridge := routeAppliedValue(r.BridgeValue)
	return routePodState(pod, r, r.BeforePodRoute, r.BeforePodEpoch, r.BeforePodBridge) ||
		routePodState(pod, r, r.BeforePodRoute, r.BeforePodEpoch, appliedBridge) ||
		routePodState(pod, r, appliedRoute, appliedRoute, appliedBridge) ||
		routePodState(pod, r, appliedRoute, appliedRoute, r.BeforePodBridge)
}

func routeServiceOwnedRecoverable(svc *corev1.Service, r operationReceipt) bool {
	return routeServiceState(svc, r, r.BeforeServiceRoute, r.BeforeServiceBridge) ||
		routeServiceState(svc, r, routeOwnedValue{}, routeAppliedValue(r.BridgeValue)) ||
		routeServiceState(svc, r, routeAppliedValue(r.RouteValue), r.BeforeServiceBridge)
}

func routeReadyOriginalSiblings(ctx context.Context, reader client.Reader, r operationReceipt) (int, error) {
	var pods corev1.PodList
	if err := reader.List(ctx, &pods, client.InNamespace(r.PolicyNamespace), client.MatchingLabels(r.OriginalServiceSelector)); err != nil {
		return 0, err
	}
	ready := 0
	for i := range pods.Items {
		if string(pods.Items[i].UID) != r.TargetUID && routeReady(&pods.Items[i]) {
			ready++
		}
	}
	return ready, nil
}

func readRouteRestoreStage(ctx context.Context, reader client.Reader, r operationReceipt) (*corev1.Pod, *corev1.Service, string, error) {
	svc := &corev1.Service{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.ServiceName}, svc); err != nil {
		return nil, nil, "", err
	}
	if string(svc.UID) != r.ServiceUID || !routeServiceOwnedRecoverable(svc, r) {
		return nil, svc, "", fmt.Errorf("bound Service cannot be restored exactly")
	}
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, svc, "target-missing", nil
		}
		return nil, svc, "", err
	}
	if string(pod.UID) != r.TargetUID {
		return pod, svc, "target-replaced", nil
	}
	if !routePodOwnedRecoverable(pod, r) {
		return pod, svc, "", fmt.Errorf("target owned fields cannot be restored exactly")
	}
	if !routeReady(pod) {
		return pod, svc, "target-unavailable", nil
	}
	beforeRoute, beforeEpoch, beforeBridge := r.BeforePodRoute, r.BeforePodEpoch, r.BeforePodBridge
	appliedRoute, appliedEpoch, appliedBridge := routeAppliedValue(r.RouteValue), routeAppliedValue(r.RouteValue), routeAppliedValue(r.BridgeValue)
	serviceBeforeRoute, serviceBeforeBridge := r.BeforeServiceRoute, r.BeforeServiceBridge
	serviceBridgeRoute := routeOwnedValue{}
	serviceBridge := appliedBridge
	serviceAppliedRoute := appliedRoute
	serviceAppliedBridge := routeOwnedValue{}
	switch {
	case routePodState(pod, r, beforeRoute, beforeEpoch, beforeBridge) && routeServiceState(svc, r, serviceBeforeRoute, serviceBeforeBridge):
		return pod, svc, "restored", nil
	case routePodState(pod, r, appliedRoute, appliedEpoch, beforeBridge) && routeServiceState(svc, r, serviceAppliedRoute, serviceAppliedBridge):
		return pod, svc, "reverse-applied", nil
	case routePodState(pod, r, appliedRoute, appliedEpoch, appliedBridge) && routeServiceState(svc, r, serviceAppliedRoute, serviceAppliedBridge):
		return pod, svc, "reverse-pod-bridged", nil
	case routePodState(pod, r, appliedRoute, appliedEpoch, appliedBridge) && routeServiceState(svc, r, serviceBridgeRoute, serviceBridge):
		return pod, svc, "reverse-service-bridged", nil
	case routePodState(pod, r, beforeRoute, beforeEpoch, appliedBridge) && routeServiceState(svc, r, serviceBridgeRoute, serviceBridge):
		return pod, svc, "reverse-target-rekeyed", nil
	case routePodState(pod, r, beforeRoute, beforeEpoch, appliedBridge) && routeServiceState(svc, r, serviceBeforeRoute, serviceBeforeBridge):
		return pod, svc, "reverse-service-original", nil
	default:
		return pod, svc, "", fmt.Errorf("route owned fields do not match a recoverable restoration phase")
	}
}

func restoreRouteCutover(ctx context.Context, ec EnactCtx, cm, guard *corev1.ConfigMap, r *operationReceipt, cause error) (HandlerResult, error) {
	if cm == nil || r == nil {
		return HandlerResult{}, cause
	}
	if guard == nil || string(guard.UID) != r.TargetGuardUID {
		var err error
		guard, err = ensureRouteGuardForReceipt(ctx, ec, cm, r)
		if err != nil {
			return routePartialResult(ec, cm, *r, "route restoration target guard unavailable; receipt retained"), errors.Join(cause, err)
		}
	}
	if err := requireRouteGuard(ctx, ec, guard, cm, *r); err != nil {
		return routePartialResult(ec, cm, *r, "route restoration target guard changed; receipt retained"), errors.Join(cause, err)
	}
	if r.Phase == "prepared" {
		pod, svc, stage, stageErr := readRouteRestoreStage(ctx, ec.Reader, *r)
		unavailableStillOriginal := stage == "target-unavailable" && routePodState(pod, *r, r.BeforePodRoute, r.BeforePodEpoch, r.BeforePodBridge)
		noTenantEffect := stage == "restored" || ((stage == "target-missing" || stage == "target-replaced" || unavailableStillOriginal) && routeServiceState(svc, *r, r.BeforeServiceRoute, r.BeforeServiceBridge))
		if stageErr == nil && noTenantEffect {
			if floorErr := waitRouteMembership(ctx, ec, *r, false); floorErr != nil {
				return routeLocksOnlyResult(guard, cm, "route stopped before tenant writes; current membership floor is unconfirmed"), errors.Join(cause, floorErr)
			}
			if finishErr := journalFinish(ctx, ec, cm); finishErr != nil {
				return routeLocksOnlyResult(guard, cm, "route stopped before tenant writes; receipt cleanup unresolved"), errors.Join(cause, finishErr)
			}
			if finishErr := finishRouteGuard(ctx, ec, guard); finishErr != nil {
				return routeLocksOnlyResult(guard, nil, "route stopped before tenant writes; target guard cleanup unresolved"), errors.Join(cause, finishErr)
			}
			return routeLocksOnlyResult(nil, nil, "route operation stopped before any confirmed tenant write; protected intent cleaned up"), cause
		}
	}
	hadTenantEffect := r.Phase != "prepared"
	if err := routeAdvance(ctx, ec, cm, r, "restoring"); err != nil {
		return routePartialResult(ec, cm, *r, "route restoration intent persistence unresolved"), errors.Join(cause, err)
	}
	for attempt := 0; attempt < 10; attempt++ {
		if err := requireRouteGuard(ctx, ec, guard, cm, *r); err != nil {
			return routePartialResult(ec, cm, *r, "route restoration target guard changed; receipt retained"), errors.Join(cause, err)
		}
		pod, svc, stage, err := readRouteRestoreStage(ctx, ec.Reader, *r)
		if err != nil {
			return routePartialResult(ec, cm, *r, "route restoration owned state unreadable or foreign; receipt retained"), errors.Join(cause, err)
		}
		if stage != "restored" {
			hadTenantEffect = true
		}
		switch stage {
		case "target-missing", "target-replaced", "target-unavailable":
			if !routeServiceState(svc, *r, r.BeforeServiceRoute, r.BeforeServiceBridge) {
				if stage == "target-unavailable" {
					floor, floorErr := routeMembershipFloor(ctx, ec, *r)
					siblings, siblingsErr := routeReadyOriginalSiblings(ctx, ec.Reader, *r)
					if floorErr != nil || siblingsErr != nil || siblings < floor {
						return routePartialResult(ec, cm, *r, "target unavailable; original-selector sibling floor unproved, current Service retained"), errors.Join(cause, floorErr, siblingsErr, fmt.Errorf("ready original siblings %d below floor %d", siblings, floor))
					}
				}
				if err := updateRouteService(ctx, ec, *r, svc, r.BeforeServiceRoute, r.BeforeServiceBridge); err != nil {
					return routePartialResult(ec, cm, *r, "target lost; original Service selector restoration unresolved"), errors.Join(cause, err)
				}
			}
			if err := waitRouteMembership(ctx, ec, *r, false); err != nil {
				return routePartialResult(ec, cm, *r, "target lost; original Service membership floor unconfirmed; receipt retained"), errors.Join(cause, err)
			}
			if stage == "target-unavailable" && !routePodState(pod, *r, r.BeforePodRoute, r.BeforePodEpoch, r.BeforePodBridge) {
				if err := patchRoutePod(ctx, ec, *r, pod, r.BeforePodRoute, r.BeforePodEpoch, r.BeforePodBridge); err != nil {
					return routePartialResult(ec, cm, *r, "Service restored; unavailable target owned-field restoration unresolved"), errors.Join(cause, err)
				}
			}
			stage = "restored"
		case "reverse-applied":
			if err := patchRoutePod(ctx, ec, *r, pod, routeAppliedValue(r.RouteValue), routeAppliedValue(r.RouteValue), routeAppliedValue(r.BridgeValue)); err != nil {
				return routePartialResult(ec, cm, *r, "reverse bridge-label patch unresolved; receipt retained"), errors.Join(cause, err)
			}
		case "reverse-pod-bridged":
			if err := waitRouteMembership(ctx, ec, *r, true); err != nil {
				return routePartialResult(ec, cm, *r, "reverse bridge preparation membership unconfirmed; receipt retained"), errors.Join(cause, err)
			}
			if err := updateRouteService(ctx, ec, *r, svc, routeOwnedValue{}, routeAppliedValue(r.BridgeValue)); err != nil {
				return routePartialResult(ec, cm, *r, "reverse Service bridge update unresolved; receipt retained"), errors.Join(cause, err)
			}
		case "reverse-service-bridged":
			if err := waitRouteMembership(ctx, ec, *r, true); err != nil {
				return routePartialResult(ec, cm, *r, "reverse Service bridge membership unconfirmed; receipt retained"), errors.Join(cause, err)
			}
			if err := patchRoutePod(ctx, ec, *r, pod, r.BeforePodRoute, r.BeforePodEpoch, routeAppliedValue(r.BridgeValue)); err != nil {
				return routePartialResult(ec, cm, *r, "reverse target re-key patch unresolved; receipt retained"), errors.Join(cause, err)
			}
		case "reverse-target-rekeyed":
			if err := waitRouteMembership(ctx, ec, *r, true); err != nil {
				return routePartialResult(ec, cm, *r, "reverse bridge membership changed before original selector; receipt retained"), errors.Join(cause, err)
			}
			if err := updateRouteService(ctx, ec, *r, svc, r.BeforeServiceRoute, r.BeforeServiceBridge); err != nil {
				return routePartialResult(ec, cm, *r, "original Service selector restoration unresolved; receipt retained"), errors.Join(cause, err)
			}
		case "reverse-service-original":
			if err := waitRouteMembership(ctx, ec, *r, false); err != nil {
				return routePartialResult(ec, cm, *r, "original Service membership floor unconfirmed before bridge cleanup; receipt retained"), errors.Join(cause, err)
			}
			if err := patchRoutePod(ctx, ec, *r, pod, r.BeforePodRoute, r.BeforePodEpoch, r.BeforePodBridge); err != nil {
				return routePartialResult(ec, cm, *r, "reverse bridge cleanup patch unresolved; receipt retained"), errors.Join(cause, err)
			}
		case "restored":
			if err := waitRouteMembership(ctx, ec, *r, false); err != nil {
				return routePartialResult(ec, cm, *r, "original Service selector restored but membership floor unconfirmed; receipt retained"), errors.Join(cause, err)
			}
		default:
			return routePartialResult(ec, cm, *r, "route restoration phase is not recoverable; receipt retained"), errors.Join(cause, fmt.Errorf("unexpected restoration stage %q", stage))
		}
		if stage != "restored" {
			continue
		}
		if err := journalFinish(ctx, ec, cm); err != nil {
			return routePartialResult(ec, cm, *r, "owned fields and membership restored; receipt cleanup unresolved"), errors.Join(cause, err)
		}
		if err := finishRouteGuard(ctx, ec, guard); err != nil {
			return routeLocksOnlyResult(guard, nil, "route restored; orphan target guard cleanup unresolved"), errors.Join(cause, err)
		}
		if !hadTenantEffect {
			return routeLocksOnlyResult(nil, nil, "route operation stopped before any confirmed tenant write; protected intent cleaned up"), cause
		}
		return HandlerResult{
			Emitted: true, MutationKind: "partial",
			ObjectsTouched: []string{objRef("Pod", r.PolicyNamespace, r.TargetName), objRef("Service", r.PolicyNamespace, r.ServiceName)},
			Note:           "route operation did not complete; reverse bridge restored exact owned fields and current Service EndpointSlice membership floor",
		}, cause
	}
	return routePartialResult(ec, cm, *r, "route restoration exceeded bounded steps; receipt retained"), errors.Join(cause, fmt.Errorf("route restoration did not converge"))
}

func routeReceiptMatchesRequest(r operationReceipt, req Request) bool {
	return r.Kind == string(req.Action) && r.PolicyNamespace == req.Namespace && r.PolicyName == req.PolicyName &&
		r.PolicyUID == req.PolicyUID && r.TargetName == req.Pod && r.TargetUID == req.TargetUID &&
		r.OperationToken == req.OperationID
}

func resumeRouteReceipt(ctx context.Context, ec EnactCtx, req Request, cm, guard *corev1.ConfigMap, r operationReceipt) (HandlerResult, error) {
	if !routeReceiptMatchesRequest(r, req) {
		return routeLocksOnlyResult(guard, cm, "route target or Service is owned by another unresolved operation"), fmt.Errorf("protected route operation tuple differs")
	}
	if r.Phase == "applied" {
		_, _, authorityErr := routeForwardAuthority(ctx, ec, r)
		if errors.Is(authorityErr, errRouteRestoreRequired) {
			if guard == nil {
				var err error
				guard, err = ensureRouteGuardForReceipt(ctx, ec, cm, &r)
				if err != nil {
					return routeLocksOnlyResult(nil, cm, "terminal route restoration guard reacquisition is unresolved"), err
				}
			}
			return restoreRouteCutover(ctx, ec, cm, guard, &r, nil)
		}
		if authorityErr != nil {
			return routeLocksOnlyResult(guard, cm, "terminal same-operation authority is unreadable or changed"), authorityErr
		}
		if exactErr := routeTerminalExact(ctx, ec, r); exactErr != nil {
			return routeLocksOnlyResult(guard, cm, "terminal same-operation route state changed; receipt retained"), exactErr
		}
		if guard != nil {
			if err := requireRouteGuard(ctx, ec, guard, cm, r); err != nil {
				return routeLocksOnlyResult(guard, cm, "terminal same-operation target guard binding is unresolved"), err
			}
			if cleanupErr := finishRouteGuard(ctx, ec, guard); cleanupErr != nil {
				return routeLocksOnlyResult(guard, cm, "terminal same-operation target guard cleanup unresolved"), cleanupErr
			}
		}
		return HandlerResult{MutationKind: "reversible", RollbackRef: cm.Namespace + "/" + cm.Name + "@" + string(cm.UID) + "#" + r.ReceiptID, Note: "exact same route operation already applied; no new write or credit"}, nil
	}
	if guard == nil {
		var err error
		guard, err = ensureRouteGuardForReceipt(ctx, ec, cm, &r)
		if err != nil {
			return routeLocksOnlyResult(nil, cm, "exact route operation found but target guard reacquisition is unresolved"), err
		}
	} else if err := requireRouteGuard(ctx, ec, guard, cm, r); err != nil {
		return routeLocksOnlyResult(guard, cm, "exact route operation guard binding is unresolved"), err
	}
	if r.Phase == "restoring" {
		return restoreRouteCutover(ctx, ec, cm, guard, &r, nil)
	}
	return runRouteForward(ctx, ec, cm, guard, r)
}

func resumeExistingRouteOperation(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error, bool) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" || req.TargetUID == "" || req.PolicyName == "" || req.PolicyUID == "" || req.OperationID == "" {
		return HandlerResult{}, nil, false
	}
	guard := &corev1.ConfigMap{}
	guardErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: routeGuardName(req.TargetUID)}, guard)
	if guardErr == nil {
		g, err := readRouteGuard(guard)
		if err != nil {
			return routeLocksOnlyResult(guard, nil, "protected route target guard is invalid or terminating"), err, true
		}
		wantID := routeReceiptID(req.PolicyUID, req.TargetUID, req.Action, req.OperationID)
		if g.PolicyNamespace != req.Namespace || g.PolicyUID != req.PolicyUID || g.TargetUID != req.TargetUID || g.Action != string(req.Action) || g.OperationID != req.OperationID || g.ReceiptID != wantID {
			return routeLocksOnlyResult(guard, nil, "route target is owned by another unresolved operation"), fmt.Errorf("protected route target guard tuple differs"), true
		}
		cm := &corev1.ConfigMap{}
		if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: g.ReceiptName}, cm); err != nil {
			return routeLocksOnlyResult(guard, nil, "exact target guard exists but its Service receipt is unresolved"), err, true
		}
		r, err := readRouteReceipt(cm)
		if err != nil || r.TargetGuardUID != string(guard.UID) {
			return routeLocksOnlyResult(guard, cm, "target guard and Service receipt binding is invalid or terminating"), errors.Join(err, fmt.Errorf("protected route lock binding differs")), true
		}
		if g.ReceiptUID == "" {
			if err := bindRouteGuard(ctx, ec, guard, cm, r); err != nil {
				return routeLocksOnlyResult(guard, cm, "target guard and Service receipt binding is unresolved"), err, true
			}
		} else if g.ReceiptUID != string(cm.UID) {
			return routeLocksOnlyResult(guard, cm, "target guard and Service receipt binding is invalid"), fmt.Errorf("protected route lock receipt UID differs"), true
		}
		result, resumeErr := resumeRouteReceipt(ctx, ec, req, cm, guard, r)
		return result, resumeErr, true
	}
	if guardErr != nil && !apierrors.IsNotFound(guardErr) {
		return routeLocksOnlyResult(nil, nil, "route target guard lookup is unresolved"), guardErr, true
	}
	entries, err := journalList(ctx, ec)
	if err != nil {
		return routeLocksOnlyResult(nil, nil, "protected operation inventory is unreadable or invalid"), err, true
	}
	for i := range entries {
		r := entries[i].Receipt
		if (r.Kind == string(model.ActionRouteRotate) || r.Kind == string(model.ActionEndpointRotate)) && r.TargetUID == req.TargetUID {
			if !routeReceiptMatchesRequest(r, req) {
				if r.Phase == "applied" {
					continue
				}
				return routeLocksOnlyResult(nil, &entries[i].CM, "route target has a Service receipt owned by another unresolved operation"), fmt.Errorf("protected route Service receipt tuple differs"), true
			}
			result, resumeErr := resumeRouteReceipt(ctx, ec, req, &entries[i].CM, nil, r)
			return result, resumeErr, true
		}
	}
	return HandlerResult{}, nil, false
}

func enactRouteCutover(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if result, err, found := resumeExistingRouteOperation(ctx, ec, req); found {
		return result, err
	}
	candidate, err := routeInitialReceipt(ctx, ec, req)
	if err != nil {
		refusal := fmt.Errorf("%s not performed: %w", req.Action, err)
		return HandlerResult{MutationKind: "none", Note: refusal.Error()}, RefusedWithoutEffect(refusal)
	}
	guard, err := acquireRouteGuard(ctx, ec, candidate)
	if err != nil {
		return HandlerResult{MutationKind: "partial", Note: "route target ownership unresolved; no tenant write attempted"}, err
	}
	candidate.TargetGuardUID = string(guard.UID)
	cm, receipt, err := acquireRouteReceipt(ctx, ec, candidate, guard)
	if err != nil {
		cleanupErr := finishRouteGuard(ctx, ec, guard)
		return routeLocksOnlyResult(guard, nil, "route Service ownership unavailable; no tenant write attempted"), errors.Join(err, cleanupErr)
	}
	if err := bindRouteGuard(ctx, ec, guard, cm, receipt); err != nil {
		return routeLocksOnlyResult(guard, cm, "route lock binding unresolved; no tenant write attempted"), err
	}
	if err := requireRouteGuard(ctx, ec, guard, cm, receipt); err != nil {
		return routeLocksOnlyResult(guard, cm, "route lock pair changed; no tenant write attempted"), err
	}
	if receipt.Phase == "restoring" {
		return restoreRouteCutover(ctx, ec, cm, guard, &receipt, restoreRequired("resuming recorded restoration"))
	}
	return runRouteForward(ctx, ec, cm, guard, receipt)
}

func parseRouteRollbackRef(ref string) (namespace, name string, uid types.UID, receiptID string, err error) {
	hash := strings.LastIndex(ref, "#")
	at := strings.LastIndex(ref, "@")
	slash := strings.Index(ref, "/")
	if slash <= 0 || at <= slash+1 || hash <= at+1 || hash == len(ref)-1 {
		return "", "", "", "", fmt.Errorf("protected route rollback reference required")
	}
	namespace, name, uid, receiptID = ref[:slash], ref[slash+1:at], types.UID(ref[at+1:hash]), ref[hash+1:]
	if namespace == "" || name == "" || uid == "" || len(receiptID) != 40 {
		return "", "", "", "", fmt.Errorf("protected route rollback reference invalid")
	}
	return namespace, name, uid, receiptID, nil
}

func rollbackRouteCutover(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	ns, name, uid, receiptID, err := parseRouteRollbackRef(ref)
	if err != nil {
		return err
	}
	if ns != ec.JournalNamespace || ec.Reader == nil || ec.Client == nil || ns == req.Namespace {
		return fmt.Errorf("route rollback journal authority unavailable")
	}
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, cm); err != nil {
		return err
	}
	r, err := readRouteReceipt(cm)
	if err != nil {
		return err
	}
	if cm.UID != uid || r.ReceiptID != receiptID || r.Phase != "applied" || r.Kind != string(req.Action) ||
		r.PolicyNamespace != req.Namespace || r.TargetName != req.Pod || r.TargetUID != req.TargetUID ||
		r.PolicyName != req.PolicyName || r.PolicyUID != req.PolicyUID || r.OperationToken != req.OperationID {
		return fmt.Errorf("route rollback reference or operation authority was superseded")
	}
	guard, err := ensureRouteGuardForReceipt(ctx, ec, cm, &r)
	if err != nil {
		return err
	}
	_, restoreErr := restoreRouteCutover(ctx, ec, cm, guard, &r, nil)
	return restoreErr
}

func recoverRouteCutover(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, error) {
	if r.Phase == "applied" {
		_, _, authorityErr := routeForwardAuthority(ctx, ec, *r)
		if errors.Is(authorityErr, errRouteRestoreRequired) {
			guard, guardErr := ensureRouteGuardForReceipt(ctx, ec, cm, r)
			if guardErr != nil {
				return "applied route receipt retained; restoration guard unresolved", errors.Join(authorityErr, guardErr)
			}
			result, restoreErr := restoreRouteCutover(ctx, ec, cm, guard, r, nil)
			return result.Note, restoreErr
		}
		if authorityErr != nil {
			return "applied route receipt retained; terminal authority unreadable or changed", authorityErr
		}
		if err := routeTerminalExact(ctx, ec, *r); err != nil {
			return "applied route receipt retained; exact terminal membership changed", err
		}
		guard := &corev1.ConfigMap{}
		err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: routeGuardName(r.TargetUID)}, guard)
		if err == nil {
			got, readErr := readRouteGuard(guard)
			if readErr != nil || !routeGuardTupleEqual(got, routeGuardFor(*r)) || got.ReceiptUID != string(cm.UID) {
				return "applied route receipt retained; foreign target guard present", errors.Join(readErr, fmt.Errorf("target guard mismatch"))
			}
			if finishErr := finishRouteGuard(ctx, ec, guard); finishErr != nil {
				return "applied route receipt retained; target guard cleanup unresolved", finishErr
			}
		} else if !apierrors.IsNotFound(err) {
			return "applied route receipt retained; target guard unreadable", err
		}
		return "applied route cutover confirmed; rollback receipt retained", nil
	}
	guard, err := ensureRouteGuardForReceipt(ctx, ec, cm, r)
	if err != nil {
		return "route receipt retained; target guard unresolved", err
	}
	if r.Phase == "restoring" {
		result, restoreErr := restoreRouteCutover(ctx, ec, cm, guard, r, nil)
		return result.Note, restoreErr
	}
	_, _, authErr := routeForwardAuthority(ctx, ec, *r)
	var result HandlerResult
	if authErr != nil && errors.Is(authErr, errRouteRestoreRequired) {
		result, err = restoreRouteCutover(ctx, ec, cm, guard, r, nil)
	} else if authErr != nil {
		return "route receipt retained; forward authority unreadable", authErr
	} else {
		result, err = runRouteForward(ctx, ec, cm, guard, *r)
	}
	return result.Note, err
}

func cleanupOrphanRouteGuards(ctx context.Context, ec EnactCtx) ([]RecoveryEvent, error) {
	if ec.Reader == nil || ec.Client == nil || ec.JournalNamespace == "" {
		return nil, fmt.Errorf("route guard recovery unavailable")
	}
	var list corev1.ConfigMapList
	if err := ec.Reader.List(ctx, &list, client.InNamespace(ec.JournalNamespace), client.MatchingLabels{routeTargetGuardLabel: "v1"}); err != nil {
		return nil, err
	}
	events := make([]RecoveryEvent, 0)
	for i := range list.Items {
		cm := list.Items[i].DeepCopy()
		g, err := readRouteGuard(cm)
		ev := RecoveryEvent{Receipt: cm.Name, Kind: "route-target-guard", PolicyNamespace: g.PolicyNamespace, PolicyUID: g.PolicyUID, TargetUID: g.TargetUID, Outcome: "refused"}
		if err != nil {
			ev.Err = err
			events = append(events, ev)
			continue
		}
		serviceReceipt := &corev1.ConfigMap{}
		readErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: g.ReceiptName}, serviceReceipt)
		if readErr == nil {
			r, receiptErr := readRouteReceipt(serviceReceipt)
			if receiptErr == nil && r.ReceiptID == g.ReceiptID && r.TargetGuardUID == string(cm.UID) && g.ReceiptUID == string(serviceReceipt.UID) {
				continue
			}
			if receiptErr == nil {
				ev.Err = fmt.Errorf("route target guard conflicts with a different Service receipt")
			} else {
				ev.Err = receiptErr
			}
			events = append(events, ev)
			continue
		}
		if !apierrors.IsNotFound(readErr) {
			ev.Err = readErr
			events = append(events, ev)
			continue
		}
		if err := finishRouteGuard(ctx, ec, cm); err != nil {
			ev.Err = err
			events = append(events, ev)
			continue
		}
		ev.Outcome, ev.Effect = "confirmed", "orphan pre-write target guard removed; no Service receipt existed"
		events = append(events, ev)
	}
	return events, nil
}
