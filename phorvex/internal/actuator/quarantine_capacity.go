package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const (
	// MaxRetainedQuarantinesUpperBound prevents an accidentally enormous flag from
	// turning the protected ledger into an unbounded object. The default remains one.
	MaxRetainedQuarantinesUpperBound = 128

	quarantineCapacityLabel       = "phorvex.ai/quarantine-capacity"
	quarantineCapacityDataKey     = "ledger"
	phoenixQuarantineMarker       = "amtd.r6security.com/network-policy"
	quarantineCapacityCASAttempts = 5
	quarantineCapacityMaxBytes    = 768 << 10
	quarantineCapacityMaxObjects  = 8
	quarantineCapacityMaxObject   = 512
)

// QuarantineInventory is the namespace-wide observed and protected occupancy used
// by the decision law. Known is represented by a nil Inventory error; callers must
// never substitute zero for an unavailable inventory.
type QuarantineInventory struct {
	NamespaceUID string
	Observed     int
	Reserved     int
	Pending      int
	Used         int
	Limit        int
}

type quarantineCapacityRecord struct {
	OperationID  string   `json:"operationID"`
	Phase        string   `json:"phase"`
	Namespace    string   `json:"namespace"`
	NamespaceUID string   `json:"namespaceUID"`
	Pod          string   `json:"pod"`
	PodUID       string   `json:"podUID"`
	PolicyName   string   `json:"policyName"`
	PolicyUID    string   `json:"policyUID"`
	Backend      string   `json:"backend"`
	EventName    string   `json:"eventName,omitempty"`
	EventUID     string   `json:"eventUID,omitempty"`
	Objects      []string `json:"objects,omitempty"`
	Detail       string   `json:"detail,omitempty"`
}

type quarantineCapacityLedger struct {
	Version      int                                 `json:"version"`
	Namespace    string                              `json:"namespace"`
	NamespaceUID string                              `json:"namespaceUID"`
	Records      map[string]quarantineCapacityRecord `json:"records"`
}

// QuarantineReservation is an opaque handle for the exact CAS-created record.
// It deliberately contains no expiry: crashes and unknown outcomes retain capacity.
type QuarantineReservation struct {
	ledgerName   string
	ledgerUID    types.UID
	namespace    string
	namespaceUID string
	targetName   string
	targetUID    string
	operationID  string
}

// QuarantineCapacity owns the hard, operator-configured namespace-wide bound.
// Reader must be the uncached API reader; Client performs resourceVersion CAS writes.
type QuarantineCapacity struct {
	client            client.Client
	reader            client.Reader
	operatorNamespace string
	limit             int
}

func NewQuarantineCapacity(c client.Client, reader client.Reader, operatorNamespace string, limit int) (*QuarantineCapacity, error) {
	if c == nil || reader == nil {
		return nil, fmt.Errorf("quarantine capacity: client and uncached reader are required")
	}
	if strings.TrimSpace(operatorNamespace) == "" {
		return nil, fmt.Errorf("quarantine capacity: operator namespace is required")
	}
	if limit < 0 || limit > MaxRetainedQuarantinesUpperBound {
		return nil, fmt.Errorf("quarantine capacity: limit must be in [0,%d], got %d", MaxRetainedQuarantinesUpperBound, limit)
	}
	return &QuarantineCapacity{client: c, reader: reader, operatorNamespace: operatorNamespace, limit: limit}, nil
}

func (q *QuarantineCapacity) Limit() int {
	if q == nil {
		return 0
	}
	return q.limit
}

func quarantineCapacityLedgerName(namespaceUID string) string {
	h := sha256.Sum256([]byte(namespaceUID))
	return fmt.Sprintf("phorvex-quarantine-capacity-%x", h[:20])
}

func quarantineCapacityOperationID(req Request) string {
	h := sha256.Sum256([]byte(req.PolicyUID + "\x00" + req.Namespace + "\x00" + req.TargetUID + "\x00" + string(req.Action)))
	return fmt.Sprintf("%x", h[:20])
}

func podCarriesQuarantineMarker(p *corev1.Pod) bool {
	if p == nil {
		return false
	}
	return p.Labels[quarantineLabel] != "" || p.Annotations[quarantineSnapAnno] != "" || p.Labels[phoenixQuarantineMarker] != ""
}

func validCapacityRecordBounds(record quarantineCapacityRecord) bool {
	if len(record.OperationID) != 40 || len(record.Namespace) > 253 || len(record.NamespaceUID) > 128 || len(record.Pod) > 253 || len(record.PodUID) > 128 || len(record.PolicyName) > 253 || len(record.PolicyUID) > 128 || len(record.Backend) > 64 || len(record.EventName) > 253 || len(record.EventUID) > 128 || len(record.Detail) > 512 || len(record.Objects) > quarantineCapacityMaxObjects {
		return false
	}
	for _, object := range record.Objects {
		if object == "" || len(object) > quarantineCapacityMaxObject {
			return false
		}
	}
	switch record.Phase {
	case "dispatching", "ambiguous":
		return record.EventName == "" && record.EventUID == "" && len(record.Objects) == 0
	case "native-effect":
		return record.EventName == "" && record.EventUID == ""
	case "phoenix-event":
		return record.EventName != "" && record.EventUID != "" && len(record.Objects) == 0
	default:
		return false
	}
}

func validateQuarantineCapacityLedgerBounds(ledger quarantineCapacityLedger) error {
	if ledger.Version != 1 || ledger.Namespace == "" || len(ledger.Namespace) > 253 || ledger.NamespaceUID == "" || len(ledger.NamespaceUID) > 128 || ledger.Records == nil || len(ledger.Records) > MaxRetainedQuarantinesUpperBound {
		return fmt.Errorf("protected capacity ledger structure exceeds configured bounds")
	}
	for uid, record := range ledger.Records {
		if uid == "" || uid != record.PodUID || record.Namespace != ledger.Namespace || record.NamespaceUID != ledger.NamespaceUID || record.Pod == "" || record.PolicyName == "" || record.PolicyUID == "" || record.Backend == "" || !validCapacityRecordBounds(record) {
			return fmt.Errorf("protected capacity ledger record exceeds configured bounds")
		}
	}
	return nil
}

func decodeQuarantineCapacityLedger(cm *corev1.ConfigMap, namespace string, namespaceUID string) (quarantineCapacityLedger, error) {
	if cm == nil || cm.Namespace == "" || cm.Name != quarantineCapacityLedgerName(namespaceUID) || cm.Labels[quarantineCapacityLabel] != "v1" || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil {
		return quarantineCapacityLedger{}, fmt.Errorf("protected capacity ledger identity is invalid")
	}
	if len(cm.Data[quarantineCapacityDataKey]) > quarantineCapacityMaxBytes {
		return quarantineCapacityLedger{}, fmt.Errorf("protected capacity ledger exceeds %d-byte storage bound", quarantineCapacityMaxBytes)
	}
	var ledger quarantineCapacityLedger
	if err := json.Unmarshal([]byte(cm.Data[quarantineCapacityDataKey]), &ledger); err != nil {
		return quarantineCapacityLedger{}, fmt.Errorf("decode protected capacity ledger: %w", err)
	}
	if ledger.Version != 1 || ledger.Namespace != namespace || ledger.NamespaceUID != namespaceUID || ledger.Records == nil {
		return quarantineCapacityLedger{}, fmt.Errorf("protected capacity ledger scope is invalid")
	}
	if err := validateQuarantineCapacityLedgerBounds(ledger); err != nil {
		return quarantineCapacityLedger{}, err
	}
	for uid, record := range ledger.Records {
		if uid == "" || record.PodUID != uid || record.OperationID == "" || record.Namespace != namespace || record.NamespaceUID != namespaceUID || record.Pod == "" || record.PolicyName == "" || record.PolicyUID == "" || record.Backend == "" {
			return quarantineCapacityLedger{}, fmt.Errorf("protected capacity ledger contains an invalid reservation")
		}
		switch record.Phase {
		case "dispatching", "native-effect", "ambiguous":
		case "phoenix-event":
			if record.EventName == "" || record.EventUID == "" {
				return quarantineCapacityLedger{}, fmt.Errorf("protected capacity ledger has unbound Phoenix event identity")
			}
		default:
			return quarantineCapacityLedger{}, fmt.Errorf("protected capacity ledger contains unknown phase %q", record.Phase)
		}
	}
	return ledger, nil
}

// pendingPhoenixQuarantines inventories cluster-scoped controlled events. Events
// emitted before the UID envelope existed cannot be safely assigned to a Pod
// incarnation, so they fail the namespace inventory closed with a migration
// diagnostic instead of being silently treated as absent. A native-only install
// without the Phoenix CRD has conclusively no Phoenix event population.
func (q *QuarantineCapacity) pendingPhoenixQuarantines(ctx context.Context, ns *corev1.Namespace) (map[string]struct{}, error) {
	events := &amtdv1beta1.SecurityEventList{}
	if err := q.reader.List(ctx, events); err != nil {
		if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			return map[string]struct{}{}, nil
		}
		return nil, fmt.Errorf("list cluster-scoped pending Phoenix quarantine events: %w", err)
	}
	pending := map[string]struct{}{}
	for i := range events.Items {
		event := &events.Items[i]
		if event.Spec.Rule.Type != RuleTypeQuarantine || event.Spec.Rule.Source != RuleSource {
			continue
		}
		if len(event.Spec.Targets) != 1 {
			return nil, fmt.Errorf("legacy or malformed controlled Phoenix quarantine event %q has %d targets; administrative reconciliation is required", event.Name, len(event.Spec.Targets))
		}
		parts := strings.Split(event.Spec.Targets[0], "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("legacy or malformed controlled Phoenix quarantine event %q has unscoped target %q; administrative reconciliation is required", event.Name, event.Spec.Targets[0])
		}
		if parts[0] != ns.Name {
			continue
		}
		targetUID := strings.TrimSpace(event.Annotations[phorvexQuarantineTargetUIDAnnotation])
		namespaceUID := strings.TrimSpace(event.Annotations[phorvexQuarantineNamespaceUIDAnnotation])
		operationID := strings.TrimSpace(event.Annotations[phorvexQuarantineOperationAnnotation])
		if event.Name == "" || len(event.Name) > 253 || event.UID == "" || len(event.UID) > 128 || targetUID == "" || len(targetUID) > 128 || namespaceUID == "" || len(namespaceUID) > 128 || len(operationID) != 40 {
			return nil, fmt.Errorf("legacy or malformed controlled Phoenix quarantine event %q for namespace %q lacks a trusted event/target/operation identity; administrative reconciliation is required", event.Name, ns.Name)
		}
		if namespaceUID != string(ns.UID) {
			return nil, fmt.Errorf("controlled Phoenix quarantine event %q names stale namespace UID %q for %q; administrative reconciliation is required", event.Name, namespaceUID, ns.Name)
		}
		pending[targetUID] = struct{}{}
	}
	return pending, nil
}

func encodeQuarantineCapacityLedger(ledger quarantineCapacityLedger) (string, error) {
	if err := validateQuarantineCapacityLedgerBounds(ledger); err != nil {
		return "", err
	}
	b, err := json.Marshal(ledger)
	if err != nil {
		return "", err
	}
	if len(b) > quarantineCapacityMaxBytes {
		return "", fmt.Errorf("protected capacity ledger would exceed %d-byte storage bound", quarantineCapacityMaxBytes)
	}
	return string(b), nil
}

func (q *QuarantineCapacity) namespace(ctx context.Context, namespace string) (*corev1.Namespace, error) {
	if q == nil || q.reader == nil {
		return nil, fmt.Errorf("quarantine capacity inventory unavailable")
	}
	ns := &corev1.Namespace{}
	if err := q.reader.Get(ctx, client.ObjectKey{Name: namespace}, ns); err != nil {
		return nil, fmt.Errorf("resolve target namespace UID: %w", err)
	}
	if ns.UID == "" || ns.DeletionTimestamp != nil {
		return nil, fmt.Errorf("target namespace identity unavailable or terminating")
	}
	if namespace == q.operatorNamespace {
		return nil, fmt.Errorf("target namespace must differ from protected operator namespace")
	}
	return ns, nil
}

func (q *QuarantineCapacity) inventoryForNamespace(ctx context.Context, ns *corev1.Namespace) (QuarantineInventory, map[string]struct{}, quarantineCapacityLedger, *corev1.ConfigMap, error) {
	if ns == nil || ns.UID == "" {
		return QuarantineInventory{}, nil, quarantineCapacityLedger{}, nil, fmt.Errorf("namespace identity unavailable")
	}
	var pods corev1.PodList
	if err := q.reader.List(ctx, &pods, client.InNamespace(ns.Name)); err != nil {
		return QuarantineInventory{}, nil, quarantineCapacityLedger{}, nil, fmt.Errorf("list complete namespace quarantine inventory: %w", err)
	}
	occupied := map[string]struct{}{}
	observed := 0
	for i := range pods.Items {
		p := &pods.Items[i]
		if !podCarriesQuarantineMarker(p) {
			continue
		}
		if p.UID == "" {
			return QuarantineInventory{}, nil, quarantineCapacityLedger{}, nil, fmt.Errorf("marked quarantine target has no UID")
		}
		uid := string(p.UID)
		if _, exists := occupied[uid]; !exists {
			occupied[uid] = struct{}{}
			observed++
		}
	}
	pendingEvents, err := q.pendingPhoenixQuarantines(ctx, ns)
	if err != nil {
		return QuarantineInventory{}, nil, quarantineCapacityLedger{}, nil, err
	}

	ledger := quarantineCapacityLedger{Version: 1, Namespace: ns.Name, NamespaceUID: string(ns.UID), Records: map[string]quarantineCapacityRecord{}}
	cm := &corev1.ConfigMap{}
	name := quarantineCapacityLedgerName(string(ns.UID))
	err = q.reader.Get(ctx, client.ObjectKey{Namespace: q.operatorNamespace, Name: name}, cm)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return QuarantineInventory{}, nil, quarantineCapacityLedger{}, nil, fmt.Errorf("read protected capacity ledger: %w", err)
		}
		cm = nil
	} else {
		ledger, err = decodeQuarantineCapacityLedger(cm, ns.Name, string(ns.UID))
		if err != nil {
			return QuarantineInventory{}, nil, quarantineCapacityLedger{}, nil, err
		}
	}
	reserved := 0
	for uid := range ledger.Records {
		if _, exists := occupied[uid]; !exists {
			occupied[uid] = struct{}{}
			reserved++
		}
	}
	pending := 0
	for uid := range pendingEvents {
		if _, exists := occupied[uid]; !exists {
			occupied[uid] = struct{}{}
			pending++
		}
	}
	return QuarantineInventory{NamespaceUID: string(ns.UID), Observed: observed, Reserved: reserved, Pending: pending, Used: len(occupied), Limit: q.limit}, occupied, ledger, cm, nil
}

func (q *QuarantineCapacity) Inventory(ctx context.Context, namespace string) (QuarantineInventory, error) {
	ns, err := q.namespace(ctx, namespace)
	if err != nil {
		return QuarantineInventory{Limit: q.Limit()}, err
	}
	inv, _, _, _, err := q.inventoryForNamespace(ctx, ns)
	return inv, err
}

// ReconcileConclusiveAbsence is an explicit administrative operation. The caller
// must first quiesce every manager dispatch and Phoenix consumer that could act on
// this namespace. It releases only the exact protected record when the original
// Pod UID is absent and no UID-bound controlled Phoenix event remains. There is no
// timer or automatic invocation of this method.
func (q *QuarantineCapacity) ReconcileConclusiveAbsence(ctx context.Context, namespace, targetUID string) error {
	if q == nil || targetUID == "" {
		return fmt.Errorf("quarantine capacity administrative reconciliation requires a target UID")
	}
	ns, err := q.namespace(ctx, namespace)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{}
	ledgerName := quarantineCapacityLedgerName(string(ns.UID))
	if err := q.reader.Get(ctx, client.ObjectKey{Namespace: q.operatorNamespace, Name: ledgerName}, cm); err != nil {
		return fmt.Errorf("read protected capacity ledger for administrative reconciliation: %w", err)
	}
	ledger, err := decodeQuarantineCapacityLedger(cm, ns.Name, string(ns.UID))
	if err != nil {
		return err
	}
	record, ok := ledger.Records[targetUID]
	if !ok {
		return fmt.Errorf("protected capacity reservation for target UID %q is absent", targetUID)
	}
	target := &corev1.Pod{}
	err = q.reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: record.Pod}, target)
	if err == nil {
		return fmt.Errorf("target name %q still exists with UID %q; administrative reconciliation refused", record.Pod, target.UID)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("verify target absence for administrative reconciliation: %w", err)
	}
	pending, err := q.pendingPhoenixQuarantines(ctx, ns)
	if err != nil {
		return err
	}
	if _, exists := pending[targetUID]; exists {
		return fmt.Errorf("controlled Phoenix work for target UID %q is still present; administrative reconciliation refused", targetUID)
	}
	reservation := &QuarantineReservation{
		ledgerName: ledgerName, ledgerUID: cm.UID, namespace: namespace, namespaceUID: string(ns.UID),
		targetName: record.Pod, targetUID: targetUID, operationID: record.OperationID,
	}
	return q.mutateReservation(ctx, reservation, func(*quarantineCapacityRecord) bool { return false })
}

func (q *QuarantineCapacity) reserve(ctx context.Context, req Request, backend string) (*QuarantineReservation, error) {
	if req.Action != model.ActionQuarantine {
		return nil, fmt.Errorf("quarantine capacity: reservation requested for %q", req.Action)
	}
	if req.PolicyName == "" || req.PolicyUID == "" || req.Namespace == "" || req.Pod == "" || req.TargetUID == "" || backend == "" {
		return nil, fmt.Errorf("quarantine capacity: complete policy, target and backend identity are required")
	}
	ns, err := q.namespace(ctx, req.Namespace)
	if err != nil {
		return nil, err
	}
	target := &corev1.Pod{}
	if err := q.reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, target); err != nil {
		return nil, fmt.Errorf("quarantine capacity target read: %w", err)
	}
	if target.UID == "" || string(target.UID) != req.TargetUID {
		return nil, fmt.Errorf("quarantine capacity target UID unavailable or mismatched")
	}
	if target.DeletionTimestamp != nil {
		return nil, RefusedWithoutEffect(fmt.Errorf("quarantine capacity: terminating target refused before reservation"))
	}
	operationID := quarantineCapacityOperationID(req)
	for attempt := 0; attempt < quarantineCapacityCASAttempts; attempt++ {
		inv, occupied, ledger, cm, invErr := q.inventoryForNamespace(ctx, ns)
		if invErr != nil {
			return nil, invErr
		}
		if existing, ok := ledger.Records[req.TargetUID]; ok {
			return nil, fmt.Errorf("quarantine capacity: target already has protected reservation %s in phase %s", existing.OperationID, existing.Phase)
		}
		if _, alreadyQuarantined := occupied[req.TargetUID]; alreadyQuarantined {
			return nil, RefusedWithoutEffect(fmt.Errorf("quarantine capacity: target is already quarantined"))
		}
		if inv.Used >= q.limit {
			return nil, RefusedWithoutEffect(fmt.Errorf("quarantine capacity exhausted in namespace %s: used=%d limit=%d", req.Namespace, inv.Used, q.limit))
		}
		record := quarantineCapacityRecord{
			OperationID: operationID, Phase: "dispatching", Namespace: req.Namespace, NamespaceUID: string(ns.UID),
			Pod: req.Pod, PodUID: req.TargetUID, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, Backend: backend,
		}
		ledger.Records[req.TargetUID] = record
		encoded, encodeErr := encodeQuarantineCapacityLedger(ledger)
		if encodeErr != nil {
			return nil, encodeErr
		}
		var ledgerUID types.UID
		if cm == nil {
			created := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: q.operatorNamespace, Name: quarantineCapacityLedgerName(string(ns.UID)), Labels: map[string]string{quarantineCapacityLabel: "v1"}}, Data: map[string]string{quarantineCapacityDataKey: encoded}}
			if createErr := q.client.Create(ctx, created); createErr != nil {
				if apierrors.IsAlreadyExists(createErr) || apierrors.IsConflict(createErr) {
					continue
				}
				return nil, fmt.Errorf("create protected capacity reservation: %w", createErr)
			}
			if created.UID == "" || created.ResourceVersion == "" {
				return nil, fmt.Errorf("create protected capacity reservation was not acknowledged")
			}
			ledgerUID = created.UID
		} else {
			next := cm.DeepCopy()
			next.Data[quarantineCapacityDataKey] = encoded
			if updateErr := q.client.Update(ctx, next); updateErr != nil {
				if apierrors.IsConflict(updateErr) {
					continue
				}
				return nil, fmt.Errorf("CAS protected capacity reservation: %w", updateErr)
			}
			if next.UID != cm.UID || next.ResourceVersion == "" || next.ResourceVersion == cm.ResourceVersion {
				return nil, fmt.Errorf("CAS protected capacity reservation was not acknowledged")
			}
			ledgerUID = next.UID
		}
		return &QuarantineReservation{ledgerName: quarantineCapacityLedgerName(string(ns.UID)), ledgerUID: ledgerUID, namespace: req.Namespace, namespaceUID: string(ns.UID), targetName: req.Pod, targetUID: req.TargetUID, operationID: operationID}, nil
	}
	return nil, fmt.Errorf("quarantine capacity reservation contention exceeded %d attempts", quarantineCapacityCASAttempts)
}

func boundedCapacityDetail(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

func capacityRecordObjects(objects []string) ([]string, bool) {
	if len(objects) > quarantineCapacityMaxObjects {
		return nil, false
	}
	bounded := make([]string, len(objects))
	for i, object := range objects {
		if object == "" || len(object) > quarantineCapacityMaxObject {
			return nil, false
		}
		bounded[i] = object
	}
	return bounded, true
}

func (q *QuarantineCapacity) mutateReservation(ctx context.Context, reservation *QuarantineReservation, mutate func(*quarantineCapacityRecord) bool) error {
	if q == nil || reservation == nil || mutate == nil {
		return fmt.Errorf("quarantine capacity reservation unavailable")
	}
	for attempt := 0; attempt < quarantineCapacityCASAttempts; attempt++ {
		cm := &corev1.ConfigMap{}
		if err := q.reader.Get(ctx, client.ObjectKey{Namespace: q.operatorNamespace, Name: reservation.ledgerName}, cm); err != nil {
			return fmt.Errorf("read protected capacity reservation: %w", err)
		}
		ledger, err := decodeQuarantineCapacityLedger(cm, reservation.namespace, reservation.namespaceUID)
		if err != nil {
			return err
		}
		if reservation.ledgerUID == "" || cm.UID != reservation.ledgerUID {
			return fmt.Errorf("protected capacity ledger UID changed")
		}
		record, ok := ledger.Records[reservation.targetUID]
		if !ok || record.OperationID != reservation.operationID {
			return fmt.Errorf("protected capacity reservation identity changed")
		}
		if !mutate(&record) {
			delete(ledger.Records, reservation.targetUID)
		} else {
			ledger.Records[reservation.targetUID] = record
		}
		encoded, err := encodeQuarantineCapacityLedger(ledger)
		if err != nil {
			return err
		}
		next := cm.DeepCopy()
		next.Data[quarantineCapacityDataKey] = encoded
		if err := q.client.Update(ctx, next); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return err
		}
		if next.UID != cm.UID || next.ResourceVersion == "" || next.ResourceVersion == cm.ResourceVersion {
			return fmt.Errorf("protected capacity reservation update was not acknowledged")
		}
		return nil
	}
	return fmt.Errorf("quarantine capacity update contention exceeded %d attempts", quarantineCapacityCASAttempts)
}

func (q *QuarantineCapacity) releaseNoEffect(ctx context.Context, reservation *QuarantineReservation) error {
	target := &corev1.Pod{}
	err := q.reader.Get(ctx, client.ObjectKey{Namespace: reservation.namespace, Name: reservation.targetName}, target)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("verify no-effect reservation release: %w", err)
	}
	if err == nil && string(target.UID) == reservation.targetUID && podCarriesQuarantineMarker(target) {
		return fmt.Errorf("refuse reservation release: target carries a quarantine marker")
	}
	return q.mutateReservation(ctx, reservation, func(record *quarantineCapacityRecord) bool {
		return false
	})
}

func (q *QuarantineCapacity) finish(ctx context.Context, reservation *QuarantineReservation, result Result, actuationErr error) error {
	if actuationErr != nil && IsNoEffectRefusal(actuationErr) && !result.Emitted && len(result.ObjectsTouched) == 0 && result.EventName == "" && result.EventUID == "" {
		return q.releaseNoEffect(ctx, reservation)
	}
	return q.mutateReservation(ctx, reservation, func(record *quarantineCapacityRecord) bool {
		record.Detail = boundedCapacityDetail(actuationErr)
		switch {
		case result.EventName != "" && result.EventUID != "" && len(result.EventName) <= 253 && len(result.EventUID) <= 128:
			record.Phase = "phoenix-event"
			record.EventName = result.EventName
			record.EventUID = result.EventUID
		case result.EventName != "" || result.EventUID != "":
			record.Phase = "ambiguous"
			record.Detail = "effect outcome included an incomplete or oversized event identity"
		case result.Emitted:
			if objects, ok := capacityRecordObjects(result.ObjectsTouched); ok {
				record.Phase = "native-effect"
				record.Objects = objects
			} else {
				record.Phase = "ambiguous"
				record.Detail = "effect acknowledged; object identity list exceeded protected ledger bounds"
			}
		default:
			record.Phase = "ambiguous"
		}
		return true
	})
}

// QuarantineCapacityProvenance states whether the capacity wrapper crossed the actual
// backend invocation boundary. Callers use this explicit fact rather than trying to infer
// it from an error string: reservation/inventory failures happen before Actuate, while a
// protected-ledger finalization error happens after it.
type QuarantineCapacityProvenance struct {
	BackendInvoked bool
}

// ActuateWithProvenance reserves capacity before the first backend effect and binds the
// durable record to the acknowledged native effect or Phoenix event. Unknown outcomes
// retain their slot. Only an explicit NoEffectRefusal releases its exact reservation.
func (q *QuarantineCapacity) ActuateWithProvenance(ctx context.Context, backend Actuator, req Request) (Result, QuarantineCapacityProvenance, error) {
	if backend == nil {
		return Result{}, QuarantineCapacityProvenance{}, fmt.Errorf("quarantine capacity: actuator unavailable")
	}
	if req.Action != model.ActionQuarantine {
		result, err := backend.Actuate(ctx, req)
		return result, QuarantineCapacityProvenance{BackendInvoked: true}, err
	}
	reservation, err := q.reserve(ctx, req, backend.Name())
	if err != nil {
		return Result{}, QuarantineCapacityProvenance{}, err
	}
	req.TargetNamespaceUID = reservation.namespaceUID
	req.OperationID = reservation.operationID
	result, actuationErr := backend.Actuate(ctx, req)
	provenance := QuarantineCapacityProvenance{BackendInvoked: true}
	finishErr := q.finish(ctx, reservation, result, actuationErr)
	if finishErr != nil {
		if actuationErr != nil {
			return result, provenance, errors.Join(actuationErr, fmt.Errorf("bind protected quarantine reservation: %w", finishErr))
		}
		return result, provenance, fmt.Errorf("bind protected quarantine reservation: %w", finishErr)
	}
	return result, provenance, actuationErr
}

// Actuate preserves the established wrapper API for direct consumers. The runner uses
// ActuateWithProvenance because it must distinguish a pre-dispatch capacity refusal from
// an actual backend attempt in metrics and feedback.
func (q *QuarantineCapacity) Actuate(ctx context.Context, backend Actuator, req Request) (Result, error) {
	result, _, err := q.ActuateWithProvenance(ctx, backend, req)
	return result, err
}
