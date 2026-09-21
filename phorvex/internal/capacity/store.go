package capacity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	ledgerName        = "phorvex-shared-capacity"
	ledgerLabel       = "phorvex.ai/shared-capacity"
	ledgerDataKey     = "ledger"
	ledgerVersion     = 1
	ledgerMaxRecords  = 512
	ledgerMaxBytes    = 900 << 10
	ledgerCASAttempts = 7
)

type admission struct {
	Scope       model.ResourceScope `json:"scope"`
	Units       int                 `json:"units"`
	Floor       int                 `json:"floor"`
	ReadyBefore int                 `json:"readyBefore"`
}

type record struct {
	OperationID string       `json:"operationID"`
	PolicyUID   string       `json:"policyUID"`
	TargetName  string       `json:"targetName"`
	TargetUID   string       `json:"targetUID"`
	Action      model.Action `json:"action"`
	Phase       string       `json:"phase"`
	Admissions  []admission  `json:"admissions"`
}

type ledger struct {
	Version int               `json:"version"`
	Records map[string]record `json:"records"`
}

// Store owns one protected ConfigMap so reservations spanning overlapping
// Services are acquired in one resourceVersion CAS. Records have no expiry:
// unknown outcomes survive process restart until recovery is proved.
type Store struct {
	client            client.Client
	reader            client.Reader
	operatorNamespace string
}

type Request struct {
	PolicyUID           string
	TargetNamespace     string
	TargetName          string
	TargetUID           string
	Action              model.Action
	OperationID         string
	MinAvailableReplica int
	Resources           []model.ResourceConsumption
}

type Reservation struct {
	OperationID string
	LedgerUID   types.UID
	// Created is false when this exact durable operation already existed. A
	// caller must reconcile that operation and must not replay its mutation.
	Created bool
}

func NewStore(c client.Client, reader client.Reader, operatorNamespace string) (*Store, error) {
	if c == nil || reader == nil || strings.TrimSpace(operatorNamespace) == "" {
		return nil, errors.New("shared capacity requires client, uncached reader and operator namespace")
	}
	return &Store{client: c, reader: reader, operatorNamespace: operatorNamespace}, nil
}

func operationID(req Request) string {
	if req.OperationID != "" {
		return req.OperationID
	}
	sum := sha256.Sum256([]byte(req.PolicyUID + "\x00" + req.TargetNamespace + "\x00" + req.TargetUID + "\x00" + string(req.Action)))
	return hex.EncodeToString(sum[:20])
}

func validateRequest(req Request, demands []model.ResourceConsumption) error {
	opID := operationID(req)
	if req.PolicyUID == "" || req.TargetNamespace == "" || req.TargetName == "" || req.TargetUID == "" ||
		req.Action == "" || req.MinAvailableReplica < 0 || opID == "" || len(opID) > 253 {
		return errors.New("shared capacity request identity is incomplete")
	}
	for _, demand := range demands {
		if demand.Scope.Namespace != req.TargetNamespace {
			return errors.New("shared capacity scope namespace differs from target namespace")
		}
	}
	return nil
}

func emptyLedger() ledger { return ledger{Version: ledgerVersion, Records: map[string]record{}} }

func validateLedger(value ledger) error {
	if value.Version != ledgerVersion || value.Records == nil || len(value.Records) > ledgerMaxRecords {
		return errors.New("shared capacity ledger structure is invalid")
	}
	for key, record := range value.Records {
		if key == "" || key != record.OperationID || len(key) > 253 || record.PolicyUID == "" || record.TargetName == "" || record.TargetUID == "" || record.Action == "" || (record.Phase != "reserved" && record.Phase != "dispatching" && record.Phase != "uncertain") || len(record.Admissions) == 0 {
			return errors.New("shared capacity ledger record is invalid")
		}
		seen := map[string]bool{}
		for _, admission := range record.Admissions {
			scopeKey := admission.Scope.Key()
			if !admission.Scope.Valid() || admission.Scope.Kind != model.ResourceUnavailableReadyReplica || admission.Units <= 0 || admission.Floor < 0 || admission.ReadyBefore <= 0 || seen[scopeKey] {
				return errors.New("shared capacity admission is invalid")
			}
			seen[scopeKey] = true
		}
	}
	return nil
}

func encodeLedger(value ledger) (string, error) {
	if err := validateLedger(value); err != nil {
		return "", err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if len(raw) > ledgerMaxBytes {
		return "", fmt.Errorf("shared capacity ledger exceeds %d bytes", ledgerMaxBytes)
	}
	return string(raw), nil
}

func (s *Store) read(ctx context.Context) (*corev1.ConfigMap, ledger, error) {
	cm := &corev1.ConfigMap{}
	err := s.reader.Get(ctx, client.ObjectKey{Namespace: s.operatorNamespace, Name: ledgerName}, cm)
	if apierrors.IsNotFound(err) {
		return nil, emptyLedger(), nil
	}
	if err != nil {
		return nil, ledger{}, fmt.Errorf("read shared capacity ledger: %w", err)
	}
	if cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Labels[ledgerLabel] != "v1" || len(cm.Data[ledgerDataKey]) > ledgerMaxBytes {
		return nil, ledger{}, errors.New("shared capacity ledger identity is invalid")
	}
	var value ledger
	if err := json.Unmarshal([]byte(cm.Data[ledgerDataKey]), &value); err != nil {
		return nil, ledger{}, fmt.Errorf("decode shared capacity ledger: %w", err)
	}
	if err := validateLedger(value); err != nil {
		return nil, ledger{}, err
	}
	return cm, value, nil
}

func (s *Store) write(ctx context.Context, prior *corev1.ConfigMap, value ledger) (*corev1.ConfigMap, error) {
	encoded, err := encodeLedger(value)
	if err != nil {
		return nil, err
	}
	if prior == nil {
		created := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: s.operatorNamespace, Name: ledgerName, Labels: map[string]string{ledgerLabel: "v1"}}, Data: map[string]string{ledgerDataKey: encoded}}
		if err := s.client.Create(ctx, created); err != nil {
			return nil, err
		}
		if created.UID == "" || created.ResourceVersion == "" {
			return nil, errors.New("shared capacity ledger create was not acknowledged")
		}
		return created, nil
	}
	next := prior.DeepCopy()
	next.Data = map[string]string{ledgerDataKey: encoded}
	if err := s.client.Update(ctx, next); err != nil {
		return nil, err
	}
	if next.UID != prior.UID || next.ResourceVersion == prior.ResourceVersion {
		return nil, errors.New("shared capacity ledger update was not acknowledged")
	}
	return next, nil
}

type observation struct {
	Ready     int
	HasTarget bool
}

func (s *Store) observeScope(ctx context.Context, scope model.ResourceScope, targetUID string) (observation, error) {
	if !scope.Valid() || scope.Kind != model.ResourceUnavailableReadyReplica {
		return observation{}, errors.New("shared capacity scope identity is incomplete")
	}
	service := &corev1.Service{}
	if err := s.reader.Get(ctx, client.ObjectKey{Namespace: scope.Namespace, Name: scope.ServiceName}, service); err != nil {
		return observation{}, fmt.Errorf("read capacity Service: %w", err)
	}
	if string(service.UID) != scope.ServiceUID || service.DeletionTimestamp != nil || len(service.Spec.Selector) == 0 {
		return observation{}, errors.New("capacity Service identity or selector changed")
	}
	selector := labels.SelectorFromSet(service.Spec.Selector)
	var slices discoveryv1.EndpointSliceList
	if err := s.reader.List(ctx, &slices, client.InNamespace(scope.Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: scope.ServiceName}); err != nil {
		return observation{}, fmt.Errorf("list capacity EndpointSlices: %w", err)
	}
	ready := map[string]struct{}{}
	for i := range slices.Items {
		slice := &slices.Items[i]
		owner := metav1.GetControllerOf(slice)
		if slice.UID == "" || slice.DeletionTimestamp != nil || owner == nil || owner.APIVersion != "v1" || owner.Kind != "Service" || owner.Name != scope.ServiceName || string(owner.UID) != scope.ServiceUID {
			return observation{}, errors.New("capacity EndpointSlice authority changed")
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready {
				continue
			}
			ref := endpoint.TargetRef
			if ref == nil || ref.Kind != "Pod" || ref.Namespace != scope.Namespace || ref.Name == "" || ref.UID == "" {
				return observation{}, errors.New("capacity ready endpoint lacks exact Pod identity")
			}
			pod := &corev1.Pod{}
			if err := s.reader.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, pod); err != nil {
				return observation{}, fmt.Errorf("read capacity endpoint Pod: %w", err)
			}
			controller := metav1.GetControllerOf(pod)
			if pod.UID != ref.UID || pod.DeletionTimestamp != nil || controller == nil || string(controller.UID) != scope.ControllerUID || !selector.Matches(labels.Set(pod.Labels)) || !podReady(pod) {
				return observation{}, errors.New("capacity endpoint Pod identity, controller, selector or readiness changed")
			}
			ready[string(pod.UID)] = struct{}{}
		}
	}
	_, hasTarget := ready[targetUID]
	return observation{Ready: len(ready), HasTarget: hasTarget}, nil
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

// Inventory returns durable outstanding consumption after releasing only
// records whose exact target disappeared from the ready set and whose Service
// recovered to at least the admitted ready population. A retained reservation
// consumes current capacity only while its target is still Ready: once the
// target is absent, the current Ready count already reflects that removal.
func (s *Store) Inventory(ctx context.Context) (map[string]int, error) {
	for attempt := 0; attempt < ledgerCASAttempts; attempt++ {
		cm, value, err := s.read(ctx)
		if err != nil {
			return nil, err
		}
		changed := false
		used := map[string]int{}
		for key, record := range value.Records {
			// A reserved record cannot have reached an actuator: dispatch is legal
			// only after Claim's CAS is acknowledged. This also safely recovers an
			// Acquire acknowledgement lost before Claim.
			if record.Phase == "reserved" {
				delete(value.Records, key)
				changed = true
				continue
			}
			recovered := true
			for _, admission := range record.Admissions {
				observed, err := s.observeScope(ctx, admission.Scope, record.TargetUID)
				if err != nil {
					return nil, err
				}
				if observed.HasTarget {
					used[admission.Scope.Key()] += admission.Units
				}
				if observed.HasTarget || observed.Ready < admission.ReadyBefore {
					recovered = false
				}
			}
			if recovered {
				delete(value.Records, key)
				changed = true
			}
		}
		if !changed {
			return used, nil
		}
		if _, err := s.write(ctx, cm, value); err != nil {
			if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
				continue
			}
			return nil, err
		}
		return used, nil
	}
	return nil, errors.New("shared capacity inventory CAS retries exhausted")
}

func serviceDemands(resources []model.ResourceConsumption) ([]model.ResourceConsumption, error) {
	out := make([]model.ResourceConsumption, 0, len(resources))
	seen := map[string]bool{}
	for _, demand := range resources {
		key := demand.Scope.Key()
		if !demand.Scope.Valid() || demand.Units <= 0 || seen[key] {
			return nil, errors.New("selected shared resource vector is invalid")
		}
		seen[key] = true
		if demand.Scope.Kind == model.ResourceMoveCount {
			continue
		}
		if demand.Scope.Kind != model.ResourceUnavailableReadyReplica {
			return nil, errors.New("selected shared resource vector is invalid")
		}
		out = append(out, demand)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope.Key() < out[j].Scope.Key() })
	return out, nil
}

func (s *Store) Acquire(ctx context.Context, req Request) (*Reservation, error) {
	demands, err := serviceDemands(req.Resources)
	if err != nil {
		return nil, err
	}
	if len(demands) == 0 {
		return nil, nil
	}
	if err := validateRequest(req, demands); err != nil {
		return nil, err
	}
	opID := operationID(req)
	for attempt := 0; attempt < ledgerCASAttempts; attempt++ {
		cm, value, err := s.read(ctx)
		if err != nil {
			return nil, err
		}
		if existing, ok := value.Records[opID]; ok {
			if existing.PolicyUID == req.PolicyUID && existing.TargetUID == req.TargetUID && existing.TargetName == req.TargetName && existing.Action == req.Action && recordDemandsMatch(existing, req, demands) {
				uid := types.UID("")
				if cm != nil {
					uid = cm.UID
				}
				return &Reservation{OperationID: opID, LedgerUID: uid, Created: existing.Phase == "reserved"}, nil
			}
			return nil, errors.New("shared capacity operation identity collision")
		}
		used, err := s.pendingUsage(ctx, value)
		if err != nil {
			return nil, err
		}
		admissions := make([]admission, 0, len(demands))
		for _, demand := range demands {
			observed, err := s.observeScope(ctx, demand.Scope, req.TargetUID)
			if err != nil {
				return nil, err
			}
			if !observed.HasTarget {
				return nil, errors.New("selected target is no longer a ready member of the capacity scope")
			}
			floor := req.MinAvailableReplica
			for _, existing := range value.Records {
				for _, prior := range existing.Admissions {
					if prior.Scope.Key() == demand.Scope.Key() && prior.Floor > floor {
						floor = prior.Floor
					}
				}
			}
			limit := observed.Ready - floor
			if limit < 0 || used[demand.Scope.Key()]+demand.Units > limit {
				return nil, fmt.Errorf("shared capacity exhausted for Service UID %s: ready=%d floor=%d reserved=%d requested=%d", demand.Scope.ServiceUID, observed.Ready, floor, used[demand.Scope.Key()], demand.Units)
			}
			admissions = append(admissions, admission{Scope: demand.Scope, Units: demand.Units, Floor: req.MinAvailableReplica, ReadyBefore: observed.Ready})
		}
		if len(value.Records) >= ledgerMaxRecords {
			return nil, errors.New("shared capacity ledger record bound reached")
		}
		value.Records[opID] = record{OperationID: opID, PolicyUID: req.PolicyUID, TargetName: req.TargetName, TargetUID: req.TargetUID, Action: req.Action, Phase: "reserved", Admissions: admissions}
		written, err := s.write(ctx, cm, value)
		if err != nil {
			if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
				continue
			}
			return nil, err
		}
		return &Reservation{OperationID: opID, LedgerUID: written.UID, Created: true}, nil
	}
	return nil, errors.New("shared capacity acquisition CAS retries exhausted")
}

func recordDemandsMatch(existing record, req Request, demands []model.ResourceConsumption) bool {
	if len(existing.Admissions) != len(demands) {
		return false
	}
	want := make([]admission, 0, len(demands))
	for _, demand := range demands {
		want = append(want, admission{Scope: demand.Scope, Units: demand.Units, Floor: req.MinAvailableReplica})
	}
	for i := range want {
		if existing.Admissions[i].Scope != want[i].Scope || existing.Admissions[i].Units != want[i].Units || existing.Admissions[i].Floor != want[i].Floor {
			return false
		}
	}
	return true
}

func (s *Store) pendingUsage(ctx context.Context, value ledger) (map[string]int, error) {
	used := map[string]int{}
	for _, existing := range value.Records {
		for _, prior := range existing.Admissions {
			observed, err := s.observeScope(ctx, prior.Scope, existing.TargetUID)
			if err != nil {
				return nil, err
			}
			if observed.HasTarget {
				used[prior.Scope.Key()] += prior.Units
			}
		}
	}
	return used, nil
}

// Exchange atomically replaces one definitely-unsent reservation with the
// same target's fallback action. There is no interval in which another policy
// can spend the released capacity.
func (s *Store) Exchange(ctx context.Context, reservation *Reservation, req Request) (*Reservation, error) {
	if reservation == nil {
		return s.Acquire(ctx, req)
	}
	demands, err := serviceDemands(req.Resources)
	if err != nil {
		return nil, err
	}
	if err := validateRequest(req, demands); err != nil {
		return nil, err
	}
	newID := operationID(req)
	for attempt := 0; attempt < ledgerCASAttempts; attempt++ {
		cm, value, err := s.read(ctx)
		if err != nil {
			return nil, err
		}
		if cm == nil || (reservation.LedgerUID != "" && cm.UID != reservation.LedgerUID) {
			return nil, errors.New("shared capacity ledger identity changed")
		}
		prior, ok := value.Records[reservation.OperationID]
		if !ok || prior.Phase != "dispatching" || prior.PolicyUID != req.PolicyUID || prior.TargetUID != req.TargetUID || prior.TargetName != req.TargetName {
			return nil, errors.New("shared capacity fallback reservation identity changed")
		}
		if newID != reservation.OperationID {
			if _, exists := value.Records[newID]; exists {
				return nil, errors.New("shared capacity fallback operation identity collision")
			}
			delete(value.Records, reservation.OperationID)
		}
		if len(demands) == 0 {
			delete(value.Records, newID)
			if _, err := s.write(ctx, cm, value); err != nil {
				if apierrors.IsConflict(err) {
					continue
				}
				return nil, err
			}
			return nil, nil
		}
		// Exclude the old reservation while evaluating its atomic replacement.
		delete(value.Records, newID)
		used, err := s.pendingUsage(ctx, value)
		if err != nil {
			return nil, err
		}
		admissions := make([]admission, 0, len(demands))
		for _, demand := range demands {
			observed, err := s.observeScope(ctx, demand.Scope, req.TargetUID)
			if err != nil {
				return nil, err
			}
			if !observed.HasTarget {
				return nil, errors.New("fallback target is no longer a ready member of the capacity scope")
			}
			floor := req.MinAvailableReplica
			for _, existing := range value.Records {
				for _, other := range existing.Admissions {
					if other.Scope.Key() == demand.Scope.Key() && other.Floor > floor {
						floor = other.Floor
					}
				}
			}
			if observed.Ready-floor < used[demand.Scope.Key()]+demand.Units {
				return nil, fmt.Errorf("shared capacity exhausted during fallback exchange for Service UID %s", demand.Scope.ServiceUID)
			}
			admissions = append(admissions, admission{Scope: demand.Scope, Units: demand.Units, Floor: req.MinAvailableReplica, ReadyBefore: observed.Ready})
		}
		value.Records[newID] = record{OperationID: newID, PolicyUID: req.PolicyUID, TargetName: req.TargetName, TargetUID: req.TargetUID, Action: req.Action, Phase: "reserved", Admissions: admissions}
		written, err := s.write(ctx, cm, value)
		if err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return nil, err
		}
		return &Reservation{OperationID: newID, LedgerUID: written.UID, Created: true}, nil
	}
	return nil, errors.New("shared capacity fallback exchange CAS retries exhausted")
}

// Claim is the last durable boundary before backend invocation. Only an
// acknowledged reserved->dispatching CAS licenses the caller to send work.
func (s *Store) Claim(ctx context.Context, reservation *Reservation) error {
	if reservation == nil {
		return nil
	}
	for attempt := 0; attempt < ledgerCASAttempts; attempt++ {
		cm, value, err := s.read(ctx)
		if err != nil {
			return err
		}
		if cm == nil || (reservation.LedgerUID != "" && cm.UID != reservation.LedgerUID) {
			return errors.New("shared capacity ledger identity changed before dispatch claim")
		}
		record, ok := value.Records[reservation.OperationID]
		if !ok || record.Phase != "reserved" {
			return errors.New("shared capacity reservation is not exclusively dispatchable")
		}
		// Revalidate the exact current routing/readiness authority immediately
		// before the dispatch claim. Exclude this reservation while counting
		// peers, then prove its own target remains Ready and its admitted floor
		// still has enough headroom for the claimed units.
		delete(value.Records, reservation.OperationID)
		used, err := s.pendingUsage(ctx, value)
		if err != nil {
			return err
		}
		for _, current := range record.Admissions {
			observed, err := s.observeScope(ctx, current.Scope, record.TargetUID)
			if err != nil {
				return err
			}
			floor := current.Floor
			for _, peer := range value.Records {
				for _, admission := range peer.Admissions {
					if admission.Scope.Key() == current.Scope.Key() && admission.Floor > floor {
						floor = admission.Floor
					}
				}
			}
			if !observed.HasTarget || observed.Ready-floor < used[current.Scope.Key()]+current.Units {
				return errors.New("shared capacity authority or availability changed before dispatch claim")
			}
		}
		record.Phase = "dispatching"
		value.Records[reservation.OperationID] = record
		if _, err := s.write(ctx, cm, value); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return err
		}
		return nil
	}
	return errors.New("shared capacity dispatch claim CAS retries exhausted")
}

func (s *Store) mutate(ctx context.Context, reservation *Reservation, remove bool) error {
	if reservation == nil {
		return nil
	}
	for attempt := 0; attempt < ledgerCASAttempts; attempt++ {
		cm, value, err := s.read(ctx)
		if err != nil {
			return err
		}
		if cm == nil || (reservation.LedgerUID != "" && cm.UID != reservation.LedgerUID) {
			return errors.New("shared capacity ledger identity changed")
		}
		record, ok := value.Records[reservation.OperationID]
		if !ok {
			return nil
		}
		if remove {
			delete(value.Records, reservation.OperationID)
		} else {
			record.Phase = "uncertain"
			value.Records[reservation.OperationID] = record
		}
		if _, err := s.write(ctx, cm, value); err != nil {
			if apierrors.IsConflict(err) {
				continue
			}
			return err
		}
		return nil
	}
	return errors.New("shared capacity reservation CAS retries exhausted")
}

func (s *Store) ReleaseNoEffect(ctx context.Context, reservation *Reservation) error {
	return s.mutate(ctx, reservation, true)
}

func (s *Store) RetainUnknown(ctx context.Context, reservation *Reservation) error {
	return s.mutate(ctx, reservation, false)
}
