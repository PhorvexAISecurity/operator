package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	validation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	journalLabel        = "phorvex.ai/operation-journal"
	servingJournalLabel = "phorvex.ai/serving-effect-journal"
)

// operationReceipt is administrative provenance, stored only in the operator namespace.
// Pod annotations and labels are never used as evidence that a receipt exists.
type operationReceipt struct {
	Version         int               `json:"version"`
	Kind            string            `json:"kind"`
	Phase           string            `json:"phase"`
	PolicyNamespace string            `json:"policyNamespace"`
	PolicyName      string            `json:"policyName"`
	PolicyUID       string            `json:"policyUID"`
	TargetName      string            `json:"targetName"`
	TargetUID       string            `json:"targetUID"`
	TargetLabels    map[string]string `json:"targetLabels"`
	OldName         string            `json:"oldName,omitempty"`
	OldUID          string            `json:"oldUID,omitempty"`
	NewName         string            `json:"newName,omitempty"`
	NewUID          string            `json:"newUID,omitempty"`
	GroupKey        string            `json:"groupKey,omitempty"`
	GroupValue      string            `json:"groupValue,omitempty"`
	NPName          string            `json:"npName,omitempty"`
	NPUID           string            `json:"npUID,omitempty"`
	RewarmName      string            `json:"rewarmName,omitempty"`
	RewarmUID       string            `json:"rewarmUID,omitempty"`
	RewarmSpecHash  string            `json:"rewarmSpecHash,omitempty"`
	Pool            *warmPoolIntent   `json:"pool,omitempty"`
	// Request-drain v3 fields. The receipt is the authority for transient restoration;
	// tenant Pod metadata alone never authorizes recovery.
	OperationToken       string            `json:"operationToken,omitempty"`
	ServiceName          string            `json:"serviceName,omitempty"`
	ServiceUID           string            `json:"serviceUID,omitempty"`
	ServiceSelector      map[string]string `json:"serviceSelector,omitempty"`
	PriorServingPresent  bool              `json:"priorServingPresent,omitempty"`
	PriorServingValue    string            `json:"priorServingValue,omitempty"`
	EndpointAddresses    []string          `json:"endpointAddresses,omitempty"`
	EndpointConfigSHA256 string            `json:"endpointConfigSHA256,omitempty"`
	Aborted              int               `json:"aborted,omitempty"`
	// Scalar warm v10 fields protect each serving drain send and the exact
	// pre-cutover routing set used by definitely-unsent compensation.
	DrainAttempts    int      `json:"drainAttempts,omitempty"`
	WarmSelectedUIDs []string `json:"warmSelectedUIDs,omitempty"`
	// Adapter-rotate v4 fields bind one protected serving operation to the
	// selected Pod, authenticated detector event and immutable source mapping.
	AdapterName           string `json:"adapterName,omitempty"`
	AdapterSource         string `json:"adapterSource,omitempty"`
	AdapterSourcePresent  bool   `json:"adapterSourcePresent,omitempty"`
	AdapterEventName      string `json:"adapterEventName,omitempty"`
	AdapterEventUID       string `json:"adapterEventUID,omitempty"`
	AdapterEventCreatedAt string `json:"adapterEventCreatedAt,omitempty"`
	AdapterCreator        string `json:"adapterCreator,omitempty"`
	AdapterEndpointSHA256 string `json:"adapterEndpointSHA256,omitempty"`
	ServingBindingSHA256  string `json:"servingBindingSHA256,omitempty"`
	ServingServiceAccount string `json:"servingServiceAccount,omitempty"`
	ServingLegacy         bool   `json:"servingLegacy,omitempty"`
	// Route-cutover v5 fields. The Service-UID-named receipt is the only
	// authority for route/endpoint continuation or restoration. Tenant metadata
	// is deliberately not an authority surface.
	NamespaceUID   string `json:"namespaceUID,omitempty"`
	ReceiptID      string `json:"receiptID,omitempty"`
	TargetGuardUID string `json:"targetGuardUID,omitempty"`
	// AdmittedFloor is shared by protected route cutover and scalar warm receipts.
	AdmittedFloor           int               `json:"admittedFloor,omitempty"`
	RouteEpochKey           string            `json:"routeEpochKey,omitempty"`
	RouteValue              string            `json:"routeValue,omitempty"`
	BridgeValue             string            `json:"bridgeValue,omitempty"`
	OriginalServiceSelector map[string]string `json:"originalServiceSelector,omitempty"`
	BeforePodRoute          routeOwnedValue   `json:"beforePodRoute,omitempty,omitzero"`
	BeforePodEpoch          routeOwnedValue   `json:"beforePodEpoch,omitempty,omitzero"`
	BeforePodBridge         routeOwnedValue   `json:"beforePodBridge,omitempty,omitzero"`
	BeforeServiceRoute      routeOwnedValue   `json:"beforeServiceRoute,omitempty,omitzero"`
	BeforeServiceBridge     routeOwnedValue   `json:"beforeServiceBridge,omitempty,omitzero"`
	// Protected serving-effect v9 fields. One stable ConfigMap name is shared by
	// all policies/actions in an exact target/effect domain.
	EffectDomain      string          `json:"effectDomain,omitempty"`
	OperationID       string          `json:"operationID,omitempty"`
	TickID            string          `json:"tickID,omitempty"`
	Generation        uint64          `json:"generation,omitempty"`
	SelectedReset     routeOwnedValue `json:"selectedReset,omitempty,omitzero"`
	SelectedMigrate   routeOwnedValue `json:"selectedMigrate,omitempty,omitzero"`
	SelectedLocal     routeOwnedValue `json:"selectedLocal,omitempty,omitzero"`
	SelectedGuardrail routeOwnedValue `json:"selectedGuardrail,omitempty,omitzero"`
	ExpectedReset     routeOwnedValue `json:"expectedReset,omitempty,omitzero"`
	ExpectedMigrate   routeOwnedValue `json:"expectedMigrate,omitempty,omitzero"`
	ExpectedLocal     routeOwnedValue `json:"expectedLocal,omitempty,omitzero"`
	ExpectedGuardrail routeOwnedValue `json:"expectedGuardrail,omitempty,omitzero"`
	PriorVariant      string          `json:"priorVariant,omitempty"`
	NextVariant       string          `json:"nextVariant,omitempty"`
	PriorSnapshot     routeOwnedValue `json:"priorSnapshot,omitempty,omitzero"`
	PeerOutcomes      []kvPeerOutcome `json:"peerOutcomes,omitempty"`
	DeclaredPeers     []string        `json:"declaredPeers,omitempty"`
	RemoteExpected    int             `json:"remoteExpected,omitempty"`
}

type routeOwnedValue struct {
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}

func (v routeOwnedValue) IsZero() bool { return !v.Present && v.Value == "" }

func boundedOwnedValue(v routeOwnedValue) bool {
	return len(v.Value) <= servingEffectEpochMaxBytes && (v.Present || v.Value == "")
}

func boundedServingIdentity(r operationReceipt) bool {
	return len(validation.IsDNS1123Label(r.PolicyNamespace)) == 0 &&
		len(validation.IsDNS1123Subdomain(r.PolicyName)) == 0 &&
		len(validation.IsDNS1123Subdomain(r.TargetName)) == 0 &&
		r.PolicyUID != "" && len(r.PolicyUID) <= 253 && r.TargetUID != "" && len(r.TargetUID) <= 253
}

func validServingEffectReceipt(r operationReceipt) bool {
	if r.Version != servingEffectReceiptVersion || r.Generation == 0 || !validDigest(r.OperationID) || r.TickID == "" || len(r.TickID) > 253 ||
		r.OperationID != servingOperationDigest(r.TickID, r.PolicyUID, r.PolicyNamespace, r.TargetUID, model.Action(r.Kind)) ||
		(!r.ServingLegacy && !validDigest(r.ServingBindingSHA256)) || (r.ServingLegacy && r.ServingBindingSHA256 != "") || len(validation.IsDNS1123Subdomain(r.ServingServiceAccount)) != 0 || !validDigest(r.EndpointConfigSHA256) ||
		!boundedServingIdentity(r) || !boundedOptionalLabelMap(r.TargetLabels) || !boundedOwnedValue(r.PriorSnapshot) ||
		!boundedOwnedValue(r.SelectedReset) || !boundedOwnedValue(r.SelectedMigrate) || !boundedOwnedValue(r.SelectedLocal) || !boundedOwnedValue(r.SelectedGuardrail) ||
		!boundedOwnedValue(r.ExpectedReset) || !boundedOwnedValue(r.ExpectedMigrate) || !boundedOwnedValue(r.ExpectedLocal) || !boundedOwnedValue(r.ExpectedGuardrail) {
		return false
	}
	apply := routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "apply")}
	unchangedKV := r.ExpectedReset == r.SelectedReset && r.ExpectedMigrate == r.SelectedMigrate && r.ExpectedLocal == r.SelectedLocal
	unchangedGuard := r.ExpectedGuardrail == r.SelectedGuardrail
	switch model.Action(r.Kind) {
	case model.ActionKVReset:
		if r.EffectDomain != kvEffectDomain || r.ExpectedReset != apply || r.ExpectedMigrate != r.SelectedMigrate || r.ExpectedLocal != r.SelectedLocal ||
			!unchangedGuard || r.RemoteExpected != 0 || len(r.DeclaredPeers) != 0 || len(r.PeerOutcomes) != 0 || r.PriorVariant != "" || r.NextVariant != "" {
			return false
		}
		switch r.Phase {
		case "prepared", "dispatching", "effect-confirmed", "metadata-ready-full", "terminal-full":
			return true
		default:
			return false
		}
	case model.ActionGuardrailRotate:
		if r.EffectDomain != guardrailEffectDomain || !unchangedKV || r.PriorVariant == "" || r.NextVariant == "" || r.PriorVariant == r.NextVariant || len(r.PriorVariant) > 1024 || len(r.NextVariant) > 1024 ||
			r.RemoteExpected != 0 || len(r.DeclaredPeers) != 0 || len(r.PeerOutcomes) != 0 {
			return false
		}
		switch r.Phase {
		case "prepared", "dispatching", "effect-confirmed", "metadata-ready-full", "terminal-full":
			return r.ExpectedGuardrail == apply
		case "rollback-dispatching":
			return r.ExpectedGuardrail == apply
		case "rollback-confirmed", "rolled-back":
			return r.ExpectedGuardrail == (routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "rollback")})
		default:
			return false
		}
	case model.ActionKVMigrateInvalidate:
		if r.EffectDomain != kvEffectDomain || !unchangedGuard || r.PriorVariant != "" || r.NextVariant != "" || r.RemoteExpected < 0 || r.RemoteExpected > 32 || len(r.DeclaredPeers) != r.RemoteExpected || (len(r.PeerOutcomes) != 0 && len(r.PeerOutcomes) != r.RemoteExpected) {
			return false
		}
		declared := make(map[string]bool, len(r.DeclaredPeers))
		for _, peer := range r.DeclaredPeers {
			if peer == "" || len(peer) > 300 || declared[peer] {
				return false
			}
			declared[peer] = true
		}
		confirmed, finalPartial, unknown := 0, 0, 0
		seen := make(map[string]bool, len(r.PeerOutcomes))
		for _, outcome := range r.PeerOutcomes {
			if !outcome.valid() || !declared[outcome.Peer] || seen[outcome.Peer] {
				return false
			}
			seen[outcome.Peer] = true
			switch outcome.Disposition {
			case kvPeerConfirmed:
				confirmed++
			case kvPeerNotSentUnimplemented, kvPeerRefusedBeforeSend:
				finalPartial++
			case kvPeerUnknownAfterDispatch:
				unknown++
			}
		}
		switch r.Phase {
		case "prepared", "dispatching", "effect-confirmed":
			return len(r.PeerOutcomes) == 0 && unchangedKV
		case "remote-dispatching":
			return r.RemoteExpected > 0 && len(r.PeerOutcomes) == 0 && unchangedKV
		case "remote-unknown":
			return r.RemoteExpected > 0 && unchangedKV && (len(r.PeerOutcomes) == 0 || unknown > 0)
		case "metadata-ready-full", "terminal-full":
			return r.ExpectedReset == r.SelectedReset && r.ExpectedLocal == r.SelectedLocal && r.ExpectedMigrate == apply &&
				((r.RemoteExpected == 0 && len(r.PeerOutcomes) == 0) || (r.RemoteExpected > 0 && confirmed == r.RemoteExpected && finalPartial == 0 && unknown == 0))
		case "metadata-ready-partial", "terminal-partial":
			return r.RemoteExpected > 0 && len(r.PeerOutcomes) == r.RemoteExpected && unknown == 0 && finalPartial > 0 &&
				r.ExpectedReset == r.SelectedReset && r.ExpectedMigrate == r.SelectedMigrate && r.ExpectedLocal == (routeOwnedValue{Present: true, Value: epochToken(r.OperationID, "local-only")})
		default:
			return false
		}
	default:
		return false
	}
}

const (
	requestDrainReceiptVersion        = 3
	adapterRotateReceiptVersion       = 4
	routeCutoverReceiptVersion        = 5
	warmSecureReceiptVersion          = 6
	requestDrainSecureReceiptVersion  = 7
	adapterRotateSecureReceiptVersion = 8
	servingEffectReceiptVersion       = 9
	warmDrainReceiptVersion           = 10
	requestDrainMaxLabels             = 64
	requestDrainMaxAddresses          = 16
	servingEffectReceiptMaxBytes      = 32 << 10
	servingEffectEpochMaxBytes        = 4 << 10
)

func validDigest(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == sha256.Size
}

func receiptName(r operationReceipt) string {
	if r.Version == servingEffectReceiptVersion && r.EffectDomain != "" {
		h := sha256.Sum256([]byte("serving-effect/" + r.EffectDomain + "/" + r.TargetUID))
		return fmt.Sprintf("phorvex-serving-effect-%x", h[:20])
	}
	if (r.Kind == string(model.ActionRouteRotate) || r.Kind == string(model.ActionEndpointRotate)) && r.ServiceUID != "" {
		h := sha256.Sum256([]byte("route-service/" + r.ServiceUID))
		return fmt.Sprintf("phorvex-route-service-%x", h[:20])
	}
	h := sha256.Sum256([]byte(r.Kind + "/" + r.PolicyUID + "/" + r.TargetUID))
	return fmt.Sprintf("phorvex-operation-%x", h[:20])
}

func podSpecDigest(p *corev1.Pod) string {
	b, _ := json.Marshal(p.Spec)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}

func (r operationReceipt) valid() bool {
	if (r.Version != 1 && r.Version != 2 && r.Version != requestDrainReceiptVersion && r.Version != adapterRotateReceiptVersion && r.Version != routeCutoverReceiptVersion && r.Version != warmSecureReceiptVersion && r.Version != requestDrainSecureReceiptVersion && r.Version != adapterRotateSecureReceiptVersion && r.Version != servingEffectReceiptVersion && r.Version != warmDrainReceiptVersion) || r.PolicyNamespace == "" || r.PolicyName == "" || r.PolicyUID == "" || r.TargetName == "" || r.TargetUID == "" {
		return false
	}
	switch r.Kind {
	case string(model.ActionKVReset), string(model.ActionKVMigrateInvalidate), string(model.ActionGuardrailRotate):
		return validServingEffectReceipt(r)
	case "warm-swap", "model-shard-replace":
		if r.Version != 1 && r.Version != 2 && r.Version != warmSecureReceiptVersion && r.Version != warmDrainReceiptVersion {
			return false
		}
		if r.Version == 2 || r.Version == warmSecureReceiptVersion || r.Version == warmDrainReceiptVersion {
			p := r.Pool
			if p == nil || p.RSName == "" || p.RSUID == "" || p.RSGeneration <= 0 || p.Desired < 2 || p.Desired > warmPoolMaxMembers || len(p.Members) != int(p.Desired) || p.RSTemplateHash == "" || p.RSSelectorHash == "" || p.ServiceName == "" || p.ServiceUID == "" || p.ServiceSelectorHash == "" || ((p.ParentName == "") != (p.ParentUID == "")) || r.RewarmSpecHash != "" || r.OldName == "" || r.OldName != r.TargetName || r.OldUID == "" || r.OldUID != r.TargetUID || r.NewName == "" || r.NewUID == "" || r.OldName == r.NewName || r.OldUID == r.NewUID || r.GroupValue == "" || !((r.Kind == "warm-swap" && r.GroupKey == labelSwapGroup) || (r.Kind == "model-shard-replace" && r.GroupKey == labelModelShard)) {
				return false
			}
			members := make(map[string]bool, len(p.Members))
			for _, uid := range p.Members {
				if uid == "" || members[uid] {
					return false
				}
				members[uid] = true
			}
			if !members[r.OldUID] || !members[r.NewUID] {
				return false
			}
			preObservation := r.Phase == "prepared" || r.Phase == "promoted" || r.Phase == "retiring" || r.Phase == "drain-dispatching" || r.Phase == "drain-unsent" || r.Phase == "drain-confirmed" || r.Phase == "restore-old-claimed" || r.Phase == "old-route-observed" || r.Phase == "restore-shadow-claimed" || r.Phase == "routing-restored" || r.Phase == "retired-awaiting-controller"
			postObservation := r.Phase == "pool-observed" || r.Phase == "pool-warm-ready"
			valid := (preObservation && r.RewarmName == "" && r.RewarmUID == "") || (postObservation && r.RewarmName != "" && r.RewarmUID != "" && r.RewarmName != r.OldName && r.RewarmName != r.NewName && r.RewarmUID != r.OldUID && r.RewarmUID != r.NewUID && !members[r.RewarmUID])
			if !valid {
				return false
			}
			if r.Version == warmSecureReceiptVersion {
				return validDigest(r.ServingBindingSHA256) && len(validation.IsDNS1123Subdomain(r.ServingServiceAccount)) == 0
			}
			if r.Version != warmDrainReceiptVersion {
				return true
			}
			if !boundedLabelMap(r.TargetLabels) || !validDigest(r.EndpointConfigSHA256) || r.DrainAttempts < 0 || r.DrainAttempts > warmDrainMaxAttempts || len(r.WarmSelectedUIDs) == 0 || len(r.WarmSelectedUIDs) > warmPoolMaxMembers || r.AdmittedFloor <= 0 || r.AdmittedFloor > len(r.WarmSelectedUIDs) || r.AdmittedFloor > int(p.Desired) || len(validation.IsDNS1123Subdomain(r.ServingServiceAccount)) != 0 {
				return false
			}
			if r.ServingLegacy {
				if r.ServingBindingSHA256 != "" {
					return false
				}
			} else if !validDigest(r.ServingBindingSHA256) {
				return false
			}
			selected := make(map[string]bool, len(r.WarmSelectedUIDs))
			for i, uid := range r.WarmSelectedUIDs {
				if uid == "" || selected[uid] || (i > 0 && r.WarmSelectedUIDs[i-1] >= uid) || !members[uid] {
					return false
				}
				selected[uid] = true
			}
			if !selected[r.OldUID] || selected[r.NewUID] {
				return false
			}
			switch r.Phase {
			case "prepared", "promoted", "retiring":
				return r.DrainAttempts == 0 && r.Aborted == 0
			case "drain-dispatching", "drain-unsent", "restore-old-claimed", "old-route-observed", "restore-shadow-claimed", "routing-restored":
				return r.DrainAttempts > 0 && r.Aborted == 0
			case "drain-confirmed", "retired-awaiting-controller", "pool-observed", "pool-warm-ready":
				return r.DrainAttempts > 0 && r.Aborted >= 0
			default:
				return false
			}
		}
		validPhase := r.Phase == "prepared" || r.Phase == "promoted" || r.Phase == "retiring" || r.Phase == "retired" || r.Phase == "rewarm-intent" || r.Phase == "rewarmed"
		validRewarm := (r.Phase != "rewarm-intent" && r.Phase != "rewarmed" && r.RewarmName == "" && r.RewarmUID == "" && r.RewarmSpecHash == "") || (r.Phase == "rewarm-intent" && r.RewarmName != "" && r.RewarmUID == "" && r.RewarmSpecHash != "") || (r.Phase == "rewarmed" && r.RewarmName != "" && r.RewarmUID != "" && r.RewarmSpecHash != "")
		return validPhase && validRewarm && r.OldName == r.TargetName && r.OldUID == r.TargetUID && r.NewName != "" && r.NewUID != "" && r.OldName != r.NewName && r.OldUID != r.NewUID && r.RewarmName != r.OldName && r.RewarmName != r.NewName && r.GroupValue != "" && ((r.Kind == "warm-swap" && r.GroupKey == labelSwapGroup) || (r.Kind == "model-shard-replace" && r.GroupKey == labelModelShard))
	case "quarantine":
		return r.Version == 1 && (r.Phase == "prepared" || r.Phase == "policy-bound") && r.NPName != "" && r.TargetLabels != nil && (r.Phase != "policy-bound" || r.NPUID != "")
	case "request-drain":
		_, hasServingSelector := r.ServiceSelector[labelServing]
		if (r.Version != requestDrainReceiptVersion && r.Version != requestDrainSecureReceiptVersion) || !boundedLabelMap(r.TargetLabels) || !boundedLabelMap(r.ServiceSelector) || !hasServingSelector || r.ServiceName == "" || r.ServiceUID == "" || r.OperationToken == "" || len(r.EndpointAddresses) != 1 || (!r.PriorServingPresent && r.PriorServingValue != "") || r.Aborted < 0 || (r.Version == requestDrainSecureReceiptVersion && (!validDigest(r.ServingBindingSHA256) || len(validation.IsDNS1123Subdomain(r.ServingServiceAccount)) != 0)) {
			return false
		}
		if token, err := hex.DecodeString(r.OperationToken); err != nil || len(token) != 16 {
			return false
		}
		if digest, err := hex.DecodeString(r.EndpointConfigSHA256); err != nil || len(digest) != sha256.Size {
			return false
		}
		seen := make(map[string]bool, len(r.EndpointAddresses))
		for _, address := range r.EndpointAddresses {
			if _, err := netip.ParseAddr(address); err != nil || seen[address] {
				return false
			}
			seen[address] = true
		}
		switch r.Phase {
		case "prepared", "claimed", "stopped", "withdrawn":
			return r.Aborted == 0
		case "stack-confirmed":
			return r.Aborted > 0
		case "restored":
			return true
		default:
			return false
		}
	case "adapter-rotate":
		if (r.Version != adapterRotateReceiptVersion && r.Version != adapterRotateSecureReceiptVersion) || !boundedLabelMap(r.TargetLabels) ||
			!validRuntimeAdapterName(r.AdapterName) || r.AdapterEventName == "" || r.AdapterEventUID == "" ||
			r.AdapterCreator == "" || len(r.AdapterEventName) > 253 || len(r.AdapterEventUID) > 253 || len(r.AdapterCreator) > 512 ||
			(r.AdapterSourcePresent && (r.AdapterSource == "" || len(r.AdapterSource) > maxAdapterSourcePathBytes)) || (!r.AdapterSourcePresent && r.AdapterSource != "") || (r.Version == adapterRotateSecureReceiptVersion && (!validDigest(r.ServingBindingSHA256) || len(validation.IsDNS1123Subdomain(r.ServingServiceAccount)) != 0)) {
			return false
		}
		createdAt, err := time.Parse(time.RFC3339Nano, r.AdapterEventCreatedAt)
		if err != nil || createdAt.IsZero() || r.AdapterEventCreatedAt != createdAt.UTC().Format(time.RFC3339Nano) {
			return false
		}
		if digest, err := hex.DecodeString(r.AdapterEndpointSHA256); err != nil || len(digest) != sha256.Size {
			return false
		}
		switch r.Phase {
		case "prepared", "unload-dispatching", "unload-acknowledged", "absent-confirmed", "load-dispatching", "load-acknowledged", "loaded-confirmed", "completed":
			return true
		default:
			return false
		}
	case string(model.ActionRouteRotate), string(model.ActionEndpointRotate):
		action := model.Action(r.Kind)
		if r.Version != routeCutoverReceiptVersion || r.NamespaceUID == "" || r.ServiceName == "" || r.ServiceUID == "" ||
			r.OperationToken == "" || r.ReceiptID == "" || r.TargetGuardUID == "" || r.AdmittedFloor != 1 ||
			r.RouteEpochKey == "" || r.RouteValue == "" || r.BridgeValue == "" ||
			!boundedLabelMap(r.TargetLabels) || !boundedLabelMap(r.OriginalServiceSelector) ||
			r.BeforePodRoute != ownedValue(r.TargetLabels, labelRouteKey) ||
			r.BeforePodBridge != ownedValue(r.TargetLabels, routeBridgeLabel) ||
			r.BeforeServiceRoute != ownedValue(r.OriginalServiceSelector, labelRouteKey) ||
			r.BeforeServiceBridge != ownedValue(r.OriginalServiceSelector, routeBridgeLabel) ||
			r.BeforePodBridge.Present || r.BeforeServiceBridge.Present || r.BeforePodRoute != r.BeforeServiceRoute ||
			r.RouteEpochKey != routeEpochKey(action) ||
			r.ReceiptID != routeReceiptID(r.PolicyUID, r.TargetUID, action, r.OperationToken) ||
			r.RouteValue != routeToken("route", r.PolicyUID, r.TargetUID, action, r.OperationToken) ||
			r.BridgeValue != routeToken("bridge", r.PolicyUID, r.TargetUID, action, r.OperationToken) {
			return false
		}
		if len(r.OperationToken) > 253 || len(r.ReceiptID) != 40 || len(r.RouteValue) > 63 || len(r.BridgeValue) > 63 {
			return false
		}
		if digest, err := hex.DecodeString(r.ReceiptID); err != nil || len(digest) != 20 {
			return false
		}
		switch r.Phase {
		case "prepared", "pod-bridged", "service-bridged", "target-rekeyed", "service-final", "applied", "restoring":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func boundedLabelMap(values map[string]string) bool {
	if len(values) == 0 || len(values) > requestDrainMaxLabels {
		return false
	}
	for key, value := range values {
		// Kubernetes already validates label syntax. These explicit bounds keep a hostile
		// object from expanding a protected receipt beyond this operation's needs.
		if key == "" || len(key) > 253 || len(value) > 63 {
			return false
		}
	}
	return true
}

func boundedOptionalLabelMap(values map[string]string) bool {
	if len(values) > requestDrainMaxLabels {
		return false
	}
	for key, value := range values {
		if key == "" || len(key) > 253 || len(value) > 63 {
			return false
		}
	}
	return true
}

func journalWrite(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.ConfigMap, error) {
	if ec.JournalNamespace == "" || ec.JournalNamespace == r.PolicyNamespace || ec.Client == nil || !r.valid() {
		return nil, fmt.Errorf("operation journal unavailable or invalid")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if r.Version == servingEffectReceiptVersion && len(b) > servingEffectReceiptMaxBytes {
		return nil, fmt.Errorf("protected serving receipt exceeds %d bytes", servingEffectReceiptMaxBytes)
	}
	journalLabels := map[string]string{journalLabel: "v1"}
	if r.Version == servingEffectReceiptVersion {
		journalLabels[servingJournalLabel] = "v1"
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ec.JournalNamespace, Name: receiptName(r), Labels: journalLabels}, Data: map[string]string{"receipt": string(b)}}
	if err := ec.Client.Create(ctx, cm); err != nil {
		return nil, err
	}
	if cm.UID == "" || cm.ResourceVersion == "" {
		return nil, fmt.Errorf("operation journal create not acknowledged")
	}
	return cm, nil
}

func journalAdvance(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r operationReceipt) error {
	if cm == nil || cm.UID == "" || cm.ResourceVersion == "" || !r.valid() {
		return fmt.Errorf("operation journal identity invalid")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if r.Version == servingEffectReceiptVersion && len(b) > servingEffectReceiptMaxBytes {
		return fmt.Errorf("protected serving receipt exceeds %d bytes", servingEffectReceiptMaxBytes)
	}
	next := cm.DeepCopy()
	next.Data["receipt"] = string(b)
	if err := ec.Client.Update(ctx, next); err != nil {
		return err
	}
	if next.UID != cm.UID || next.ResourceVersion == "" {
		return fmt.Errorf("operation journal update unconfirmed")
	}
	*cm = *next
	return nil
}

func journalFinish(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap) error {
	if cm == nil || cm.UID == "" || cm.ResourceVersion == "" {
		return fmt.Errorf("operation journal finish identity invalid")
	}
	uid := cm.UID
	rv := cm.ResourceVersion
	err := ec.Client.Delete(ctx, cm, client.Preconditions{UID: &uid, ResourceVersion: &rv})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func journalList(ctx context.Context, ec EnactCtx) ([]struct {
	CM      corev1.ConfigMap
	Receipt operationReceipt
}, error) {
	if ec.JournalNamespace == "" || ec.Reader == nil {
		return nil, fmt.Errorf("operation journal reader unavailable")
	}
	var list corev1.ConfigMapList
	if err := ec.Reader.List(ctx, &list, client.InNamespace(ec.JournalNamespace), client.MatchingLabels{journalLabel: "v1"}); err != nil {
		return nil, err
	}
	out := make([]struct {
		CM      corev1.ConfigMap
		Receipt operationReceipt
	}, 0, len(list.Items))
	for i := range list.Items {
		cm := list.Items[i]
		var r operationReceipt
		if err := json.Unmarshal([]byte(cm.Data["receipt"]), &r); err != nil || !r.valid() || cm.Name != receiptName(r) || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil {
			return nil, fmt.Errorf("invalid operation journal %s/%s: %v", cm.Namespace, cm.Name, err)
		}
		out = append(out, struct {
			CM      corev1.ConfigMap
			Receipt operationReceipt
		}{cm, r})
	}
	return out, nil
}

func journalRequire(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.ConfigMap, operationReceipt, error) {
	if ec.JournalNamespace == "" || ec.JournalNamespace == r.PolicyNamespace || ec.Reader == nil || !r.valid() {
		return nil, operationReceipt{}, fmt.Errorf("operation journal unavailable")
	}
	cm := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: receiptName(r)}, cm); err != nil {
		return nil, operationReceipt{}, err
	}
	var recorded operationReceipt
	if err := json.Unmarshal([]byte(cm.Data["receipt"]), &recorded); err != nil {
		return nil, operationReceipt{}, err
	}
	if !recorded.valid() || cm.Name != receiptName(recorded) || cm.Namespace != ec.JournalNamespace || cm.Labels[journalLabel] != "v1" || recorded.TargetUID != r.TargetUID || recorded.PolicyUID != r.PolicyUID || recorded.PolicyName != r.PolicyName || recorded.PolicyNamespace != r.PolicyNamespace || cm.UID == "" || cm.ResourceVersion == "" {
		return nil, operationReceipt{}, fmt.Errorf("operation journal identity mismatch")
	}
	return cm, recorded, nil
}

func receiptAuthority(ctx context.Context, reader client.Reader, r operationReceipt, action model.Action) (*v1alpha1.PhorvexPolicy, error) {
	if reader == nil {
		return nil, fmt.Errorf("authoritative reader unavailable")
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.PolicyName}, pol); err != nil {
		return nil, err
	}
	if string(pol.UID) != r.PolicyUID || pol.DeletionTimestamp != nil || pol.Spec.IsDryRun() {
		return nil, fmt.Errorf("policy identity retired or dry-run")
	}
	enabled := len(pol.Spec.Actions.Enabled) == 0 && (action == model.ActionQuarantine)
	for _, a := range pol.Spec.Actions.Enabled {
		if model.Action(a) == action {
			enabled = true
		}
	}
	if !enabled {
		return nil, fmt.Errorf("action disabled by policy")
	}
	if len(pol.Spec.Selector.MatchLabels) == 0 && len(pol.Spec.Selector.MatchExpressions) == 0 {
		return nil, fmt.Errorf("current policy selector empty")
	}
	sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil {
		return nil, err
	}
	if (r.Kind == "quarantine" || r.Kind == "request-drain" || r.Kind == "adapter-rotate" || r.Version == servingEffectReceiptVersion) && !sel.Matches(labels.Set(r.TargetLabels)) {
		return nil, fmt.Errorf("recorded target outside policy selector")
	}
	ns := &corev1.Namespace{}
	if err := reader.Get(ctx, client.ObjectKey{Name: r.PolicyNamespace}, ns); err != nil {
		return nil, err
	}
	if observation := actuationbrake.Namespace(ns.Annotations); observation.Engaged {
		return nil, fmt.Errorf("namespace dry-run: %s", observation.Cause)
	}
	return pol, nil
}

func warmCurrentScope(pol *v1alpha1.PhorvexPolicy, r operationReceipt, old, promoted *corev1.Pod) error {
	if pol == nil || old == nil || promoted == nil {
		return fmt.Errorf("warm scope unavailable")
	}
	if old.Name != r.OldName || string(old.UID) != r.OldUID || promoted.Name != r.NewName || string(promoted.UID) != r.NewUID {
		return fmt.Errorf("warm pair UID/name changed")
	}
	sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil {
		return err
	}
	for _, p := range []*corev1.Pod{old, promoted} {
		if p.Namespace != r.PolicyNamespace || p.DeletionTimestamp != nil || p.UID == "" || p.Labels[r.GroupKey] != r.GroupValue || !sel.Matches(labels.Set(p.Labels)) {
			return fmt.Errorf("current pod %s outside policy/group scope", p.Name)
		}
	}
	return nil
}

func warmSurvivorScope(pol *v1alpha1.PhorvexPolicy, r operationReceipt, promoted *corev1.Pod) error {
	if pol == nil || promoted == nil || promoted.Name != r.NewName || string(promoted.UID) != r.NewUID || promoted.Namespace != r.PolicyNamespace || promoted.DeletionTimestamp != nil || promoted.Labels[r.GroupKey] != r.GroupValue {
		return fmt.Errorf("survivor identity/scope changed")
	}
	sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil {
		return err
	}
	if !sel.Matches(labels.Set(promoted.Labels)) {
		return fmt.Errorf("survivor outside current policy selector")
	}
	return nil
}

func uidPrecondition(p *corev1.Pod) client.DeleteOption {
	u := types.UID(p.UID)
	rv := p.ResourceVersion
	return client.Preconditions{UID: &u, ResourceVersion: &rv}
}
