/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WarmInferenceSet is the cap#2 warm-pool / LeaderWorkerSet CONTROL-PLANE kind
// (arch §2.4 item 1, §3 cap#2, decisions D11/D12). It owns N warm pods built from
// a golden-image pod template plus a leader-selecting Service, and it is the home
// of D3's PRIMARY per-instance durable-mutation mechanism: create-new-then-cutover.
//
// SCOPE = NAMESPACED: a WarmInferenceSet owns bare pods + a Service that live in a
// workload namespace, and its WarmSwapAction.WarmInferenceSetRef (a name-only
// LocalRef) resolves within the triggering pod's namespace. It is the ONLY
// reference to the warm pool (no embedded WarmPool block on AMTDSpec) so there is a
// single source of truth (arch §2.4 item 1).
//
// TWO CLASSES OF RECONCILE (arch §1.2 / §1.3 invariant):
//   - CLASS-B MAINTENANCE (the routine reconcile): keep N warm pods, exactly one
//     leader carrying the leader label, shadows warmed, the Service selecting the
//     leader. This reconcile MUST NOT self-initiate a swap. It is a readiness loop,
//     exactly like a Deployment keeping replicas Ready.
//   - CLASS-A SWAP (LeaderSwapper.Swap): triggered ONLY by a matched WarmSwap action
//     the matcher selected from a SecurityEvent. The action sets Spec.SwapRequest;
//     the reconciler then progresses Ready->flip->drain->retire->rewarm across
//     reconciles and clears the request. No request => no swap (which is what keeps
//     class-B provably honest, arch §3 / §1.3).
//
// GPU-PENDING NOTE: on KIND there is NO GPU and NO real model server, so
// RequireModelLoaded's "weights GPU-resident + warm-up inference" verification is
// GPU-PENDING. On kind "warm" is realized via the pod Ready condition + MinWarmSeconds
// + an optional model-loaded SIGNAL (a readiness-gate condition OR the
// amtd.r6security.com/model-loaded=true annotation a test/manifest sets). True
// GPU-weights-resident verification is deferred to a real-GPU run. The
// LastSwapDurationMillis recorded here is the CONTROL-PLANE cutover time (flip+drain)
// — explicitly NOT the GPU model-load downtime SLO.

// TrafficCutStrategy enumerates how a swap moves traffic from the old leader to the
// new one (arch §2.4 item 1, design-authored per D12). Only ServiceSelectorSwap is
// realized in the in-tree/bare-pod control plane that runs on kind; the others are
// reserved seams.
//
// +kubebuilder:validation:Enum=EndpointSwap;ServiceSelectorSwap;GatewayWeight;LeaderLabel
type TrafficCutStrategy string

const (
	// TrafficCutEndpointSwap rewrites the leader Service's Endpoints/EndpointSlice
	// directly (reserved seam; not wired in-tree).
	TrafficCutEndpointSwap TrafficCutStrategy = "EndpointSwap"
	// TrafficCutServiceSelectorSwap (DEFAULT) keeps the leader label in the Service
	// selector; the leader pod carries the label and the swap flips the label to the
	// new leader so the Service resolves to it. This is the realized in-tree path.
	TrafficCutServiceSelectorSwap TrafficCutStrategy = "ServiceSelectorSwap"
	// TrafficCutGatewayWeight shifts a Gateway/ingress weight (reserved seam).
	TrafficCutGatewayWeight TrafficCutStrategy = "GatewayWeight"
	// TrafficCutLeaderLabel is the bare leader-label flip without a Service selector
	// (reserved seam; ServiceSelectorSwap is the realized superset).
	TrafficCutLeaderLabel TrafficCutStrategy = "LeaderLabel"
)

// Swap-phase constants for WarmInferenceSetStatus.SwapPhase (the restart-safe
// progressive realization, arch §3).
const (
	// SwapPhaseIdle = no swap in flight (no SwapRequest).
	SwapPhaseIdle = "Idle"
	// SwapPhaseFlipping = a Ready shadow was picked; the leader label is being moved.
	SwapPhaseFlipping = "Flipping"
	// SwapPhaseDraining = the label has moved; in-flight requests are draining for
	// DrainTimeoutSeconds before the old leader is retired.
	SwapPhaseDraining = "Draining"
	// SwapPhaseRetiring = the drain elapsed; the old leader is being deleted.
	SwapPhaseRetiring = "Retiring"
	// SwapPhaseRewarming = the old leader is gone; a replacement shadow is being
	// provisioned back to N by EnsurePool.
	SwapPhaseRewarming = "Rewarming"
)

// Condition type constants on WarmInferenceSetStatus.Conditions.
const (
	// ConditionSwapBlockedNoReadyShadow=True means a SwapRequest is present but NO
	// shadow passes the readiness gate, so the swap is BLOCKED/deferred (the readiness
	// gate is the gate — arch §3). The request is retained; nothing is swapped.
	ConditionSwapBlockedNoReadyShadow = "SwapBlockedNoReadyShadow"
	// ConditionWarmGuaranteeVoid=True means the pool could not maintain N warm shadows
	// (e.g. fewer than the requested replicas exist/are warm), so the warm guarantee is
	// temporarily void (observability).
	ConditionWarmGuaranteeVoid = "WarmGuaranteeVoid"
)

// ModelLoadedAnnotation is the kind-realization signal for RequireModelLoaded. A
// test/manifest sets it to "true" on a warm pod to assert the (GPU-PENDING) model
// weights are resident. On real GPU this is replaced by a DCGM/model-server probe.
const ModelLoadedAnnotation = "amtd.r6security.com/model-loaded"

// LeaderRoleShadow / LeaderRoleLeader are the pod-role label values the pool stamps
// alongside the (configurable) leader label so the reconciler can distinguish a
// leader from a shadow deterministically.
const (
	// PoolPodLabel marks a pod as belonging to a given WarmInferenceSet (value = set
	// name). Used to list the pool's pods.
	PoolPodLabel = "amtd.r6security.com/warm-inference-set"
)

// WarmReadyGate is the strict operational definition of "warm" (arch §2.4 / cap#2,
// the load-bearing answer to the false-readiness trap, D11). A shadow is WARM iff:
//   - its pod Ready condition is True (probe), AND
//   - at least MinWarmSeconds have elapsed since it became Ready, AND
//   - RequireModelLoaded is satisfied (GPU-PENDING: on kind via the model-loaded
//     signal, on real GPU via weights-resident verification).
type WarmReadyGate struct {
	// +kubebuilder:validation:Optional
	// Probe is the readiness probe the warm pods carry (golden-image model-server
	// health). On kind a TCP/exec/httpGet probe drives the pod Ready condition that
	// the gate reads; nil means rely on the pod's own template probe.
	Probe *corev1.Probe `json:"probe,omitempty"`

	// +kubebuilder:validation:Optional
	// MinWarmSeconds is the minimum seconds a shadow must have been Ready before it
	// counts as warm (anti-false-readiness dwell). nil/0 => no dwell requirement.
	MinWarmSeconds *int `json:"minWarmSeconds,omitempty"`

	// +kubebuilder:validation:Optional
	// RequireModelLoaded gates on model weights being resident. Code default TRUE (set
	// via EffectiveRequireModelLoaded()). GPU-PENDING: on kind this is satisfied by the
	// model-loaded signal (the amtd.r6security.com/model-loaded=true annotation or a
	// readiness-gate condition); true GPU-weights-resident verification is deferred.
	RequireModelLoaded *bool `json:"requireModelLoaded,omitempty"`
}

// WarmSwapRequest is the restart-safe swap REQUEST the WarmSwap action sets on the
// WarmInferenceSet (arch §3 progressive realization). Its presence is the ONLY thing
// that lets the reconciler initiate a swap — class-B maintenance never sets it, so no
// request => no swap.
type WarmSwapRequest struct {
	// +kubebuilder:validation:Required
	// RequestID dedupes a swap request (e.g. the triggering SecurityEvent name) so a
	// re-reconcile of the same event does not start a second swap.
	RequestID string `json:"requestID"`

	// +kubebuilder:validation:Optional
	// RequestedAt is when the action set the request (audit).
	RequestedAt metav1.Time `json:"requestedAt,omitempty"`

	// +kubebuilder:validation:Optional
	// DrainTimeoutSeconds overrides Spec.DrainTimeoutSeconds for this swap (from the
	// WarmSwapAction.DrainTimeoutSeconds). nil => use the spec/default.
	DrainTimeoutSeconds *int64 `json:"drainTimeoutSeconds,omitempty"`
}

// WarmInferenceSetSpec is the desired state of a warm pool (arch §2.4 item 1).
type WarmInferenceSetSpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// Replicas is the number of warm pods (1 leader + N-1 shadows) to maintain. Min=1;
	// code default 2 via EffectiveReplicas() (FLAGGED design-authored, D11). nil => 2.
	Replicas *int `json:"replicas,omitempty"`

	// +kubebuilder:validation:Required
	// Template is the golden warm-pod template every warm pod is built from (carries
	// the golden image / model-server). The pool stamps the pool + leader labels on
	// top of Template.Labels.
	Template corev1.PodTemplateSpec `json:"template"`

	// +kubebuilder:validation:Optional
	// WarmReadyGate is the strict definition of "warm" (probe + MinWarmSeconds +
	// RequireModelLoaded). Zero-value => Ready-only + RequireModelLoaded default true.
	WarmReadyGate WarmReadyGate `json:"warmReadyGate,omitempty"`

	// +kubebuilder:validation:Optional
	// TrafficCutStrategy selects how a swap moves traffic. Code default
	// ServiceSelectorSwap via EffectiveTrafficCutStrategy() (design-authored, D12).
	TrafficCutStrategy TrafficCutStrategy `json:"trafficCutStrategy,omitempty"`

	// +kubebuilder:validation:Optional
	// LeaderLabelKey is the label key the leader-selecting Service selects on. Code
	// default "amtd.r6security.com/leader" via EffectiveLeaderLabelKey().
	LeaderLabelKey string `json:"leaderLabelKey,omitempty"`

	// +kubebuilder:validation:Optional
	// LeaderLabelValue is the label value the leader carries (and the Service selects).
	// Code default "active" via EffectiveLeaderLabelValue().
	LeaderLabelValue string `json:"leaderLabelValue,omitempty"`

	// +kubebuilder:validation:Optional
	// ServiceName is the name of the leader-selecting Service the pool owns. Code
	// default "<wis-name>-leader" via EffectiveServiceName().
	ServiceName string `json:"serviceName,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// ServicePort is the port the leader Service exposes. Code default 8000 via
	// EffectiveServicePort().
	ServicePort *int32 `json:"servicePort,omitempty"`

	// +kubebuilder:validation:Optional
	// DrainTimeoutSeconds is how long in-flight requests drain after the leader flips
	// before the old leader is retired. Code default 30 (reuse NIM grace) via
	// EffectiveDrainTimeoutSeconds(). nil => 30.
	DrainTimeoutSeconds *int64 `json:"drainTimeoutSeconds,omitempty"`

	// +kubebuilder:validation:Optional
	// SwapRequest, when set, requests a swap (restart-safe progressive realization,
	// arch §3). Set ONLY by the WarmSwap action; class-B maintenance never sets it.
	// The reconciler clears it on swap completion.
	SwapRequest *WarmSwapRequest `json:"swapRequest,omitempty"`
}

// WarmInferenceSetStatus is the observability + restart-safe swap-progress surface.
type WarmInferenceSetStatus struct {
	// +kubebuilder:validation:Optional
	// ObservedGeneration is the .metadata.generation the Status reflects.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +kubebuilder:validation:Optional
	// ActiveLeader is the name of the pod currently carrying the leader label (the pod
	// the Service resolves to). Empty until a leader is elected.
	ActiveLeader string `json:"activeLeader,omitempty"`

	// +kubebuilder:validation:Optional
	// ReadyShadows is the number of non-leader pods that currently pass the readiness
	// gate (warm and swap-eligible).
	ReadyShadows int `json:"readyShadows,omitempty"`

	// +kubebuilder:validation:Optional
	// LastSwapDurationMillis is the CONTROL-PLANE cutover time of the last completed
	// swap (flip + drain), in milliseconds. GPU-PENDING: this is explicitly NOT the GPU
	// model-load downtime SLO (400s->15s / p50<=5s / p95<=15s are real-GPU runs).
	LastSwapDurationMillis int64 `json:"lastSwapDurationMillis,omitempty"`

	// +kubebuilder:validation:Optional
	// SwapPhase is the restart-safe progress of an in-flight swap
	// (Idle|Flipping|Draining|Retiring|Rewarming).
	SwapPhase string `json:"swapPhase,omitempty"`

	// +kubebuilder:validation:Optional
	// CurrentReplicas is the number of pool pods that currently exist (any state).
	CurrentReplicas int `json:"currentReplicas,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// Conditions carries SwapBlockedNoReadyShadow / WarmGuaranteeVoid.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=wis
// +kubebuilder:printcolumn:name="Leader",type=string,JSONPath=`.status.activeLeader`
// +kubebuilder:printcolumn:name="ReadyShadows",type=integer,JSONPath=`.status.readyShadows`
// +kubebuilder:printcolumn:name="SwapPhase",type=string,JSONPath=`.status.swapPhase`
// +kubebuilder:printcolumn:name="LastSwapMillis",type=integer,JSONPath=`.status.lastSwapDurationMillis`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// WarmInferenceSet is the Schema for the warminferencesets API (cap#2, D11/D12).
type WarmInferenceSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WarmInferenceSetSpec   `json:"spec,omitempty"`
	Status WarmInferenceSetStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// WarmInferenceSetList contains a list of WarmInferenceSet.
type WarmInferenceSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WarmInferenceSet `json:"items"`
}

// ---------------------------------------------------------------------------
// CODE DEFAULT HELPERS (FLAGGED via code, NOT CRD-default markers, per the
// orchestrator brief). A nil/zero field resolves to the design-authored default
// here so callers never special-case nil.
// ---------------------------------------------------------------------------

// EffectiveReplicas returns Spec.Replicas, defaulting to 2 (flagged, D11).
func (w *WarmInferenceSet) EffectiveReplicas() int {
	if w.Spec.Replicas != nil && *w.Spec.Replicas >= 1 {
		return *w.Spec.Replicas
	}
	return 2
}

// EffectiveRequireModelLoaded returns WarmReadyGate.RequireModelLoaded, default TRUE.
func (w *WarmInferenceSet) EffectiveRequireModelLoaded() bool {
	if w.Spec.WarmReadyGate.RequireModelLoaded != nil {
		return *w.Spec.WarmReadyGate.RequireModelLoaded
	}
	return true
}

// EffectiveMinWarmSeconds returns WarmReadyGate.MinWarmSeconds, default 0.
func (w *WarmInferenceSet) EffectiveMinWarmSeconds() int {
	if w.Spec.WarmReadyGate.MinWarmSeconds != nil && *w.Spec.WarmReadyGate.MinWarmSeconds > 0 {
		return *w.Spec.WarmReadyGate.MinWarmSeconds
	}
	return 0
}

// EffectiveTrafficCutStrategy returns Spec.TrafficCutStrategy, default
// ServiceSelectorSwap (design-authored, D12).
func (w *WarmInferenceSet) EffectiveTrafficCutStrategy() TrafficCutStrategy {
	if w.Spec.TrafficCutStrategy != "" {
		return w.Spec.TrafficCutStrategy
	}
	return TrafficCutServiceSelectorSwap
}

// EffectiveLeaderLabelKey returns Spec.LeaderLabelKey, default
// "amtd.r6security.com/leader".
func (w *WarmInferenceSet) EffectiveLeaderLabelKey() string {
	if w.Spec.LeaderLabelKey != "" {
		return w.Spec.LeaderLabelKey
	}
	return "amtd.r6security.com/leader"
}

// EffectiveLeaderLabelValue returns Spec.LeaderLabelValue, default "active".
func (w *WarmInferenceSet) EffectiveLeaderLabelValue() string {
	if w.Spec.LeaderLabelValue != "" {
		return w.Spec.LeaderLabelValue
	}
	return "active"
}

// EffectiveServiceName returns Spec.ServiceName, default "<name>-leader".
func (w *WarmInferenceSet) EffectiveServiceName() string {
	if w.Spec.ServiceName != "" {
		return w.Spec.ServiceName
	}
	return w.Name + "-leader"
}

// EffectiveServicePort returns Spec.ServicePort, default 8000.
func (w *WarmInferenceSet) EffectiveServicePort() int32 {
	if w.Spec.ServicePort != nil && *w.Spec.ServicePort >= 1 {
		return *w.Spec.ServicePort
	}
	return 8000
}

// EffectiveDrainTimeoutSeconds returns Spec.DrainTimeoutSeconds, default 30 (reuse
// the NIM grace).
func (w *WarmInferenceSet) EffectiveDrainTimeoutSeconds() int64 {
	if w.Spec.DrainTimeoutSeconds != nil && *w.Spec.DrainTimeoutSeconds >= 0 {
		return *w.Spec.DrainTimeoutSeconds
	}
	return 30
}

func init() {
	SchemeBuilder.Register(&WarmInferenceSet{}, &WarmInferenceSetList{})
}
