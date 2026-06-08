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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AdaptiveMovingTargetDefenseSpec defines the desired state of AdaptiveMovingTargetDefense
type AdaptiveMovingTargetDefenseSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:Required
	// PodSelector is the selector of the Kubernetes Pods on which the user desires to enable moving target defense
	PodSelector map[string]string `json:"podSelector"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// Define strategy that maps actions to security events (based on the security event fields)
	Strategy []ResponseStrategy `json:"strategy"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Exact
	// MatcherMode gates the relaxed (scored) matcher. In "Exact" (the default) any
	// Rule.Match / Rule.ScoreThreshold clause is IGNORED — preserving today's exact
	// {Type,ThreatLevel,Source} behavior byte-for-byte — and a MatcherModeWarning
	// Status condition warns that scored clauses are inert. In "Scored" the matcher
	// additionally evaluates Match / ScoreThreshold against the SecurityEvent spec.
	// Enum (Exact;Scored) is declared on the MatcherMode type.
	MatcherMode MatcherMode `json:"matcherMode,omitempty"`

	// +kubebuilder:validation:Optional
	// InferenceRotation is the embedded (Phase 1) rotation mutation overlay +
	// rotation/adaptive policy block (D1 HYBRID, arch §2.4). nil ⇒ today's
	// behavior (a Rotate degrades to a pure cold reschedule). It is the policy
	// surface that RotateAction.PolicyRef resolves to.
	InferenceRotation *InferenceRotationSpec `json:"inferenceRotation,omitempty"`

	// +kubebuilder:validation:Optional
	// Baseline is the embedded (Phase 5) cap#6 signed-baseline digest-pin block
	// (D1 HYBRID, arch §2.4 item 3 / §2.4 BaselineSpec, D6/D6g). It carries
	// REFERENCES only (pinned ImageDigests[], the SignaturePolicy refs, an optional
	// PodSpecSnapshotRef + a DriftPolicy) — never trust-root secret material. Its
	// Baseline.BaselineRef may point at a standalone WorkloadBaseline that is then
	// the source of truth for the pins/SignaturePolicy. nil ⇒ no baseline drift
	// self-heal for this AMTD. A matched Regenerate action resolves its
	// RegenerateAction.BaselineRef to a WorkloadBaseline; this embedded block is the
	// in-AMTD alternative policy home (D1 precedence: a referenced CR wins).
	Baseline *BaselineSpec `json:"baseline,omitempty"`

	// +kubebuilder:validation:Optional
	// NodeRotationPolicy is the embedded (Phase 6) cap#7 SCHEDULED node-rotation
	// cadence block (arch §2.4, D25g). DEFAULT-OFF: nil ⇒ panic/event-driven node
	// rotation only (no scheduled cadence), because node rotation is far costlier than
	// pod rotation. Per Rule #1 it is NOT a hidden timer — it only tunes cadence; the
	// scheduled rotation is still a {Type:'timed',Source:'TimeBasedTrigger'} event
	// matched to a NodeRotate action. It also carries the MaxConcurrentNodes+Stagger
	// no-mass-eviction ceiling the NodeRotationReconciler honors.
	NodeRotationPolicy *NodeRotationPolicy `json:"nodeRotationPolicy,omitempty"`

	// +kubebuilder:validation:Optional
	// NodeRotateTrust is the per-AMTD D26 trust gate for the NodeRotate action (the
	// cluster-DoS lever): a trusted-Source allowlist + a ThreatLevel floor +
	// human-approval-for-Delete. nil ⇒ the code defaults apply (allowlist
	// {KubeArmorIntegrator,FalcoIntegrator}; floor {high,critical}; Delete needs
	// approval) — the gate is ALWAYS on, never silently bypassed (D26).
	NodeRotateTrust *NodeRotateTrustPolicy `json:"nodeRotateTrust,omitempty"`
}

// MatcherMode selects how strategy rules are matched against a SecurityEvent.
// +kubebuilder:validation:Enum=Exact;Scored
type MatcherMode string

const (
	// MatcherModeExact is the default: only the exact 3-string projection
	// {Type,ThreatLevel,Source} is evaluated; any Match/ScoreThreshold is inert.
	MatcherModeExact MatcherMode = "Exact"
	// MatcherModeScored additionally evaluates Match/ScoreThreshold against the event spec.
	MatcherModeScored MatcherMode = "Scored"
)

type DisableAction struct{}
type DeleteAction struct{}
type QuarantineAction struct{}
type Debugger struct {

	// +kubebuilder:validation:Optional
	Name string `json:"name,omitempty"`

	// +kubebuilder:validation:Required
	Image string `json:"image,omitempty"`

	// +kubebuilder:validation:Optional
	Terminal bool `json:"terminal,omitempty"`
}

// CustomContainerPort represents a network port in a single EphemeralContainer.
type CustomContainerPort struct {
	// Number of port to expose on the pod's IP address.
	// This must be a valid port number, 0 < x < 65536.
	ContainerPort int32 `json:"containerPort"`

	// What host IP to bind the external port to.
	HostIP string `json:"hostIP,omitempty"`

	// Number of port to expose on the host.
	// If specified, this must be a valid port number, 0 < x < 65536.
	HostPort *int32 `json:"hostPort,omitempty"`

	// If specified, this must be an IANA_SVC_NAME and unique within the pod.
	// Name for the port that can be referred to by services.
	Name string `json:"name,omitempty"`

	// Protocol for port. Must be UDP, TCP, or SCTP. Defaults to "TCP".
	// +kubebuilder:validation:Enum="TCP";"UDP";"SCTP"
	// +kubebuilder:default:="TCP"
	Protocol string `json:"protocol,omitempty"`
}

// CustomAction defines the custom action with an overridden Ports field.
// controller-gen v0.19 generates for EphemeralContainers a protocol with an allOf field with two defaults which throws an error under k8@1.30.4
type CustomAction struct {
	// EphemeralContainer Fields except Ports for correct json representation.
	// Ports are forrbiden in EphemeralContainers. In this scenario Ports are a CustomContainerPort type.

	// Name of the ephemeral container specified as a DNS_LABEL.
	// This name must be unique among all containers, init containers and ephemeral containers.
	Name string `json:"name" protobuf:"bytes,1,opt,name=name"`
	// Container image name.
	// More info: https://kubernetes.io/docs/concepts/containers/images
	Image string `json:"image,omitempty" protobuf:"bytes,2,opt,name=image"`
	// Entrypoint array. Not executed within a shell.
	// The image's ENTRYPOINT is used if this is not provided.
	// Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
	// cannot be resolved, the reference in the input string will be unchanged. Double $$ are reduced
	// to a single $, which allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will
	// produce the string literal "$(VAR_NAME)". Escaped references will never be expanded, regardless
	// of whether the variable exists or not. Cannot be updated.
	// More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
	// +optional
	// +listType=atomic
	Command []string `json:"command,omitempty" protobuf:"bytes,3,rep,name=command"`
	// Arguments to the entrypoint.
	// The image's CMD is used if this is not provided.
	// Variable references $(VAR_NAME) are expanded using the container's environment. If a variable
	// cannot be resolved, the reference in the input string will be unchanged. Double $$ are reduced
	// to a single $, which allows for escaping the $(VAR_NAME) syntax: i.e. "$$(VAR_NAME)" will
	// produce the string literal "$(VAR_NAME)". Escaped references will never be expanded, regardless
	// of whether the variable exists or not. Cannot be updated.
	// More info: https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#running-a-command-in-a-shell
	// +optional
	// +listType=atomic
	Args []string `json:"args,omitempty" protobuf:"bytes,4,rep,name=args"`
	// Container's working directory.
	// If not specified, the container runtime's default will be used, which
	// might be configured in the container image.
	// Cannot be updated.
	// +optional
	WorkingDir string `json:"workingDir,omitempty" protobuf:"bytes,5,opt,name=workingDir"`
	// List of sources to populate environment variables in the container.
	// The keys defined within a source must be a C_IDENTIFIER. All invalid keys
	// will be reported as an event when the container is starting. When a key exists in multiple
	// sources, the value associated with the last source will take precedence.
	// Values defined by an Env with a duplicate key will take precedence.
	// Cannot be updated.
	// +optional
	// +listType=atomic
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty" protobuf:"bytes,19,rep,name=envFrom"`
	// List of environment variables to set in the container.
	// Cannot be updated.
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=name
	Env []corev1.EnvVar `json:"env,omitempty" patchStrategy:"merge" patchMergeKey:"name" protobuf:"bytes,7,rep,name=env"`
	// Resources are not allowed for ephemeral containers. Ephemeral containers use spare resources
	// already allocated to the pod.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty" protobuf:"bytes,8,opt,name=resources"`
	// Resources resize policy for the container.
	// +featureGate=InPlacePodVerticalScaling
	// +optional
	// +listType=atomic
	ResizePolicy []corev1.ContainerResizePolicy `json:"resizePolicy,omitempty" protobuf:"bytes,23,rep,name=resizePolicy"`
	// Restart policy for the container to manage the restart behavior of each
	// container within a pod.
	// This may only be set for init containers. You cannot set this field on
	// ephemeral containers.
	// +featureGate=SidecarContainers
	// +optional
	RestartPolicy *corev1.ContainerRestartPolicy `json:"restartPolicy,omitempty" protobuf:"bytes,24,opt,name=restartPolicy,casttype=ContainerRestartPolicy"`
	// Pod volumes to mount into the container's filesystem. Subpath mounts are not allowed for ephemeral containers.
	// Cannot be updated.
	// +optional
	// +patchMergeKey=mountPath
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=mountPath
	VolumeMounts []corev1.VolumeMount `json:"volumeMounts,omitempty" patchStrategy:"merge" patchMergeKey:"mountPath" protobuf:"bytes,9,rep,name=volumeMounts"`
	// volumeDevices is the list of block devices to be used by the container.
	// +patchMergeKey=devicePath
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=devicePath
	// +optional
	VolumeDevices []corev1.VolumeDevice `json:"volumeDevices,omitempty" patchStrategy:"merge" patchMergeKey:"devicePath" protobuf:"bytes,21,rep,name=volumeDevices"`
	// Probes are not allowed for ephemeral containers.
	// +optional
	LivenessProbe *corev1.Probe `json:"livenessProbe,omitempty" protobuf:"bytes,10,opt,name=livenessProbe"`
	// Probes are not allowed for ephemeral containers.
	// +optional
	ReadinessProbe *corev1.Probe `json:"readinessProbe,omitempty" protobuf:"bytes,11,opt,name=readinessProbe"`
	// Probes are not allowed for ephemeral containers.
	// +optional
	StartupProbe *corev1.Probe `json:"startupProbe,omitempty" protobuf:"bytes,22,opt,name=startupProbe"`
	// Lifecycle is not allowed for ephemeral containers.
	// +optional
	Lifecycle *corev1.Lifecycle `json:"lifecycle,omitempty" protobuf:"bytes,12,opt,name=lifecycle"`
	// Optional: Path at which the file to which the container's termination message
	// will be written is mounted into the container's filesystem.
	// Message written is intended to be brief final status, such as an assertion failure message.
	// Will be truncated by the node if greater than 4096 bytes. The total message length across
	// all containers will be limited to 12kb.
	// Defaults to /dev/termination-log.
	// Cannot be updated.
	// +optional
	TerminationMessagePath string `json:"terminationMessagePath,omitempty" protobuf:"bytes,13,opt,name=terminationMessagePath"`
	// Indicate how the termination message should be populated. File will use the contents of
	// terminationMessagePath to populate the container status message on both success and failure.
	// FallbackToLogsOnError will use the last chunk of container log output if the termination
	// message file is empty and the container exited with an error.
	// The log output is limited to 2048 bytes or 80 lines, whichever is smaller.
	// Defaults to File.
	// Cannot be updated.
	// +optional
	TerminationMessagePolicy corev1.TerminationMessagePolicy `json:"-"` /* 129-byte string literal not displayed */
	// Image pull policy.
	// One of Always, Never, IfNotPresent.
	// Defaults to Always if :latest tag is specified, or IfNotPresent otherwise.
	// Cannot be updated.
	// More info: https://kubernetes.io/docs/concepts/containers/images#updating-images
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty" protobuf:"bytes,14,opt,name=imagePullPolicy,casttype=PullPolicy"`
	// Optional: SecurityContext defines the security options the ephemeral container should be run with.
	// If set, the fields of SecurityContext override the equivalent fields of PodSecurityContext.
	// +optional
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty" protobuf:"bytes,15,opt,name=securityContext"`

	// Ports are not allowed for ephemeral containers.
	// +optional
	// +patchMergeKey=containerPort
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=containerPort
	// +listMapKey=protocol
	Ports []CustomContainerPort `json:"ports,omitempty" patchStrategy:"merge" patchMergeKey:"containerPort" protobuf:"bytes,6,rep,name=ports"`

	// Whether this container should allocate a buffer for stdin in the container runtime. If this
	// is not set, reads from stdin in the container will always result in EOF.
	// Default is false.
	// +optional
	Stdin bool `json:"stdin,omitempty" protobuf:"varint,16,opt,name=stdin"`
	// Whether the container runtime should close the stdin channel after it has been opened by
	// a single attach. When stdin is true the stdin stream will remain open across multiple attach
	// sessions. If stdinOnce is set to true, stdin is opened on container start, is empty until the
	// first client attaches to stdin, and then remains open and accepts data until the client disconnects,
	// at which time stdin is closed and remains closed until the container is restarted. If this
	// flag is false, a container processes that reads from stdin will never receive an EOF.
	// Default is false
	// +optional
	StdinOnce bool `json:"stdinOnce,omitempty" protobuf:"varint,17,opt,name=stdinOnce"`
	// Whether this container should allocate a TTY for itself, also requires 'stdin' to be true.
	// Default is false.
	// +optional
	TTY bool `json:"tty,omitempty" protobuf:"varint,18,opt,name=tty"`
	// If set, the name of the container from PodSpec that this ephemeral container targets.
	// The ephemeral container will be run in the namespaces (IPC, PID, etc) of this container.
	// If not set then the ephemeral container uses the namespaces configured in the Pod spec.
	//
	// The container runtime must implement support for this feature. If the runtime does not
	// support namespace targeting then the result of setting this field is undefined.
	// +optional
	TargetContainerName string `json:"targetContainerName,omitempty" protobuf:"bytes,2,opt,name=targetContainerName"`
}

// +kubebuilder:validation:MaxProperties=1
type AMTDAction struct {
	Disable      *DisableAction    `json:"disable,omitempty"`
	Delete       *DeleteAction     `json:"delete,omitempty"`
	Quarantine   *QuarantineAction `json:"quarantine,omitempty"`
	Debugger     *Debugger         `json:"debugger,omitempty"`
	CustomAction *CustomAction     `json:"customAction,omitempty"`

	// Rotate is the NEW (caps #1/#3) mutating-rotation action. In Phase 0 the Rotate
	// branch reproduces today's cold reschedule (annotate-then-delete) so the
	// {type:'timed', source:'TimeBasedTrigger'} -> {rotate:{}} strategy works
	// end-to-end through the CRD; the image/env/gpu/memory/RAG mutation set is a
	// later phase.
	// +kubebuilder:validation:Optional
	Rotate *RotateAction `json:"rotate,omitempty"`

	// WarmSwap is the NEW (cap #2) leader->warm-shadow cutover action. TYPE-ONLY in
	// Phase 0: the dispatch recognizes it but logs "not yet implemented" and no-ops.
	// +kubebuilder:validation:Optional
	WarmSwap *WarmSwapAction `json:"warmSwap,omitempty"`

	// Regenerate is the NEW (cap #6) restore-from-signed-baseline action. TYPE-ONLY in
	// Phase 0: the dispatch recognizes it but logs "not yet implemented" and no-ops.
	// +kubebuilder:validation:Optional
	Regenerate *RegenerateAction `json:"regenerate,omitempty"`

	// NodeRotate is the NEW (cap #7) panic-move-to-clean-node action. TYPE-ONLY in
	// Phase 0: the dispatch recognizes it but logs "not yet implemented" and no-ops.
	// +kubebuilder:validation:Optional
	NodeRotate *NodeRotateAction `json:"nodeRotate,omitempty"`
}

// LocalRef is a name-only reference to another namespaced object (e.g. a
// WarmInferenceSet or WorkloadBaseline) in the same namespace.
type LocalRef struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// LocalPolicyRef references an embedded InferenceRotation block on the matched
// AMTD or a standalone ContextMutationPolicy. Phase 0 carries the type only.
type LocalPolicyRef struct {
	// +kubebuilder:validation:Optional
	// Kind selects which policy surface the Name refers to (e.g.
	// "InferenceRotation" or "ContextMutationPolicy"). Empty defaults to the
	// matched AMTD's InferenceRotation.
	Kind string `json:"kind,omitempty"`

	// +kubebuilder:validation:Optional
	Name string `json:"name,omitempty"`
}

// InferenceRotationOverlay is an inline image/env/gpu overlay applied for
// panic-only mutations (e.g. gpuResource:'0'). Phase 0 carries the type only;
// no field here is interpreted yet.
type InferenceRotationOverlay struct {
	// +kubebuilder:validation:Optional
	// Image is the (golden) image digest/ref to rotate to.
	Image string `json:"image,omitempty"`

	// +kubebuilder:validation:Optional
	// EnvPatch is a list of environment variables to set on rotation
	// (e.g. RUNTIME_MODE=SECURE).
	// +listType=atomic
	EnvPatch []corev1.EnvVar `json:"envPatch,omitempty"`

	// +kubebuilder:validation:Optional
	// GPUResource is the quantity to set for the GPU resource on rotation
	// (e.g. '0' for DropToZero quarantine). String to avoid quantity
	// canonicalization in Phase 0.
	GPUResource string `json:"gpuResource,omitempty"`
}

// DrainPolicy controls co-tenant draining during a node rotation. nil on
// NodeRotateAction means relocate the targeted pod only, with no co-tenant
// drain. Phase 0 carries the type only.
type DrainPolicy struct {
	// +kubebuilder:validation:Optional
	// DrainCoTenants opts into Eviction-API draining of co-resident pods
	// (PDB-honoring). Default false.
	DrainCoTenants bool `json:"drainCoTenants,omitempty"`

	// +kubebuilder:validation:Optional
	// GracePeriodSeconds is the eviction grace period; nil reuses the NIM 30s grace.
	GracePeriodSeconds *int64 `json:"gracePeriodSeconds,omitempty"`
}

// RotateAction subsumes the image/env/gpu/key/RAG mutation set. Its fields mirror
// InferenceRotationSpec so a Rotate action and Spec.InferenceRotation resolve through
// the SAME MutationApplier (later phase). With all fields nil, RotateAction degrades
// to today's cold delete, which is exactly the Phase 0 behavior.
type RotateAction struct {
	// +kubebuilder:validation:Optional
	// PolicyRef references an AMTDSpec.InferenceRotation block or a
	// ContextMutationPolicy; nil resolves to the matched AMTD's InferenceRotation.
	PolicyRef *LocalPolicyRef `json:"policyRef,omitempty"`

	// +kubebuilder:validation:Optional
	// Overrides is an inline image/env/gpu overlay for panic-only mutations.
	Overrides *InferenceRotationOverlay `json:"overrides,omitempty"`
}

// InferenceRotationSpec is the embedded (Phase 1) home of the rotation mutation
// overlay and the rotation/adaptive policies (D1 HYBRID, arch §2.4). It is
// referenced by RotateAction.PolicyRef (Kind empty/"InferenceRotation" resolves
// here) and resolves through the SAME MutationApplier as RotateAction.Overrides.
//
// PHASE 1 INTERPRETS ONLY the image/env/gpu-quantity overlay
// (ContainerName/GoldenImage/EnvPatch/GPUResource) plus the storm-guard knobs on
// RotationPolicy.MinInterval and AdaptiveRotation.MaxFailedRotations. The
// GPU-shuffle / encrypted-memory / RAG-sandbox / endpoint / confidential-computing
// sub-policies (Phase 3+) are intentionally NOT declared here so they stay
// honestly uninterpreted. Field names mirror arch §2.4.
type InferenceRotationSpec struct {
	// +kubebuilder:validation:Optional
	// ContainerName selects the target container for the image/env/gpu overlay.
	// Empty selects the first (or only) container. (Phase 1.)
	ContainerName string `json:"containerName,omitempty"`

	// +kubebuilder:validation:Optional
	// GoldenImage is the image digest/ref to rotate the target container to
	// (verbatim values trace ADA Listing 1, e.g. nvcr.io/nim/secure-nim:latest).
	// (Phase 1.)
	GoldenImage string `json:"goldenImage,omitempty"`

	// +kubebuilder:validation:Optional
	// EnvPatch sets/overwrites environment variables on the target container by
	// Name (e.g. RUNTIME_MODE=SECURE). (Phase 1.)
	// +listType=atomic
	EnvPatch []corev1.EnvVar `json:"envPatch,omitempty"`

	// +kubebuilder:validation:Optional
	// GPUResource is the nvidia.com/gpu limit quantity as a string ("0" =
	// DropToZero quarantine). The resource name is fixed to nvidia.com/gpu in
	// Phase 1 (GPUShufflePolicy.ResourceName override is Phase 3). (Phase 1.)
	GPUResource string `json:"gpuResource,omitempty"`

	// +kubebuilder:validation:Optional
	// RotationPolicy carries the cadence FLOOR (MinInterval) and the
	// concurrency cap. Phase 1 uses only MinInterval (and declares
	// MaxConcurrentRotations; enforcement is Phase 2).
	RotationPolicy *RotationPolicy `json:"rotationPolicy,omitempty"`

	// +kubebuilder:validation:Optional
	// AdaptiveRotation carries the crash-loop failure ceiling
	// (MaxFailedRotations). Phase 1 uses only MaxFailedRotations.
	AdaptiveRotation *AdaptiveRotationPolicy `json:"adaptiveRotation,omitempty"`
}

// RotationPolicy carries the cadence controls (cap #4, arch §2.4). PHASE 1 used
// only the anti-flap FLOOR (MinInterval) and DECLARED the concurrency cap. PHASE
// 2 ADDS the cadence-period + jitter band + distribution + entropy + stagger
// fields (all optional/pointer; nil reproduces today's deterministic cadence
// bit-for-bit) and ENFORCES MaxConcurrentRotations in the executor.
//
// MinInterval (the anti-flap storm FLOOR / minimum gap between rotations) is
// DISTINCT from BaseInterval (the cadence PERIOD the single owner emits on): a
// 60m BaseInterval cadence still honors the 60s MinInterval floor that suppresses
// a re-fire storm. The 5m BaseInterval floor (D9) is enforced in the
// effective-policy code (effectiveBaseInterval clamps up + records a
// BaseIntervalFloored Status condition); the jitter bounds
// (0<=JitterMinPercent<=JitterMaxPercent<=100) are enforced apiserver-side by the
// CEL XValidation rule below (a cert-free realization of the D9 ":9443 webhook" —
// see the deviation note on JitterMinPercent).
//
// +kubebuilder:validation:XValidation:rule="!has(self.jitterMinPercent) || !has(self.jitterMaxPercent) || (self.jitterMinPercent >= 0 && self.jitterMaxPercent <= 100 && self.jitterMinPercent <= self.jitterMaxPercent)",message="jitter bounds must satisfy 0<=jitterMinPercent<=jitterMaxPercent<=100"
type RotationPolicy struct {
	// +kubebuilder:validation:Optional
	// MinInterval is the anti-flap FLOOR: a rotation is skipped if it would fire
	// sooner than MinInterval after Status.LastRotationTime. nil defaults to 60s
	// in code (effectiveMinInterval), keeping nil == today's behavior and
	// avoiding a CRD-default round-trip. (Phase 1.) This is the storm guard, NOT
	// the cadence period (see BaseInterval).
	MinInterval *metav1.Duration `json:"minInterval,omitempty"`

	// +kubebuilder:validation:Optional
	// MaxConcurrentRotations bounds concurrent rotations under this AMTD; nil means
	// unlimited (today's behavior). DECLARED in Phase 1; ENFORCED in Phase 2: the
	// Rotate executor counts pods carrying the in-progress annotation for this
	// AMTD's PodSelector and DEFERS (skip + RotationThrottled condition) a rotation
	// that would exceed the cap (D24). (Phase 2.)
	MaxConcurrentRotations *int `json:"maxConcurrentRotations,omitempty"`

	// +kubebuilder:validation:Optional
	// BaseInterval is the cadence PERIOD R (the mean rotation interval the single
	// cadence owner emits on, D9). nil defaults to 60m in code
	// (effectiveBaseInterval, the AMTD-AI §3.2 verbatim default), keeping nil ==
	// today's behavior without a CRD-default round-trip. A HARD FLOOR of 5m (D9, a
	// flagged design proposal) is enforced in effectiveBaseInterval: a sub-5m value
	// is clamped UP to 5m and a BaseIntervalFloored Status condition is recorded
	// (availability-safe clamp + honest/observable condition). The 5m floor is NOT a
	// CEL rule because metav1.Duration serializes as a Go duration string (not a
	// number) and is not portably comparable in CEL. (Phase 2.)
	BaseInterval *metav1.Duration `json:"baseInterval,omitempty"`

	// +kubebuilder:validation:Optional
	// JitterMinPercent is the LOWER endpoint of the symmetric +/- jitter band as a
	// percentage of BaseInterval (D10, the paper "10-30%" band). nil defaults to 10
	// in code. Per cycle the scheduler draws a magnitude m in
	// [JitterMinPercent,JitterMaxPercent]/100 and a symmetric sign, so the effective
	// interval = BaseInterval*(1 +/- m). JitterMin==JitterMax==0 (or both nil)
	// reproduces today's deterministic cadence bit-for-bit. Apiserver-validated
	// bounds: 0<=JitterMinPercent<=JitterMaxPercent<=100 (CEL rule on the struct).
	// (Phase 2.)
	JitterMinPercent *int `json:"jitterMinPercent,omitempty"`

	// +kubebuilder:validation:Optional
	// JitterMaxPercent is the UPPER endpoint of the symmetric +/- jitter band as a
	// percentage of BaseInterval (D10). nil defaults to 30 in code (the paper band
	// upper endpoint). It bounds the maximum instance lifetime to
	// BaseInterval*(1+JitterMaxPercent/100) (the exposure-window upper bound).
	// (Phase 2.)
	JitterMaxPercent *int `json:"jitterMaxPercent,omitempty"`

	// +kubebuilder:validation:Optional
	// JitterDistribution selects the shape used to draw the jitter magnitude within
	// the band (D12g). "Uniform" (the default; max Shannon entropy over the bounded
	// band) or "TruncatedNormal" (an honestly-flagged lower-entropy opt-in,
	// mean=(min+max)/2, stddev=(max-min)/4, resampled until in-band). Empty defaults
	// to Uniform in code. Enum is declared on the JitterDistribution type. (Phase 2.)
	JitterDistribution JitterDistribution `json:"jitterDistribution,omitempty"`

	// +kubebuilder:validation:Optional
	// EntropySource selects the RNG backing the jitter draw (D13). "Crypto" (the
	// default; crypto/rand, unforgeable cadence) or "PseudoRandom" (seeded math/rand,
	// permitted only for test determinism — selecting it on a live AMTD records an
	// EntropyWarning Status condition because a leaked PRNG seed makes every future
	// rotation forecastable). Empty defaults to Crypto in code. Enum is declared on
	// the EntropySource type. (Phase 2.)
	EntropySource EntropySource `json:"entropySource,omitempty"`

	// +kubebuilder:validation:Optional
	// StaggerMode selects the per-key de-sync layered on top of the crypto jitter
	// (D14). "PerPodPhaseOffset" (the default; a deterministic per-key phase offset =
	// hash(seed||key) mod BaseInterval that de-syncs the fleet and is restart-safe
	// from the persisted seed), "Independent" (jitter only, no fixed offset), or
	// "None" (no offset). Empty defaults to PerPodPhaseOffset in code. The hard
	// availability cap is the separate MaxConcurrentRotations budget (D24), not the
	// stagger. Enum is declared on the StaggerMode type. (Phase 2.)
	StaggerMode StaggerMode `json:"staggerMode,omitempty"`
}

// JitterDistribution selects the distribution shape used to draw the per-cycle
// jitter magnitude within the [JitterMinPercent,JitterMaxPercent] band (D12g).
// +kubebuilder:validation:Enum=Uniform;TruncatedNormal
type JitterDistribution string

const (
	// JitterDistributionUniform is the default: a uniform draw over the band
	// (maximum Shannon entropy over a bounded interval; zero invented parameters).
	JitterDistributionUniform JitterDistribution = "Uniform"
	// JitterDistributionTruncatedNormal is an honestly-flagged lower-entropy opt-in
	// (mean=(min+max)/2, stddev=(max-min)/4, resampled until in-band).
	JitterDistributionTruncatedNormal JitterDistribution = "TruncatedNormal"
)

// EntropySource selects the RNG backing the cadence jitter (D13). Crypto is the
// production default; PseudoRandom is a test/opt-in lower-assurance source.
// +kubebuilder:validation:Enum=Crypto;PseudoRandom
type EntropySource string

const (
	// EntropySourceCrypto is the default: crypto/rand-backed, unforgeable cadence.
	EntropySourceCrypto EntropySource = "Crypto"
	// EntropySourcePseudoRandom is a seeded math/rand source permitted only for test
	// determinism; on a live AMTD it records an EntropyWarning Status condition.
	EntropySourcePseudoRandom EntropySource = "PseudoRandom"
)

// StaggerMode selects the per-key de-sync layered on the crypto jitter (D14).
// +kubebuilder:validation:Enum=PerPodPhaseOffset;Independent;None
type StaggerMode string

const (
	// StaggerModePerPodPhaseOffset is the default: a deterministic per-key phase
	// offset = hash(seed||key) mod BaseInterval (restart-safe from the persisted
	// seed) that de-syncs the fleet.
	StaggerModePerPodPhaseOffset StaggerMode = "PerPodPhaseOffset"
	// StaggerModeIndependent applies jitter only, with no fixed per-key offset.
	StaggerModeIndependent StaggerMode = "Independent"
	// StaggerModeNone applies no per-key offset.
	StaggerModeNone StaggerMode = "None"
)

// AdaptiveRotationPolicy carries the score-driven adaptive controls (cap #5,
// arch §2.4 / D20 / D22 / D25). PHASE 1 used only the crash-loop failure ceiling
// (MaxFailedRotations). PHASE 3 ADDS the SCORE-driven telemetry-scoring knobs —
// PanicThreshold / ScoringPolicy / StalenessWindow / EWMAAlpha /
// ConsecutiveHighSamples — that drive the EWMA SmoothedScore, the
// N-consecutive-high hysteresis, the ComputedInterval cadence, the staleness
// decay, and the panic gate. All are additive/pointer/optional: nil reproduces
// today's behavior (the Status SmoothedScore/ConsecutiveHighCount fields stay
// unwritten until MatcherMode=Scored AND a score is present). The code defaults
// (effectivePanicThreshold 0.85 / effectiveEWMAAlpha 0.3 /
// effectiveConsecutiveHighSamples 3 / effectiveStalenessWindow 0=disabled) are
// FLAGGED design proposals, never paper values.
type AdaptiveRotationPolicy struct {
	// +kubebuilder:validation:Optional
	// MaxFailedRotations is the crash-loop backoff/rollback threshold: when
	// Status.FailedRotationCount exceeds it, BackoffUntil is set (exponential) and
	// the rotation rolls back to LastKnownGoodRef. nil defaults to 3 in code
	// (effectiveMaxFailedRotations). (Phase 1.)
	MaxFailedRotations *int `json:"maxFailedRotations,omitempty"`

	// +kubebuilder:validation:Optional
	// PanicThreshold is the decimal-string score in [0,1] at/above which the
	// SmoothedScore is treated as a panic candidate: when SmoothedScore >=
	// PanicThreshold AND ConsecutiveHighCount >= ConsecutiveHighSamples the executor
	// PANICS, bypassing ONLY the G3 min-interval floor (NEVER readiness / backoff /
	// max-concurrent — D25/arch L330 LOCKED). nil defaults to "0.85" in code
	// (effectivePanicThreshold), a FLAGGED proposal — never a paper value. (Phase 3.)
	PanicThreshold *string `json:"panicThreshold,omitempty"`

	// +kubebuilder:validation:Optional
	// StalenessWindow decays a score to 0 once the SecurityEvent age exceeds it
	// (D25/D26g): a stale score neither accelerates nor suppresses rotation. nil (or
	// 0) defaults to DISABLED in code (effectiveStalenessWindow), i.e. no staleness
	// decay — today's behavior. (Phase 3.)
	StalenessWindow *metav1.Duration `json:"stalenessWindow,omitempty"`

	// +kubebuilder:validation:Optional
	// EWMAAlpha is the EWMA smoothing factor in (0,1] for
	// SmoothedScore = alpha*score + (1-alpha)*prevSmoothed (D22 anti-flap). A larger
	// alpha tracks the raw score faster (less smoothing). nil defaults to "0.3" in
	// code (effectiveEWMAAlpha). (Phase 3.)
	EWMAAlpha *string `json:"ewmaAlpha,omitempty"`

	// +kubebuilder:validation:Optional
	// ConsecutiveHighSamples is N: a panic requires Status.ConsecutiveHighCount >= N
	// (D22 anti-flap; a single spike does NOT panic). nil defaults to 3 in code
	// (effectiveConsecutiveHighSamples). (Phase 3.)
	ConsecutiveHighSamples *int `json:"consecutiveHighSamples,omitempty"`

	// +kubebuilder:validation:Optional
	// ScoringPolicy optionally selects the opt-in WeightedScorer over Spec.Metrics.
	// nil => the default PassthroughScorer (consumes Spec.AnomalyScore as-is, no
	// invented math; D20). There are NO default weights: the scorer is INERT unless
	// ScoringPolicy is set with a non-empty Weights map (the illustrative {0.5,0.3,
	// 0.2} weights never ship). (Phase 3.)
	ScoringPolicy *ScoringPolicy `json:"scoringPolicy,omitempty"`
}

// ScoringPolicy parameterizes the opt-in WeightedScorer (D20). It has NO default
// weights — Weights is mandatory-if-used, so the illustrative {0.5,0.3,0.2}
// weights never ship: an empty Weights map leaves the scorer inert (returns
// unscored). When set, the operator SA (which holds the securityevents grant)
// writes the recomputed score back to Spec.AnomalyScore, so the D26g trust root
// holds on the recompute path too.
type ScoringPolicy struct {
	// +kubebuilder:validation:Optional
	// Weights maps a Spec.Metrics key to its decimal-string weight. REQUIRED if
	// ScoringPolicy is used (there is no default): an empty/nil map => inert.
	Weights map[string]string `json:"weights,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=minmax;zscore;clamp
	// Normalization is one of minmax|zscore|clamp (D20). Empty defaults to clamp
	// (clamp the weighted sum into [0,1]). (Phase 3.)
	Normalization string `json:"normalization,omitempty"`
}

// WarmSwapAction cuts the leader to a pre-warmed shadow (cap #2). TYPE-ONLY in
// Phase 0.
type WarmSwapAction struct {
	// +kubebuilder:validation:Optional
	WarmInferenceSetRef *LocalRef `json:"warmInferenceSetRef,omitempty"`

	// +kubebuilder:validation:Optional
	// DrainTimeoutSeconds defaults to reuse the NIM 30s grace when nil.
	DrainTimeoutSeconds *int64 `json:"drainTimeoutSeconds,omitempty"`
}

// RegenerateAction restores a workload from a signed baseline (cap #6).
// TYPE-ONLY in Phase 0.
type RegenerateAction struct {
	// +kubebuilder:validation:Optional
	BaselineRef *LocalRef `json:"baselineRef,omitempty"`

	// +kubebuilder:validation:Optional
	ResetHardeningProfile bool `json:"resetHardeningProfile,omitempty"`
}

// NodeRotateAction relocates a compromised pod onto a clean node (cap #7).
// TYPE-ONLY in Phase 0.
type NodeRotateAction struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=Cordon;Taint;Delete
	// Strategy is the source-node disposition; defaults to Cordon (a flagged proposal).
	Strategy string `json:"strategy,omitempty"`

	// +kubebuilder:validation:Optional
	// DrainPolicy; nil relocates the targeted pod only, with no co-tenant drain.
	DrainPolicy *DrainPolicy `json:"drainPolicy,omitempty"`

	// +kubebuilder:validation:Optional
	// TargetNodeSelector selects the clean-pool nodes to relocate onto.
	TargetNodeSelector map[string]string `json:"targetNodeSelector,omitempty"`
}

// MovingStrategy Substructure for strategy definitions
type ResponseStrategy struct {
	//TODO: use enum for the specific values of these fields

	// +kubebuilder:validation:Required
	Rule Rule `json:"rule"`

	// +kubebuilder:validation:Required
	// Action field value of the SecurityEvent that arrives
	Action AMTDAction `json:"action"`
}

type Rule struct {
	// +kubebuilder:validation:Optional
	// Type field value of the SecurityEvent that arrives
	Type string `json:"type"`

	// +kubebuilder:validation:Optional
	// ThreatLevel field value of the SecurityEvent that arrives
	ThreatLevel string `json:"threatLevel"`

	// +kubebuilder:validation:Optional
	// Source field value of the SecurityEvent that arrives
	Source string `json:"source"`

	// +kubebuilder:validation:Optional
	// Match is a set of computed-score / metric predicates (matcher-side ONLY).
	// Emitters never set this on events. Evaluated only when Spec.MatcherMode=Scored;
	// nil (together with a nil ScoreThreshold) selects the exact fast path that is
	// outcome-identical to today's reflect.DeepEqual.
	// +listType=atomic
	Match []MatchExpression `json:"match,omitempty"`

	// +kubebuilder:validation:Optional
	// ScoreThreshold is sugar for a single Match{Field:"anomalyScore",Op:"Gte",Value:X}
	// clause (decimal string in [0,1]). Matcher-side ONLY; evaluated only when
	// Spec.MatcherMode=Scored.
	ScoreThreshold *string `json:"scoreThreshold,omitempty"`
}

// MatchExpression is a single predicate evaluated against a SecurityEvent spec
// in the scored matcher path. Field selects the projected value; numeric ops
// parse the value as a decimal.
type MatchExpression struct {
	// +kubebuilder:validation:Required
	// Field is the projected value: 'type'|'threatLevel'|'source'|'anomalyScore'|'metrics.<k>'.
	Field string `json:"field"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Eq;NotEq;In;NotIn;Gte;Gt;Lte;Lt;Exists
	// Op is the comparison operator.
	Op string `json:"op"`

	// +kubebuilder:validation:Optional
	// Value is a scalar or comma-separated list; numeric ops (Gte/Gt/Lte/Lt) parse
	// it as a decimal. Ignored by the Exists op.
	Value string `json:"value,omitempty"`
}

// AdaptiveMovingTargetDefenseStatus is the per-workload AGGREGATE on the policy
// object. The subresource is already enabled. All fields are optional so an
// AMTD created before this stage has an empty-but-valid status.
type AdaptiveMovingTargetDefenseStatus struct {
	// +kubebuilder:validation:Optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +kubebuilder:validation:Optional
	CurrentInterval metav1.Duration `json:"currentInterval,omitempty"`

	// +kubebuilder:validation:Optional
	// LastObservedScore is a decimal string in [0,1]; empty when unscored.
	LastObservedScore string `json:"lastObservedScore,omitempty"`

	// +kubebuilder:validation:Optional
	LastRotationTime metav1.Time `json:"lastRotationTime,omitempty"`

	// +kubebuilder:validation:Optional
	// RotationCount mirrors the NIM reschedule count.
	RotationCount int64 `json:"rotationCount,omitempty"`

	// --- D22 anti-flap state (restart-safe; lives here, NOT in controller memory) ---

	// +kubebuilder:validation:Optional
	// SmoothedScore is the EWMA-smoothed anomaly score as a decimal string.
	SmoothedScore string `json:"smoothedScore,omitempty"`

	// +kubebuilder:validation:Optional
	ConsecutiveHighCount int `json:"consecutiveHighCount,omitempty"`

	// +kubebuilder:validation:Optional
	FailedRotationCount int `json:"failedRotationCount,omitempty"`

	// +kubebuilder:validation:Optional
	LastKnownGoodRef *LocalRef `json:"lastKnownGoodRef,omitempty"`

	// +kubebuilder:validation:Optional
	BackoffUntil metav1.Time `json:"backoffUntil,omitempty"`

	// --- provenance / durability of the last action (D1/D2/D3) ---

	// +kubebuilder:validation:Optional
	// EffectiveSource records whether the embedded block or a referenced CR won (D1).
	EffectiveSource string `json:"effectiveSource,omitempty"`

	// +kubebuilder:validation:Optional
	// RotationPathFired is one of Rotate|WarmSwap|NodeRotate|cold (D2).
	RotationPathFired string `json:"rotationPathFired,omitempty"`

	// +kubebuilder:validation:Optional
	MutationDurable bool `json:"mutationDurable,omitempty"`

	// +kubebuilder:validation:Optional
	// MutationNotDurableReason is one of BarePod|ImmutableJobTemplate|PerPodOnSharedTemplate (D3).
	MutationNotDurableReason string `json:"mutationNotDurableReason,omitempty"`

	// --- per-capability sub-status (populated by later phases) ---

	// +kubebuilder:validation:Optional
	WarmPool *WarmPoolStatus `json:"warmPool,omitempty"`

	// +kubebuilder:validation:Optional
	Baseline *BaselineStatus `json:"baseline,omitempty"`

	// +kubebuilder:validation:Optional
	// NodeRotations is a BOUNDED history (cap N=20, a flagged proposal).
	// +listType=atomic
	NodeRotations []NodeRotationRecord `json:"nodeRotations,omitempty"`

	// +kubebuilder:validation:Optional
	ThreatBoundary *ThreatBoundaryStatus `json:"threatBoundary,omitempty"`

	// +kubebuilder:validation:Optional
	// Conditions includes MatcherModeWarning, Panic, MutationNotDurable,
	// VerificationUnavailable, EntropyWarning, NoCleanTarget.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// WarmPoolStatus is the warm-pool sub-status (cap #2).
type WarmPoolStatus struct {
	// +kubebuilder:validation:Optional
	ActiveLeader string `json:"activeLeader,omitempty"`
	// +kubebuilder:validation:Optional
	ReadyShadows int `json:"readyShadows,omitempty"`
	// +kubebuilder:validation:Optional
	LastSwapDurationMillis int64 `json:"lastSwapDurationMillis,omitempty"`
}

// BaselineStatus is the drift/baseline sub-status (cap #6).
type BaselineStatus struct {
	// +kubebuilder:validation:Optional
	LastVerifiedTime metav1.Time `json:"lastVerifiedTime,omitempty"`
	// +kubebuilder:validation:Optional
	// +listType=atomic
	PinnedDigests []string `json:"pinnedDigests,omitempty"`
	// +kubebuilder:validation:Optional
	DriftDetections int `json:"driftDetections,omitempty"`
	// +kubebuilder:validation:Optional
	LastRegeneration metav1.Time `json:"lastRegeneration,omitempty"`
}

// NodeRotationRecord is one bounded node-rotation history entry (cap #7).
type NodeRotationRecord struct {
	// +kubebuilder:validation:Optional
	SourceNode string `json:"sourceNode,omitempty"`
	// +kubebuilder:validation:Optional
	TargetNode string `json:"targetNode,omitempty"`
	// +kubebuilder:validation:Optional
	PodName string `json:"podName,omitempty"`
	// +kubebuilder:validation:Optional
	Time metav1.Time `json:"time,omitempty"`
	// +kubebuilder:validation:Optional
	Phase string `json:"phase,omitempty"`
}

// ThreatBoundaryStatus documents the co-residency threat boundary.
type ThreatBoundaryStatus struct {
	// +kubebuilder:validation:Optional
	CoResidentScope string `json:"coResidentScope,omitempty"`
	// +kubebuilder:validation:Optional
	PrivilegedAdversary string `json:"privilegedAdversary,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// AdaptiveMovingTargetDefense is the Schema for the adaptivemovingtargetdefenses API
type AdaptiveMovingTargetDefense struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AdaptiveMovingTargetDefenseSpec   `json:"spec,omitempty"`
	Status AdaptiveMovingTargetDefenseStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AdaptiveMovingTargetDefenseList contains a list of AdaptiveMovingTargetDefense
type AdaptiveMovingTargetDefenseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AdaptiveMovingTargetDefense `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AdaptiveMovingTargetDefense{}, &AdaptiveMovingTargetDefenseList{})
}
