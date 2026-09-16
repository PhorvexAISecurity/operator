// Package actuationbrake owns the operator-facing namespace and Pod annotation
// controls which suppress new Phorvex work. It deliberately does not model the
// global kill switch: the controls have different scope, status and recovery semantics.
package actuationbrake

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	NamespaceDryRunAnnotation = "phorvex.ai/dry-run"
	PodOptOutAnnotation       = "phorvex.ai/opt-out"
	DefaultReadTimeout        = 2 * time.Second
)

const (
	NamespaceDryRunAbsent     = "NamespaceDryRunAbsent"
	NamespaceDryRunDisengaged = "NamespaceDryRunDisengaged"
	NamespaceDryRunEngaged    = "NamespaceDryRunEngaged"
	NamespaceDryRunMalformed  = "NamespaceDryRunMalformed"
	NamespaceReadError        = "NamespaceReadError"
	NamespaceTerminating      = "NamespaceTerminating"

	PodOptOutAbsent     = "PodOptOutAbsent"
	PodOptOutDisengaged = "PodOptOutDisengaged"
	PodOptOutEngaged    = "PodOptOutEngaged"
	PodOptOutMalformed  = "PodOptOutMalformed"
	PodReadError        = "PodReadError"
	PodUIDChanged       = "PodUIDChanged"
	PodTerminating      = "PodTerminating"

	BoundaryReaderUnavailable = "BoundaryReaderUnavailable"
	PolicyDryRun              = "PolicyDryRun"
)

func parse(annotations map[string]string, key, absent, disengaged, engaged, malformed string) model.ActuationBrakeObservation {
	raw, present := annotations[key]
	if !present {
		return model.ActuationBrakeObservation{Cause: absent}
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes":
		return model.ActuationBrakeObservation{Engaged: true, Cause: engaged}
	case "false", "0", "no":
		return model.ActuationBrakeObservation{Cause: disengaged}
	default:
		// A present empty or unknown value is operator intent whose meaning is
		// uncertain. Suppress new work rather than silently enabling mutation.
		return model.ActuationBrakeObservation{Engaged: true, Cause: malformed}
	}
}

func Namespace(annotations map[string]string) model.ActuationBrakeObservation {
	return parse(annotations, NamespaceDryRunAnnotation, NamespaceDryRunAbsent,
		NamespaceDryRunDisengaged, NamespaceDryRunEngaged, NamespaceDryRunMalformed)
}

func NamespaceObject(namespace *corev1.Namespace) model.ActuationBrakeObservation {
	if namespace == nil {
		return model.ActuationBrakeObservation{Engaged: true, Cause: NamespaceReadError}
	}
	if namespace.DeletionTimestamp != nil {
		return model.ActuationBrakeObservation{Engaged: true, Cause: NamespaceTerminating}
	}
	return Namespace(namespace.Annotations)
}

func Pod(annotations map[string]string) model.ActuationBrakeObservation {
	return parse(annotations, PodOptOutAnnotation, PodOptOutAbsent,
		PodOptOutDisengaged, PodOptOutEngaged, PodOptOutMalformed)
}

func readContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = DefaultReadTimeout
	}
	return context.WithTimeout(parent, timeout)
}

// ObserveNamespace performs one bounded authoritative read. Read uncertainty is
// conservative because this observation is used immediately before new work.
func ObserveNamespace(ctx context.Context, reader client.Reader, timeout time.Duration, namespace string) model.ActuationBrakeObservation {
	if reader == nil || namespace == "" {
		return model.ActuationBrakeObservation{Engaged: true, Cause: BoundaryReaderUnavailable}
	}
	readCtx, cancel := readContext(ctx, timeout)
	defer cancel()
	var ns corev1.Namespace
	if err := reader.Get(readCtx, client.ObjectKey{Name: namespace}, &ns); err != nil {
		return model.ActuationBrakeObservation{Engaged: true, Cause: NamespaceReadError}
	}
	return NamespaceObject(&ns)
}

// ObservePod performs one bounded authoritative read and binds the result to the
// identity selected by the tick. An empty expectedUID is reserved for explicit
// direct/manual callers which did not select from a snapshot.
func ObservePod(ctx context.Context, reader client.Reader, timeout time.Duration, namespace, name, expectedUID string) model.ActuationBrakeObservation {
	observation, _ := ObservePodIdentity(ctx, reader, timeout, namespace, name, expectedUID)
	return observation
}

// ObservePodIdentity is ObservePod plus the live UID. Direct administrative
// callers use the first read to bind a subsequent pre-dispatch observation;
// tick-selected callers already have an expected UID and ignore the second result.
func ObservePodIdentity(ctx context.Context, reader client.Reader, timeout time.Duration, namespace, name, expectedUID string) (model.ActuationBrakeObservation, string) {
	if reader == nil || namespace == "" || name == "" {
		return model.ActuationBrakeObservation{Engaged: true, Cause: BoundaryReaderUnavailable}, ""
	}
	readCtx, cancel := readContext(ctx, timeout)
	defer cancel()
	var pod corev1.Pod
	if err := reader.Get(readCtx, client.ObjectKey{Namespace: namespace, Name: name}, &pod); err != nil {
		return model.ActuationBrakeObservation{Engaged: true, Cause: PodReadError}, ""
	}
	if pod.UID == "" || (expectedUID != "" && string(pod.UID) != expectedUID) {
		return model.ActuationBrakeObservation{Engaged: true, Cause: PodUIDChanged}, string(pod.UID)
	}
	if pod.DeletionTimestamp != nil {
		return model.ActuationBrakeObservation{Engaged: true, Cause: PodTerminating}, string(pod.UID)
	}
	return Pod(pod.Annotations), string(pod.UID)
}

func Message(observation model.ActuationBrakeObservation) string {
	switch observation.Cause {
	case NamespaceDryRunEngaged:
		return "namespace dry-run annotation suppresses new actuation"
	case NamespaceDryRunMalformed:
		return "namespace dry-run annotation is malformed; new actuation is suppressed"
	case NamespaceReadError:
		return "namespace actuation authority could not be read; new actuation is suppressed"
	case NamespaceTerminating:
		return "namespace is terminating; new actuation is suppressed"
	case PodOptOutEngaged:
		return "Pod opt-out annotation suppresses new actuation"
	case PodOptOutMalformed:
		return "Pod opt-out annotation is malformed; new actuation is suppressed"
	case PodReadError:
		return "Pod actuation authority could not be read; new actuation is suppressed"
	case PodUIDChanged:
		return "selected Pod identity changed; new actuation is suppressed"
	case PodTerminating:
		return "selected Pod is terminating; new actuation is suppressed"
	case BoundaryReaderUnavailable:
		return "actuation authority reader is unavailable; new actuation is suppressed"
	case PolicyDryRun:
		return "policy dry-run mode suppresses new actuation"
	case NamespaceDryRunDisengaged:
		return "namespace dry-run annotation explicitly permits actuation"
	case PodOptOutDisengaged:
		return "Pod opt-out annotation explicitly permits actuation"
	default:
		return "actuation annotation is absent"
	}
}
