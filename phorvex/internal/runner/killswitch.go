/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package runner

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// KillSwitch is the global actuation kill-switch (PRD FR8). It is engaged when EITHER
// the static startup flag is set OR a sentinel ConfigMap says so (so an operator can
// freeze actuation with no restart). When engaged, the engine still DECIDES + LOGS +
// emits metrics, but NO actuation occurs regardless of a policy's Mode.
type KillSwitch struct {
	Static    bool
	Client    client.Reader
	Namespace string
	Name      string
	// ReadTimeout bounds every dynamic actuation observation. A caller deadline that
	// expires sooner still wins. Zero uses DefaultKillSwitchReadTimeout.
	ReadTimeout time.Duration
}

// DefaultKillSwitchName is the sentinel ConfigMap name.
const DefaultKillSwitchName = "phorvex-killswitch"

// DefaultKillSwitchReadTimeout bounds one fresh sentinel read at an actuation boundary.
const DefaultKillSwitchReadTimeout = 2 * time.Second

// KillSwitchCause is a stable, non-sensitive explanation of one observation.
type KillSwitchCause string

const (
	KillSwitchStaticFlag         KillSwitchCause = "StaticFlag"
	KillSwitchSentinelEngaged    KillSwitchCause = "SentinelEngaged"
	KillSwitchMissingNamespace   KillSwitchCause = "MissingNamespace"
	KillSwitchReadError          KillSwitchCause = "SentinelReadError"
	KillSwitchMalformedValue     KillSwitchCause = "SentinelMalformed"
	KillSwitchSentinelDisengaged KillSwitchCause = "SentinelDisengaged"
	KillSwitchSentinelAbsent     KillSwitchCause = "SentinelAbsent"
	KillSwitchSentinelKeyAbsent  KillSwitchCause = "SentinelKeyAbsent"
	KillSwitchStaticOnly         KillSwitchCause = "StaticOnly"
)

// KillSwitchObservation is the one value and cause used at a boundary. It contains no
// ConfigMap data so status and logs cannot disclose sentinel contents.
type KillSwitchObservation struct {
	Engaged bool
	Cause   KillSwitchCause
}

func (o KillSwitchObservation) message() string {
	switch o.Cause {
	case KillSwitchStaticFlag:
		return "actuation suppressed by the static startup flag"
	case KillSwitchSentinelEngaged:
		return "actuation suppressed by the dynamic sentinel"
	case KillSwitchMissingNamespace:
		return "actuation suppressed because the sentinel namespace is not configured"
	case KillSwitchReadError:
		return "actuation suppressed because the dynamic sentinel could not be read"
	case KillSwitchMalformedValue:
		return "actuation suppressed because the dynamic sentinel value is invalid"
	case KillSwitchSentinelDisengaged:
		return "actuation is permitted; the dynamic sentinel is explicitly disengaged"
	case KillSwitchSentinelAbsent:
		return "actuation is permitted; the dynamic sentinel is absent"
	case KillSwitchSentinelKeyAbsent:
		return "actuation is permitted; the dynamic sentinel has no engaged key"
	default:
		return "actuation is permitted; only the static kill-switch is configured"
	}
}

// Observe returns one fresh bounded dynamic observation. Explicit accepted sentinel
// values are true/True/1/yes and false/False/0/no. A missing key remains disengaged;
// every other value is malformed and fails closed.
func (k *KillSwitch) Observe(ctx context.Context) KillSwitchObservation {
	if k == nil {
		return KillSwitchObservation{Cause: KillSwitchStaticOnly}
	}
	if k.Static {
		return KillSwitchObservation{Engaged: true, Cause: KillSwitchStaticFlag}
	}
	if k.Client == nil {
		return KillSwitchObservation{Cause: KillSwitchStaticOnly}
	}
	if k.Namespace == "" {
		return KillSwitchObservation{Engaged: true, Cause: KillSwitchMissingNamespace}
	}
	name := k.Name
	if name == "" {
		name = DefaultKillSwitchName
	}
	timeout := k.ReadTimeout
	if timeout <= 0 {
		timeout = DefaultKillSwitchReadTimeout
	}
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var cm corev1.ConfigMap
	if err := k.Client.Get(readCtx, client.ObjectKey{Namespace: k.Namespace, Name: name}, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return KillSwitchObservation{Cause: KillSwitchSentinelAbsent}
		}
		return KillSwitchObservation{Engaged: true, Cause: KillSwitchReadError}
	}
	value, present := cm.Data["engaged"]
	if !present {
		return KillSwitchObservation{Cause: KillSwitchSentinelKeyAbsent}
	}
	switch value {
	case "true", "True", "1", "yes":
		return KillSwitchObservation{Engaged: true, Cause: KillSwitchSentinelEngaged}
	case "false", "False", "0", "no":
		return KillSwitchObservation{Cause: KillSwitchSentinelDisengaged}
	default:
		return KillSwitchObservation{Engaged: true, Cause: KillSwitchMalformedValue}
	}
}

// Engaged reports whether actuation is currently frozen.
func (k *KillSwitch) Engaged(ctx context.Context) bool {
	return k.Observe(ctx).Engaged
}

// CalibrationFrozen reports whether ONLINE COST CALIBRATION should be suppressed (PHVX-2). It reads
// the `costCalibration` key of the SAME sentinel ConfigMap the actuation kill-switch uses, because
// that is where an operator already looks during an incident and it needs no restart — a restart
// would be a poor off-switch here, since in-process RLS state is lost on restart anyway.
//
// Deliberately DIFFERENT from Engaged in two ways:
//
//   - It is a separate key. Freezing actuation and freezing learning are different decisions: an
//     operator may want the defence to stop moving while the cost model keeps observing, or to
//     distrust the learned costs while the defence keeps running on the shipped prior.
//   - A read failure does NOT fail closed. Engaged fails closed because acting on an unreadable
//     kill-switch is dangerous. Here the dangerous direction is inverted: freezing REVERTS theta to
//     the prior and discards every tenant's calibration, so a transient API hiccup must not throw
//     that away. `ok=false` means "no answer, leave the current state alone".
func (k *KillSwitch) CalibrationFrozen(ctx context.Context) (frozen, ok bool) {
	if k == nil || k.Client == nil || k.Namespace == "" {
		return false, false
	}
	name := k.Name
	if name == "" {
		name = DefaultKillSwitchName
	}
	var cm corev1.ConfigMap
	if err := k.Client.Get(ctx, client.ObjectKey{Namespace: k.Namespace, Name: name}, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return false, true // sentinel absent => calibration runs (the normal case)
		}
		return false, false // uncertainty: hold the current state rather than discard calibration
	}
	switch cm.Data["costCalibration"] {
	case "off", "Off", "OFF", "false", "False", "frozen", "0", "no":
		return true, true
	}
	return false, true
}
