/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package runner

import (
	"context"

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
	Client    client.Client
	Namespace string
	Name      string
}

// DefaultKillSwitchName is the sentinel ConfigMap name.
const DefaultKillSwitchName = "phorvex-killswitch"

// Engaged reports whether actuation is currently frozen.
func (k *KillSwitch) Engaged(ctx context.Context) bool {
	if k == nil {
		return false
	}
	if k.Static {
		return true
	}
	if k.Client == nil {
		return false // no API client wired => static-only kill-switch (not a ConfigMap sentinel)
	}
	if k.Namespace == "" {
		// [P4c D4/F6 FAIL-CLOSED FIX] A client is wired but no namespace to LOCATE the sentinel
		// => the ConfigMap kill-switch is non-functional (misconfiguration). A defense actuator
		// must NOT actuate when its kill-switch cannot be evaluated — fail-CLOSED (engaged) until
		// the operator namespace is set. (Previously this early-returned "not engaged" = fail-OPEN.)
		return true
	}
	name := k.Name
	if name == "" {
		name = DefaultKillSwitchName
	}
	var cm corev1.ConfigMap
	if err := k.Client.Get(ctx, client.ObjectKey{Namespace: k.Namespace, Name: name}, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return false // sentinel genuinely absent => not engaged (the normal case)
		}
		// [P4b fail-closed FIX] ANY OTHER error (API hiccup, timeout, RBAC denial, server
		// error, severed/slow API) is UNCERTAINTY. A defense actuator must NOT actuate when
		// it cannot read its own kill-switch — treat a read failure as ENGAGED (fail-CLOSED).
		return true
	}
	switch cm.Data["engaged"] {
	case "true", "True", "1", "yes":
		return true
	}
	return false
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
