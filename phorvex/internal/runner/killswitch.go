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
