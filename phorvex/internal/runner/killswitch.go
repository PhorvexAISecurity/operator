/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package runner

import (
	"context"

	corev1 "k8s.io/api/core/v1"
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
	if k.Client == nil || k.Namespace == "" {
		return false
	}
	name := k.Name
	if name == "" {
		name = DefaultKillSwitchName
	}
	var cm corev1.ConfigMap
	if err := k.Client.Get(ctx, client.ObjectKey{Namespace: k.Namespace, Name: name}, &cm); err != nil {
		return false // absent sentinel => not engaged
	}
	switch cm.Data["engaged"] {
	case "true", "True", "1", "yes":
		return true
	}
	return false
}
