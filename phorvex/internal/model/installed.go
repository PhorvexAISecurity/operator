/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package model

// installed.go holds ONLY the installability set + its membership test + a pure set-diff
// (R3): model stays a leaf package. The CRD DISCOVERY that reads the deployed enum and
// populates NotInstallable lives at the wiring layer, not here.

// InstallSet is a set of actions. Used for NotInstallable — the actions the installed
// CRD does not admit.
type InstallSet map[Action]struct{}

// Has reports membership.
func (s InstallSet) Has(a Action) bool { _, ok := s[a]; return ok }

// NotInstallable is the boot-computed set of actions ABSENT from the installed CRD's
// action enum: (AllKnownActions − installedEnum). Empty (the healthy case, e.g. an
// installed CRD carrying all 17 values) means every action is installable, so the gate's
// first check never fires. "not-installable" is the one exclusion reason that is a
// property of the cluster, not the asset. The wiring layer assigns this at boot from
// ComputeNotInstallable(discoveredEnum); the capability gate only READS it.
var NotInstallable = InstallSet{}

// AllKnownActions is the full action vocabulary the installed enum is diffed against —
// MutatingActions ∪ {noop, disable} (mirrors the action-completeness vocabulary).
func AllKnownActions() []Action {
	out := make([]Action, 0, len(MutatingActions)+2)
	out = append(out, MutatingActions...)
	return append(out, ActionNoop, ActionDisable)
}

// ComputeNotInstallable returns (AllKnownActions − installed) as an InstallSet. Pure:
// the wiring layer supplies the discovered installed enum; no cluster access here.
func ComputeNotInstallable(installed []Action) InstallSet {
	have := make(map[Action]struct{}, len(installed))
	for _, a := range installed {
		have[a] = struct{}{}
	}
	ni := InstallSet{}
	for _, a := range AllKnownActions() {
		if _, ok := have[a]; !ok {
			ni[a] = struct{}{}
		}
	}
	return ni
}
