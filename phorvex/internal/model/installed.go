/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package model

// installed.go holds only the installability set and a pure set difference. Discovery
// and its manager-owned knowledge state live at the wiring layer.

// InstallSet is a set of actions. Used for NotInstallable — the actions the installed
// CRD does not admit.
type InstallSet map[Action]struct{}

// Has reports membership.
func (s InstallSet) Has(a Action) bool { _, ok := s[a]; return ok }

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
