package console

import "errors"

// The profile's immutable SHA pins this single maintenance transition. The old
// source UID is archival attribution; only the normal current snapshot proves
// the currently serving source, Pods, route and unchanged Secret authority.
type endpointLeaseSourceUpgrade struct {
	Version                 int    `json:"version"`
	PriorStateJSON          string `json:"priorStateJSON"`
	PriorStateSHA256        string `json:"priorStateSHA256"`
	PriorJournalSHA256      string `json:"priorJournalSHA256"`
	CurrentStateSHA256      string `json:"currentStateSHA256"`
	PriorSourceConfigMapUID string `json:"priorSourceConfigMapUID"`
}

func endpointLeaseUpgradePrior(p endpointLeaseProfile) (endpointLeaseProfile, endpointLeaseState, error) {
	bad := errors.New("endpoint lease source upgrade witness invalid")
	w := p.SourceUpgrade
	if w == nil || w.Version != 1 || !staticUID.MatchString(w.PriorSourceConfigMapUID) ||
		w.PriorSourceConfigMapUID == p.SourceConfigMapUID || !staticSHA256.MatchString(w.PriorStateSHA256) ||
		!staticSHA256.MatchString(w.PriorJournalSHA256) || !staticSHA256.MatchString(w.CurrentStateSHA256) ||
		endpointLeaseSHA([]byte(w.PriorStateJSON)) != w.PriorStateSHA256 {
		return endpointLeaseProfile{}, endpointLeaseState{}, bad
	}
	var prior endpointLeaseState
	if endpointLeaseStrictJSON([]byte(w.PriorStateJSON), &prior, 16<<10) != nil ||
		!staticSHA256.MatchString(prior.ProxySourceSHA256) || prior.ProxySourceSHA256 == p.ProxySourceSHA256 {
		return endpointLeaseProfile{}, prior, bad
	}
	old := p
	old.SourceUpgrade = nil
	old.SourceConfigMapUID = w.PriorSourceConfigMapUID
	old.ProxySourceSHA256 = prior.ProxySourceSHA256
	prior, err := parseEndpointLeaseState([]byte(w.PriorStateJSON), old)
	if err != nil || prior.Revision != 1 || len(prior.AllowedClientHMACs) != 1 ||
		prior.AllowedClientHMACs[0] != p.ClientBHMAC || len(prior.RevokedClientHMACs) != 1 ||
		prior.RevokedClientHMACs[0] != p.ClientAHMAC {
		return old, prior, bad
	}
	current := prior
	current.Revision++
	current.ProxySourceSHA256 = p.ProxySourceSHA256
	if endpointLeaseSHA(endpointLeaseStateBytes(current)) != w.CurrentStateSHA256 {
		return old, prior, bad
	}
	return old, prior, nil
}

func retainedCallerUpgradeAllowed(current endpointLeaseState, journal endpointLeaseJournal, p endpointLeaseProfile) bool {
	old, prior, err := endpointLeaseUpgradePrior(p)
	if err != nil || endpointLeaseSHA(endpointLeaseStateBytes(current)) != p.SourceUpgrade.CurrentStateSHA256 ||
		endpointLeaseSHA(endpointLeaseJournalBytes(journal)) != p.SourceUpgrade.PriorJournalSHA256 ||
		!retainedCallerAllowed(prior, journal, old) {
		return false
	}
	// Require the completed A revocation, rather than merely an unrelated B row.
	before := prior
	before.Revision = 0
	before.LastOperationID = ""
	before.AllowedClientHMACs = []string{p.ClientAHMAC, p.ClientBHMAC}
	if before.AllowedClientHMACs[0] > before.AllowedClientHMACs[1] {
		before.AllowedClientHMACs[0], before.AllowedClientHMACs[1] = before.AllowedClientHMACs[1], before.AllowedClientHMACs[0]
	}
	before.RevokedClientHMACs = []string{}
	for _, row := range journal.Receipts {
		if row.Phase == "terminal-full" && row.NewStateSHA256 == p.SourceUpgrade.PriorStateSHA256 &&
			row.OperationID == prior.LastOperationID && row.OldRevision == 0 && row.NewRevision == 1 &&
			row.OldStateSHA256 == endpointLeaseSHA(endpointLeaseStateBytes(before)) &&
			row.RevokedClientHMAC == p.ClientAHMAC && row.RetainedClientHMAC == p.ClientBHMAC &&
			row.SeedSHA256 == p.SeedSHA256 && row.PolicyUID == p.PolicyUID &&
			row.PolicyConfigMapUID == p.PolicyConfigMapUID && row.SecretUID == p.TenantSecretUID &&
			row.ServiceUID == p.ServiceUID && row.ProxySourceSHA256 == old.ProxySourceSHA256 {
			return true
		}
	}
	return false
}
