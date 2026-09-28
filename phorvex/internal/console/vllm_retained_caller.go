package console

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// retainedCallerAuthority borrows the lease case's pinned, read-only source
// checks. It never requires the pre-revocation A/B roster: a completed lease
// cutover must leave B usable by unrelated existing vLLM probes.
type retainedCallerAuthority struct {
	server       *Server
	kube         kubernetes.Interface
	profile      endpointLeaseProfile
	tokens       endpointLeaseTokens
	targetPodUID string
}

func newRetainedCallerAuthority(cfg Config, profileSHA, serviceUID, policyUID, sourceUID, targetPodUID string) (*retainedCallerAuthority, error) {
	if profileSHA == "" {
		return nil, nil
	}
	if !cfg.EndpointLeaseEnabled || cfg.EndpointLeaseProfileSHA256 != profileSHA {
		return nil, errors.New("reviewed retained caller profile is not mounted")
	}
	p, err := loadEndpointLeaseProfile(cfg)
	if err != nil || p.ServiceUID != serviceUID || p.PolicyUID != policyUID ||
		(sourceUID != "" && p.SourceConfigMapUID != sourceUID) || !staticUID.MatchString(targetPodUID) {
		return nil, errors.New("retained caller lease and target authority differ")
	}
	tokens, err := endpointLeaseMountedTokens(p)
	if err != nil {
		return nil, errors.New("retained caller Secret copy unavailable")
	}
	kube, err := clientForContext("")
	if err != nil {
		return nil, errors.New("retained caller Kubernetes authority unavailable")
	}
	return &retainedCallerAuthority{server: &Server{cfg: cfg}, kube: kube, profile: p, tokens: tokens, targetPodUID: targetPodUID}, nil
}

func retainedCallerAllowed(state endpointLeaseState, journal endpointLeaseJournal, p endpointLeaseProfile) bool {
	if p.SourceUpgrade != nil {
		return retainedCallerUpgradeAllowed(state, journal, p)
	}
	if !endpointLeasePreflightJournal(journal, state) {
		return false
	}
	allowed := sort.SearchStrings(state.AllowedClientHMACs, p.ClientBHMAC)
	revoked := sort.SearchStrings(state.RevokedClientHMACs, p.ClientBHMAC)
	if allowed == len(state.AllowedClientHMACs) || state.AllowedClientHMACs[allowed] != p.ClientBHMAC ||
		revoked < len(state.RevokedClientHMACs) && state.RevokedClientHMACs[revoked] == p.ClientBHMAC {
		return false
	}
	if state.Revision == 0 {
		return endpointLeaseBefore(state, p)
	}
	// A post-cutover state needs a durable matching terminal row. Historical
	// aborted attempts are allowed, unresolved prepared attempts are not.
	for _, row := range journal.Receipts {
		if row.Phase == "terminal-full" && row.NewRevision == state.Revision &&
			row.NewStateSHA256 == endpointLeaseSHA(endpointLeaseStateBytes(state)) &&
			row.OperationID == state.LastOperationID && row.PolicyUID == p.PolicyUID &&
			row.PolicyConfigMapUID == p.PolicyConfigMapUID && row.SecretUID == p.TenantSecretUID &&
			row.ServiceUID == p.ServiceUID && row.ProxySourceSHA256 == p.ProxySourceSHA256 &&
			row.RetainedClientHMAC == p.ClientBHMAC {
			return true
		}
	}
	return false
}

func (a *retainedCallerAuthority) check(ctx context.Context) error {
	if a == nil {
		return nil
	}
	snap, err := a.server.endpointLeaseSnapshot(ctx, a.kube, a.profile, a.tokens)
	if err != nil {
		return errors.New("retained caller source or route unavailable")
	}
	found := false
	for _, pod := range snap.Pods {
		found = found || string(pod.UID) == a.targetPodUID
	}
	if !found {
		return errors.New("retained caller target no longer serves")
	}
	cm, err := a.kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, endpointLeaseJournalCM, metav1.GetOptions{})
	if err != nil || string(cm.UID) != a.profile.JournalUID || len(cm.Data) != 1 {
		return errors.New("retained caller protected journal unavailable")
	}
	journal, err := parseEndpointLeaseJournal([]byte(cm.Data["receipts.json"]))
	if err != nil || a.profile.SourceUpgrade != nil && endpointLeaseSHA([]byte(cm.Data["receipts.json"])) != a.profile.SourceUpgrade.PriorJournalSHA256 ||
		!retainedCallerAllowed(snap.State, journal, a.profile) {
		return errors.New("retained caller B or terminal lease state unavailable")
	}
	return nil
}

func endpointLeaseJournalBytes(j endpointLeaseJournal) []byte {
	b, _ := json.Marshal(j)
	var canonical any
	_ = json.Unmarshal(b, &canonical)
	b, _ = json.Marshal(canonical)
	return b
}

func (a *retainedCallerAuthority) bearer() []byte {
	if a == nil {
		return nil
	}
	return a.tokens.B
}
