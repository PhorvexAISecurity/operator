/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package eventtrust is the SecurityEvent trust boundary every service shares: the
// creator-identity stamp, the allowlists of authenticated identities whose events
// are evidence, and the check that the stamp is enforced. The sensor classifies
// events with it, the dispatcher admits completed-disclosure and current-inventory
// evidence with it, and the admission webhook stamps and checks the same identities.
package eventtrust

import (
	"sort"
	"strings"
	"sync"
)

// SecurityEvent trust boundary (PHORVEXSEC-193 / M-94).
//
// A SecurityEvent's `spec.rule.source` is a string the CREATOR writes. It is not an identity:
// the CR is cluster-scoped and carries no record of who created it, so ingest used to believe
// any event whose source was not Phorvex's own — the live campaign steered the brain ~25 times
// with `source: K3Detector`, a self-declared name from an identity with no trust relationship.
//
// The trust boundary is therefore drawn on the AUTHENTICATED creator identity, which only the
// API server knows: the admission stamp (internal/controller) writes the admission request's
// UserInfo into the CreatorIdentityAnnotation on CREATE and UPDATE, overwriting whatever the
// client sent, and the sensor believes an event only when that stamp names an allowlisted detector.
//
// That stamp is worth trusting only because a second, server-side control enforces it. The
// mutating webhook is failurePolicy=Ignore (it must never block the cluster's event flow), and
// while its endpoint is down the API server stores the object UNCHANGED — a client-written
// annotation would then reach this code as if it had been stamped. The chart therefore also
// ships a ValidatingAdmissionPolicy + Deny binding
// (charts/phorvex/templates/securityevent-identity-policy.yaml) that runs in-process in the API
// server and rejects any CREATE/UPDATE whose non-empty creator-identity is not the authenticated
// requester's own username. Without that policy installed, an identity read here is a CLAIM, not
// a fact: `phorvex.eventIdentityPolicy.enabled=false` is only permitted with an empty allowlist.
// The policy does not retroactively authenticate events that were already stored.
//
// An event that fails the check is NOT deleted and NOT hidden: it is ingested, recorded with
// Trusted=false and the reason, and counted — it simply carries no belief evidence. An empty
// allowlist trusts no external detector (fail-closed); the chart ships the identities that
// actually hold securityevents-create on the fleet.
const (
	// CreatorIdentityAnnotation carries the authenticated creator, e.g.
	// "system:serviceaccount:vllm/detector-kv-canary". Written by admission only.
	CreatorIdentityAnnotation = "phorvex.ai/creator-identity"

	// Trust verdicts, recorded per event and used as the metric label.
	TrustTrusted    = "trusted"
	TrustSelf       = "self"               // Phorvex's own emitted event (never evidence)
	TrustUnstamped  = "unstamped"          // no admission stamp: creator unknown
	TrustUntrusted  = "untrusted-identity" // stamped, but not an allowlisted detector
	TrustNoAllowed  = "no-allowlist"       // enforcement on with an empty allowlist (fail-closed)
	TargetUnresolvd = "target-unresolved"  // cluster-scoped ref: no namespace to key on
)

// TrustedDetectors is an allowlist of authenticated detector identities.
type TrustedDetectors struct {
	ids map[string]struct{}
}

// NormalizeIdentity canonicalises the accepted spellings of a ServiceAccount identity to the
// API server's own form, so chart values and UserInfo compare exactly:
//
//	system:serviceaccount:vllm:detector-kv-canary   (UserInfo.Username)
//	vllm/detector-kv-canary                          (chart-friendly)
//	vllm:detector-kv-canary
//
// A non-ServiceAccount username (a human, a node) is kept verbatim: it can be allowlisted, but
// it is never rewritten into an SA.
func NormalizeIdentity(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "system:serviceaccount:") {
		rest := strings.TrimPrefix(s, "system:serviceaccount:")
		rest = strings.ReplaceAll(rest, "/", ":")
		return "system:serviceaccount:" + rest
	}
	if ns, name, ok := strings.Cut(s, "/"); ok && ns != "" && name != "" && !strings.Contains(name, "/") {
		return "system:serviceaccount:" + ns + ":" + name
	}
	if ns, name, ok := strings.Cut(s, ":"); ok && ns != "" && name != "" && !strings.Contains(name, ":") {
		return "system:serviceaccount:" + ns + ":" + name
	}
	return s
}

// NewTrustedDetectors builds the allowlist from configured identities. Blank entries are
// dropped; order and spelling do not matter.
func NewTrustedDetectors(ids []string) TrustedDetectors {
	out := TrustedDetectors{ids: map[string]struct{}{}}
	for _, raw := range ids {
		for _, part := range strings.Split(raw, ",") {
			if id := NormalizeIdentity(part); id != "" {
				out.ids[id] = struct{}{}
			}
		}
	}
	return out
}

// Empty reports an allowlist that trusts no external detector (fail-closed).
func (t TrustedDetectors) Empty() bool { return len(t.ids) == 0 }

// Allows reports whether an authenticated identity is an allowlisted detector.
func (t TrustedDetectors) Allows(identity string) bool {
	if identity == "" {
		return false
	}
	_, ok := t.ids[NormalizeIdentity(identity)]
	return ok
}

// List returns the configured identities in canonical form (for the startup log and the record).
func (t TrustedDetectors) List() []string {
	out := make([]string, 0, len(t.ids))
	for id := range t.ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

var (
	trustMu                       sync.RWMutex
	trustedDetects                TrustedDetectors
	trustedLossActors             TrustedDetectors
	trustedCurrentInventoryActors TrustedDetectors
)

// ConfigureEventTrust installs the detector allowlist process-wide (from --trusted-detectors).
// It is set once at startup; tests set it directly. Never configured => fail-closed.
func ConfigureEventTrust(t TrustedDetectors) {
	trustMu.Lock()
	defer trustMu.Unlock()
	trustedDetects = t
}

// EventTrust returns the installed allowlist.
func EventTrust() TrustedDetectors {
	trustMu.RLock()
	defer trustMu.RUnlock()
	return trustedDetects
}

// ConfigureCompletedDisclosureTrust installs the narrower authority allowed to
// create completed-disclosure evidence. General detector trust is insufficient.
func ConfigureCompletedDisclosureTrust(t TrustedDetectors) {
	trustMu.Lock()
	defer trustMu.Unlock()
	trustedLossActors = t
}

func CompletedDisclosureTrust() TrustedDetectors {
	trustMu.RLock()
	defer trustMu.RUnlock()
	return trustedLossActors
}

func ConfigureCurrentInventoryTrust(t TrustedDetectors) {
	trustMu.Lock()
	defer trustMu.Unlock()
	trustedCurrentInventoryActors = t
}

func CurrentInventoryTrust() TrustedDetectors {
	trustMu.RLock()
	defer trustMu.RUnlock()
	return trustedCurrentInventoryActors
}

// Classify returns the trust verdict for an event's stamped creator identity.
func Classify(identity string) string {
	allow := EventTrust()
	switch {
	case allow.Empty():
		return TrustNoAllowed
	case identity == "":
		return TrustUnstamped
	case !allow.Allows(identity):
		return TrustUntrusted
	default:
		return TrustTrusted
	}
}
