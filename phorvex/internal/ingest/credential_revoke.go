package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

const credentialTheftHorizon = 120 * time.Second

type credentialTheftPayload struct {
	TargetPodUID       string   `json:"targetPodUID"`
	PolicyName         string   `json:"policyName"`
	PolicyUID          string   `json:"policyUID"`
	PolicyGeneration   int64    `json:"policyGeneration"`
	ServiceAccountName string   `json:"serviceAccountName"`
	CredentialSecrets  []string `json:"credentialSecrets"`
}

// bindCredentialRevokeObservation binds a trusted stolen-SA-credential assertion to THIS Pod. It
// is NAMESPACE-PARAMETRIC: the namespace flows from the Pod, and the SA + token Secret(s) are
// bound to the Pod's own reactive PhorvexPolicy (UID + generation + selector) — no production-
// namespace literal and no console-injector pin, so a lane detector (pN/pN-attacks) is an
// accepted trusted producer. The SA name + Secret set and their audit digest come from the
// trusted event; a non-trusted or policy-mismatched event can never produce the observation (M-94).
func bindCredentialRevokeObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.CredentialRevokeObservation = nil
	if p.UID == "" || p.Namespace == "" || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload credentialTheftPayload
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorCredentialTheft ||
			e.Name == "" || e.UID == "" || e.CreatorIdentity == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= credentialTheftHorizon {
			continue
		}
		cand, err := parseCredentialTheftPayload(e.CredentialRevokeRaw)
		if err != nil || cand.TargetPodUID != p.UID {
			continue
		}
		if chosen != nil {
			return // more than one trusted credential-theft event for this pod: ambiguous, bind nothing
		}
		chosen, payload = e, cand
	}
	if chosen == nil {
		return
	}
	sa, ok := canonicalName(payload.ServiceAccountName)
	if !ok {
		return
	}
	secrets, ok := canonicalSecretNames(payload.CredentialSecrets)
	if !ok {
		return
	}
	// Bind to the Pod's own reactive policy (parametric): the SA + Secret set is only honoured when
	// the current policy identity matches and its selector still matches the live Pod.
	policy := &v1alpha1.PhorvexPolicy{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: payload.PolicyName}, policy); err != nil ||
		string(policy.UID) != payload.PolicyUID || policy.Generation != payload.PolicyGeneration {
		return
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || selector.Empty() {
		return
	}
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, pod); err != nil ||
		string(pod.UID) != p.UID || !selector.Matches(labels.Set(pod.Labels)) {
		return
	}
	p.CredentialRevokeObservation = &model.CredentialRevokeObservation{
		EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		TargetPodUID:       p.UID,
		PolicyName:         payload.PolicyName,
		PolicyUID:          payload.PolicyUID,
		PolicyGeneration:   payload.PolicyGeneration,
		ServiceAccountName: sa,
		CredentialSecrets:  secrets,
		CredentialSHA256:   credentialDigest(sa, secrets),
		CreatedAt:          chosen.CreatedAt,
	}
}

func parseCredentialTheftPayload(raw string) (credentialTheftPayload, error) {
	var p credentialTheftPayload
	if len(raw) == 0 || len(raw) > 8192 {
		return p, errEmptyCredentialRevoke
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, err
	}
	return p, nil
}

var errEmptyCredentialRevoke = errorString("credential-revoke observation annotation absent or oversized")

// canonicalName validates one Kubernetes object name (DNS-1123 subdomain-ish): non-empty,
// <=253 chars, lowercase alphanumerics plus '-' and '.'. A name we cannot express is refused.
func canonicalName(name string) (string, bool) {
	if len(name) == 0 || len(name) > 253 {
		return "", false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return "", false
	}
	return name, true
}

// canonicalSecretNames validates, de-duplicates and sorts the token-Secret name set for a stable
// digest. An empty or invalid set is refused — a revocation we cannot express is never bound.
func canonicalSecretNames(names []string) ([]string, bool) {
	if len(names) == 0 || len(names) > 16 {
		return nil, false
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		norm, ok := canonicalName(n)
		if !ok {
			return nil, false
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	sort.Strings(out)
	return out, true
}

// credentialDigest is the stable audit binding over the ServiceAccount name + the sorted token
// Secret name set.
func credentialDigest(sa string, sortedSecrets []string) string {
	h := sha256.New()
	h.Write([]byte(sa))
	h.Write([]byte{0})
	for _, s := range sortedSecrets {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
