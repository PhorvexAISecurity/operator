package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
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

const networkEdgeHorizon = 120 * time.Second

type networkEdgePayload struct {
	TargetPodUID     string   `json:"targetPodUID"`
	PolicyName       string   `json:"policyName"`
	PolicyUID        string   `json:"policyUID"`
	PolicyGeneration int64    `json:"policyGeneration"`
	ForbiddenEdges   []string `json:"forbiddenEdges"`
}

// bindNetworkIsolateObservation binds a trusted open-egress-channel assertion to THIS Pod. It is
// NAMESPACE-PARAMETRIC: the namespace flows from the Pod, and the forbidden edges are bound to the
// Pod's own reactive PhorvexPolicy (UID + generation + selector) — no production-namespace literal
// and no console-injector pin, so a lane detector (pN/pN-attacks) is an accepted trusted producer.
// The forbidden-edge set and its audit digest come from the trusted event; a non-trusted or
// policy-mismatched event can never produce the observation (M-94).
func bindNetworkIsolateObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.NetworkIsolateObservation = nil
	if p.UID == "" || p.Namespace == "" || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload networkEdgePayload
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorNetworkEdge ||
			e.Name == "" || e.UID == "" || e.CreatorIdentity == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= networkEdgeHorizon {
			continue
		}
		cand, err := parseNetworkEdgePayload(e.NetworkEdgeRaw)
		if err != nil || cand.TargetPodUID != p.UID {
			continue
		}
		if chosen != nil {
			return // more than one trusted edge event for this pod: ambiguous, bind nothing
		}
		chosen, payload = e, cand
	}
	if chosen == nil {
		return
	}
	edges, ok := canonicalEdges(payload.ForbiddenEdges)
	if !ok {
		return
	}
	// Bind to the Pod's own reactive policy (parametric): the forbidden set is only honoured when
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
	p.NetworkIsolateObservation = &model.NetworkIsolateObservation{
		EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		TargetPodUID:     p.UID,
		PolicyName:       payload.PolicyName,
		PolicyUID:        payload.PolicyUID,
		PolicyGeneration: payload.PolicyGeneration,
		ForbiddenEdges:   edges,
		ChannelSHA256:    channelDigest(edges),
		CreatedAt:        chosen.CreatedAt,
	}
}

func parseNetworkEdgePayload(raw string) (networkEdgePayload, error) {
	var p networkEdgePayload
	if len(raw) == 0 || len(raw) > 8192 {
		return p, errEmptyNetworkEdge
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, err
	}
	return p, nil
}

var errEmptyNetworkEdge = errorString("network-edge observation annotation absent or oversized")

type errorString string

func (e errorString) Error() string { return string(e) }

// canonicalEdges validates and normalises the forbidden-edge set: each entry becomes a CIDR
// (a bare IP widens to a host route), the set is de-duplicated and sorted for a stable digest.
// An empty or invalid set is refused — a policy we cannot express is never bound.
func canonicalEdges(edges []string) ([]string, bool) {
	if len(edges) == 0 || len(edges) > 64 {
		return nil, false
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		norm := ""
		if _, _, err := net.ParseCIDR(e); err == nil {
			norm = e
		} else if ip := net.ParseIP(e); ip != nil {
			if ip.To4() != nil {
				norm = e + "/32"
			} else {
				norm = e + "/128"
			}
		} else {
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

// channelDigest is the stable audit binding over the sorted forbidden-edge set.
func channelDigest(sortedEdges []string) string {
	h := sha256.New()
	for _, e := range sortedEdges {
		h.Write([]byte(e))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
