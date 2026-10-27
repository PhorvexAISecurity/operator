package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

const nodeEscapeHorizon = 120 * time.Second

type nodeEscapePayload struct {
	TargetPodUID     string `json:"targetPodUID"`
	NodeName         string `json:"nodeName"`       // the detector's claimed compromised node; cross-checked against the live pod
	EscapeEvidence   string `json:"escapeEvidence"` // detector evidence blob (e.g. hostPath+nsenter indicator); digested for audit
	PolicyName       string `json:"policyName"`
	PolicyUID        string `json:"policyUID"`
	PolicyGeneration int64  `json:"policyGeneration"`
}

// bindNodeEscapeObservation binds a trusted container→host escape assertion (AML.T0105) to THIS
// Pod. It is NAMESPACE-PARAMETRIC: the namespace flows from the Pod, and the node to recycle is
// RE-DERIVED from the live Pod's spec.nodeName — NEVER trusted free-form from the event. The
// detector's claimed node (if present) must equal the Pod's actual node, and the observation always
// records the live node, so a forged/trusted-looking event cannot name an arbitrary node to recycle
// (a whole-cluster-DoS primitive). The reactive policy identity + selector must still match (M-94).
func bindNodeEscapeObservation(ctx context.Context, reader client.Reader, p *model.Pod, events []model.SecurityEventInfo) {
	p.NodeEscapeObservation = nil
	if p.UID == "" || p.Namespace == "" || reader == nil {
		return
	}
	var chosen *model.SecurityEventInfo
	var payload nodeEscapePayload
	for i := range events {
		e := &events[i]
		if e.Trust != eventtrust.TrustTrusted || !e.TargetsPod || e.Type != model.AttackVectorHostEscape ||
			e.Name == "" || e.UID == "" || e.CreatorIdentity == "" ||
			e.TimestampMissing || e.Age < 0 || e.Age >= nodeEscapeHorizon {
			continue
		}
		cand, err := parseNodeEscapePayload(e.NodeEscapeRaw)
		if err != nil || cand.TargetPodUID != p.UID || cand.EscapeEvidence == "" {
			continue
		}
		if chosen != nil {
			return // more than one trusted host-escape event for this pod: ambiguous, bind nothing
		}
		chosen, payload = e, cand
	}
	if chosen == nil {
		return
	}
	// SAFETY GATE: read the live Pod and DERIVE the node from it. Refuse if the pod identity changed,
	// the pod is not assigned to a node, or the detector's claimed node disagrees with reality.
	pod := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.Name}, pod); err != nil ||
		string(pod.UID) != p.UID || pod.Spec.NodeName == "" {
		return
	}
	if payload.NodeName != "" && payload.NodeName != pod.Spec.NodeName {
		return // event names a node other than the one the pod actually runs on: refuse (never recycle an attacker-chosen node)
	}
	liveNode := pod.Spec.NodeName
	// Bind to the Pod's own reactive policy (parametric): honoured only when the current policy
	// identity matches and its selector still matches the live Pod.
	policy := &v1alpha1.PhorvexPolicy{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: payload.PolicyName}, policy); err != nil ||
		string(policy.UID) != payload.PolicyUID || policy.Generation != payload.PolicyGeneration {
		return
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) {
		return
	}
	p.NodeEscapeObservation = &model.NodeEscapeObservation{
		EventName: chosen.Name, EventUID: chosen.UID, CreatorIdentity: chosen.CreatorIdentity,
		TargetPodUID:     p.UID,
		NodeName:         liveNode,
		PolicyName:       payload.PolicyName,
		PolicyUID:        payload.PolicyUID,
		PolicyGeneration: payload.PolicyGeneration,
		EscapeSHA256:     escapeDigest(liveNode, p.UID, payload.EscapeEvidence),
		CreatedAt:        chosen.CreatedAt,
	}
}

func parseNodeEscapePayload(raw string) (nodeEscapePayload, error) {
	var p nodeEscapePayload
	if len(raw) == 0 || len(raw) > 8192 {
		return p, errEmptyNodeEscape
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, err
	}
	return p, nil
}

var errEmptyNodeEscape = errors.New("node-escape observation annotation absent or oversized")

// escapeDigest is the stable audit binding over the live node, the target pod UID and the
// detector's evidence blob.
func escapeDigest(node, podUID, evidence string) string {
	h := sha256.New()
	h.Write([]byte(node))
	h.Write([]byte{0})
	h.Write([]byte(podUID))
	h.Write([]byte{0})
	h.Write([]byte(evidence))
	return hex.EncodeToString(h.Sum(nil))
}
