/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * network-isolate: the SURGICAL egress edge cut. EXTEND(quarantine) — it reuses quarantine's
 * NetworkPolicy primitive but scoped to the channel edge: it removes exactly the forbidden
 * egress edge(s) (C2 / exfil / IMDS / east-west) while the pod stays Ready and in-service.
 * Unlike quarantine it does NOT disown/replace the pod and does NOT cut ingress. Reversible.
 */

package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type networkIsolateHandler struct{}

func (networkIsolateHandler) Name() string { return string(model.ActionNetworkIsolate) }

const (
	networkIsolatedLabel = "phorvex.ai/network-isolated"
	networkIsolateSnap   = "phorvex.ai/network-isolate-snapshot"
	networkIsolateEpoch  = "phorvex.ai/network-isolate-epoch"
)

type netIsolateSnapshot struct {
	Version       int        `json:"version"`
	UID           string     `json:"uid"`
	LabelBefore   labelState `json:"labelBefore"`   // the selector label's prior state (for exact rollback)
	PolicyName    string     `json:"policyName"`    // the egress NetworkPolicy created
	ForbiddenEdges []string  `json:"forbiddenEdges"`
}

// networkIsolatePolicy builds the egress-only NetworkPolicy that removes exactly the forbidden
// edges while leaving the pod Ready + in-service: DNS stays allowed, and all other egress is
// permitted EXCEPT the forbidden CIDRs (ipBlock 0.0.0.0/0 except forbidden). Ingress is untouched.
func networkIsolatePolicy(p *corev1.Pod, forbidden []string) *networkingv1.NetworkPolicy {
	name := fmt.Sprintf("phorvex-netisolate-%x", sha256.Sum256([]byte(p.UID)))
	dns := intstr.FromInt(53)
	udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: p.Namespace,
			Labels:          map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/network-isolate-of": quarantineTargetLabel(p)},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: p.Name, UID: p.UID}}},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{networkIsolatedLabel: string(p.UID)}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				// 1) DNS always allowed, so the pod keeps functioning.
				{Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: &dns}, {Protocol: &tcp, Port: &dns}}},
				// 2) All other egress allowed EXCEPT the forbidden channel edges.
				{To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: forbidden}}}},
			},
		},
	}
}

func (networkIsolateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	if ec.Reader == nil {
		return HandlerResult{}, fmt.Errorf("network-isolate: authoritative reader unavailable")
	}
	o := req.NetworkIsolateObservation
	if o == nil || len(o.ForbiddenEdges) == 0 {
		return HandlerResult{}, fmt.Errorf("network-isolate: no bound egress-edge observation on the request")
	}
	forbidden, err := validForbiddenEdges(o.ForbiddenEdges)
	if err != nil {
		return HandlerResult{}, err
	}
	p := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, p); err != nil {
		return HandlerResult{}, err
	}
	if p.DeletionTimestamp != nil && !p.DeletionTimestamp.IsZero() {
		return HandlerResult{}, fmt.Errorf("%w: %s/%s; network-isolate will not start new egress-cut effects", errPodTerminating, req.Namespace, req.Pod)
	}
	// Enact-time authority re-check: the selection-time observation must still bind THIS exact
	// live Pod UID. The forbidden set is operator/detector-declared and never attacker-widened.
	if p.UID == "" || o.TargetPodUID != string(p.UID) || (req.TargetUID != "" && req.TargetUID != string(p.UID)) {
		return HandlerResult{}, fmt.Errorf("network-isolate: target UID unavailable or mismatched")
	}

	np := networkIsolatePolicy(p, forbidden)
	alreadyLabeled := p.Labels[networkIsolatedLabel] == string(p.UID)
	existing := &networkingv1.NetworkPolicy{}
	npErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: np.Namespace, Name: np.Name}, existing)
	if npErr != nil && !apierrors.IsNotFound(npErr) {
		return HandlerResult{}, npErr
	}
	npExists := npErr == nil
	if alreadyLabeled && npExists {
		return HandlerResult{
			ObjectsTouched: []string{objRef("NetworkPolicy", np.Namespace, np.Name)},
			RollbackRef:    req.Namespace + "/" + req.Pod + "@" + string(p.UID),
			MutationKind:   "reversible", NoEffect: NoEffectReconciled,
			Note: "network-isolate already in place for UID=" + string(p.UID) + "; reconciled",
		}, nil
	}

	// Create the egress NetworkPolicy first (idempotent on AlreadyExists).
	if !npExists {
		if err := ec.Client.Create(ctx, np); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return HandlerResult{}, fmt.Errorf("network-isolate: create egress policy: %w", err)
			}
		}
	}

	result := HandlerResult{
		ObjectsTouched: []string{objRef("NetworkPolicy", np.Namespace, np.Name)},
		RollbackRef:    req.Namespace + "/" + req.Pod + "@" + string(p.UID),
		MutationKind:   "reversible",
	}

	// Stamp the selector label (additive — it does NOT touch app/service selectors, so the pod
	// stays in the Service endpoints and keeps serving) + a snapshot annotation for exact rollback.
	snap := netIsolateSnapshot{Version: 1, UID: string(p.UID), LabelBefore: labelAt(p.Labels, networkIsolatedLabel), PolicyName: np.Name, ForbiddenEdges: forbidden}
	data, err := json.Marshal(snap)
	if err != nil {
		return result, err
	}
	after := p.DeepCopy()
	after.Labels = ensureMap(after.Labels)
	after.Labels[networkIsolatedLabel] = string(p.UID)
	after.Annotations = ensureMap(after.Annotations)
	after.Annotations[networkIsolateSnap] = string(data)
	after.Annotations[networkIsolateEpoch] = p.ResourceVersion
	if err := ec.Client.Update(ctx, after); err != nil {
		result.Note = "network-isolate: egress policy retained, selector-label stamp unconfirmed: " + err.Error()
		return result, fmt.Errorf("network-isolate label: %w", err)
	}
	result.Emitted = true
	result.ObjectsTouched = append(result.ObjectsTouched, objRef("Pod", p.Namespace, p.Name))
	result.Note = "egress edge cut for UID=" + string(p.UID) + "; forbidden=" + fmt.Sprint(forbidden) + "; DNS + all other egress retained, ingress untouched; dataplane enforcement is CNI-dependent"
	return result, nil
}

// Rollback re-opens the channel: delete the egress NetworkPolicy and strip the selector label.
func (networkIsolateHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	if ec.DryRun {
		return errDryRunGuard
	}
	p := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, p); err != nil {
		return err
	}
	var snap netIsolateSnapshot
	if err := json.Unmarshal([]byte(p.Annotations[networkIsolateSnap]), &snap); err != nil {
		return fmt.Errorf("network-isolate rollback: unreadable snapshot: %w", err)
	}
	if snap.UID != string(p.UID) || ref != req.Namespace+"/"+req.Pod+"@"+string(p.UID) {
		return fmt.Errorf("network-isolate rollback: snapshot/identity mismatch")
	}
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: snap.PolicyName, Namespace: p.Namespace}}
	if err := ec.Client.Delete(ctx, np); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("network-isolate rollback: delete egress policy: %w", err)
	}
	restored := p.DeepCopy()
	if snap.LabelBefore.Present {
		restored.Labels[networkIsolatedLabel] = snap.LabelBefore.Value
	} else {
		delete(restored.Labels, networkIsolatedLabel)
	}
	delete(restored.Annotations, networkIsolateSnap)
	delete(restored.Annotations, networkIsolateEpoch)
	if reflect.DeepEqual(restored.Labels, p.Labels) && reflect.DeepEqual(restored.Annotations, p.Annotations) {
		return nil
	}
	return ec.Client.Update(ctx, restored)
}

// validForbiddenEdges parses each operator/detector-declared edge as a CIDR. A bare IP is
// accepted and widened to a /32 host route. Invalid entries are refused — the handler never
// applies an unverifiable policy.
func validForbiddenEdges(edges []string) ([]string, error) {
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		if _, _, err := net.ParseCIDR(e); err == nil {
			out = append(out, e)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			if ip.To4() != nil {
				out = append(out, e+"/32")
			} else {
				out = append(out, e+"/128")
			}
			continue
		}
		return nil, fmt.Errorf("network-isolate: forbidden edge %q is not a valid CIDR or IP", e)
	}
	return out, nil
}

func init() { HandlerRegistry.Register(networkIsolateHandler{}) }
