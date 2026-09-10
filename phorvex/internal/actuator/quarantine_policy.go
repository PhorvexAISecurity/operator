package actuator

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func quarantineResult(p *corev1.Pod) HandlerResult {
	return HandlerResult{MutationKind: "reversible", RollbackRef: p.Namespace + "/" + p.Name + "@" + string(p.UID)}
}

func validQuarantineSnapshot(p *corev1.Pod, s *qtnSnapshot) bool {
	if (s.Version != 2 && s.Version != 3) || s.UID != p.UID || s.PolicyUID == "" || s.Before == nil || s.Applied == nil {
		return false
	}
	if s.Applied[quarantineLabel] != (labelState{string(p.UID), true}) || !s.Applied[quarantineEpochLabel].Present {
		return false
	}
	for k := range s.Applied {
		if _, ok := s.Before[k]; !ok {
			return false
		}
	}
	for k := range s.Before {
		if _, ok := s.Applied[k]; !ok {
			return false
		}
	}
	if s.Version == 2 {
		return s.PolicyName == "phorvex-quarantine-"+p.Name && s.LegacyName == "" && s.LegacyUID == ""
	}
	return s.PolicyName == quarantinePolicy(p).Name && ((s.LegacyName == "" && s.LegacyUID == "") || (s.LegacyName == "phorvex-quarantine-"+p.Name && s.LegacyUID != ""))
}

// Snapshot metadata retains the existing trust boundary; it is not a new label
// attestation system. Management labels alone never authorize adoption.
func quarantineAuthority(np *networkingv1.NetworkPolicy, p *corev1.Pod, recorded types.UID, legacy bool) error {
	if np.UID == "" || np.ResourceVersion == "" || np.Namespace != p.Namespace || np.DeletionTimestamp != nil || np.Labels["app.kubernetes.io/managed-by"] != "phorvex" || np.Labels["phorvex.ai/quarantine-of"] != quarantineTargetLabel(p) {
		return fmt.Errorf("quarantine: policy identity/management unavailable")
	}
	if legacy {
		if np.Name != "phorvex-quarantine-"+p.Name || recorded == "" || np.UID != recorded || len(np.OwnerReferences) != 0 {
			return fmt.Errorf("quarantine: ambiguous legacy policy authority")
		}
		return verifyQuarantinePolicy(np, quarantinePolicy(p))
	}
	if np.Name != quarantinePolicy(p).Name {
		return fmt.Errorf("quarantine: noncanonical policy identity")
	}
	if len(np.OwnerReferences) > 1 {
		return fmt.Errorf("quarantine: shared policy ownership")
	}
	if len(np.OwnerReferences) == 1 {
		o := np.OwnerReferences[0]
		if o.APIVersion != "v1" || o.Kind != "Pod" || o.Name != p.Name || o.UID != p.UID {
			return fmt.Errorf("quarantine: foreign policy owner")
		}
		return nil
	}
	if recorded != "" && np.UID == recorded {
		return nil
	}
	return fmt.Errorf("quarantine: policy collision without exclusive owner or recorded identity")
}

func sameQuarantinePod(ctx context.Context, ec EnactCtx, p *corev1.Pod) error {
	fresh := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKeyFromObject(p), fresh); err != nil {
		return err
	}
	if fresh.UID != p.UID || fresh.ResourceVersion != p.ResourceVersion || fresh.DeletionTimestamp != nil {
		return fmt.Errorf("quarantine: target changed concurrently")
	}
	return nil
}

func noCopiedQuarantineLabel(ctx context.Context, ec EnactCtx, p *corev1.Pod) error {
	var pods corev1.PodList
	if err := ec.Reader.List(ctx, &pods, client.InNamespace(p.Namespace), client.MatchingLabels{quarantineLabel: string(p.UID)}); err != nil {
		return err
	}
	for _, other := range pods.Items {
		if other.UID != p.UID || other.Name != p.Name {
			return fmt.Errorf("quarantine: selector label copied to another Pod")
		}
	}
	return nil
}

func policyMutationFailure(r *HandlerResult, err error) {
	// The result interface has no separate unknown bit. Preserve the attempted
	// mutation and ambiguity in Note without asserting that it was accepted.
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || apierrors.IsInvalid(err) || apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
		r.Note = "quarantine: policy request rejected: " + err.Error()
		return
	}
	r.Note = "partial/unknown quarantine: policy mutation or readback failed; retained protection requires reconciliation: " + err.Error()
}
func touchedPolicy(r *HandlerResult, np *networkingv1.NetworkPolicy) {
	r.Emitted = true
	r.ObjectsTouched = append(r.ObjectsTouched, objRef("NetworkPolicy", np.Namespace, np.Name))
}

func ensureQuarantinePolicy(ctx context.Context, ec EnactCtx, p *corev1.Pod, s *qtnSnapshot, r *HandlerResult) (*networkingv1.NetworkPolicy, error) {
	if err := sameQuarantinePod(ctx, ec, p); err != nil {
		return nil, err
	}
	if err := noCopiedQuarantineLabel(ctx, ec, p); err != nil {
		return nil, err
	}
	want := quarantinePolicy(p)
	got := &networkingv1.NetworkPolicy{}
	err := ec.Reader.Get(ctx, client.ObjectKeyFromObject(want), got)
	if apierrors.IsNotFound(err) {
		if err = sameQuarantinePod(ctx, ec, p); err != nil {
			return nil, err
		}
		err = ec.Client.Create(ctx, want)
		accepted := err == nil
		if err == nil {
			touchedPolicy(r, want)
		} else if !apierrors.IsAlreadyExists(err) {
			policyMutationFailure(r, err)
			return nil, err
		}
		if err = ec.Reader.Get(ctx, client.ObjectKeyFromObject(want), got); err != nil {
			policyMutationFailure(r, err)
			return nil, err
		}
		if accepted && (want.UID == "" || got.UID != want.UID) {
			return nil, fmt.Errorf("quarantine: created policy identity changed at readback")
		}
	} else if err != nil {
		return nil, err
	}
	recorded := types.UID("")
	if s.Version == 3 && s.PolicyName == want.Name {
		recorded = s.PolicyUID
	}
	if err = quarantineAuthority(got, p, recorded, false); err != nil {
		return nil, err
	}
	if verifyQuarantinePolicy(got, want) != nil || !reflect.DeepEqual(got.OwnerReferences, want.OwnerReferences) {
		if err = sameQuarantinePod(ctx, ec, p); err != nil {
			return nil, err
		}
		next := got.DeepCopy()
		next.Spec = want.Spec
		next.OwnerReferences = want.OwnerReferences
		if err = ec.Client.Update(ctx, next); err != nil {
			policyMutationFailure(r, err)
			return nil, err
		}
		touchedPolicy(r, next)
		if err = ec.Reader.Get(ctx, client.ObjectKeyFromObject(next), got); err != nil {
			policyMutationFailure(r, err)
			return nil, err
		}
		if got.UID != next.UID {
			return nil, fmt.Errorf("quarantine: policy replaced during readback")
		}
	}
	if err = quarantineAuthority(got, p, recorded, false); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(got.OwnerReferences, want.OwnerReferences) {
		return nil, fmt.Errorf("quarantine: owner readback mismatch")
	}
	if err = verifyQuarantinePolicy(got, want); err != nil {
		return nil, err
	}
	if err = sameQuarantinePod(ctx, ec, p); err != nil {
		return nil, err
	}
	return got, nil
}

func verifyQuarantineTarget(ctx context.Context, ec EnactCtx, p *corev1.Pod, np *networkingv1.NetworkPolicy) error {
	if err := sameQuarantinePod(ctx, ec, p); err != nil {
		return err
	}
	if p.Labels[quarantineLabel] != string(p.UID) {
		return fmt.Errorf("quarantine: selector does not match target")
	}
	got := &networkingv1.NetworkPolicy{}
	if err := ec.Reader.Get(ctx, client.ObjectKeyFromObject(np), got); err != nil {
		return err
	}
	if got.UID != np.UID {
		return fmt.Errorf("quarantine: policy readback identity changed")
	}
	if err := quarantineAuthority(got, p, np.UID, false); err != nil {
		return err
	}
	if !reflect.DeepEqual(got.OwnerReferences, quarantinePolicy(p).OwnerReferences) {
		return fmt.Errorf("quarantine: owner readback changed")
	}
	if err := verifyQuarantinePolicy(got, quarantinePolicy(p)); err != nil {
		return err
	}
	return noCopiedQuarantineLabel(ctx, ec, p)
}

func retryQuarantine(ctx context.Context, ec EnactCtx, req Request, p *corev1.Pod) (r HandlerResult, err error) {
	r = quarantineResult(p)
	var s qtnSnapshot
	if json.Unmarshal([]byte(p.Annotations[quarantineSnapAnno]), &s) != nil || !validQuarantineSnapshot(p, &s) || s.Released {
		return r, fmt.Errorf("quarantine: existing marker has no verified active recovery baseline")
	}
	for k, v := range s.Applied {
		if k != quarantineLabel && labelAt(p.Labels, k) != v {
			return r, fmt.Errorf("quarantine: applied labels drifted, inspection required")
		}
	}
	if !reflect.DeepEqual(p.OwnerReferences, s.AppliedOwners) {
		return r, fmt.Errorf("quarantine: owner references drifted")
	}
	if s.Version == 2 {
		legacy := &networkingv1.NetworkPolicy{}
		if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: s.PolicyName}, legacy); err != nil {
			return r, err
		}
		if err = quarantineAuthority(legacy, p, s.PolicyUID, true); err != nil {
			return r, err
		}
		s.LegacyName, s.LegacyUID = s.PolicyName, s.PolicyUID
	}
	np, err := ensureQuarantinePolicy(ctx, ec, p, &s, &r)
	if err != nil {
		return r, err
	}
	// Durable progress precedes legacy cleanup and retains the original detach
	// baseline. A crash at any subsequent step can resume without detaching again.
	s.Version, s.PolicyName, s.PolicyUID = 3, np.Name, np.UID
	data, _ := json.Marshal(s)
	if string(data) != p.Annotations[quarantineSnapAnno] || p.Labels[quarantineLabel] != string(p.UID) || r.Emitted {
		next := p.DeepCopy()
		next.Labels = ensureMap(next.Labels)
		next.Labels[quarantineLabel] = string(p.UID)
		next.Annotations[quarantineSnapAnno] = string(data)
		if err = ec.Client.Update(ctx, next); err != nil {
			r.Note = "partial/unknown quarantine: Pod checkpoint not acknowledged: " + err.Error()
			return r, err
		}
		r.Emitted = true
		r.ObjectsTouched = append(r.ObjectsTouched, objRef("Pod", p.Namespace, p.Name))
		p = next
	}
	if err = verifyQuarantineTarget(ctx, ec, p, np); err != nil {
		return r, err
	}
	if s.LegacyName != "" {
		legacy := &networkingv1.NetworkPolicy{}
		err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: s.LegacyName}, legacy)
		if err != nil && !apierrors.IsNotFound(err) {
			return r, err
		}
		if err == nil {
			if err = quarantineAuthority(legacy, p, s.LegacyUID, true); err != nil {
				return r, err
			}
			if err = sameQuarantinePod(ctx, ec, p); err != nil {
				return r, err
			}
			if err = deleteQuarantinePolicy(ctx, ec, legacy); err != nil {
				return r, err
			}
			touchedPolicy(&r, legacy)
		}
	}
	if err = verifyQuarantineTarget(ctx, ec, p, np); err != nil {
		return r, err
	}
	r.Note = "already quarantined; UID=" + string(p.UID) + " policy and selector verified; endpoint convergence and network enforcement unverified"
	if !r.Emitted {
		r.Note += "; no new mutation"
	}
	return r, nil
}

func deleteQuarantinePolicy(ctx context.Context, ec EnactCtx, np *networkingv1.NetworkPolicy) error {
	if np.UID == "" || np.ResourceVersion == "" {
		return fmt.Errorf("quarantine: cleanup identity unavailable")
	}
	uid, rv := np.UID, np.ResourceVersion
	err := ec.Client.Delete(ctx, np, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
func recordedQuarantinePolicies(ctx context.Context, ec EnactCtx, p *corev1.Pod, s *qtnSnapshot) ([]*networkingv1.NetworkPolicy, error) {
	var policies []*networkingv1.NetworkPolicy
	records := []struct {
		name   string
		uid    types.UID
		legacy bool
	}{{s.PolicyName, s.PolicyUID, s.Version == 2}}
	if s.LegacyName != "" {
		records = append(records, struct {
			name   string
			uid    types.UID
			legacy bool
		}{s.LegacyName, s.LegacyUID, true})
	}
	for _, id := range records {
		np := &networkingv1.NetworkPolicy{}
		err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: id.name}, np)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if np.UID != id.uid {
			return nil, fmt.Errorf("quarantine: recorded cleanup policy replaced")
		}
		if err = quarantineAuthority(np, p, id.uid, id.legacy); err != nil {
			return nil, err
		}
		policies = append(policies, np)
	}
	return policies, nil
}
func finishQuarantineRelease(ctx context.Context, ec EnactCtx, p *corev1.Pod, s *qtnSnapshot) error {
	// Once released, only cleanup is retried. A new quarantine must wait until
	// this record is removed; there is no request-generation contract here.
	for k, v := range s.Before {
		if labelAt(p.Labels, k) != v {
			return fmt.Errorf("quarantine: released labels changed concurrently")
		}
	}
	if !reflect.DeepEqual(p.OwnerReferences, s.OwnerRefs) {
		return fmt.Errorf("quarantine: released owners changed concurrently")
	}
	policies, err := recordedQuarantinePolicies(ctx, ec, p, s)
	if err != nil {
		return err
	}
	for _, np := range policies {
		if err = sameQuarantinePod(ctx, ec, p); err != nil {
			return err
		}
		if err = deleteQuarantinePolicy(ctx, ec, np); err != nil {
			return fmt.Errorf("quarantine rollback: Pod restored but policy cleanup failed: %w", err)
		}
	}
	next := p.DeepCopy()
	delete(next.Annotations, quarantineSnapAnno)
	return ec.Client.Update(ctx, next)
}
