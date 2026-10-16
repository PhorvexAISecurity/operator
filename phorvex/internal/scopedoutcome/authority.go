package scopedoutcome

import (
	"context"
	"errors"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/ownership"
)

const maxReplacementInventory = 64

// KubernetesBindingResolver re-reads the exact policy, Pod UID, termination
// grace, and stable workload owner before a synthetic session can be prepared.
// It runs only in the external observer path, never in a decision tick.
type KubernetesBindingResolver struct {
	Reader  client.Reader
	Timeout time.Duration
}

func (r KubernetesBindingResolver) Resolve(parent context.Context, config PrepareConfig) (model.PersistenceWorkloadScope, int64, error) {
	ctx, cancel, err := r.context(parent)
	if err != nil {
		return model.PersistenceWorkloadScope{}, 0, err
	}
	defer cancel()
	if err := r.currentPolicy(ctx, config); err != nil {
		return model.PersistenceWorkloadScope{}, 0, err
	}
	var pod corev1.Pod
	if err := r.Reader.Get(ctx, client.ObjectKey{Namespace: config.Workload.Namespace, Name: config.TargetName}, &pod); err != nil ||
		string(pod.UID) != config.TargetUID || pod.DeletionTimestamp != nil {
		return model.PersistenceWorkloadScope{}, 0, errors.New("scoped outcome target Pod identity is not current")
	}
	resolved, err := r.stableScope(ctx, &pod)
	if err != nil {
		return model.PersistenceWorkloadScope{}, 0, err
	}
	grace := int64(30)
	if pod.Spec.TerminationGracePeriodSeconds != nil {
		grace = *pod.Spec.TerminationGracePeriodSeconds
	}
	return resolved, grace, nil
}

// SnapshotReplacementBoundary records every Pod UID already present in the
// isolated fixture namespace before dispatch. A later replacement can never be
// inferred from a pre-existing peer, even if that peer becomes Ready later.
func (r KubernetesBindingResolver) SnapshotReplacementBoundary(parent context.Context, config PrepareConfig) ([]string, error) {
	ctx, cancel, err := r.context(parent)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if err := r.currentPolicy(ctx, config); err != nil {
		return nil, err
	}
	pods, err := r.boundedPods(ctx, config.Workload.Namespace)
	if err != nil {
		return nil, err
	}
	uids := make([]string, 0, len(pods))
	for i := range pods {
		if pods[i].UID == "" {
			return nil, errors.New("scoped outcome pre-dispatch Pod inventory lacks UID")
		}
		uids = append(uids, string(pods[i].UID))
	}
	sort.Strings(uids)
	return uids, nil
}

// ResolveReplacement discovers the post-dispatch object rather than accepting
// a caller-selected name or UID. Exactly one new Ready Pod under the same stable
// owner must exist, and the authenticated session response must name its UID.
// The API-server creation timestamp must be strictly later than the acknowledged
// dispatch; same-second precision ambiguity is conservatively unavailable.
func (r KubernetesBindingResolver) ResolveReplacement(parent context.Context, config PrepareConfig, preexistingUIDs []string, claimedUID string, dispatchedAt time.Time) error {
	ctx, cancel, err := r.context(parent)
	if err != nil {
		return err
	}
	defer cancel()
	if claimedUID == "" || len(claimedUID) > 253 || dispatchedAt.IsZero() {
		return errors.New("scoped outcome replacement session or action boundary is invalid")
	}
	if err := r.currentPolicy(ctx, config); err != nil {
		return err
	}
	excluded := make(map[string]struct{}, len(preexistingUIDs)+1)
	for _, uid := range preexistingUIDs {
		if uid == "" {
			return errors.New("scoped outcome pre-dispatch Pod inventory is invalid")
		}
		excluded[uid] = struct{}{}
	}
	excluded[config.TargetUID] = struct{}{}
	pods, err := r.boundedPods(ctx, config.Workload.Namespace)
	if err != nil {
		return err
	}
	candidates := make([]string, 0, 2)
	for i := range pods {
		pod := &pods[i]
		uid := string(pod.UID)
		if uid == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || !m106PodReady(pod) ||
			pod.CreationTimestamp.IsZero() || !pod.CreationTimestamp.Time.After(dispatchedAt) {
			continue
		}
		if _, existed := excluded[uid]; existed {
			continue
		}
		resolved, err := r.stableScope(ctx, pod)
		if err != nil {
			return err
		}
		if resolved == config.Workload {
			candidates = append(candidates, uid)
		}
	}
	if len(candidates) != 1 || candidates[0] != claimedUID {
		return errors.New("scoped outcome replacement is absent, ambiguous, or disagrees with the authenticated session")
	}
	return nil
}

func (r KubernetesBindingResolver) context(parent context.Context) (context.Context, context.CancelFunc, error) {
	if r.Reader == nil || r.Timeout <= 0 || r.Timeout > 5*time.Second {
		return nil, nil, errors.New("scoped outcome Kubernetes authority is unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, r.Timeout)
	return ctx, cancel, nil
}

func (r KubernetesBindingResolver) currentPolicy(ctx context.Context, config PrepareConfig) error {
	var policy v1alpha1.PhorvexPolicy
	if err := r.Reader.Get(ctx, client.ObjectKey{Namespace: config.Policy.Namespace, Name: config.Policy.Name}, &policy); err != nil ||
		string(policy.UID) != config.Policy.UID || policy.Generation != config.Policy.Generation || policy.DeletionTimestamp != nil {
		return errors.New("scoped outcome policy epoch is not current")
	}
	return nil
}

func (r KubernetesBindingResolver) stableScope(ctx context.Context, pod *corev1.Pod) (model.PersistenceWorkloadScope, error) {
	_, stable, err := ownership.ResolveStableWorkloadOwner(ctx, r.Reader, pod.Namespace, pod.Name, string(pod.UID))
	if err != nil {
		return model.PersistenceWorkloadScope{}, err
	}
	return model.PersistenceWorkloadScope{Namespace: stable.Namespace, OwnerKind: stable.Kind, OwnerName: stable.Name, OwnerUID: stable.UID}, nil
}

func (r KubernetesBindingResolver) boundedPods(ctx context.Context, namespace string) ([]corev1.Pod, error) {
	var list corev1.PodList
	if err := r.Reader.List(ctx, &list, client.InNamespace(namespace), client.Limit(maxReplacementInventory+1)); err != nil {
		return nil, err
	}
	if len(list.Items) > maxReplacementInventory || list.Continue != "" {
		return nil, errors.New("scoped outcome replacement inventory exceeds its exact bound")
	}
	return list.Items, nil
}

func m106PodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}
