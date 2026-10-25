package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

type history struct {
	pods                 map[string]time.Time
	last                 time.Time
	removed, replacement string
	removedAt            time.Time
	recreatedAt          time.Time
	emittedReplacement   string
}

// Observer is a single-threaded poll observer. It never evicts a Pod to manufacture
// its signal. Restarts and failed/gapped inventories discard recreation authority.
type Observer struct {
	Client            client.Client
	OperatorNamespace string
	Identity          string
	Namespaces        []string
	Interval          time.Duration
	histories         map[string]*history
}

func (o *Observer) Scan(ctx context.Context, now time.Time) ([]string, error) {
	if o.Client == nil || o.Identity == "" || o.OperatorNamespace == "" || len(o.Namespaces) == 0 || o.Interval <= 0 {
		return nil, fmt.Errorf("observer configuration incomplete")
	}
	if o.histories == nil {
		o.histories = map[string]*history{}
	}
	if err := o.reap(ctx, now); err != nil {
		return nil, err
	}
	created := []string{}
	active := map[string]bool{}
	for _, ns := range o.Namespaces {
		var pods corev1.PodList
		if err := o.Client.List(ctx, &pods, client.InNamespace(ns)); err != nil {
			o.histories = nil
			return created, err
		}
		var policies v1alpha1.PhorvexPolicyList
		if err := o.Client.List(ctx, &policies, client.InNamespace(ns)); err != nil {
			o.histories = nil
			return created, err
		}
		owners := map[string]Owner{}
		// Controllers remain observable while every child is absent. Discovering
		// owners only from Pods would erase the very deletion/recreation history.
		var deployments appsv1.DeploymentList
		var statefulsets appsv1.StatefulSetList
		var replicasets appsv1.ReplicaSetList
		for _, list := range []client.ObjectList{&deployments, &statefulsets, &replicasets} {
			if err := o.Client.List(ctx, list, client.InNamespace(ns)); err != nil {
				o.histories = nil
				return created, err
			}
		}
		add := func(kind, name string) {
			owner, err := ReadOwner(ctx, o.Client, ns, kind, name)
			if err == nil {
				owners[string(owner.Object.GetUID())] = owner
			}
		}
		for _, v := range deployments.Items {
			add("Deployment", v.Name)
		}
		for _, v := range statefulsets.Items {
			add("StatefulSet", v.Name)
		}
		for _, v := range replicasets.Items {
			add("ReplicaSet", v.Name)
		}
		for i := range pods.Items {
			owner, err := ResolvePodOwner(ctx, o.Client, &pods.Items[i])
			if err != nil {
				continue
			}
			owners[string(owner.Object.GetUID())] = owner
		}
		keys := make([]string, 0, len(owners))
		for k := range owners {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, uid := range keys {
			owner := owners[uid]
			active[uid] = true
			children, err := Children(ctx, o.Client, owner)
			if err != nil {
				o.histories = nil
				return created, err
			}
			h := o.histories[uid]
			if h == nil || now.Sub(h.last) > 3*o.Interval || now.Before(h.last) {
				h = &history{}
				o.histories[uid] = h
			}
			current := map[string]time.Time{}
			for _, p := range children {
				current[string(p.UID)] = p.CreationTimestamp.Time
			}
			// A UID that was actually listed must disappear before a newly created UID
			// can count as recreation. Pure scale-up and the initial list never count.
			removed := []string{}
			for id := range h.pods {
				if _, ok := current[id]; !ok {
					removed = append(removed, id)
				}
			}
			sort.Strings(removed)
			if len(removed) > 0 {
				h.removed = removed[0]
				h.removedAt = now
				h.replacement = ""
				h.recreatedAt = time.Time{}
			}
			if h.removed != "" && h.replacement == "" && now.Sub(h.removedAt) < Horizon {
				fresh := []string{}
				for id, createdAt := range current {
					if _, seen := h.pods[id]; !seen && !createdAt.IsZero() && !createdAt.Before(h.last.Truncate(time.Second)) && id != h.removed {
						fresh = append(fresh, id)
					}
				}
				sort.Strings(fresh)
				if len(fresh) > 0 {
					h.replacement = fresh[0]
					h.recreatedAt = now
				}
			}
			h.pods = current
			h.last = now
			if h.replacement == "" || !Fresh(h.recreatedAt, now) || h.emittedReplacement == h.replacement || owner.Desired <= 0 {
				continue
			}
			if _, exists := current[h.replacement]; !exists {
				continue
			}
			var chosen *v1alpha1.PhorvexPolicy
			for i := range policies.Items {
				p := &policies.Items[i]
				if err := CurrentPolicy(ctx, o.Client, ns, p.Name, string(p.UID), p.Generation, children); err != nil {
					continue
				}
				if chosen != nil {
					chosen = nil
					break
				}
				chosen = p
			}
			if chosen == nil {
				continue
			}
			if err := CheckSafety(ctx, o.Client, o.OperatorNamespace, owner, children, chosen.Name); err != nil {
				continue
			}
			sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
			if len(children) == 0 {
				continue
			}
			target := children[0]
			if !target.DeletionTimestamp.IsZero() {
				continue
			}
			zero := 0
			a := Assertion{ControllerName: owner.Object.GetName(), OwnerKind: owner.Kind, Namespace: ns, OwnerDeclaredMinAvailable: &zero, Unmanaged: true, NoLegitimateServiceRole: true, ObservedRecreation: true, PolicyName: chosen.Name, PolicyUID: string(chosen.UID), PolicyGeneration: chosen.Generation, TargetPodUID: string(target.UID), RemovedPodUID: h.removed, ReplacementPodUID: h.replacement, ObservedAt: h.recreatedAt, Replicas: int(owner.Desired)}
			if len(children) > a.Replicas {
				a.Replicas = len(children)
			}
			raw, err := json.Marshal(a)
			if err != nil {
				return created, err
			}
			event := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
				"metadata": map[string]any{"generateName": "phorvex-persistence-", "labels": map[string]any{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/persistence-observer": "true"}, "annotations": map[string]any{
					"phorvex.ai/creator-identity": o.Identity, model.ConsoleTargetControllerUIDAnnotation: uid,
					"phorvex.ai/console-target-pod-uid": string(target.UID), Annotation: string(raw),
				}},
				"spec": map[string]any{"rule": map[string]any{"type": model.AttackVectorControllerPersistence, "threatLevel": "critical", "source": Source}, "targets": []any{ns + "/" + target.Name}, "description": "Positively attested attacker controller recreated an absent child; no declared serving or availability role"},
			}}
			// Identity is asserted by this process and authenticated by the existing M94
			// admission policy (it must equal request.userInfo.username and is immutable).
			if err := o.Client.Create(ctx, event); err != nil {
				return created, err
			}
			h.emittedReplacement = h.replacement
			created = append(created, event.GetName())
		}
	}
	for uid := range o.histories {
		if !active[uid] {
			delete(o.histories, uid)
		}
	}
	return created, nil
}

// Reap only this authenticated observer's labelled, expired evidence. Never infer
// ownership from a name prefix or remove a fresh authority event.
func (o *Observer) reap(ctx context.Context, now time.Time) error {
	list := &unstructured.UnstructuredList{}
	list.SetAPIVersion("amtd.r6security.com/v1beta1")
	list.SetKind("SecurityEventList")
	if err := o.Client.List(ctx, list, client.MatchingLabels{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/persistence-observer": "true"}); err != nil {
		return err
	}
	for i := range list.Items {
		e := &list.Items[i]
		createdAt := e.GetCreationTimestamp().Time
		if e.GetAnnotations()["phorvex.ai/creator-identity"] != o.Identity || createdAt.IsZero() || now.Before(createdAt.Add(Horizon)) {
			continue
		}
		uid := e.GetUID()
		if uid == "" {
			continue
		}
		if err := o.Client.Delete(ctx, e, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}
