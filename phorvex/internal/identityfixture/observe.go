package identityfixture

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Snapshot struct {
	Pod         *corev1.Pod
	Account     *corev1.ServiceAccount
	Observation *model.IdentityRotationObservation
	Projection  *model.PodBoundKubeAPIAuthProjection
}

// Observe reads directly from the API, rather than trusting tenant annotations.
// active=true additionally requires the short-lived, exact positive-control
// receipt written by Console only after the stolen bearer actually succeeded.
func Observe(ctx context.Context, r client.Reader, cfg Profile, name, uid string, active bool) (Snapshot, error) {
	out, err := ObserveKubernetes(ctx, r, cfg, name, uid, active)
	if err != nil || FederationAbsent(ctx, cfg, out.Observation.ServiceAccountName) != nil {
		return Snapshot{}, errors.New("Console/test dedicated identity fixture evidence unavailable or changed")
	}
	out.Observation.FederatedIdentityAbsent = true
	return out, nil
}

// ObserveKubernetes applies the existing bounded fixture's Kubernetes-object oracle without the
// external EKS federation query. It is used by the Console producer for preflight and physical
// validation; the sensor still calls Observe and therefore admits no decision observation unless
// the independent federation oracle also passes. The policy generation gate is taken from the
// profile (cfg.PolicyGeneration): 0 binds to the live, fully-reconciled generation, a positive
// value pins one exact generation. Callers that have already bound a run to one live generation
// (the Console preflight) use ObserveKubernetesAt to carry it forward unchanged.
func ObserveKubernetes(ctx context.Context, r client.Reader, cfg Profile, name, uid string, active bool) (Snapshot, error) {
	return ObserveKubernetesAt(ctx, r, cfg, name, uid, active, cfg.PolicyGeneration)
}

// ObserveKubernetesAt is ObserveKubernetes with an explicit run-bound policy generation.
//
//	wantGeneration == 0 binds the observation to whatever generation the pinned-UID policy
//	  currently reports — the policy actually in force — and additionally requires it to be
//	  fully reconciled (status.observedGeneration == metadata.generation), so a policy caught
//	  mid-edit is never observed. The live generation is returned in Observation.PolicyGeneration.
//	wantGeneration > 0 keeps the above reconciled requirement and ALSO pins the generation to the
//	  exact value captured earlier in the same run, so a policy change between preflight and a
//	  later marker/physical observation invalidates the run instead of silently re-binding.
//
// In both modes the generation is never read from a static deployment pin, which is what drifted
// (committed 2 vs live 3) and blocked every identity-sa-rotate ID.
func ObserveKubernetesAt(ctx context.Context, r client.Reader, cfg Profile, name, uid string, active bool, wantGeneration int64) (Snapshot, error) {
	var out Snapshot
	fail := func() (Snapshot, error) {
		return out, errors.New("Console/test dedicated identity fixture evidence unavailable or changed")
	}
	if cfg.Validate() != nil || r == nil || uid == "" {
		return fail()
	}
	var ns corev1.Namespace
	if r.Get(ctx, client.ObjectKey{Name: cfg.Namespace}, &ns) != nil || string(ns.UID) != cfg.NamespaceUID || ns.DeletionTimestamp != nil || ns.Labels[Label] != NamespaceOwnedLabelValue {
		return fail()
	}
	var pod corev1.Pod
	if r.Get(ctx, client.ObjectKey{Namespace: cfg.Namespace, Name: name}, &pod) != nil || string(pod.UID) != uid || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return fail()
	}
	run := pod.Labels[Label]
	if !strings.HasPrefix(run, RunPrefix) || pod.Spec.ServiceAccountName != run || len(pod.Spec.Containers) != 1 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 {
		return fail()
	}
	c := pod.Spec.Containers[0]
	if c.Name != "workload" || c.Image != Image || !reflect.DeepEqual(c.Command, Command) || len(c.Args) != 0 || len(c.Env) != 0 || len(c.EnvFrom) != 0 || len(c.VolumeMounts) != 1 || c.VolumeMounts[0].Name != "api" || c.VolumeMounts[0].MountPath != Mount || !c.VolumeMounts[0].ReadOnly || c.VolumeMounts[0].SubPath != "" || c.VolumeMounts[0].SubPathExpr != "" {
		return fail()
	}
	if len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].Name != "api" || pod.Spec.Volumes[0].Projected == nil {
		return fail()
	}
	tokens := 0
	for _, s := range pod.Spec.Volumes[0].Projected.Sources {
		if s.ServiceAccountToken != nil {
			t := s.ServiceAccountToken
			if t.Audience != "" || t.Path != "token" || t.ExpirationSeconds == nil || *t.ExpirationSeconds != TokenExpirationSeconds {
				return fail()
			}
			tokens++
		}
	}
	if tokens != 1 {
		return fail()
	}
	ready := false
	for _, s := range pod.Status.ContainerStatuses {
		if s.Name == c.Name && s.Ready && s.Started != nil && *s.Started && s.State.Running != nil && s.RestartCount == 0 {
			ready = true
		}
	}
	if !ready {
		return fail()
	}
	var sa corev1.ServiceAccount
	if r.Get(ctx, client.ObjectKey{Namespace: cfg.Namespace, Name: run}, &sa) != nil || sa.UID == "" || sa.ResourceVersion == "" || sa.Labels[Label] != run || sa.DeletionTimestamp != nil || !sa.CreationTimestamp.Before(&pod.CreationTimestamp) || !NoFederation(&pod, &sa) {
		return fail()
	}
	// Prove this is the run's singleton Deployment, through its real controller RS.
	owner := metav1.GetControllerOf(&pod)
	if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
		return fail()
	}
	var rs appsv1.ReplicaSet
	if r.Get(ctx, client.ObjectKey{Namespace: cfg.Namespace, Name: owner.Name}, &rs) != nil || rs.UID != owner.UID {
		return fail()
	}
	depOwner := metav1.GetControllerOf(&rs)
	var dep appsv1.Deployment
	if depOwner == nil || depOwner.Kind != "Deployment" || depOwner.Name != run || r.Get(ctx, client.ObjectKey{Namespace: cfg.Namespace, Name: run}, &dep) != nil || dep.UID != depOwner.UID || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 || dep.Spec.Template.Spec.ServiceAccountName != run || dep.DeletionTimestamp != nil {
		return fail()
	}
	var pods corev1.PodList
	if r.List(ctx, &pods, client.InNamespace(cfg.Namespace)) != nil || pods.Continue != "" || pods.RemainingItemCount != nil || pods.ResourceVersion == "" {
		return fail()
	}
	consumers := 0
	for _, p := range pods.Items {
		if p.Spec.ServiceAccountName == run {
			if p.UID != pod.UID || p.DeletionTimestamp != nil {
				return fail()
			}
			consumers++
		}
	}
	if consumers != 1 {
		return fail()
	}
	var secrets corev1.SecretList
	if r.List(ctx, &secrets, client.InNamespace(cfg.Namespace)) != nil || secrets.Continue != "" || secrets.RemainingItemCount != nil {
		return fail()
	}
	legacy := []model.IdentityRotationSecret{}
	seen := map[string]bool{}
	for _, s := range secrets.Items {
		if s.Type == corev1.SecretTypeServiceAccountToken && s.Annotations[corev1.ServiceAccountNameKey] == run {
			if s.Annotations[corev1.ServiceAccountUIDKey] != string(sa.UID) || s.UID == "" || s.ResourceVersion == "" || s.DeletionTimestamp != nil || len(s.Finalizers) != 0 {
				return fail()
			}
			legacy = append(legacy, model.IdentityRotationSecret{Name: s.Name, UID: string(s.UID), ResourceVersion: s.ResourceVersion})
			seen[s.Name] = true
		}
	}
	for _, ref := range sa.Secrets {
		if !seen[ref.Name] {
			return fail()
		}
	}
	var pol v1alpha1.PhorvexPolicy
	if r.Get(ctx, client.ObjectKey{Namespace: cfg.Namespace, Name: cfg.PolicyName}, &pol) != nil || string(pol.UID) != cfg.PolicyUID ||
		pol.Generation <= 0 || pol.Status.ObservedGeneration != pol.Generation || (wantGeneration > 0 && pol.Generation != wantGeneration) ||
		pol.DeletionTimestamp != nil || pol.Spec.IsDryRun() || !pol.Spec.ActionEnabled(v1alpha1.ActionType(model.ActionIdentityRotate)) {
		return fail()
	}
	selector, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil || selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) {
		return fail()
	}
	if active {
		var marker corev1.ConfigMap
		if r.Get(ctx, client.ObjectKey{Namespace: cfg.Namespace, Name: run}, &marker) != nil || marker.Data[MarkerKeyPodUID] != uid || marker.Data[MarkerKeySAUID] != string(sa.UID) || marker.Data[MarkerKeyProducer] != MarkerProducer {
			return fail()
		}
		at, err := time.Parse(time.RFC3339Nano, marker.Data[MarkerKeyLandedAt])
		if err != nil || time.Since(at) < 0 || time.Since(at) > MarkerMaxAge {
			return fail()
		}
	}
	out.Pod = &pod
	out.Account = &sa
	out.Projection = &model.PodBoundKubeAPIAuthProjection{PodUID: uid, PodResourceVersion: pod.ResourceVersion, ServiceAccountName: run, ServiceAccountUID: string(sa.UID), VolumeName: "api", MountedContainer: "workload", AudienceSource: "kube-apiserver-default", EvidenceSource: "admitted-pod-and-serviceaccount"}
	out.Observation = &model.IdentityRotationObservation{Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID, PodName: name, PodUID: uid, PodResourceVersion: pod.ResourceVersion, ServiceAccountName: run, ServiceAccountUID: string(sa.UID), ServiceAccountResourceVersion: sa.ResourceVersion, PodInventoryVersion: pods.ResourceVersion, PolicyName: cfg.PolicyName, PolicyUID: cfg.PolicyUID, PolicyGeneration: pol.Generation, DedicatedServiceAccount: true, ExternalTokenTheftOnly: true, FederatedIdentityAbsent: false, LegacyTokenInventoryComplete: true, LegacyTokenSecrets: legacy, EvidenceSource: "validated-dedicated-sa-credential"}
	return out, nil
}
