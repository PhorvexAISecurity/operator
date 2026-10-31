package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/identityfixture"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const attackCatalogCorrelationAnnotation = "phorvex.ai/attack-catalogue-run"

type identityCatalogFixture struct {
	Namespace, PodName, PodUID, ServiceAccountName, ServiceAccountUID string
	PolicyName, PolicyUID                                             string
	PolicyGeneration                                                  int64
	ReactiveOnly                                                      bool
	Credential, Username                                              string
}

type identityCatalogSignal struct {
	Name, UID, Creator string
	CreatedAt          time.Time
}

type identityCatalogCluster interface {
	Prepare(context.Context) (identityCatalogFixture, error)
	CreateMarker(context.Context, identityCatalogFixture, time.Time) (string, error)
	CreateSignal(context.Context, attackcatalog.Entry, identityCatalogFixture, string) (identityCatalogSignal, error)
	Physical(context.Context, identityCatalogFixture) (AttackCatalogPhysicalResult, error)
	Cleanup(context.Context, identityCatalogFixture, identityCatalogSignal, string) AttackCatalogCleanupResult
}

type kubernetesIdentityCatalogCluster struct {
	profile identityfixture.Profile
	kube    kubernetes.Interface
	dynamic dynamic.Interface
	client  ctrlclient.Client
}

func newKubernetesIdentityCatalogCluster(cfg Config, profile identityfixture.Profile) (identityCatalogCluster, error) {
	var rc *rest.Config
	if cfg.ExperimentRESTConfig != nil {
		rc = rest.CopyConfig(cfg.ExperimentRESTConfig)
	} else {
		var err error
		rc, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.New("in-cluster identity catalogue authority unavailable")
		}
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, errors.New("identity catalogue Kubernetes client unavailable")
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, errors.New("identity catalogue event client unavailable")
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err = add(scheme); err != nil {
			return nil, errors.New("identity catalogue scheme unavailable")
		}
	}
	reader, err := ctrlclient.New(rc, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, errors.New("identity catalogue fixture client unavailable")
	}
	return &kubernetesIdentityCatalogCluster{profile: profile, kube: kube, dynamic: dyn, client: reader}, nil
}

func (k *kubernetesIdentityCatalogCluster) Prepare(ctx context.Context) (identityCatalogFixture, error) {
	p := k.profile
	if err := p.Validate(); err != nil {
		return identityCatalogFixture{}, errors.New("reviewed identity fixture profile is invalid")
	}
	pods, err := k.kube.CoreV1().Pods(p.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: identityfixture.Label + "=" + p.PolicyName, Limit: 2,
	})
	if err != nil || pods.Continue != "" || len(pods.Items) != 1 {
		return identityCatalogFixture{}, errors.New("identity fixture must have exactly one selected Pod")
	}
	pod := &pods.Items[0]
	// Bind this run to the generation the pinned-UID policy actually reports now, rather than a
	// static profile pin that drifts on every re-apply. wantGeneration==0 accepts the live, fully
	// reconciled generation; boundGeneration then pins the rest of the run (marker + physical).
	observed, err := identityfixture.ObserveKubernetesAt(ctx, k.client, p, pod.Name, string(pod.UID), false, 0)
	if err != nil {
		return identityCatalogFixture{}, err
	}
	boundGeneration := observed.Observation.PolicyGeneration
	var policy v1alpha1.PhorvexPolicy
	if err = k.client.Get(ctx, ctrlclient.ObjectKey{Namespace: p.Namespace, Name: p.PolicyName}, &policy); err != nil ||
		string(policy.UID) != p.PolicyUID || policy.Generation != boundGeneration ||
		policy.Status.ObservedGeneration != policy.Generation ||
		policy.Spec.EffectiveMode() != v1alpha1.ModeActive || !policy.Spec.Triggers.EventDriven {
		return identityCatalogFixture{}, errors.New("identity fixture policy is not the pinned active event-driven policy")
	}
	if _, err = k.kube.CoreV1().ConfigMaps(p.Namespace).Get(ctx, observed.Observation.ServiceAccountName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		return identityCatalogFixture{}, errors.New("identity fixture marker is not clean; reconcile before launch")
	}
	expiration := int64(3600)
	token, err := k.kube.CoreV1().ServiceAccounts(p.Namespace).CreateToken(ctx, observed.Observation.ServiceAccountName,
		&authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &expiration}}, metav1.CreateOptions{})
	if err != nil || strings.TrimSpace(token.Status.Token) == "" {
		return identityCatalogFixture{}, errors.New("bounded identity fixture credential could not be minted")
	}
	authenticated, username, err := k.review(ctx, token.Status.Token)
	wantUser := "system:serviceaccount:" + p.Namespace + ":" + observed.Observation.ServiceAccountName
	if err != nil || !authenticated || username != wantUser {
		return identityCatalogFixture{}, errors.New("identity fixture credential did not authenticate as the pinned ServiceAccount")
	}
	return identityCatalogFixture{Namespace: p.Namespace, PodName: pod.Name, PodUID: string(pod.UID),
		ServiceAccountName: observed.Observation.ServiceAccountName, ServiceAccountUID: observed.Observation.ServiceAccountUID,
		PolicyName: p.PolicyName, PolicyUID: p.PolicyUID, PolicyGeneration: boundGeneration,
		ReactiveOnly: policy.Spec.Triggers.ReactiveOnly, Credential: token.Status.Token, Username: username}, nil
}

func (k *kubernetesIdentityCatalogCluster) review(ctx context.Context, token string) (bool, string, error) {
	review, err := k.kube.AuthenticationV1().TokenReviews().Create(ctx,
		&authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token}}, metav1.CreateOptions{})
	if err != nil {
		return false, "", err
	}
	return review.Status.Authenticated, review.Status.User.Username, nil
}

func (k *kubernetesIdentityCatalogCluster) CreateMarker(ctx context.Context, f identityCatalogFixture, landed time.Time) (string, error) {
	marker := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: f.ServiceAccountName, Namespace: f.Namespace,
		Labels: map[string]string{"phorvex.ai/redteam": "true"}}, Data: map[string]string{
		identityfixture.MarkerKeyPodUID: f.PodUID, identityfixture.MarkerKeySAUID: f.ServiceAccountUID,
		identityfixture.MarkerKeyProducer: identityfixture.MarkerProducer,
		identityfixture.MarkerKeyLandedAt: landed.UTC().Format(time.RFC3339Nano),
	}}
	created, err := k.kube.CoreV1().ConfigMaps(f.Namespace).Create(ctx, marker, metav1.CreateOptions{})
	if err != nil || created.UID == "" {
		return "", errors.New("identity fixture positive-control marker creation failed")
	}
	// Enforce the generation captured at preflight: a policy edit between preflight and the stolen
	// bearer landing invalidates the positive-control marker instead of silently re-binding.
	if _, err = identityfixture.ObserveKubernetesAt(ctx, k.client, k.profile, f.PodName, f.PodUID, true, f.PolicyGeneration); err != nil {
		uid := created.UID
		_ = k.kube.CoreV1().ConfigMaps(f.Namespace).Delete(ctx, created.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		return "", errors.New("identity fixture marker did not satisfy the reviewed observation contract")
	}
	return string(created.UID), nil
}

func (k *kubernetesIdentityCatalogCluster) CreateSignal(ctx context.Context, entry attackcatalog.Entry, f identityCatalogFixture, runID string) (identityCatalogSignal, error) {
	if entry.ID != attackcatalog.FirstID || entry.EventType != model.AttackVectorPodBoundAPIAuth || entry.ExpectedAction != string(model.ActionIdentityRotate) {
		return identityCatalogSignal{}, errors.New("catalogue entry has no identity signal adapter")
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return identityCatalogSignal{}, errors.New("signal identity generation failed")
	}
	name := "catalog-aml-t0012-" + hex.EncodeToString(random)
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{
			"name":        name,
			"labels":      map[string]any{"phorvex.ai/redteam": "true", "phorvex.ai/catalogue-id": catalogueIDLabelValue(entry.ID)},
			"annotations": map[string]any{model.ConsoleTargetPodUIDAnnotation: f.PodUID, attackCatalogCorrelationAnnotation: runID, catalogueIDAnnotationKey: entry.ID},
		},
		"spec": map[string]any{
			"description": entry.Description, "targets": []any{f.Namespace + "/" + f.PodName},
			"rule": map[string]any{"type": entry.EventType, "threatLevel": "critical", "source": "console-catalogue"},
		},
	}}
	created, err := k.dynamic.Resource(securityEventGVR).Create(ctx, object, metav1.CreateOptions{})
	if err != nil {
		// Retain the server-generated name so cleanup can prove that an
		// ambiguous create did not leave an unbound object behind.
		return identityCatalogSignal{Name: name}, errors.New("identity catalogue signal admission failed")
	}
	if created.GetUID() == "" {
		return identityCatalogSignal{Name: name}, errors.New("identity catalogue signal admission returned no stable identity")
	}
	creator := created.GetAnnotations()["phorvex.ai/creator-identity"]
	admitted := identityCatalogSignal{Name: name, UID: string(created.GetUID()), Creator: creator, CreatedAt: created.GetCreationTimestamp().Time}
	if admitted.CreatedAt.IsZero() {
		return admitted, errors.New("identity catalogue signal admission returned no creation time")
	}
	targets, _, _ := unstructured.NestedStringSlice(created.Object, "spec", "targets")
	typeName, _, _ := unstructured.NestedString(created.Object, "spec", "rule", "type")
	if created.GetName() != name || creator != eventtrust.Injector() || created.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != f.PodUID ||
		created.GetAnnotations()[attackCatalogCorrelationAnnotation] != runID || !slices.Equal(targets, []string{f.Namespace + "/" + f.PodName}) || typeName != entry.EventType {
		uid := created.GetUID()
		_ = k.dynamic.Resource(securityEventGVR).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		return admitted, errors.New("identity catalogue signal identity or target admission differs")
	}
	return admitted, nil
}

func (k *kubernetesIdentityCatalogCluster) Physical(ctx context.Context, f identityCatalogFixture) (AttackCatalogPhysicalResult, error) {
	result := AttackCatalogPhysicalResult{OldServiceAccountUID: f.ServiceAccountUID, PodUID: f.PodUID, CredentialAuthenticatedBefore: true}
	sa, err := k.kube.CoreV1().ServiceAccounts(f.Namespace).Get(ctx, f.ServiceAccountName, metav1.GetOptions{})
	if err != nil {
		return result, err
	}
	pod, err := k.kube.CoreV1().Pods(f.Namespace).Get(ctx, f.PodName, metav1.GetOptions{})
	if err != nil {
		return result, err
	}
	authenticated, _, err := k.review(ctx, f.Credential)
	if err != nil {
		return result, err
	}
	result.NewServiceAccountUID = string(sa.UID)
	result.CredentialAuthenticatedAfter = authenticated
	result.PodRetained = string(pod.UID) == f.PodUID && pod.Status.Phase == corev1.PodRunning && podReady(pod) && pod.DeletionTimestamp == nil && pod.Spec.ServiceAccountName == f.ServiceAccountName
	result.Validated = result.NewServiceAccountUID != "" && result.NewServiceAccountUID != result.OldServiceAccountUID &&
		!result.CredentialAuthenticatedAfter && result.PodRetained && sa.DeletionTimestamp == nil && sa.Labels[identityfixture.Label] == f.ServiceAccountName
	return result, nil
}

func (k *kubernetesIdentityCatalogCluster) Cleanup(ctx context.Context, f identityCatalogFixture, signal identityCatalogSignal, markerUID string) AttackCatalogCleanupResult {
	result := AttackCatalogCleanupResult{Attempted: true}
	problems := []string{}
	if signal.Name != "" && signal.UID != "" {
		uid := types.UID(signal.UID)
		err := k.dynamic.Resource(securityEventGVR).Delete(ctx, signal.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		if err == nil || apierrors.IsNotFound(err) {
			_, err = k.dynamic.Resource(securityEventGVR).Get(ctx, signal.Name, metav1.GetOptions{})
			result.EventDeleted = apierrors.IsNotFound(err)
		}
		if !result.EventDeleted {
			problems = append(problems, "exact SecurityEvent absence unverified")
		}
	} else if signal.Name == "" {
		result.EventDeleted = true
	} else {
		_, err := k.dynamic.Resource(securityEventGVR).Get(ctx, signal.Name, metav1.GetOptions{})
		result.EventDeleted = apierrors.IsNotFound(err)
		if !result.EventDeleted {
			problems = append(problems, "ambiguous SecurityEvent creation cannot be reconciled without an admitted UID")
		}
	}
	if markerUID != "" {
		uid := types.UID(markerUID)
		err := k.kube.CoreV1().ConfigMaps(f.Namespace).Delete(ctx, f.ServiceAccountName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		if err == nil || apierrors.IsNotFound(err) {
			_, err = k.kube.CoreV1().ConfigMaps(f.Namespace).Get(ctx, f.ServiceAccountName, metav1.GetOptions{})
			result.MarkerDeleted = apierrors.IsNotFound(err)
		}
		if !result.MarkerDeleted {
			problems = append(problems, "exact marker absence unverified")
		}
	} else {
		_, err := k.kube.CoreV1().ConfigMaps(f.Namespace).Get(ctx, f.ServiceAccountName, metav1.GetOptions{})
		result.MarkerDeleted = apierrors.IsNotFound(err)
		if !result.MarkerDeleted {
			problems = append(problems, "ambiguous marker creation cannot be reconciled without an admitted UID")
		}
	}
	result.Verified = result.EventDeleted && result.MarkerDeleted
	result.Reason = strings.Join(problems, "; ")
	return result
}

func identityServiceAccountObject(f identityCatalogFixture) string {
	return fmt.Sprintf("ServiceAccount/%s/%s", f.Namespace, f.ServiceAccountName)
}
