package console

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var k8sCatalogueSecurityEventGVR = schema.GroupVersionResource{
	Group: "amtd.r6security.com", Version: "v1beta1", Resource: "securityevents",
}

type kubernetesK8sCatalogueCluster struct {
	profile      k8sCatalogueProfile
	kube         kubernetes.Interface
	eventKube    kubernetes.Interface
	dynamic      dynamic.Interface
	eventDynamic dynamic.Interface
	// cleanupKube acts as the dedicated delete-only cleanup identity (impersonated) so the
	// removal of ACTUATOR-created quarantine artifacts never runs as the red-team attacks SA.
	// nil when no cleanup principal is configured (then quarantine preflight fails closed).
	cleanupKube kubernetes.Interface
	reader      ctrlclient.Client
	// actuatorIdentity / cleanupIdentity are the exact ServiceAccount usernames whose
	// actuation and cleanup grants the preflight proves with SubjectAccessReview. Empty
	// disables the catalogue (checked in Preflight) rather than silently skipping the proof.
	actuatorIdentity  string
	cleanupIdentity   string
	operatorNamespace string
}

func newKubernetesK8sCatalogueCluster(cfg Config, profile k8sCatalogueProfile) (k8sCatalogueCluster, error) {
	if err := profile.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.AttackCatalogOperatorNamespace) == "" {
		return nil, errors.New("Kubernetes catalogue operator namespace is not configured")
	}
	var rc *rest.Config
	if cfg.ExperimentRESTConfig != nil {
		rc = rest.CopyConfig(cfg.ExperimentRESTConfig)
	} else {
		var err error
		rc, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.New("in-cluster Kubernetes catalogue authority is unavailable")
		}
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, errors.New("Kubernetes catalogue client is unavailable")
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, errors.New("Kubernetes catalogue dynamic client is unavailable")
	}
	impersonated := rest.CopyConfig(rc)
	impersonated.Impersonate = rest.ImpersonationConfig{UserName: profile.DetectorIdentity}
	eventKube, err := kubernetes.NewForConfig(impersonated)
	if err != nil {
		return nil, errors.New("Kubernetes catalogue detector client is unavailable")
	}
	eventDyn, err := dynamic.NewForConfig(impersonated)
	if err != nil {
		return nil, errors.New("Kubernetes catalogue detector event client is unavailable")
	}
	// The cleanup identity is a dedicated delete-only ServiceAccount, impersonated ONLY to
	// undo actuator-created artifacts. The attacks SA never holds those verbs; it only holds
	// resourceName-pinned impersonate on this one SA (NO broad or actuator impersonation).
	var cleanupKube kubernetes.Interface
	if cfg.AttackCatalogCleanupPrincipal != "" {
		cleanupConfig := rest.CopyConfig(rc)
		cleanupConfig.Impersonate = rest.ImpersonationConfig{UserName: cfg.AttackCatalogCleanupPrincipal}
		if cleanupKube, err = kubernetes.NewForConfig(cleanupConfig); err != nil {
			return nil, errors.New("Kubernetes catalogue cleanup identity client is unavailable")
		}
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, discoveryv1.AddToScheme, networkingv1.AddToScheme, v1alpha1.AddToScheme} {
		if err = add(scheme); err != nil {
			return nil, errors.New("Kubernetes catalogue scheme is unavailable")
		}
	}
	reader, err := ctrlclient.New(rc, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, errors.New("Kubernetes catalogue authoritative reader is unavailable")
	}
	return &kubernetesK8sCatalogueCluster{profile: profile, kube: kube, eventKube: eventKube,
		dynamic: dyn, eventDynamic: eventDyn, cleanupKube: cleanupKube, reader: reader,
		actuatorIdentity: cfg.AttackCatalogActuatorPrincipal, cleanupIdentity: cfg.AttackCatalogCleanupPrincipal,
		operatorNamespace: cfg.AttackCatalogOperatorNamespace}, nil
}

type k8sCatalogueAccess struct {
	// kube is the client the review is issued through (always the attacks SA, which holds
	// self/subjectaccessreviews create). user empty => SelfSubjectAccessReview (does the
	// attacks SA hold this?); user set => SubjectAccessReview naming that principal (does the
	// actuator/cleanup identity hold this?), so an actuation verb is proven against the
	// defender identity and never granted to the red-team SA.
	kube        kubernetes.Interface
	user        string
	verb        string
	group       string
	resource    string
	subresource string
	namespace   string
	name        string
}

func requireK8sCatalogueAccess(ctx context.Context, checks ...k8sCatalogueAccess) error {
	for _, check := range checks {
		attrs := &authorizationv1.ResourceAttributes{Verb: check.verb, Group: check.group,
			Resource: check.resource, Subresource: check.subresource, Namespace: check.namespace, Name: check.name}
		var allowed, denied bool
		var err error
		if check.user == "" {
			var review *authorizationv1.SelfSubjectAccessReview
			review, err = check.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx,
				&authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: attrs}}, metav1.CreateOptions{})
			if review != nil {
				allowed, denied = review.Status.Allowed, review.Status.Denied
			}
		} else {
			var review *authorizationv1.SubjectAccessReview
			review, err = check.kube.AuthorizationV1().SubjectAccessReviews().Create(ctx,
				&authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: check.user, ResourceAttributes: attrs}}, metav1.CreateOptions{})
			if review != nil {
				allowed, denied = review.Status.Allowed, review.Status.Denied
			}
		}
		if err != nil || !allowed || denied {
			who := "attacks service"
			if check.user != "" {
				who = check.user
			}
			resource := check.resource
			if check.subresource != "" {
				resource += "/" + check.subresource
			}
			if check.name != "" {
				resource += "/" + check.name
			}
			return fmt.Errorf("Kubernetes catalogue preflight: %s lacks %s %s/%s in %q", who, check.verb, check.group, resource, check.namespace)
		}
	}
	return nil
}

func (k *kubernetesK8sCatalogueCluster) Preflight(ctx context.Context, entry attackcatalog.Entry, profile k8sCatalogueProfile) (k8sCatalogueFixture, error) {
	if err := validateK8sCatalogueBinding(entry, profile); err != nil || profile.Key != k.profile.Key {
		return k8sCatalogueFixture{}, errors.New("Kubernetes catalogue cluster received a substituted fixed profile")
	}
	// The actuation/remediation verbs are proven against the defender identities, never
	// self-checked against the red-team attacks SA. Without a configured actuator (and, for
	// quarantine, a configured cleanup identity) the preflight fails closed rather than
	// silently skipping the trust-boundary proof.
	if k.actuatorIdentity == "" {
		return k8sCatalogueFixture{}, errors.New("Kubernetes catalogue actuator identity is not configured for the reactive remediation preflight")
	}
	if profile.Family == k8sCatalogueFamilyQuarantine && (k.cleanupIdentity == "" || k.cleanupKube == nil) {
		return k8sCatalogueFixture{}, errors.New("Kubernetes catalogue quarantine cleanup identity is not configured")
	}
	// Read the target Namespace only after proving that cluster-scoped read. Its immutable UID
	// binds the exact quarantine ledger name used by resourceName-scoped RBAC below.
	if err := requireK8sCatalogueAccess(ctx, k8sCatalogueAccess{kube: k.kube, verb: "get", resource: "namespaces", name: profile.Namespace}); err != nil {
		return k8sCatalogueFixture{}, err
	}
	ns, err := k.kube.CoreV1().Namespaces().Get(ctx, profile.Namespace, metav1.GetOptions{})
	if err != nil || ns.UID == "" || ns.DeletionTimestamp != nil {
		return k8sCatalogueFixture{}, errors.New("fixed Kubernetes catalogue namespace is unavailable or terminating")
	}
	// (1) The attacks SA's OWN fixture-lifecycle authority: reads of the fixed workload and
	// the lane event lifecycle. It holds NO actuation verb; those are proven below.
	checks := []k8sCatalogueAccess{
		{kube: k.kube, verb: "get", resource: "pods", namespace: profile.Namespace},
		{kube: k.kube, verb: "list", resource: "pods", namespace: profile.Namespace},
		{kube: k.kube, verb: "get", group: "apps", resource: "deployments", namespace: profile.Namespace},
		{kube: k.kube, verb: "get", group: "apps", resource: "replicasets", namespace: profile.Namespace},
		{kube: k.kube, verb: "get", resource: "services", namespace: profile.Namespace},
		{kube: k.kube, verb: "list", group: "discovery.k8s.io", resource: "endpointslices", namespace: profile.Namespace},
		{kube: k.kube, verb: "get", group: "networking.k8s.io", resource: "networkpolicies", namespace: profile.Namespace},
		{kube: k.kube, verb: "get", group: "phorvex.ai", resource: "phorvexpolicies", namespace: profile.Namespace},
		{kube: k.kube, verb: "get", group: k8sCatalogueSecurityEventGVR.Group, resource: k8sCatalogueSecurityEventGVR.Resource},
		{kube: k.kube, verb: "delete", group: k8sCatalogueSecurityEventGVR.Group, resource: k8sCatalogueSecurityEventGVR.Resource},
		{kube: k.eventKube, verb: "create", group: k8sCatalogueSecurityEventGVR.Group, resource: k8sCatalogueSecurityEventGVR.Resource},
	}
	// (2) The defender ACTUATOR identity holds the remediation verbs the brain will dispatch.
	switch profile.Family {
	case k8sCatalogueFamilyQuarantine:
		quarantineLedger := k8sQuarantineCapacityLedgerName(string(ns.UID))
		checks = append(checks,
			k8sCatalogueAccess{kube: k.kube, user: k.actuatorIdentity, verb: "update", resource: "pods", namespace: profile.Namespace},
			k8sCatalogueAccess{kube: k.kube, user: k.actuatorIdentity, verb: "create", group: "networking.k8s.io", resource: "networkpolicies", namespace: profile.Namespace},
			k8sCatalogueAccess{kube: k.kube, user: k.actuatorIdentity, verb: "update", resource: "configmaps", namespace: k.operatorNamespace},
			// The attacks SA reads only the two exact operator ledgers during the quarantine
			// capacity preflight/oracle; mutation stays on the actuator/cleanup identities.
			k8sCatalogueAccess{kube: k.kube, verb: "get", resource: "configmaps", namespace: k.operatorNamespace, name: "phorvex-shared-capacity"},
			k8sCatalogueAccess{kube: k.kube, verb: "get", resource: "configmaps", namespace: k.operatorNamespace, name: quarantineLedger},
		)
	default:
		// The pod-rotate / controller-stop families map to a native Pod Eviction.
		checks = append(checks,
			k8sCatalogueAccess{kube: k.kube, user: k.actuatorIdentity, verb: "create", resource: "pods", subresource: "eviction", namespace: profile.Namespace},
		)
	}
	// (3) The dedicated delete-only CLEANUP identity holds exactly the undo verbs used after a
	// quarantine. It can never create/isolate/evict, so it cannot itself remediate.
	if profile.Family == k8sCatalogueFamilyQuarantine {
		quarantineLedger := k8sQuarantineCapacityLedgerName(string(ns.UID))
		checks = append(checks,
			k8sCatalogueAccess{kube: k.kube, user: k.cleanupIdentity, verb: "delete", resource: "pods", namespace: profile.Namespace},
			k8sCatalogueAccess{kube: k.kube, user: k.cleanupIdentity, verb: "delete", group: "networking.k8s.io", resource: "networkpolicies", namespace: profile.Namespace},
			k8sCatalogueAccess{kube: k.kube, user: k.cleanupIdentity, verb: "update", resource: "configmaps", namespace: k.operatorNamespace, name: "phorvex-shared-capacity"},
			k8sCatalogueAccess{kube: k.kube, user: k.cleanupIdentity, verb: "update", resource: "configmaps", namespace: k.operatorNamespace, name: quarantineLedger},
		)
	}
	if err := requireK8sCatalogueAccess(ctx, checks...); err != nil {
		return k8sCatalogueFixture{}, err
	}
	deployment, err := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
	if err != nil || deployment.UID == "" || deployment.DeletionTimestamp != nil || deployment.Status.ObservedGeneration < deployment.Generation ||
		deployment.Spec.Replicas == nil || *deployment.Spec.Replicas < int32(profile.MinReady) ||
		deployment.Status.AvailableReplicas < int32(profile.MinReady) || !exactDemoSelector(deployment.Spec.Selector) {
		return k8sCatalogueFixture{}, errors.New("fixed demo-api Deployment is not the reviewed available three-replica profile")
	}
	service, err := k.kube.CoreV1().Services(profile.Namespace).Get(ctx, profile.Service, metav1.GetOptions{})
	if err != nil || service.UID == "" || service.DeletionTimestamp != nil || len(service.Spec.Selector) != 1 ||
		service.Spec.Selector["app.kubernetes.io/name"] != "demo-api" {
		return k8sCatalogueFixture{}, errors.New("fixed demo-api Service differs from the reviewed selector profile")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err = k.reader.Get(ctx, ctrlclient.ObjectKey{Namespace: profile.Namespace, Name: profile.PolicyName}, policy); err != nil ||
		policy.UID == "" || policy.Generation < 1 || policy.DeletionTimestamp != nil || policy.EffectiveTenant() != profile.Namespace ||
		!exactDemoSelector(&policy.Spec.Selector) || !policy.Spec.Triggers.EventDriven ||
		policy.Spec.EffectiveMinAvailableReplicas() != profile.MinAvailable || !sameActionSet(policy.Spec.Actions.Enabled, profile.EnabledActions) {
		return k8sCatalogueFixture{}, errors.New("fixed PhorvexPolicy differs from the reviewed family profile")
	}
	execution := AttackCatalogExecutionMode(policy.Spec.EffectiveMode())
	if execution != AttackCatalogExecutionActive && execution != AttackCatalogExecutionDryRun {
		return k8sCatalogueFixture{}, errors.New("fixed PhorvexPolicy execution mode is invalid")
	}
	pods, err := k.kube.CoreV1().Pods(profile.Namespace).List(ctx, metav1.ListOptions{LabelSelector: profile.Selector})
	if err != nil {
		return k8sCatalogueFixture{}, errors.New("fixed demo-api Pod inventory is unavailable")
	}
	ready := make([]k8sCataloguePodIdentity, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil || pod.UID == "" || !podReady(pod) || pod.Status.StartTime == nil || pod.Status.StartTime.IsZero() {
			continue
		}
		if err = k.podOwnedByDeployment(ctx, pod, deployment); err != nil {
			return k8sCatalogueFixture{}, err
		}
		ready = append(ready, k8sCataloguePodIdentity{Name: pod.Name, UID: string(pod.UID), StartTime: pod.Status.StartTime.Time})
	}
	if len(ready) < profile.MinReady {
		return k8sCatalogueFixture{}, fmt.Errorf("fixed demo-api profile requires at least %d Ready owned Pods", profile.MinReady)
	}
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].StartTime.Equal(ready[j].StartTime) {
			return ready[i].Name < ready[j].Name
		}
		return ready[i].StartTime.Before(ready[j].StartTime)
	})
	eligible := make([]k8sCataloguePodIdentity, 0, len(ready))
	now := time.Now().UTC()
	for _, pod := range ready {
		if !pod.StartTime.After(now) && now.Sub(pod.StartTime) >= profile.TargetMinAge {
			eligible = append(eligible, pod)
		}
	}
	if len(eligible) == 0 {
		return k8sCatalogueFixture{}, fmt.Errorf("fixed demo-api profile has no Ready target older than %s", profile.TargetMinAge)
	}
	target := eligible[0]
	currentTarget, err := k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
	if err != nil || string(currentTarget.UID) != target.UID || currentTarget.DeletionTimestamp != nil ||
		currentTarget.Labels["phorvex.ai/quarantined"] != "" || currentTarget.Annotations["phorvex.ai/quarantine-snapshot"] != "" {
		return k8sCatalogueFixture{}, errors.New("selected fixed demo-api target changed or already carries a quarantine effect")
	}
	npName := k8sQuarantineNetworkPolicyName(target.UID)
	if _, err = k.kube.NetworkingV1().NetworkPolicies(profile.Namespace).Get(ctx, npName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		return k8sCatalogueFixture{}, errors.New("selected target already has an exact-name quarantine NetworkPolicy")
	}
	if profile.Family == k8sCatalogueFamilyQuarantine {
		if err = k.preflightK8sQuarantineCapacity(ctx, profile, string(ns.UID)); err != nil {
			return k8sCatalogueFixture{}, err
		}
	}
	endpointUIDs, err := k.serviceEndpointUIDs(ctx, profile, string(service.UID))
	if err != nil {
		return k8sCatalogueFixture{}, err
	}
	for _, pod := range ready {
		if !endpointUIDs[pod.UID] {
			return k8sCatalogueFixture{}, errors.New("Ready demo-api baseline is not fully represented by Ready Service endpoints")
		}
	}
	siblings := make([]string, 0, len(ready)-1)
	for _, pod := range ready {
		if pod.UID != target.UID {
			siblings = append(siblings, pod.UID)
		}
	}
	sort.Strings(siblings)
	return k8sCatalogueFixture{CatalogueID: entry.ID, ProfileKey: profile.Key, Namespace: profile.Namespace,
		NamespaceUID: string(ns.UID), DeploymentUID: string(deployment.UID), ServiceUID: string(service.UID),
		PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation,
		ExecutionMode: execution, ReactiveOnly: policy.Spec.Triggers.ReactiveOnly, Target: target,
		BaselineReadyPods: ready, SiblingUIDs: siblings, NetworkPolicyName: npName}, nil
}

func (k *kubernetesK8sCatalogueCluster) preflightK8sQuarantineCapacity(ctx context.Context, profile k8sCatalogueProfile, namespaceUID string) error {
	type capacityObject struct {
		name  string
		label string
		check func(string) bool
	}
	objects := []capacityObject{
		{name: k8sQuarantineCapacityLedgerName(namespaceUID), label: "phorvex.ai/quarantine-capacity", check: func(raw string) bool {
			var ledger k8sQuarantineCapacityLedger
			return json.Unmarshal([]byte(raw), &ledger) == nil && ledger.Version == 1 && ledger.Namespace == profile.Namespace &&
				ledger.NamespaceUID == namespaceUID && ledger.Records != nil && len(ledger.Records) == 0
		}},
		{name: "phorvex-shared-capacity", label: "phorvex.ai/shared-capacity", check: func(raw string) bool {
			var ledger k8sSharedCapacityLedger
			return json.Unmarshal([]byte(raw), &ledger) == nil && ledger.Version == 1 && ledger.Records != nil && len(ledger.Records) == 0
		}},
	}
	for _, object := range objects {
		cm, err := k.kube.CoreV1().ConfigMaps(k.operatorNamespace).Get(ctx, object.name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil ||
			cm.Labels[object.label] != "v1" || !object.check(cm.Data["ledger"]) {
			return errors.New("fixed quarantine capacity ledgers are not in the reviewed empty preflight state")
		}
	}
	return nil
}

func exactDemoSelector(selector *metav1.LabelSelector) bool {
	return selector != nil && len(selector.MatchLabels) == 1 && len(selector.MatchExpressions) == 0 &&
		selector.MatchLabels["app.kubernetes.io/name"] == "demo-api"
}

func sameActionSet(got []v1alpha1.ActionType, want []string) bool {
	values := make([]string, 0, len(got))
	for _, action := range got {
		values = append(values, string(action))
	}
	if len(values) == 0 {
		values = []string{string(model.ActionRotate), string(model.ActionQuarantine)}
	}
	sort.Strings(values)
	wanted := slices.Clone(want)
	sort.Strings(wanted)
	return slices.Equal(values, wanted)
}

func (k *kubernetesK8sCatalogueCluster) podOwnedByDeployment(ctx context.Context, pod *corev1.Pod, deployment *appsv1.Deployment) error {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" || owner.UID == "" {
		return errors.New("fixed demo-api Pod is not controlled by one apps/v1 ReplicaSet")
	}
	rs, err := k.kube.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil || rs.UID != owner.UID || rs.DeletionTimestamp != nil {
		return errors.New("fixed demo-api ReplicaSet identity is unavailable")
	}
	parent := metav1.GetControllerOf(rs)
	if parent == nil || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" ||
		parent.Name != deployment.Name || parent.UID != deployment.UID {
		return errors.New("fixed demo-api Pod does not belong to the pinned Deployment UID")
	}
	return nil
}

func (k *kubernetesK8sCatalogueCluster) CreateSignal(ctx context.Context, entry attackcatalog.Entry, profile k8sCatalogueProfile, fixture k8sCatalogueFixture, runID string) (k8sCatalogueSignal, error) {
	if err := fixture.validate(entry, profile); err != nil || profile.Key != k.profile.Key || strings.TrimSpace(runID) == "" {
		return k8sCatalogueSignal{}, errors.New("Kubernetes catalogue signal binding changed after preflight")
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return k8sCatalogueSignal{}, errors.New("Kubernetes catalogue signal identity generation failed")
	}
	name := "catalog-" + k8sCatalogueSlug(entry.ID, 40) + "-" + hex.EncodeToString(random)
	annotations := map[string]any{
		model.ConsoleTargetPodUIDAnnotation: fixture.Target.UID,
		"phorvex.ai/target-pod-uid":         fixture.Target.UID,
		attackCatalogCorrelationAnnotation:  runID,
		catalogueIDAnnotationKey:            entry.ID,
	}
	if profile.Family == k8sCatalogueFamilyQuarantine {
		uidPrefix := fixture.Target.UID
		if len(uidPrefix) > 8 {
			uidPrefix = uidPrefix[:8]
		}
		outcome := model.ProtectedOutcome{ID: "rt-" + strings.ToLower(entry.ID) + "-" + uidPrefix,
			PolicyUID: fixture.PolicyUID, DecisionAsset: fixture.Namespace + "/" + fixture.Target.Name,
			DecisionAssetUID: fixture.Target.UID, ProtectedAsset: "demo-api customer PII store", Version: "v1",
			Portion: "all-records", Property: "confidentiality", Outcome: "unauthorized-disclosure",
			ClassBasis: "detector-asserted-disclosure-scope", ScopeBasis: "policy-scope-resolved",
			LossState: "at-risk", StateBasis: "active-exfiltration-signal-observed",
			RequiredKeys: []string{"pod|" + fixture.Namespace + "/" + fixture.Target.Name + "|networkIdentity"},
			MappingBasis: "recon-network-identity-representation", MappingComplete: true}
		raw, err := json.Marshal([]model.ProtectedOutcome{outcome})
		if err != nil {
			return k8sCatalogueSignal{}, errors.New("quarantine protected outcome encoding failed")
		}
		annotations["phorvex.ai/protected-outcomes-v1"] = string(raw)
	}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": name,
			"labels": map[string]any{"phorvex.ai/redteam": "true", "phorvex.ai/catalogue-id": catalogueIDLabelValue(entry.ID),
				"phorvex.ai/catalogue-family": profile.Family},
			"annotations": annotations},
		"spec": map[string]any{"description": entry.Description, "targets": []any{fixture.Namespace + "/" + fixture.Target.Name},
			"rule": map[string]any{"type": entry.EventType, "threatLevel": "critical", "source": profile.Lane + "-attacks"}},
	}}
	created, err := k.eventDynamic.Resource(k8sCatalogueSecurityEventGVR).Create(ctx, object, metav1.CreateOptions{})
	if err != nil {
		return k8sCatalogueSignal{Name: name}, errors.New("Kubernetes catalogue signal admission failed")
	}
	signal := k8sCatalogueSignal{Name: created.GetName(), UID: string(created.GetUID()),
		Creator: created.GetAnnotations()[eventtrust.CreatorIdentityAnnotation], CreatedAt: created.GetCreationTimestamp().Time}
	targets, _, _ := unstructured.NestedStringSlice(created.Object, "spec", "targets")
	eventType, _, _ := unstructured.NestedString(created.Object, "spec", "rule", "type")
	source, _, _ := unstructured.NestedString(created.Object, "spec", "rule", "source")
	level, _, _ := unstructured.NestedString(created.Object, "spec", "rule", "threatLevel")
	description, _, _ := unstructured.NestedString(created.Object, "spec", "description")
	valid := signal.Name == name && signal.UID != "" && !signal.CreatedAt.IsZero() && signal.Creator == profile.DetectorIdentity &&
		created.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] == fixture.Target.UID &&
		created.GetAnnotations()["phorvex.ai/target-pod-uid"] == fixture.Target.UID &&
		created.GetAnnotations()[attackCatalogCorrelationAnnotation] == runID &&
		created.GetAnnotations()[catalogueIDAnnotationKey] == entry.ID &&
		created.GetLabels()["phorvex.ai/catalogue-id"] == catalogueIDLabelValue(entry.ID) && created.GetLabels()["phorvex.ai/catalogue-family"] == profile.Family &&
		slices.Equal(targets, []string{fixture.Namespace + "/" + fixture.Target.Name}) && eventType == entry.EventType &&
		source == profile.Lane+"-attacks" && level == "critical" && description == entry.Description
	if profile.Family == k8sCatalogueFamilyQuarantine && created.GetAnnotations()["phorvex.ai/protected-outcomes-v1"] != annotations["phorvex.ai/protected-outcomes-v1"] {
		valid = false
	}
	if !valid {
		uid := created.GetUID()
		_ = k.dynamic.Resource(k8sCatalogueSecurityEventGVR).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		return signal, errors.New("Kubernetes catalogue signal admission identity or profile differs")
	}
	return signal, nil
}

func k8sCatalogueSlug(value string, limit int) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(value) {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if valid {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
		if b.Len() >= limit {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

func k8sQuarantineNetworkPolicyName(uid string) string {
	sum := sha256.Sum256([]byte(uid))
	return fmt.Sprintf("phorvex-quarantine-%x", sum[:])
}

func (k *kubernetesK8sCatalogueCluster) Physical(ctx context.Context, entry attackcatalog.Entry, profile k8sCatalogueProfile, fixture k8sCatalogueFixture, signal k8sCatalogueSignal) (AttackCatalogPhysicalResult, error) {
	result := AttackCatalogPhysicalResult{Oracle: profile.Oracle}
	if err := fixture.validate(entry, profile); err != nil || signal.UID == "" || signal.Creator != profile.DetectorIdentity {
		return result, errors.New("Kubernetes catalogue physical read binding changed")
	}
	deployment, err := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
	if err != nil || string(deployment.UID) != fixture.DeploymentUID || deployment.DeletionTimestamp != nil ||
		deployment.Status.ObservedGeneration < deployment.Generation {
		return result, errors.New("fixed Deployment identity changed during physical validation")
	}
	service, err := k.kube.CoreV1().Services(profile.Namespace).Get(ctx, profile.Service, metav1.GetOptions{})
	if err != nil || string(service.UID) != fixture.ServiceUID || service.DeletionTimestamp != nil {
		return result, errors.New("fixed Service identity changed during physical validation")
	}
	policy := &v1alpha1.PhorvexPolicy{}
	if err = k.reader.Get(ctx, ctrlclient.ObjectKey{Namespace: fixture.Namespace, Name: fixture.PolicyName}, policy); err != nil ||
		string(policy.UID) != fixture.PolicyUID || policy.Generation != fixture.PolicyGeneration || policy.DeletionTimestamp != nil ||
		AttackCatalogExecutionMode(policy.Spec.EffectiveMode()) != fixture.ExecutionMode || policy.Spec.Triggers.ReactiveOnly != fixture.ReactiveOnly ||
		!policy.Spec.Triggers.EventDriven || !sameActionSet(policy.Spec.Actions.Enabled, profile.EnabledActions) {
		return result, errors.New("fixed policy epoch or runtime mode changed during physical validation")
	}
	allPods, err := k.kube.CoreV1().Pods(profile.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return result, err
	}
	ready := make([]k8sCataloguePodIdentity, 0)
	var target *corev1.Pod
	for i := range allPods.Items {
		pod := &allPods.Items[i]
		if string(pod.UID) == fixture.Target.UID {
			target = pod.DeepCopy()
		}
		if pod.DeletionTimestamp == nil && podReady(pod) && labels.SelectorFromSet(labels.Set{"app.kubernetes.io/name": "demo-api"}).Matches(labels.Set(pod.Labels)) && pod.Status.StartTime != nil {
			if k.podOwnedByDeployment(ctx, pod, deployment) == nil {
				ready = append(ready, k8sCataloguePodIdentity{Name: pod.Name, UID: string(pod.UID), StartTime: pod.Status.StartTime.Time})
			}
		}
	}
	readyUIDs := map[string]bool{}
	for _, pod := range ready {
		readyUIDs[pod.UID] = true
	}
	baseline := map[string]bool{}
	for _, pod := range fixture.BaselineReadyPods {
		baseline[pod.UID] = true
	}
	replacements := []string{}
	for uid := range readyUIDs {
		if !baseline[uid] {
			replacements = append(replacements, uid)
		}
	}
	sort.Strings(replacements)
	endpointSet, err := k.serviceEndpointUIDs(ctx, profile, fixture.ServiceUID)
	if err != nil {
		return result, err
	}
	serviceReady := true
	for uid := range readyUIDs {
		serviceReady = serviceReady && endpointSet[uid]
	}
	siblingsIntact := true
	for _, uid := range fixture.SiblingUIDs {
		siblingsIntact = siblingsIntact && readyUIDs[uid] && endpointSet[uid]
	}
	replacementReady := false
	for _, uid := range replacements {
		replacementReady = replacementReady || endpointSet[uid]
	}
	endpointUIDs := make([]string, 0, len(endpointSet))
	for uid := range endpointSet {
		endpointUIDs = append(endpointUIDs, uid)
	}
	sort.Strings(endpointUIDs)
	evidence := k8sCataloguePhysicalEvidence{Schema: k8sCataloguePhysicalSchema, CatalogueID: entry.ID,
		Profile: profile.Key, Family: profile.Family, Lane: profile.Lane, Namespace: profile.Namespace,
		LogicalAction: profile.ExpectedAction, NativeAction: profile.NativeAction, PolicyName: fixture.PolicyName,
		PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGeneration, DeploymentUID: fixture.DeploymentUID,
		ServiceUID: fixture.ServiceUID, TargetName: fixture.Target.Name, TargetUID: fixture.Target.UID,
		ReadyReplicas: len(ready), AvailableReplicas: int(deployment.Status.AvailableReplicas),
		SiblingUIDs: slices.Clone(fixture.SiblingUIDs), ReplacementUIDs: replacements, EndpointUIDs: endpointUIDs,
		AvailabilityHeld: len(ready) >= profile.MinAvailable && int(deployment.Status.AvailableReplicas) >= profile.MinAvailable && serviceReady,
		SiblingsIntact:   siblingsIntact, ReplacementReady: replacementReady,
		TargetEndpointAbsent: !endpointSet[fixture.Target.UID], TargetGone: target == nil}
	if profile.Family == k8sCatalogueFamilyQuarantine {
		np, npErr := k.kube.NetworkingV1().NetworkPolicies(profile.Namespace).Get(ctx, fixture.NetworkPolicyName, metav1.GetOptions{})
		if npErr == nil {
			evidence.NetworkPolicyName, evidence.NetworkPolicyUID = np.Name, string(np.UID)
			evidence.NetworkPolicyValid = validK8sQuarantineNetworkPolicy(np, fixture)
		}
		evidence.TargetQuarantined = target != nil && target.Name == fixture.Target.Name && target.DeletionTimestamp == nil &&
			target.Labels["phorvex.ai/quarantined"] == fixture.Target.UID && noControllerOwner(target.OwnerReferences)
	}
	evidenceRaw, err := json.Marshal(evidence)
	if err != nil {
		return result, err
	}
	result.Evidence = evidenceRaw
	if profile.Family == k8sCatalogueFamilyQuarantine {
		result.Validated = evidence.TargetQuarantined && !evidence.TargetGone && evidence.NetworkPolicyValid &&
			evidence.AvailabilityHeld && evidence.SiblingsIntact && evidence.ReplacementReady && evidence.TargetEndpointAbsent
	} else {
		result.Validated = evidence.TargetGone && evidence.AvailabilityHeld && evidence.SiblingsIntact &&
			evidence.ReplacementReady && evidence.TargetEndpointAbsent
	}
	return result, nil
}

func noControllerOwner(refs []metav1.OwnerReference) bool {
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller {
			return false
		}
	}
	return true
}

func validK8sQuarantineNetworkPolicy(np *networkingv1.NetworkPolicy, fixture k8sCatalogueFixture) bool {
	if np == nil || np.UID == "" || np.DeletionTimestamp != nil || np.Name != fixture.NetworkPolicyName ||
		np.Namespace != fixture.Namespace || np.Labels["app.kubernetes.io/managed-by"] != "phorvex" ||
		np.Labels["phorvex.ai/quarantine-of"] != fixture.Target.Name || len(np.OwnerReferences) != 1 ||
		len(np.Spec.PodSelector.MatchLabels) != 1 || len(np.Spec.PodSelector.MatchExpressions) != 0 ||
		np.Spec.PodSelector.MatchLabels["phorvex.ai/quarantined"] != fixture.Target.UID ||
		len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 || len(np.Spec.PolicyTypes) != 2 {
		return false
	}
	typesSeen := map[networkingv1.PolicyType]bool{}
	for _, policyType := range np.Spec.PolicyTypes {
		typesSeen[policyType] = true
	}
	ownerMatches := false
	for _, owner := range np.OwnerReferences {
		if owner.APIVersion == "v1" && owner.Kind == "Pod" && owner.Name == fixture.Target.Name && string(owner.UID) == fixture.Target.UID &&
			(owner.Controller == nil || !*owner.Controller) {
			ownerMatches = true
		}
	}
	return ownerMatches && typesSeen[networkingv1.PolicyTypeIngress] && typesSeen[networkingv1.PolicyTypeEgress]
}

func (k *kubernetesK8sCatalogueCluster) serviceEndpointUIDs(ctx context.Context, profile k8sCatalogueProfile, serviceUID string) (map[string]bool, error) {
	if serviceUID == "" {
		return nil, errors.New("fixed demo-api Service UID is unavailable")
	}
	slicesList, err := k.kube.DiscoveryV1().EndpointSlices(profile.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + profile.Service})
	if err != nil || len(slicesList.Items) == 0 {
		return nil, errors.New("fixed demo-api EndpointSlice inventory is unavailable")
	}
	uids := map[string]bool{}
	for _, slice := range slicesList.Items {
		owned := false
		for _, owner := range slice.OwnerReferences {
			owned = owned || owner.APIVersion == "v1" && owner.Kind == "Service" && owner.Name == profile.Service && string(owner.UID) == serviceUID
		}
		if slice.UID == "" || slice.DeletionTimestamp != nil || slice.Labels[discoveryv1.LabelServiceName] != profile.Service || !owned {
			return nil, errors.New("fixed demo-api EndpointSlice identity differs from the pinned Service UID")
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready {
				continue
			}
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.UID == "" ||
				(endpoint.TargetRef.Namespace != "" && endpoint.TargetRef.Namespace != profile.Namespace) {
				continue
			}
			uids[string(endpoint.TargetRef.UID)] = true
		}
	}
	return uids, nil
}

func (k *kubernetesK8sCatalogueCluster) Cleanup(ctx context.Context, entry attackcatalog.Entry, profile k8sCatalogueProfile, fixture k8sCatalogueFixture, signal k8sCatalogueSignal, decisionID, runID string) AttackCatalogCleanupResult {
	result := AttackCatalogCleanupResult{Attempted: true}
	evidence := k8sCatalogueCleanupEvidence{Schema: k8sCatalogueCleanupSchema, CatalogueID: entry.ID, RunID: runID,
		Profile: profile.Key, Family: profile.Family, TargetUID: fixture.Target.UID, SignalName: signal.Name, SignalUID: signal.UID}
	problems := []string{}
	if err := fixture.validate(entry, profile); err != nil || profile.Key != k.profile.Key {
		problems = append(problems, "exact cleanup fixture binding changed")
	} else {
		evidence.EventAbsent = k.cleanupK8sCatalogueEvent(ctx, entry, fixture, signal, runID)
		if !evidence.EventAbsent {
			problems = append(problems, "exact SecurityEvent absence is unverified")
		}
		if profile.Family == k8sCatalogueFamilyQuarantine {
			evidence.FamilyArtifactsAbsent = k.cleanupK8sQuarantineArtifacts(ctx, fixture)
			evidence.CapacityRecordsAbsent = k.cleanupK8sQuarantineCapacity(ctx, fixture, decisionID)
			if !evidence.FamilyArtifactsAbsent {
				problems = append(problems, "exact quarantined Pod or deny-all NetworkPolicy remains")
			}
			if !evidence.CapacityRecordsAbsent {
				problems = append(problems, "exact quarantine capacity reservation remains or changed identity")
			}
		} else {
			evidence.FamilyArtifactsAbsent = k.rotationCleanupSafe(ctx, fixture)
			evidence.CapacityRecordsAbsent = true
			if !evidence.FamilyArtifactsAbsent {
				problems = append(problems, "target Pod termination state is unresolved")
			}
		}
		evidence.ReadyRestored = k.waitK8sReadyRestored(ctx, profile, fixture)
		if !evidence.ReadyRestored {
			problems = append(problems, "fixed demo-api Ready capacity did not return to its baseline")
		}
	}
	result.EventDeleted = evidence.EventAbsent
	result.MarkerDeleted = evidence.FamilyArtifactsAbsent && evidence.CapacityRecordsAbsent
	result.Verified = result.EventDeleted && result.MarkerDeleted && evidence.ReadyRestored
	result.Reason = strings.Join(problems, "; ")
	result.Evidence, _ = json.Marshal(evidence)
	return result
}

// ReconcileRetrySafety is deliberately read-only. It proves that the prior
// run's exact SecurityEvent and family artifacts are absent, that quarantine
// ledgers are globally empty, and that the fixed workload is healthy enough for
// another run. It does not repair anything and cannot upgrade the old verdict.
func (k *kubernetesK8sCatalogueCluster) ReconcileRetrySafety(ctx context.Context, entry attackcatalog.Entry, profile k8sCatalogueProfile, persisted AttackCatalogResult) (AttackCatalogRetrySafety, error) {
	safety := AttackCatalogRetrySafety{CheckedAt: time.Now().UTC()}
	if err := validateK8sCatalogueBinding(entry, profile); err != nil || k == nil || profile.Key != k.profile.Key ||
		persisted.CatalogueID != entry.ID || persisted.Family != profile.Family || persisted.RunID == "" ||
		persisted.Signal.Name == "" || persisted.Signal.TargetUID == "" {
		return safety, errors.New("Kubernetes catalogue retry reconciliation identity is incomplete")
	}
	var physical k8sCataloguePhysicalEvidence
	if err := decodeStrictK8sCatalogueEvidence(persisted.PhysicalValidation.Evidence, &physical); err != nil {
		return safety, fmt.Errorf("Kubernetes catalogue retry physical evidence: %w", err)
	}
	if physical.Schema != k8sCataloguePhysicalSchema || physical.CatalogueID != entry.ID || physical.Profile != profile.Key ||
		physical.Family != profile.Family || physical.Lane != profile.Lane || physical.Namespace != profile.Namespace ||
		physical.TargetName == "" || physical.TargetUID == "" || physical.TargetUID != persisted.Signal.TargetUID ||
		physical.PolicyName != profile.PolicyName || physical.PolicyUID == "" || physical.DeploymentUID == "" || physical.ServiceUID == "" {
		return safety, errors.New("Kubernetes catalogue retry physical identity differs from the fixed profile")
	}
	if _, err := k.dynamic.Resource(k8sCatalogueSecurityEventGVR).Get(ctx, persisted.Signal.Name, metav1.GetOptions{}); err == nil {
		safety.Reason = "run-owned SecurityEvent is still present"
		return safety, nil
	} else if !apierrors.IsNotFound(err) {
		return safety, errors.New("run-owned SecurityEvent absence is unverified")
	}

	// Preflight is itself read-only. In addition to workload and policy health it
	// proves that quarantine capacity ledgers contain zero records.
	fresh, err := k.Preflight(ctx, entry, profile)
	if err != nil {
		safety.Reason = "fixed Kubernetes fixture is not clean: " + err.Error()
		return safety, nil
	}
	if fresh.ExecutionMode != AttackCatalogExecutionActive || !fresh.ReactiveOnly {
		safety.Reason = "fixed Kubernetes fixture is not active reactive"
		return safety, nil
	}

	prior := fresh
	prior.Target = k8sCataloguePodIdentity{Name: physical.TargetName, UID: physical.TargetUID}
	prior.NetworkPolicyName = k8sQuarantineNetworkPolicyName(physical.TargetUID)
	if profile.Family == k8sCatalogueFamilyQuarantine {
		if physical.NetworkPolicyName != prior.NetworkPolicyName {
			return safety, errors.New("Kubernetes catalogue retry NetworkPolicy identity differs from the exact target")
		}
		pod, podErr := k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, physical.TargetName, metav1.GetOptions{})
		if podErr != nil && !apierrors.IsNotFound(podErr) {
			return safety, errors.New("prior quarantine target absence is unverified")
		}
		if podErr == nil && string(pod.UID) == physical.TargetUID && (pod.DeletionTimestamp != nil ||
			pod.Labels["phorvex.ai/quarantined"] != "" || pod.Annotations["phorvex.ai/quarantine-snapshot"] != "" || noControllerOwner(pod.OwnerReferences)) {
			safety.Reason = "prior target still carries a quarantine mutation"
			return safety, nil
		}
		if _, npErr := k.kube.NetworkingV1().NetworkPolicies(profile.Namespace).Get(ctx, prior.NetworkPolicyName, metav1.GetOptions{}); npErr == nil {
			safety.Reason = "prior target quarantine NetworkPolicy is still present"
			return safety, nil
		} else if !apierrors.IsNotFound(npErr) {
			return safety, errors.New("prior quarantine NetworkPolicy absence is unverified")
		}
	} else if !k.rotationCleanupSafe(ctx, prior) {
		safety.Reason = "prior target termination state remains unresolved"
		return safety, nil
	}

	safety.Verified, safety.RetrySafe = true, true
	safety.Reason = "prior Kubernetes catalogue identities are absent and the fixed active-reactive fixture is clean"
	return safety, nil
}

func (k *kubernetesK8sCatalogueCluster) cleanupK8sCatalogueEvent(ctx context.Context, entry attackcatalog.Entry, fixture k8sCatalogueFixture, signal k8sCatalogueSignal, runID string) bool {
	if signal.Name == "" {
		return true
	}
	uid := types.UID(signal.UID)
	if uid == "" {
		current, err := k.dynamic.Resource(k8sCatalogueSecurityEventGVR).Get(ctx, signal.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true
		}
		if err != nil || current.GetAnnotations()[attackCatalogCorrelationAnnotation] != runID ||
			current.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != fixture.Target.UID ||
			current.GetLabels()["phorvex.ai/catalogue-id"] != catalogueIDLabelValue(entry.ID) ||
			current.GetAnnotations()[catalogueIDAnnotationKey] != entry.ID || current.GetUID() == "" {
			return false
		}
		uid = current.GetUID()
	}
	err := k.dynamic.Resource(k8sCatalogueSecurityEventGVR).Delete(ctx, signal.Name,
		metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if err != nil && !apierrors.IsNotFound(err) {
		return false
	}
	_, err = k.dynamic.Resource(k8sCatalogueSecurityEventGVR).Get(ctx, signal.Name, metav1.GetOptions{})
	return apierrors.IsNotFound(err)
}

func (k *kubernetesK8sCatalogueCluster) cleanupK8sQuarantineArtifacts(ctx context.Context, fixture k8sCatalogueFixture) bool {
	// The quarantined Pod and its deny-all NetworkPolicy are ACTUATOR-created defense
	// artifacts; they are removed through the dedicated delete-only cleanup identity, never as
	// the red-team attacks SA. Reads below stay on the attacks SA.
	if k.cleanupKube == nil {
		return false
	}
	pod, err := k.kube.CoreV1().Pods(fixture.Namespace).Get(ctx, fixture.Target.Name, metav1.GetOptions{})
	if err == nil && string(pod.UID) == fixture.Target.UID {
		switch pod.Labels["phorvex.ai/quarantined"] {
		case fixture.Target.UID:
			uid := pod.UID
			if err = k.cleanupKube.CoreV1().Pods(fixture.Namespace).Delete(ctx, pod.Name,
				metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
				return false
			}
		case "":
			if pod.Annotations["phorvex.ai/quarantine-snapshot"] != "" || noControllerOwner(pod.OwnerReferences) {
				return false
			}
		default:
			return false
		}
	} else if err != nil && !apierrors.IsNotFound(err) {
		return false
	}
	np, err := k.kube.NetworkingV1().NetworkPolicies(fixture.Namespace).Get(ctx, fixture.NetworkPolicyName, metav1.GetOptions{})
	if err == nil {
		if !validK8sQuarantineNetworkPolicy(np, fixture) {
			return false
		}
		uid := np.UID
		if err = k.cleanupKube.NetworkingV1().NetworkPolicies(fixture.Namespace).Delete(ctx, np.Name,
			metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
			return false
		}
	} else if !apierrors.IsNotFound(err) {
		return false
	}
	for {
		pod, podErr := k.kube.CoreV1().Pods(fixture.Namespace).Get(ctx, fixture.Target.Name, metav1.GetOptions{})
		_, npErr := k.kube.NetworkingV1().NetworkPolicies(fixture.Namespace).Get(ctx, fixture.NetworkPolicyName, metav1.GetOptions{})
		podAbsent := apierrors.IsNotFound(podErr) || podErr == nil && (string(pod.UID) != fixture.Target.UID ||
			pod.Labels["phorvex.ai/quarantined"] == "" && pod.Annotations["phorvex.ai/quarantine-snapshot"] == "" && !noControllerOwner(pod.OwnerReferences))
		npAbsent := apierrors.IsNotFound(npErr)
		if podAbsent && npAbsent {
			return true
		}
		if podErr != nil && !apierrors.IsNotFound(podErr) || npErr != nil && !apierrors.IsNotFound(npErr) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (k *kubernetesK8sCatalogueCluster) rotationCleanupSafe(ctx context.Context, fixture k8sCatalogueFixture) bool {
	pod, err := k.kube.CoreV1().Pods(fixture.Namespace).Get(ctx, fixture.Target.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true
	}
	if err != nil {
		return false
	}
	return string(pod.UID) != fixture.Target.UID || pod.DeletionTimestamp == nil
}

func (k *kubernetesK8sCatalogueCluster) waitK8sReadyRestored(ctx context.Context, profile k8sCatalogueProfile, fixture k8sCatalogueFixture) bool {
	want := len(fixture.BaselineReadyPods)
	for {
		deployment, depErr := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
		pods, podsErr := k.kube.CoreV1().Pods(profile.Namespace).List(ctx, metav1.ListOptions{LabelSelector: profile.Selector})
		readyUIDs := map[string]bool{}
		if podsErr == nil {
			for i := range pods.Items {
				if pods.Items[i].DeletionTimestamp == nil && pods.Items[i].UID != "" && podReady(&pods.Items[i]) &&
					depErr == nil && k.podOwnedByDeployment(ctx, &pods.Items[i], deployment) == nil {
					readyUIDs[string(pods.Items[i].UID)] = true
				}
			}
		}
		endpointUIDs, endpointErr := k.serviceEndpointUIDs(ctx, profile, fixture.ServiceUID)
		serviceReady := endpointErr == nil
		for uid := range readyUIDs {
			serviceReady = serviceReady && endpointUIDs[uid]
		}
		if depErr == nil && string(deployment.UID) == fixture.DeploymentUID && deployment.Status.ObservedGeneration >= deployment.Generation &&
			int(deployment.Status.AvailableReplicas) >= want && len(readyUIDs) >= want && serviceReady {
			return true
		}
		if depErr != nil || podsErr != nil || endpointErr != nil {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
	}
}

type k8sQuarantineCapacityRecord struct {
	OperationID  string   `json:"operationID"`
	Phase        string   `json:"phase"`
	Namespace    string   `json:"namespace"`
	NamespaceUID string   `json:"namespaceUID"`
	Pod          string   `json:"pod"`
	PodUID       string   `json:"podUID"`
	PolicyName   string   `json:"policyName"`
	PolicyUID    string   `json:"policyUID"`
	Backend      string   `json:"backend"`
	EventName    string   `json:"eventName,omitempty"`
	EventUID     string   `json:"eventUID,omitempty"`
	Objects      []string `json:"objects,omitempty"`
	Detail       string   `json:"detail,omitempty"`
}

type k8sQuarantineCapacityLedger struct {
	Version      int                                    `json:"version"`
	Namespace    string                                 `json:"namespace"`
	NamespaceUID string                                 `json:"namespaceUID"`
	Records      map[string]k8sQuarantineCapacityRecord `json:"records"`
}

type k8sSharedCapacityRecord struct {
	OperationID string                       `json:"operationID"`
	PolicyUID   string                       `json:"policyUID"`
	TargetName  string                       `json:"targetName"`
	TargetUID   string                       `json:"targetUID"`
	Action      string                       `json:"action"`
	Phase       string                       `json:"phase"`
	Admissions  []k8sSharedCapacityAdmission `json:"admissions"`
}

type k8sSharedCapacityAdmission struct {
	Scope       model.ResourceScope `json:"scope"`
	Units       int                 `json:"units"`
	Floor       int                 `json:"floor"`
	ReadyBefore int                 `json:"readyBefore"`
}

type k8sSharedCapacityLedger struct {
	Version int                                `json:"version"`
	Records map[string]k8sSharedCapacityRecord `json:"records"`
}

func (k *kubernetesK8sCatalogueCluster) cleanupK8sQuarantineCapacity(ctx context.Context, fixture k8sCatalogueFixture, decisionID string) bool {
	// The actuator writes the capacity-ledger records; the delete-only cleanup identity edits
	// them back out. Reads stay on the attacks SA, but the writes require the cleanup client.
	if k.cleanupKube == nil {
		return false
	}
	return k.removeExactQuarantineCapacityRecord(ctx, fixture) && k.removeExactSharedCapacityRecord(ctx, fixture, decisionID)
}

func k8sQuarantineCapacityOperationID(fixture k8sCatalogueFixture) string {
	sum := sha256.Sum256([]byte(fixture.PolicyUID + "\x00" + fixture.Namespace + "\x00" + fixture.Target.UID + "\x00" + string(model.ActionQuarantine)))
	return hex.EncodeToString(sum[:20])
}

func k8sQuarantineCapacityLedgerName(namespaceUID string) string {
	sum := sha256.Sum256([]byte(namespaceUID))
	return fmt.Sprintf("phorvex-quarantine-capacity-%x", sum[:20])
}

func (k *kubernetesK8sCatalogueCluster) removeExactQuarantineCapacityRecord(ctx context.Context, fixture k8sCatalogueFixture) bool {
	name := k8sQuarantineCapacityLedgerName(fixture.NamespaceUID)
	wantOp := k8sQuarantineCapacityOperationID(fixture)
	for attempt := 0; attempt < 5; attempt++ {
		cm, err := k.kube.CoreV1().ConfigMaps(k.operatorNamespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true
		}
		if err != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil ||
			cm.Labels["phorvex.ai/quarantine-capacity"] != "v1" {
			return false
		}
		var ledger k8sQuarantineCapacityLedger
		if json.Unmarshal([]byte(cm.Data["ledger"]), &ledger) != nil || ledger.Version != 1 || ledger.Namespace != fixture.Namespace ||
			ledger.NamespaceUID != fixture.NamespaceUID || ledger.Records == nil {
			return false
		}
		record, ok := ledger.Records[fixture.Target.UID]
		if !ok {
			return true
		}
		podObject := "Pod/" + fixture.Namespace + "/" + fixture.Target.Name
		npObject := "NetworkPolicy/" + fixture.Namespace + "/" + fixture.NetworkPolicyName
		if record.OperationID != wantOp || record.Phase != "native-effect" || record.Namespace != fixture.Namespace ||
			record.NamespaceUID != fixture.NamespaceUID || record.Pod != fixture.Target.Name || record.PodUID != fixture.Target.UID ||
			record.PolicyName != fixture.PolicyName || record.PolicyUID != fixture.PolicyUID || record.Backend != "native" ||
			!slices.Contains(record.Objects, podObject) || !slices.Contains(record.Objects, npObject) {
			return false
		}
		delete(ledger.Records, fixture.Target.UID)
		raw, err := json.Marshal(ledger)
		if err != nil {
			return false
		}
		next := cm.DeepCopy()
		next.Data = map[string]string{"ledger": string(raw)}
		updated, updateErr := k.cleanupKube.CoreV1().ConfigMaps(k.operatorNamespace).Update(ctx, next, metav1.UpdateOptions{})
		if apierrors.IsConflict(updateErr) {
			continue
		} else if updateErr != nil || updated.UID != cm.UID || updated.ResourceVersion == "" || updated.ResourceVersion == cm.ResourceVersion {
			return false
		}
	}
	cm, err := k.kube.CoreV1().ConfigMaps(k.operatorNamespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true
	}
	if err != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil ||
		cm.Labels["phorvex.ai/quarantine-capacity"] != "v1" {
		return false
	}
	var ledger k8sQuarantineCapacityLedger
	return json.Unmarshal([]byte(cm.Data["ledger"]), &ledger) == nil && ledger.Records != nil && ledger.Records[fixture.Target.UID].PodUID == ""
}

func (k *kubernetesK8sCatalogueCluster) removeExactSharedCapacityRecord(ctx context.Context, fixture k8sCatalogueFixture, decisionID string) bool {
	const name = "phorvex-shared-capacity"
	for attempt := 0; attempt < 5; attempt++ {
		cm, err := k.kube.CoreV1().ConfigMaps(k.operatorNamespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true
		}
		if err != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil ||
			cm.Labels["phorvex.ai/shared-capacity"] != "v1" {
			return false
		}
		var ledger k8sSharedCapacityLedger
		if json.Unmarshal([]byte(cm.Data["ledger"]), &ledger) != nil || ledger.Version != 1 || ledger.Records == nil {
			return false
		}
		if decisionID == "" {
			for _, record := range ledger.Records {
				if record.PolicyUID == fixture.PolicyUID && record.TargetUID == fixture.Target.UID && record.Action == string(model.ActionQuarantine) {
					return false
				}
			}
			return true
		}
		record, ok := ledger.Records[decisionID]
		if !ok {
			return true
		}
		if record.OperationID != decisionID || record.PolicyUID != fixture.PolicyUID || record.TargetName != fixture.Target.Name ||
			record.TargetUID != fixture.Target.UID || record.Action != string(model.ActionQuarantine) ||
			(record.Phase != "dispatching" && record.Phase != "uncertain") || !validK8sSharedCapacityAdmissions(record.Admissions) {
			return false
		}
		delete(ledger.Records, decisionID)
		raw, err := json.Marshal(ledger)
		if err != nil {
			return false
		}
		next := cm.DeepCopy()
		next.Data = map[string]string{"ledger": string(raw)}
		updated, updateErr := k.cleanupKube.CoreV1().ConfigMaps(k.operatorNamespace).Update(ctx, next, metav1.UpdateOptions{})
		if apierrors.IsConflict(updateErr) {
			continue
		} else if updateErr != nil || updated.UID != cm.UID || updated.ResourceVersion == "" || updated.ResourceVersion == cm.ResourceVersion {
			return false
		}
	}
	cm, err := k.kube.CoreV1().ConfigMaps(k.operatorNamespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true
	}
	if err != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil ||
		cm.Labels["phorvex.ai/shared-capacity"] != "v1" {
		return false
	}
	var ledger k8sSharedCapacityLedger
	if json.Unmarshal([]byte(cm.Data["ledger"]), &ledger) != nil || ledger.Records == nil {
		return false
	}
	_, exists := ledger.Records[decisionID]
	return !exists
}

func validK8sSharedCapacityAdmissions(admissions []k8sSharedCapacityAdmission) bool {
	if len(admissions) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, admission := range admissions {
		key := admission.Scope.Key()
		if !admission.Scope.Valid() || admission.Scope.Kind != model.ResourceUnavailableReadyReplica ||
			admission.Units <= 0 || admission.Floor < 0 || admission.ReadyBefore <= 0 || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

var _ k8sCatalogueCluster = (*kubernetesK8sCatalogueCluster)(nil)
var _ k8sCatalogueRetryVerifier = (*kubernetesK8sCatalogueCluster)(nil)
