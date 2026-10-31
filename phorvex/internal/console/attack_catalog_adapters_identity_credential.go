package console

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const credentialCatalogueObjectLabel = "phorvex.ai/console-credential-fixture"

type identityCredentialCatalogueBinding struct {
	server       *Server
	cfg          Config
	fixedCluster identityCredentialCatalogueCluster
}

type identityCredentialCatalogueFixture struct {
	Profile                  identityCredentialServerProfile
	PodName, PodUID          string
	ReplicaSetUID            string
	DeploymentUID            string
	PolicyUID                string
	PolicyGeneration         int64
	MinimumAvailableReplicas int
	ReactiveOnly             bool
}

type identityCredentialCatalogueRunState struct {
	serviceAccountUID string
	roleUID           string
	roleBindingUID    string
	secretUID         string
	credential        string
	signal            identityCatalogueBindingSignal
}

type identityCredentialPrivatePreparation struct {
	cluster identityCredentialCatalogueCluster
	fixture identityCredentialCatalogueFixture
	state   identityCredentialCatalogueRunState
}

type identityCredentialCatalogueCluster interface {
	Prepare(context.Context, identityCredentialServerProfile) (identityCredentialCatalogueFixture, error)
	Launch(context.Context, identityCatalogueProfile, identityCredentialCatalogueFixture, string, *identityCredentialCatalogueRunState) (identityCatalogueBindingSignal, bool, error)
	Physical(context.Context, identityCredentialCatalogueFixture, *identityCredentialCatalogueRunState) (identityCataloguePhysicalObservation, error)
	Cleanup(context.Context, identityCredentialCatalogueFixture, *identityCredentialCatalogueRunState) (identityCatalogueCleanupObservation, error)
}

func (b *identityCredentialCatalogueBinding) Availability(profile identityCatalogueProfile) AttackCatalogAdapterAvailability {
	availability := AttackCatalogAdapterAvailability{TargetLabel: "This cluster (server-fixed)",
		UnavailableReason: profile.ID + " reviewed credential-revoke profile is unavailable or invalid."}
	if validateIdentityCatalogueProfile(profile) != nil || profile.Family != identityCatalogueCredential {
		availability.UnavailableReason = "credential-revoke catalogue metadata binding is invalid."
		return availability
	}
	if !b.cfg.AttackCatalogEnabled {
		availability.UnavailableReason = profile.ID + " launch adapter is not enabled by this deployment."
		return availability
	}
	if b.cfg.Service == ServiceConsole {
		availability.UnavailableReason = profile.ID + " is served by the attacks service; no attacks-service runtime is active here."
		return availability
	}
	if b.cfg.AuditSource == nil {
		availability.UnavailableReason = profile.ID + " requires the authenticated manager audit source."
		return availability
	}
	if b.cfg.AttackCatalogAuthorizationTenant == "" {
		return availability
	}
	availability.Available = true
	availability.UnavailableReason = ""
	availability.RunnableNote = "Server-fixed leaked-credential validation; destination, grant, policy, and physical oracle are revalidated before mutation."
	availability.RuntimeContext = defaultTargetID
	availability.FixtureTenant = credentialCatalogueNamespace
	return availability
}

func (b *identityCredentialCatalogueBinding) Destination(profile identityCatalogueProfile) (runDestination, error) {
	if validateIdentityCatalogueProfile(profile) != nil || profile.Family != identityCatalogueCredential {
		return runDestination{}, errors.New("credential-revoke catalogue metadata binding is invalid")
	}
	if b.cfg.Service == ServiceConsole {
		if b.cfg.AttacksURL == "" || b.cfg.AttackCatalogAuthorizationTenant == "" {
			return runDestination{}, errors.New("credential-revoke attacks-service proxy destination is unavailable")
		}
		return identityCredentialDestination(b.cfg), nil
	}
	if !b.Availability(profile).Available {
		return runDestination{}, errors.New("credential-revoke launch adapter is unavailable in this attacks-service deployment")
	}
	return identityCredentialDestination(b.cfg), nil
}

func identityCredentialDestination(cfg Config) runDestination {
	return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{cfg.AttackCatalogAuthorizationTenant},
		ScopeTarget: defaultTargetID, ScopeTenant: cfg.AttackCatalogAuthorizationTenant}
}

func (b *identityCredentialCatalogueBinding) Preflight(ctx context.Context, profile identityCatalogueProfile) (*identityCatalogueBindingPreparation, error) {
	if !b.Availability(profile).Available {
		return nil, errors.New("reviewed credential-revoke binding is unavailable")
	}
	serverProfile, ok := credentialCatalogueServerProfiles[profile.ID]
	if !ok || validateCredentialCatalogueServerProfile(profile.ID) != nil {
		return nil, errors.New("reviewed credential-revoke server profile is unavailable")
	}
	cluster := b.fixedCluster
	if cluster == nil {
		if b.server == nil {
			return nil, errors.New("credential-revoke server runtime is unavailable")
		}
		var err error
		cluster, err = newKubernetesCredentialCatalogueCluster(b.cfg)
		if err != nil {
			return nil, err
		}
	}
	fixture, err := cluster.Prepare(ctx, serverProfile)
	if err != nil {
		return nil, err
	}
	trigger := AttackCatalogTriggerProactiveReactive
	if fixture.ReactiveOnly {
		trigger = AttackCatalogTriggerReactive
	}
	private := &identityCredentialPrivatePreparation{cluster: cluster, fixture: fixture}
	return &identityCatalogueBindingPreparation{
		Execution: AttackCatalogExecutionActive, Trigger: trigger, EvidenceTenant: serverProfile.Namespace,
		Namespace: serverProfile.Namespace, PodName: fixture.PodName, TargetUID: fixture.PodUID,
		PolicyName: serverProfile.PolicyName, PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGeneration,
		ReceiptObject: "Secret/" + serverProfile.Namespace + "/" + serverProfile.TokenSecret, private: private,
	}, nil
}

func (b *identityCredentialCatalogueBinding) Launch(ctx context.Context, profile identityCatalogueProfile, run AttackCatalogRunContext, prepared *identityCatalogueBindingPreparation) (identityCatalogueBindingSignal, bool, error) {
	private, ok := identityCredentialPrivate(prepared)
	if !ok || run.CatalogueID != profile.ID || run.ExpectedAction != profile.ExpectedAction || private.fixture.Profile.CatalogueID != profile.ID {
		return identityCatalogueBindingSignal{}, false, errors.New("credential-revoke launch preparation changed")
	}
	signal, mutated, err := private.cluster.Launch(ctx, profile, private.fixture, run.RunID, &private.state)
	private.state.signal = signal
	return signal, mutated, err
}

func (b *identityCredentialCatalogueBinding) Physical(ctx context.Context, profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation) (identityCataloguePhysicalObservation, error) {
	private, ok := identityCredentialPrivate(prepared)
	if !ok || profile.Family != identityCatalogueCredential || private.fixture.Profile.CatalogueID != profile.ID {
		return identityCataloguePhysicalObservation{}, errors.New("credential-revoke physical preparation changed")
	}
	return private.cluster.Physical(ctx, private.fixture, &private.state)
}

func (b *identityCredentialCatalogueBinding) Cleanup(ctx context.Context, profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation, signal identityCatalogueBindingSignal) (identityCatalogueCleanupObservation, error) {
	private, ok := identityCredentialPrivate(prepared)
	if !ok || profile.Family != identityCatalogueCredential || private.fixture.Profile.CatalogueID != profile.ID {
		return identityCatalogueCleanupObservation{Attempted: true}, errors.New("credential-revoke cleanup preparation changed")
	}
	if signal != private.state.signal {
		return identityCatalogueCleanupObservation{Attempted: true}, errors.New("credential-revoke cleanup signal binding changed")
	}
	return private.cluster.Cleanup(ctx, private.fixture, &private.state)
}

func identityCredentialPrivate(prepared *identityCatalogueBindingPreparation) (*identityCredentialPrivatePreparation, bool) {
	if prepared == nil {
		return nil, false
	}
	private, ok := prepared.private.(*identityCredentialPrivatePreparation)
	return private, ok && private != nil && private.cluster != nil
}

// credentialCatalogueRetryVerifier is the read-only cleanliness oracle on the
// fixed cluster. It is a separate optional interface so test fakes of the cluster
// need not implement it unless they exercise reconciliation.
type credentialCatalogueRetryVerifier interface {
	reconcileRetrySafety(ctx context.Context, p identityCredentialServerProfile, signalName string) (AttackCatalogRetrySafety, error)
}

// reconcileRetrySafety re-verifies, read-only, that a prior credential-revoke run
// left the cluster clean enough to launch again. It never mutates or deletes a
// resource and never asserts DEFENDED — it only answers the retry gate.
func (b *identityCredentialCatalogueBinding) reconcileRetrySafety(ctx context.Context, profile identityCatalogueProfile, persisted AttackCatalogResult) (AttackCatalogRetrySafety, error) {
	safety := AttackCatalogRetrySafety{CheckedAt: time.Now().UTC()}
	if profile.Family != identityCatalogueCredential || persisted.CatalogueID != profile.ID {
		return safety, errors.New("credential-revoke retry reconciliation binding is invalid")
	}
	if !b.Availability(profile).Available {
		return safety, errors.New("credential-revoke retry reconciliation is unavailable in this deployment")
	}
	serverProfile, ok := credentialCatalogueServerProfiles[profile.ID]
	if !ok || validateCredentialCatalogueServerProfile(profile.ID) != nil {
		return safety, errors.New("credential-revoke retry reconciliation server profile is unavailable")
	}
	cluster := b.fixedCluster
	if cluster == nil {
		if b.server == nil {
			return safety, errors.New("credential-revoke retry reconciliation runtime is unavailable")
		}
		var err error
		cluster, err = newKubernetesCredentialCatalogueCluster(b.cfg)
		if err != nil {
			return safety, err
		}
	}
	verifier, ok := cluster.(credentialCatalogueRetryVerifier)
	if !ok {
		return safety, errors.New("credential-revoke cluster does not support read-only retry reconciliation")
	}
	return verifier.reconcileRetrySafety(ctx, serverProfile, persisted.Signal.Name)
}

type kubernetesCredentialCatalogueCluster struct {
	restConfig *rest.Config
	kube       kubernetes.Interface
	dynamic    dynamic.Interface
	client     ctrlclient.Client
}

func newKubernetesCredentialCatalogueCluster(cfg Config) (identityCredentialCatalogueCluster, error) {
	var rc *rest.Config
	if cfg.ExperimentRESTConfig != nil {
		rc = rest.CopyConfig(cfg.ExperimentRESTConfig)
	} else {
		var err error
		rc, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.New("in-cluster credential catalogue authority unavailable")
		}
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, errors.New("credential catalogue Kubernetes client unavailable")
	}
	dynamicClient, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, errors.New("credential catalogue event client unavailable")
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, rbacv1.AddToScheme, v1alpha1.AddToScheme} {
		if err = add(scheme); err != nil {
			return nil, errors.New("credential catalogue scheme unavailable")
		}
	}
	reader, err := ctrlclient.New(rc, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, errors.New("credential catalogue fixture client unavailable")
	}
	return &kubernetesCredentialCatalogueCluster{restConfig: rest.CopyConfig(rc), kube: kube, dynamic: dynamicClient, client: reader}, nil
}

func (k *kubernetesCredentialCatalogueCluster) Prepare(ctx context.Context, p identityCredentialServerProfile) (identityCredentialCatalogueFixture, error) {
	if validateCredentialCatalogueServerProfile(p.CatalogueID) != nil || credentialCatalogueServerProfiles[p.CatalogueID] != p {
		return identityCredentialCatalogueFixture{}, errors.New("credential catalogue server profile changed")
	}
	if _, err := k.kube.CoreV1().Namespaces().Get(ctx, p.Namespace, metav1.GetOptions{}); err != nil {
		return identityCredentialCatalogueFixture{}, errors.New("credential catalogue fixture namespace is unavailable")
	}
	deployment, err := k.kube.AppsV1().Deployments(p.Namespace).Get(ctx, p.Deployment, metav1.GetOptions{})
	if err != nil || deployment.UID == "" || deployment.DeletionTimestamp != nil ||
		deployment.Spec.Selector.MatchLabels[p.SelectorKey] != p.SelectorValue {
		return identityCredentialCatalogueFixture{}, errors.New("credential catalogue deployment is not the reviewed destination")
	}
	var policy v1alpha1.PhorvexPolicy
	if err = k.client.Get(ctx, ctrlclient.ObjectKey{Namespace: p.Namespace, Name: p.PolicyName}, &policy); err != nil ||
		policy.UID == "" || policy.Generation < 1 || policy.DeletionTimestamp != nil ||
		policy.Spec.EffectiveMode() != v1alpha1.ModeActive || !policy.Spec.Triggers.EventDriven ||
		policy.Spec.Selector.MatchLabels[p.SelectorKey] != p.SelectorValue || !credentialActionEnabled(policy.Spec.Actions.Enabled) {
		return identityCredentialCatalogueFixture{}, errors.New("credential catalogue policy is not the reviewed active event-driven profile")
	}
	minimum := policy.Spec.SLO.MinAvailableReplicas
	if minimum < 1 {
		minimum = 1
	}
	if int(deployment.Status.AvailableReplicas) < minimum {
		return identityCredentialCatalogueFixture{}, errors.New("credential catalogue deployment is below its availability floor")
	}
	selector := labels.Set{p.SelectorKey: p.SelectorValue}.AsSelector().String()
	pods, err := k.kube.CoreV1().Pods(p.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return identityCredentialCatalogueFixture{}, errors.New("credential catalogue target Pods are unavailable")
	}
	sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })
	var target *corev1.Pod
	var targetReplicaSet *appsv1.ReplicaSet
	for i := range pods.Items {
		pod := &pods.Items[i]
		if strings.HasPrefix(pod.Name, p.PodPrefix) {
			replicaSet := k.credentialTargetReplicaSet(ctx, pod, deployment)
			if replicaSet == nil {
				continue
			}
			target = pod
			targetReplicaSet = replicaSet
			break
		}
	}
	if target == nil {
		return identityCredentialCatalogueFixture{}, errors.New("credential catalogue has no ready Pod owned by the reviewed deployment")
	}
	policySelector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil || policySelector.Empty() || !policySelector.Matches(labels.Set(target.Labels)) {
		return identityCredentialCatalogueFixture{}, errors.New("credential catalogue policy does not select the exact target Pod")
	}
	for _, absent := range []func() error{
		func() error {
			_, err := k.kube.CoreV1().ServiceAccounts(p.Namespace).Get(ctx, p.ServiceAccount, metav1.GetOptions{})
			return err
		},
		func() error {
			_, err := k.kube.CoreV1().Secrets(p.Namespace).Get(ctx, p.TokenSecret, metav1.GetOptions{})
			return err
		},
		func() error {
			_, err := k.kube.RbacV1().Roles(p.Namespace).Get(ctx, p.ServiceAccount, metav1.GetOptions{})
			return err
		},
		func() error {
			_, err := k.kube.RbacV1().RoleBindings(p.Namespace).Get(ctx, p.ServiceAccount, metav1.GetOptions{})
			return err
		},
	} {
		if err = absent(); !apierrors.IsNotFound(err) {
			return identityCredentialCatalogueFixture{}, errors.New("credential catalogue run-owned fixture is not clean")
		}
	}
	if err = k.preflightAuthority(ctx, p); err != nil {
		return identityCredentialCatalogueFixture{}, err
	}
	return identityCredentialCatalogueFixture{Profile: p, PodName: target.Name, PodUID: string(target.UID),
		ReplicaSetUID: string(targetReplicaSet.UID), DeploymentUID: string(deployment.UID),
		PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation,
		MinimumAvailableReplicas: minimum, ReactiveOnly: policy.Spec.Triggers.ReactiveOnly}, nil
}

func credentialActionEnabled(actions []v1alpha1.ActionType) bool {
	for _, action := range actions {
		if string(action) == string(model.ActionCredentialRevoke) {
			return true
		}
	}
	return false
}

func (k *kubernetesCredentialCatalogueCluster) credentialTargetReplicaSet(ctx context.Context, pod *corev1.Pod, deployment *appsv1.Deployment) *appsv1.ReplicaSet {
	if pod == nil || deployment == nil || pod.UID == "" || pod.DeletionTimestamp != nil ||
		pod.Status.Phase != corev1.PodRunning || !podReady(pod) {
		return nil
	}
	for _, owner := range pod.OwnerReferences {
		if owner.APIVersion != appsv1.SchemeGroupVersion.String() || owner.Kind != "ReplicaSet" || owner.UID == "" {
			continue
		}
		replicaSet, err := k.kube.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil || replicaSet.UID != owner.UID || replicaSet.DeletionTimestamp != nil {
			continue
		}
		for _, replicaSetOwner := range replicaSet.OwnerReferences {
			if replicaSetOwner.APIVersion == appsv1.SchemeGroupVersion.String() && replicaSetOwner.Kind == "Deployment" &&
				replicaSetOwner.Name == deployment.Name && replicaSetOwner.UID == deployment.UID {
				return replicaSet
			}
		}
	}
	return nil
}

func (k *kubernetesCredentialCatalogueCluster) preflightAuthority(ctx context.Context, p identityCredentialServerProfile) error {
	checks := []authorizationv1.ResourceAttributes{
		{Namespace: p.Namespace, Verb: "create", Resource: "serviceaccounts"},
		{Namespace: p.Namespace, Verb: "delete", Resource: "serviceaccounts"},
		{Namespace: p.Namespace, Verb: "create", Resource: "secrets"},
		{Namespace: p.Namespace, Verb: "get", Resource: "secrets"},
		{Namespace: p.Namespace, Verb: "delete", Resource: "secrets"},
		{Namespace: p.Namespace, Verb: "create", Group: rbacv1.GroupName, Resource: "roles"},
		{Namespace: p.Namespace, Verb: "delete", Group: rbacv1.GroupName, Resource: "roles"},
		{Namespace: p.Namespace, Verb: "create", Group: rbacv1.GroupName, Resource: "rolebindings"},
		{Namespace: p.Namespace, Verb: "delete", Group: rbacv1.GroupName, Resource: "rolebindings"},
		{Verb: "create", Group: "amtd.r6security.com", Resource: "securityevents"},
		{Verb: "delete", Group: "amtd.r6security.com", Resource: "securityevents"},
		{Namespace: p.Namespace, Verb: "create", Resource: "serviceaccounts", Subresource: "token"},
		{Verb: "create", Group: authenticationv1.GroupName, Resource: "tokenreviews"},
	}
	for _, attrs := range checks {
		review, err := k.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx,
			&authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &attrs}}, metav1.CreateOptions{})
		if err != nil || !review.Status.Allowed {
			return errors.New("credential catalogue server lacks its fixed fixture or oracle authority")
		}
	}
	for _, subject := range []string{"p4-phorvex-manager", "p4-actuator"} {
		checks := []authorizationv1.ResourceAttributes{
			{Namespace: p.Namespace, Verb: "get", Resource: "secrets"},
			{Namespace: p.Namespace, Verb: "list", Resource: "secrets"},
			{Namespace: p.Namespace, Verb: "get", Resource: "serviceaccounts"},
			{Namespace: p.Namespace, Verb: "get", Resource: "pods"},
		}
		if subject == "p4-actuator" {
			checks = append(checks,
				authorizationv1.ResourceAttributes{Namespace: p.Namespace, Verb: "delete", Resource: "secrets"},
				authorizationv1.ResourceAttributes{Namespace: p.Namespace, Verb: "update", Resource: "serviceaccounts"})
		}
		for _, attrs := range checks {
			review, err := k.kube.AuthorizationV1().SubjectAccessReviews().Create(ctx,
				&authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "system:serviceaccount:p4:" + subject, ResourceAttributes: &attrs}}, metav1.CreateOptions{})
			if err != nil || !review.Status.Allowed {
				return errors.New("credential-revoke manager or actuator fixture RBAC is not installed")
			}
		}
	}
	return nil
}

func (k *kubernetesCredentialCatalogueCluster) Launch(ctx context.Context, profile identityCatalogueProfile, f identityCredentialCatalogueFixture, runID string, state *identityCredentialCatalogueRunState) (identityCatalogueBindingSignal, bool, error) {
	p := f.Profile
	entry, ok := attackcatalog.Lookup(profile.ID)
	if !ok || validateIdentityCatalogueProfile(profile) != nil || entry.ID != p.CatalogueID ||
		entry.EventType != model.AttackVectorCredentialTheft || entry.ExpectedAction != string(model.ActionCredentialRevoke) ||
		state == nil || strings.TrimSpace(runID) == "" {
		return identityCatalogueBindingSignal{}, false, errors.New("credential-revoke launch profile changed")
	}
	metadata := metav1.ObjectMeta{Name: p.ServiceAccount, Namespace: p.Namespace,
		Labels:      map[string]string{credentialCatalogueObjectLabel: "true"},
		Annotations: map[string]string{attackCatalogCorrelationAnnotation: runID, "phorvex.ai/catalogue-id": profile.ID}}
	sa, err := k.kube.CoreV1().ServiceAccounts(p.Namespace).Create(ctx,
		&corev1.ServiceAccount{ObjectMeta: metadata}, metav1.CreateOptions{})
	if err != nil || sa.UID == "" {
		return identityCatalogueBindingSignal{}, false, errors.New("credential-revoke fixture ServiceAccount creation failed")
	}
	state.serviceAccountUID = string(sa.UID)
	role, err := k.kube.RbacV1().Roles(p.Namespace).Create(ctx, &rbacv1.Role{ObjectMeta: metadata,
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{p.GrantResource}, Verbs: p.GrantVerbs[:]}}}, metav1.CreateOptions{})
	if err != nil || role.UID == "" {
		return identityCatalogueBindingSignal{}, true, errors.New("credential-revoke fixture Role creation failed")
	}
	state.roleUID = string(role.UID)
	binding, err := k.kube.RbacV1().RoleBindings(p.Namespace).Create(ctx, &rbacv1.RoleBinding{ObjectMeta: metadata,
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: p.ServiceAccount},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: p.ServiceAccount, Namespace: p.Namespace}}}, metav1.CreateOptions{})
	if err != nil || binding.UID == "" {
		return identityCatalogueBindingSignal{}, true, errors.New("credential-revoke fixture RoleBinding creation failed")
	}
	state.roleBindingUID = string(binding.UID)
	secretMeta := *metadata.DeepCopy()
	secretMeta.Name = p.TokenSecret
	secretMeta.Annotations[corev1.ServiceAccountNameKey] = p.ServiceAccount
	secret, err := k.kube.CoreV1().Secrets(p.Namespace).Create(ctx,
		&corev1.Secret{ObjectMeta: secretMeta, Type: corev1.SecretTypeServiceAccountToken}, metav1.CreateOptions{})
	if err != nil || secret.UID == "" {
		return identityCatalogueBindingSignal{}, true, errors.New("credential-revoke token fixture creation failed")
	}
	state.secretUID = string(secret.UID)
	credential, err := k.waitForCredential(ctx, p, state)
	if err != nil {
		return identityCatalogueBindingSignal{}, true, err
	}
	authenticated, authorized, err := k.credentialState(ctx, credential, p)
	if err != nil || !authenticated || !authorized {
		return identityCatalogueBindingSignal{}, true, errors.New("credential-revoke positive-control credential did not authorize")
	}
	state.credential = credential
	signal, err := k.createCredentialSignal(ctx, entry, f, runID)
	state.signal = signal
	if err != nil {
		return signal, true, err
	}
	return signal, true, nil
}

func (k *kubernetesCredentialCatalogueCluster) waitForCredential(ctx context.Context, p identityCredentialServerProfile, state *identityCredentialCatalogueRunState) (string, error) {
	timer := time.NewTimer(40 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		secret, err := k.kube.CoreV1().Secrets(p.Namespace).Get(ctx, p.TokenSecret, metav1.GetOptions{})
		if err == nil && string(secret.UID) == state.secretUID && secret.Type == corev1.SecretTypeServiceAccountToken &&
			secret.Annotations[corev1.ServiceAccountNameKey] == p.ServiceAccount &&
			secret.Annotations[corev1.ServiceAccountUIDKey] == state.serviceAccountUID && len(secret.Data[corev1.ServiceAccountTokenKey]) > 0 {
			return string(secret.Data[corev1.ServiceAccountTokenKey]), nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
			return "", errors.New("credential-revoke token controller did not populate the exact Secret")
		case <-ticker.C:
		}
	}
}

func (k *kubernetesCredentialCatalogueCluster) credentialState(ctx context.Context, token string, p identityCredentialServerProfile) (bool, bool, error) {
	if token == "" {
		return false, false, errors.New("credential material is absent")
	}
	review, err := k.kube.AuthenticationV1().TokenReviews().Create(ctx,
		&authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token}}, metav1.CreateOptions{})
	if err != nil {
		return false, false, err
	}
	if !review.Status.Authenticated {
		return false, false, nil
	}
	want := "system:serviceaccount:" + p.Namespace + ":" + p.ServiceAccount
	if review.Status.User.Username != want {
		return true, false, errors.New("credential authenticated as a different identity")
	}
	rc := rest.AnonymousClientConfig(k.restConfig)
	rc.BearerToken = token
	credentialClient, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return true, false, errors.New("credential positive-control client unavailable")
	}
	access, err := credentialClient.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx,
		&authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{
			Namespace: p.Namespace, Verb: "list", Resource: p.GrantResource}}}, metav1.CreateOptions{})
	if err != nil {
		return true, false, err
	}
	return true, access.Status.Allowed, nil
}

func (k *kubernetesCredentialCatalogueCluster) createCredentialSignal(ctx context.Context, entry attackcatalog.Entry, f identityCredentialCatalogueFixture, runID string) (identityCatalogueBindingSignal, error) {
	random := make([]byte, 6)
	if _, err := cryptorand.Read(random); err != nil {
		return identityCatalogueBindingSignal{}, errors.New("credential-revoke signal identity generation failed")
	}
	name := "catalog-credential-" + hex.EncodeToString(random)
	payload, err := json.Marshal(map[string]any{
		"targetPodUID": f.PodUID, "policyName": f.Profile.PolicyName, "policyUID": f.PolicyUID,
		"policyGeneration": f.PolicyGeneration, "serviceAccountName": f.Profile.ServiceAccount,
		"credentialSecrets": []string{f.Profile.TokenSecret},
	})
	if err != nil {
		return identityCatalogueBindingSignal{}, errors.New("credential-revoke observation encoding failed")
	}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{
			"name": name, "labels": map[string]any{"phorvex.ai/redteam": "true", "phorvex.ai/catalogue-id": catalogueIDLabelValue(entry.ID)},
			"annotations": map[string]any{model.ConsoleTargetPodUIDAnnotation: f.PodUID,
				attackCatalogCorrelationAnnotation: runID, f.Profile.ObservationKey: string(payload),
				catalogueIDAnnotationKey: entry.ID},
		},
		"spec": map[string]any{
			"description": entry.Description, "targets": []any{f.Profile.Namespace + "/" + f.PodName},
			"rule": map[string]any{"type": entry.EventType, "threatLevel": "critical", "source": "console-catalogue"},
		},
	}}
	created, err := k.dynamic.Resource(securityEventGVR).Create(ctx, object, metav1.CreateOptions{})
	if err != nil {
		return identityCatalogueBindingSignal{Name: name}, errors.New("credential-revoke catalogue signal admission failed")
	}
	signal := identityCatalogueBindingSignal{Name: created.GetName(), UID: string(created.GetUID()),
		Creator: created.GetAnnotations()["phorvex.ai/creator-identity"], CreatedAt: created.GetCreationTimestamp().Time}
	targets, _, _ := unstructured.NestedStringSlice(created.Object, "spec", "targets")
	ruleType, _, _ := unstructured.NestedString(created.Object, "spec", "rule", "type")
	if signal.Name != name || signal.UID == "" || signal.Creator != eventtrust.Injector() || signal.CreatedAt.IsZero() ||
		created.GetLabels()["phorvex.ai/catalogue-id"] != catalogueIDLabelValue(entry.ID) ||
		created.GetAnnotations()[catalogueIDAnnotationKey] != entry.ID ||
		created.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != f.PodUID ||
		created.GetAnnotations()[attackCatalogCorrelationAnnotation] != runID ||
		created.GetAnnotations()[f.Profile.ObservationKey] != string(payload) ||
		!slices.Equal(targets, []string{f.Profile.Namespace + "/" + f.PodName}) || ruleType != entry.EventType {
		uid := created.GetUID()
		_ = k.dynamic.Resource(securityEventGVR).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		return signal, errors.New("credential-revoke catalogue signal identity, target, or observation admission differs")
	}
	return signal, nil
}

func (k *kubernetesCredentialCatalogueCluster) Physical(ctx context.Context, f identityCredentialCatalogueFixture, state *identityCredentialCatalogueRunState) (identityCataloguePhysicalObservation, error) {
	if state == nil || state.serviceAccountUID == "" || state.credential == "" {
		return identityCataloguePhysicalObservation{PodUID: f.PodUID}, errors.New("credential-revoke positive-control state is incomplete")
	}
	result := identityCataloguePhysicalObservation{ServiceAccountUID: state.serviceAccountUID,
		PodUID: f.PodUID, CredentialAuthenticatedBefore: true}
	_, err := k.kube.CoreV1().Secrets(f.Profile.Namespace).Get(ctx, f.Profile.TokenSecret, metav1.GetOptions{})
	result.CredentialObjectAbsent = apierrors.IsNotFound(err)
	if err != nil && !apierrors.IsNotFound(err) {
		return result, errors.New("credential-revoke token Secret state is unavailable")
	}
	authenticated, _, err := k.credentialState(ctx, state.credential, f.Profile)
	if err != nil {
		return result, errors.New("credential-revoke stolen-token rejection is unavailable")
	}
	result.CredentialAuthenticatedAfter = authenticated
	sa, err := k.kube.CoreV1().ServiceAccounts(f.Profile.Namespace).Get(ctx, f.Profile.ServiceAccount, metav1.GetOptions{})
	if err != nil || string(sa.UID) != state.serviceAccountUID || sa.DeletionTimestamp != nil {
		return result, errors.New("credential-revoke fixture ServiceAccount identity changed")
	}
	pod, err := k.kube.CoreV1().Pods(f.Profile.Namespace).Get(ctx, f.PodName, metav1.GetOptions{})
	if err != nil {
		return result, errors.New("credential-revoke target Pod is unavailable")
	}
	deployment, err := k.kube.AppsV1().Deployments(f.Profile.Namespace).Get(ctx, f.Profile.Deployment, metav1.GetOptions{})
	if err != nil || string(deployment.UID) != f.DeploymentUID || deployment.DeletionTimestamp != nil {
		return result, errors.New("credential-revoke deployment identity changed")
	}
	replicaSet := k.credentialTargetReplicaSet(ctx, pod, deployment)
	result.PodRetained = string(pod.UID) == f.PodUID && replicaSet != nil && string(replicaSet.UID) == f.ReplicaSetUID
	result.AvailabilityFloorRetained = int(deployment.Status.AvailableReplicas) >= f.MinimumAvailableReplicas
	expiration := int64(600)
	fresh, err := k.kube.CoreV1().ServiceAccounts(f.Profile.Namespace).CreateToken(ctx, f.Profile.ServiceAccount,
		&authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &expiration}}, metav1.CreateOptions{})
	if err != nil || strings.TrimSpace(fresh.Status.Token) == "" {
		return result, errors.New("credential-revoke fresh-token positive control is unavailable")
	}
	freshAuthenticated, freshAuthorized, err := k.credentialState(ctx, fresh.Status.Token, f.Profile)
	if err != nil {
		return result, errors.New("credential-revoke fresh-token positive control failed")
	}
	result.FreshCredentialAuthenticated = freshAuthenticated && freshAuthorized
	return result, nil
}

func (k *kubernetesCredentialCatalogueCluster) Cleanup(ctx context.Context, f identityCredentialCatalogueFixture, state *identityCredentialCatalogueRunState) (identityCatalogueCleanupObservation, error) {
	result := identityCatalogueCleanupObservation{Attempted: true}
	if state == nil {
		return result, errors.New("credential-revoke cleanup state is absent")
	}
	problems := []string{}
	result.EventAbsent = k.deleteCredentialEvent(ctx, state.signal)
	if !result.EventAbsent {
		problems = append(problems, "exact SecurityEvent absence unverified")
	}
	p := f.Profile
	checks := []bool{
		k.deleteCredentialSecret(ctx, p.Namespace, p.TokenSecret, state.secretUID),
		k.deleteCredentialRoleBinding(ctx, p.Namespace, p.ServiceAccount, state.roleBindingUID),
		k.deleteCredentialRole(ctx, p.Namespace, p.ServiceAccount, state.roleUID),
		k.deleteCredentialServiceAccount(ctx, p.Namespace, p.ServiceAccount, state.serviceAccountUID),
	}
	if slices.Contains(checks, false) {
		problems = append(problems, "run-owned credential fixture absence unverified")
	}
	pod, podErr := k.kube.CoreV1().Pods(p.Namespace).Get(ctx, f.PodName, metav1.GetOptions{})
	deployment, deploymentErr := k.kube.AppsV1().Deployments(p.Namespace).Get(ctx, p.Deployment, metav1.GetOptions{})
	var replicaSet *appsv1.ReplicaSet
	if podErr == nil && deploymentErr == nil {
		replicaSet = k.credentialTargetReplicaSet(ctx, pod, deployment)
	}
	var policy v1alpha1.PhorvexPolicy
	policyErr := k.client.Get(ctx, ctrlclient.ObjectKey{Namespace: p.Namespace, Name: p.PolicyName}, &policy)
	artifactsAbsent := !slices.Contains(checks, false)
	deploymentIdentityOK := deploymentErr == nil && string(deployment.UID) == f.DeploymentUID
	floorRetained := deploymentErr == nil && int(deployment.Status.AvailableReplicas) >= f.MinimumAvailableReplicas
	policyUnmutated := policyErr == nil && string(policy.UID) == f.PolicyUID && policy.Generation == f.PolicyGeneration
	// FixtureRestored is the full DEFENDED cleanup oracle, unchanged: run-owned
	// objects gone AND the exact prepare-time Pod and ReplicaSet identity preserved.
	result.FixtureRestored = artifactsAbsent && podErr == nil && string(pod.UID) == f.PodUID &&
		replicaSet != nil && string(replicaSet.UID) == f.ReplicaSetUID && deploymentIdentityOK &&
		floorRetained && policyUnmutated
	if !result.FixtureRestored {
		problems = append(problems, "credential target or run-owned fixture was not restored")
	}
	// RetrySafe is the weaker safe-to-retry oracle: run-owned SecurityEvent and
	// credential artifacts (Secret/Role/RoleBinding/ServiceAccount) are absent, the
	// Deployment is the same healthy, non-terminating fixture at its availability
	// floor, and the PhorvexPolicy carries no leftover active mutation (same UID and
	// generation). It deliberately does NOT require the prepare-time Pod or ReplicaSet
	// UID, so an unrelated Pod rollout (a new, healthy Pod owned by the same
	// Deployment) is not treated as contamination — while leftover credentials or
	// genuine drift are.
	result.RetrySafe = result.EventAbsent && artifactsAbsent && podErr == nil && replicaSet != nil &&
		deploymentIdentityOK && deployment.DeletionTimestamp == nil && floorRetained && policyUnmutated
	state.credential = ""
	if len(problems) != 0 {
		return result, errors.New(strings.Join(problems, "; "))
	}
	return result, nil
}

// reconcileRetrySafety is the read-only cleanliness oracle. It confirms the run's
// own SecurityEvent (by name, when known) is absent and then reuses Prepare — which
// is read-only with respect to persistent fixture state — to confirm the run-owned
// credential artifacts (fixed names) are absent and the fixture Deployment and
// PhorvexPolicy are the same healthy, unmutated objects. Prepare binds whatever Pod
// is currently ready, so an environmental Pod rollout is not treated as drift; a
// leftover credential/artifact or a genuinely altered fixture is.
func (k *kubernetesCredentialCatalogueCluster) reconcileRetrySafety(ctx context.Context, p identityCredentialServerProfile, signalName string) (AttackCatalogRetrySafety, error) {
	safety := AttackCatalogRetrySafety{CheckedAt: time.Now().UTC()}
	if signalName != "" {
		_, err := k.dynamic.Resource(securityEventGVR).Get(ctx, signalName, metav1.GetOptions{})
		if err == nil {
			safety.Reason = "run-owned SecurityEvent " + signalName + " is still present"
			return safety, nil
		}
		if !apierrors.IsNotFound(err) {
			return safety, errors.New("credential-revoke SecurityEvent absence is unverified")
		}
	}
	if _, err := k.Prepare(ctx, p); err != nil {
		safety.Reason = "credential fixture is not clean or healthy: " + err.Error()
		return safety, nil
	}
	safety.Verified, safety.RetrySafe = true, true
	safety.Reason = "run-owned SecurityEvent and credential artifacts absent; fixture healthy"
	return safety, nil
}

func (k *kubernetesCredentialCatalogueCluster) deleteCredentialEvent(ctx context.Context, signal identityCatalogueBindingSignal) bool {
	if signal.Name == "" {
		return true
	}
	if signal.UID == "" {
		_, err := k.dynamic.Resource(securityEventGVR).Get(ctx, signal.Name, metav1.GetOptions{})
		return apierrors.IsNotFound(err)
	}
	uid := types.UID(signal.UID)
	err := k.dynamic.Resource(securityEventGVR).Delete(ctx, signal.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if err != nil && !apierrors.IsNotFound(err) {
		return false
	}
	_, err = k.dynamic.Resource(securityEventGVR).Get(ctx, signal.Name, metav1.GetOptions{})
	return apierrors.IsNotFound(err)
}

func exactCredentialDelete(ctx context.Context, uid string, get func() (types.UID, error), del func(types.UID) error) bool {
	current, err := get()
	if apierrors.IsNotFound(err) {
		return true
	}
	if err != nil || uid == "" || current != types.UID(uid) {
		return false
	}
	if err = del(current); err != nil && !apierrors.IsNotFound(err) {
		return false
	}
	_, err = get()
	return apierrors.IsNotFound(err)
}

func (k *kubernetesCredentialCatalogueCluster) deleteCredentialSecret(ctx context.Context, namespace, name, uid string) bool {
	return exactCredentialDelete(ctx, uid,
		func() (types.UID, error) {
			o, err := k.kube.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			return o.UID, nil
		},
		func(current types.UID) error {
			return k.kube.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &current}})
		})
}

func (k *kubernetesCredentialCatalogueCluster) deleteCredentialRoleBinding(ctx context.Context, namespace, name, uid string) bool {
	return exactCredentialDelete(ctx, uid,
		func() (types.UID, error) {
			o, err := k.kube.RbacV1().RoleBindings(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			return o.UID, nil
		},
		func(current types.UID) error {
			return k.kube.RbacV1().RoleBindings(namespace).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &current}})
		})
}

func (k *kubernetesCredentialCatalogueCluster) deleteCredentialRole(ctx context.Context, namespace, name, uid string) bool {
	return exactCredentialDelete(ctx, uid,
		func() (types.UID, error) {
			o, err := k.kube.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			return o.UID, nil
		},
		func(current types.UID) error {
			return k.kube.RbacV1().Roles(namespace).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &current}})
		})
}

func (k *kubernetesCredentialCatalogueCluster) deleteCredentialServiceAccount(ctx context.Context, namespace, name, uid string) bool {
	return exactCredentialDelete(ctx, uid,
		func() (types.UID, error) {
			o, err := k.kube.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return "", err
			}
			return o.UID, nil
		},
		func(current types.UID) error {
			return k.kube.CoreV1().ServiceAccounts(namespace).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &current}})
		})
}

var _ identityCatalogueFamilyBinding = (*identityCredentialCatalogueBinding)(nil)
var _ identityCredentialCatalogueCluster = (*kubernetesCredentialCatalogueCluster)(nil)
