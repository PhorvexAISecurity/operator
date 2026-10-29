package console

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/agentdeny"
	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	agentCatalogueNamespace      = "p6-demo"
	agentCatalogueDeployment     = "agent-sim"
	agentCatalogueServiceAccount = "agent-sim"
	agentCatalogueOwnershipLabel = "phorvex.ai/attack-catalog-agent-action"
	agentCatalogueOwnershipValue = "true"
	agentCatalogueBenignCaller   = "caller-z"
	agentCatalogueBenignAction   = "read-report"
	agentCatalogueSurgicalAction = "read-report"
	agentCatalogueContainer      = "agent-sim"
	agentCatalogueCPURequest     = "10m"
	agentCatalogueCPULimit       = "100m"
	agentCatalogueMemoryRequest  = "16Mi"
	agentCatalogueMemoryLimit    = "32Mi"
)

var immutableAgentFixtureImage = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$`)

// ValidAttackCatalogAgentActionImage admits one pullable immutable image name.
// Tags, schemes, whitespace, shell syntax, and tag+digest combinations are rejected.
func ValidAttackCatalogAgentActionImage(value string) bool {
	return len(value) <= 512 && immutableAgentFixtureImage.MatchString(value)
}

type identityAgentCatalogueFixture struct {
	Profile          identityAgentServerProfile
	DeploymentUID    string
	PolicyUID        string
	PolicyGeneration int64
	TargetPodName    string
	TargetPodUID     string
	ServiceUID       string
	GuardUID         string
	PodUIDs          []string
	ReactiveOnly     bool
}

type identityAgentCatalogueRunState struct {
	runID              string
	signal             identityCatalogueBindingSignal
	acceptedDecisionID string
}

type identityAgentPrivatePreparation struct {
	cluster identityAgentCatalogueCluster
	fixture identityAgentCatalogueFixture
	state   identityAgentCatalogueRunState
}

type identityAgentCatalogueCluster interface {
	Prepare(context.Context, identityAgentServerProfile) (identityAgentCatalogueFixture, error)
	Launch(context.Context, identityCatalogueProfile, identityAgentCatalogueFixture, string, *identityAgentCatalogueRunState) (identityCatalogueBindingSignal, bool, error)
	BindAcceptedReceipt(identityAgentCatalogueFixture, *identityAgentCatalogueRunState, identityCatalogueBindingSignal, string) error
	Physical(context.Context, identityAgentCatalogueFixture, *identityAgentCatalogueRunState) (identityCataloguePhysicalObservation, error)
	Cleanup(context.Context, identityAgentCatalogueFixture, *identityAgentCatalogueRunState) (identityCatalogueCleanupObservation, error)
}

type identityAgentCatalogueBinding struct {
	server       *Server
	cfg          Config
	fixedCluster identityAgentCatalogueCluster
}

func (b *identityAgentCatalogueBinding) Availability(profile identityCatalogueProfile) AttackCatalogAdapterAvailability {
	availability := AttackCatalogAdapterAvailability{TargetLabel: "This cluster (server-fixed)",
		UnavailableReason: profile.ID + " reviewed immutable agent-action fixture is unavailable or invalid."}
	if validateIdentityCatalogueProfile(profile) != nil || profile.Family != identityCatalogueAgent {
		availability.UnavailableReason = "agent-action catalogue metadata binding is invalid."
		return availability
	}
	if !b.cfg.AttackCatalogEnabled {
		availability.UnavailableReason = profile.ID + " launch adapter is not enabled by this deployment."
		return availability
	}
	if !b.cfg.AttackCatalogAgentActionEnabled {
		availability.UnavailableReason = profile.ID + " immutable agent-action fixture is not enabled by this deployment."
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
		availability.UnavailableReason = profile.ID + " requires the deployment-owned authorization tenant."
		return availability
	}
	if !ValidAttackCatalogAgentActionImage(b.cfg.AttackCatalogAgentActionImage) {
		availability.UnavailableReason = profile.ID + " requires a complete repository@sha256:<64hex> agent-sim image pin."
		return availability
	}
	for _, required := range []struct{ role, principal string }{
		{"manager", b.cfg.AttackCatalogAgentManagerPrincipal},
		{"sensor", b.cfg.AttackCatalogAgentSensorPrincipal},
		{"actuator", b.cfg.AttackCatalogAgentActuatorPrincipal},
	} {
		if !identityCatalogueServiceAccountPrincipal(required.principal) {
			availability.UnavailableReason = profile.ID + " requires the exact in-cluster " + required.role + " ServiceAccount principal."
			return availability
		}
	}
	availability.Available = true
	availability.UnavailableReason = ""
	availability.RunnableNote = "Server-fixed digest-pinned agent fixture; exact signal, accepted decision ledger, two-sided physical deny oracle, and cleanup are revalidated."
	availability.RuntimeContext = defaultTargetID
	availability.FixtureTenant = agentCatalogueNamespace
	return availability
}

func (b *identityAgentCatalogueBinding) Destination(profile identityCatalogueProfile) (runDestination, error) {
	if validateIdentityCatalogueProfile(profile) != nil || profile.Family != identityCatalogueAgent {
		return runDestination{}, errors.New("agent-action catalogue metadata binding is invalid")
	}
	if b.cfg.Service == ServiceConsole {
		if b.cfg.AttacksURL == "" || b.cfg.AttackCatalogAuthorizationTenant == "" {
			return runDestination{}, errors.New("agent-action attacks-service proxy destination is unavailable")
		}
		return identityAgentDestination(b.cfg), nil
	}
	availability := b.Availability(profile)
	if !availability.Available {
		return runDestination{}, errors.New(availability.UnavailableReason)
	}
	return identityAgentDestination(b.cfg), nil
}

func identityAgentDestination(cfg Config) runDestination {
	return runDestination{Targets: []string{defaultTargetID}, Tenants: []string{cfg.AttackCatalogAuthorizationTenant},
		ScopeTarget: defaultTargetID, ScopeTenant: cfg.AttackCatalogAuthorizationTenant}
}

func (b *identityAgentCatalogueBinding) Preflight(ctx context.Context, profile identityCatalogueProfile) (*identityCatalogueBindingPreparation, error) {
	if !b.Availability(profile).Available {
		return nil, errors.New("reviewed agent-action binding is unavailable")
	}
	serverProfile, ok := agentCatalogueServerProfiles[profile.ID]
	if !ok || validateAgentCatalogueServerProfile(profile.ID) != nil {
		return nil, errors.New("reviewed agent-action server profile is unavailable")
	}
	cluster := b.fixedCluster
	if cluster == nil {
		var err error
		cluster, err = newKubernetesAgentCatalogueCluster(b.cfg)
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
	private := &identityAgentPrivatePreparation{cluster: cluster, fixture: fixture}
	return &identityCatalogueBindingPreparation{
		Execution: AttackCatalogExecutionActive, Trigger: trigger, EvidenceTenant: serverProfile.Namespace,
		Namespace: serverProfile.Namespace, PodName: fixture.TargetPodName, TargetUID: fixture.TargetPodUID,
		PolicyName: serverProfile.PolicyName, PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGeneration,
		ReceiptObject: serverProfile.Namespace + "/" + serverProfile.GuardConfigMap, private: private,
	}, nil
}

func (b *identityAgentCatalogueBinding) Launch(ctx context.Context, profile identityCatalogueProfile, run AttackCatalogRunContext, prepared *identityCatalogueBindingPreparation) (identityCatalogueBindingSignal, bool, error) {
	private, ok := identityAgentPrivate(prepared)
	if !ok || run.CatalogueID != profile.ID || run.ExpectedAction != profile.ExpectedAction || private.fixture.Profile.CatalogueID != profile.ID {
		return identityCatalogueBindingSignal{}, false, errors.New("agent-action launch preparation changed")
	}
	private.state.runID = run.RunID
	signal, mutated, err := private.cluster.Launch(ctx, profile, private.fixture, run.RunID, &private.state)
	private.state.signal = signal
	return signal, mutated, err
}

func (b *identityAgentCatalogueBinding) BindAcceptedReceipt(profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation, signal identityCatalogueBindingSignal, decisionID string) error {
	private, ok := identityAgentPrivate(prepared)
	if !ok || profile.Family != identityCatalogueAgent || private.fixture.Profile.CatalogueID != profile.ID {
		return errors.New("agent-action receipt preparation changed")
	}
	return private.cluster.BindAcceptedReceipt(private.fixture, &private.state, signal, decisionID)
}

func (b *identityAgentCatalogueBinding) Physical(ctx context.Context, profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation) (identityCataloguePhysicalObservation, error) {
	private, ok := identityAgentPrivate(prepared)
	if !ok || profile.Family != identityCatalogueAgent || private.fixture.Profile.CatalogueID != profile.ID {
		return identityCataloguePhysicalObservation{}, errors.New("agent-action physical preparation changed")
	}
	return private.cluster.Physical(ctx, private.fixture, &private.state)
}

func (b *identityAgentCatalogueBinding) Cleanup(ctx context.Context, profile identityCatalogueProfile, prepared *identityCatalogueBindingPreparation, signal identityCatalogueBindingSignal) (identityCatalogueCleanupObservation, error) {
	private, ok := identityAgentPrivate(prepared)
	if !ok || profile.Family != identityCatalogueAgent || private.fixture.Profile.CatalogueID != profile.ID {
		return identityCatalogueCleanupObservation{Attempted: true}, errors.New("agent-action cleanup preparation changed")
	}
	if signal != private.state.signal {
		return identityCatalogueCleanupObservation{Attempted: true}, errors.New("agent-action cleanup signal binding changed")
	}
	return private.cluster.Cleanup(ctx, private.fixture, &private.state)
}

func identityAgentPrivate(prepared *identityCatalogueBindingPreparation) (*identityAgentPrivatePreparation, bool) {
	if prepared == nil {
		return nil, false
	}
	private, ok := prepared.private.(*identityAgentPrivatePreparation)
	return private, ok && private != nil && private.cluster != nil
}

type kubernetesAgentCatalogueCluster struct {
	cfg     Config
	kube    kubernetes.Interface
	dynamic dynamic.Interface
	client  ctrlclient.Client
	http    *http.Client
}

func newKubernetesAgentCatalogueCluster(cfg Config) (identityAgentCatalogueCluster, error) {
	var rc *rest.Config
	if cfg.ExperimentRESTConfig != nil {
		rc = rest.CopyConfig(cfg.ExperimentRESTConfig)
	} else {
		var err error
		rc, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.New("in-cluster agent catalogue authority unavailable")
		}
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, errors.New("agent catalogue Kubernetes client unavailable")
	}
	dynamicClient, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, errors.New("agent catalogue event client unavailable")
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, discoveryv1.AddToScheme, v1alpha1.AddToScheme} {
		if err = add(scheme); err != nil {
			return nil, errors.New("agent catalogue scheme unavailable")
		}
	}
	reader, err := ctrlclient.New(rc, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, errors.New("agent catalogue fixture client unavailable")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxIdleConns: 0}
	httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("agent catalogue fixture redirect refused")
	}}
	return &kubernetesAgentCatalogueCluster{cfg: cfg, kube: kube, dynamic: dynamicClient, client: reader, http: httpClient}, nil
}

func (k *kubernetesAgentCatalogueCluster) Prepare(ctx context.Context, p identityAgentServerProfile) (identityAgentCatalogueFixture, error) {
	if validateAgentCatalogueServerProfile(p.CatalogueID) != nil || agentCatalogueServerProfiles[p.CatalogueID] != p {
		return identityAgentCatalogueFixture{}, errors.New("agent catalogue server profile changed")
	}
	namespace, err := k.kube.CoreV1().Namespaces().Get(ctx, p.Namespace, metav1.GetOptions{})
	if err != nil || namespace.DeletionTimestamp != nil || namespace.Labels[agentCatalogueOwnershipLabel] != agentCatalogueOwnershipValue {
		return identityAgentCatalogueFixture{}, errors.New("agent catalogue fixture namespace is not chart-owned")
	}
	deployment, err := k.kube.AppsV1().Deployments(p.Namespace).Get(ctx, agentCatalogueDeployment, metav1.GetOptions{})
	if err != nil || !k.validDeployment(deployment, p) {
		return identityAgentCatalogueFixture{}, errors.New("agent catalogue deployment is not the immutable reviewed fixture")
	}
	serviceAccount, err := k.kube.CoreV1().ServiceAccounts(p.Namespace).Get(ctx, agentCatalogueServiceAccount, metav1.GetOptions{})
	if err != nil || serviceAccount.DeletionTimestamp != nil || serviceAccount.AutomountServiceAccountToken == nil || *serviceAccount.AutomountServiceAccountToken {
		return identityAgentCatalogueFixture{}, errors.New("agent catalogue fixture ServiceAccount is not tokenless")
	}
	var policy v1alpha1.PhorvexPolicy
	if err = k.client.Get(ctx, ctrlclient.ObjectKey{Namespace: p.Namespace, Name: p.PolicyName}, &policy); err != nil ||
		policy.UID == "" || policy.Generation < 1 || policy.DeletionTimestamp != nil || !validAgentCataloguePolicy(&policy, p) {
		return identityAgentCatalogueFixture{}, errors.New("agent catalogue policy is not the reviewed active reactive profile")
	}
	pods, err := k.kube.CoreV1().Pods(p.Namespace).List(ctx, metav1.ListOptions{LabelSelector: p.SelectorKey + "=" + p.SelectorVal})
	if err != nil || len(pods.Items) != 2 {
		return identityAgentCatalogueFixture{}, errors.New("agent catalogue fixture must have exactly two selected Pods")
	}
	sort.Slice(pods.Items, func(i, j int) bool { return string(pods.Items[i].UID) < string(pods.Items[j].UID) })
	target := &pods.Items[0]
	live, err := agentdeny.ValidateLive(ctx, k.client, p.Namespace, string(target.UID))
	if err != nil || len(live.Pods) != 2 || len(live.State.Entries) != 0 {
		return identityAgentCatalogueFixture{}, errors.New("agent catalogue live deny boundary is not clean")
	}
	podUIDs := agentCataloguePodUIDs(live)
	if !k.exactServingEndpoints(ctx, p.Namespace, podUIDs) {
		return identityAgentCatalogueFixture{}, errors.New("agent catalogue serving set differs from the two ready fixture Pods")
	}
	for _, pod := range live.Pods {
		if !k.probePod(ctx, pod.IP, p.CallerID, p.ActionID, http.StatusOK, "allow") ||
			!k.probePod(ctx, pod.IP, agentCatalogueBenignCaller, agentCatalogueBenignAction, http.StatusOK, "allow") ||
			!k.probePod(ctx, pod.IP, p.CallerID, agentCatalogueSurgicalAction, http.StatusOK, "allow") ||
			!k.probeGuard(ctx, pod.IP, nil) {
			return identityAgentCatalogueFixture{}, errors.New("agent catalogue baseline physical controls are not clean")
		}
	}
	if err = k.preflightAuthority(ctx, p); err != nil {
		return identityAgentCatalogueFixture{}, err
	}
	return identityAgentCatalogueFixture{Profile: p, DeploymentUID: string(deployment.UID), PolicyUID: string(policy.UID),
		PolicyGeneration: policy.Generation, TargetPodName: target.Name, TargetPodUID: string(target.UID),
		ServiceUID: live.ServiceUID, GuardUID: live.GuardUID, PodUIDs: podUIDs, ReactiveOnly: true}, nil
}

func validAgentCataloguePolicy(policy *v1alpha1.PhorvexPolicy, p identityAgentServerProfile) bool {
	if policy == nil || policy.Spec.Tenant != p.Namespace || policy.Spec.EffectiveMode() != v1alpha1.ModeActive ||
		len(policy.Spec.Selector.MatchLabels) != 1 || len(policy.Spec.Selector.MatchExpressions) != 0 ||
		policy.Spec.Selector.MatchLabels[p.SelectorKey] != p.SelectorVal || !exactAgentCatalogueActions(policy.Spec.Actions.Enabled) ||
		!policy.Spec.Triggers.EventDriven || !policy.Spec.Triggers.ReactiveOnly || policy.Spec.Triggers.EventAgeHorizon == nil ||
		policy.Spec.Triggers.EventAgeHorizon.Duration != time.Hour || len(policy.Spec.Triggers.KillChainSource) != 0 ||
		policy.Spec.Budget.MaxMovesPerTick == nil || *policy.Spec.Budget.MaxMovesPerTick != 1 ||
		policy.Spec.Budget.MaxGracePeriodSeconds == nil || *policy.Spec.Budget.MaxGracePeriodSeconds != 30 ||
		policy.Spec.Budget.TickInterval.Duration != 5*time.Second ||
		policy.Spec.Budget.AntiOverRotationWindow.Duration != 90*time.Second ||
		policy.Spec.Budget.ProactiveFloor.Duration != 15*time.Minute ||
		policy.Spec.Objective.Lambda != "0" || policy.Spec.Objective.DisruptionAversion != "1" ||
		policy.Spec.Objective.CostPreferences != nil || policy.Spec.Objective.CostWeights.NormSparsity != "0.4" ||
		policy.Spec.Objective.CostWeights.FlowDisruption != "0.6" || policy.Spec.SLO.CostCeiling != "1.2" ||
		policy.Spec.SLO.MinAvailableReplicas != 1 || policy.Spec.SLO.P99Ms != 0 || policy.Spec.SLO.MinTokensPerSec != 0 ||
		policy.Spec.SLO.Window.Duration != 0 || policy.Spec.SLO.AvailabilityBudget.Duration != 0 ||
		policy.Spec.SLO.LatencyBudget != "" || policy.Spec.SLO.DisruptionBudgetReplicaSeconds != 0 ||
		policy.Spec.SLO.ReserveFraction != "" || !policy.Spec.AssetValue.BlastRadiusFromGraph ||
		policy.Spec.AssetValue.WeightSecrets != "0.8" || len(policy.Spec.AssetValue.FromLabels) != 1 {
		return false
	}
	weights, ok := policy.Spec.AssetValue.FromLabels["data-class"]
	return ok && len(weights) == 3 && weights["internal"] == "0.4" && weights["public"] == "0.1" && weights["restricted"] == "1.0"
}

func exactAgentCatalogueActions(actions []v1alpha1.ActionType) bool {
	actual := make([]string, 0, len(actions))
	for _, action := range actions {
		actual = append(actual, string(action))
	}
	sort.Strings(actual)
	return slices.Equal(actual, []string{string(v1alpha1.ActionAgentActionDeny), string(v1alpha1.ActionRotate)})
}

func (k *kubernetesAgentCatalogueCluster) validDeployment(d *appsv1.Deployment, p identityAgentServerProfile) bool {
	if d == nil || d.UID == "" || d.DeletionTimestamp != nil || d.Labels[agentCatalogueOwnershipLabel] != agentCatalogueOwnershipValue ||
		d.Spec.Replicas == nil || *d.Spec.Replicas != 2 || d.Status.ObservedGeneration < d.Generation ||
		d.Status.AvailableReplicas != 2 || d.Status.ReadyReplicas != 2 || d.Status.UpdatedReplicas != 2 ||
		len(d.Spec.Selector.MatchLabels) != 1 || d.Spec.Selector.MatchLabels[p.SelectorKey] != p.SelectorVal ||
		len(d.Spec.Template.Labels) < 1 || d.Spec.Template.Labels[p.SelectorKey] != p.SelectorVal {
		return false
	}
	pod := d.Spec.Template.Spec
	if pod.NodeName != "" || len(pod.NodeSelector) != 0 || pod.Affinity != nil || pod.HostNetwork || pod.HostPID || pod.HostIPC ||
		pod.ServiceAccountName != agentCatalogueServiceAccount || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken ||
		len(pod.InitContainers) != 0 || len(pod.Containers) != 1 || len(pod.Volumes) != 1 || pod.SecurityContext == nil ||
		pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot || pod.SecurityContext.SeccompProfile == nil ||
		pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		return false
	}
	volume := pod.Volumes[0]
	if volume.ConfigMap == nil || volume.ConfigMap.Name != p.GuardConfigMap {
		return false
	}
	c := pod.Containers[0]
	if c.Name != agentCatalogueContainer || c.Image != k.cfg.AttackCatalogAgentActionImage || c.ImagePullPolicy != corev1.PullIfNotPresent ||
		len(c.Command) != 0 || len(c.Args) != 0 || len(c.Env) != 0 || len(c.EnvFrom) != 0 || c.WorkingDir != "" ||
		c.Lifecycle != nil || c.Stdin || c.TTY || c.SecurityContext == nil ||
		c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation ||
		c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem ||
		c.SecurityContext.RunAsNonRoot == nil || !*c.SecurityContext.RunAsNonRoot ||
		len(c.SecurityContext.Capabilities.Drop) != 1 || c.SecurityContext.Capabilities.Drop[0] != corev1.Capability("ALL") ||
		len(c.Ports) != 1 || c.Ports[0].ContainerPort != agentdeny.ServingPort ||
		len(c.VolumeMounts) != 1 || c.VolumeMounts[0].Name != volume.Name || !c.VolumeMounts[0].ReadOnly || c.VolumeMounts[0].MountPath != agentdeny.GuardMountPath ||
		c.ReadinessProbe == nil || c.ReadinessProbe.HTTPGet == nil || c.ReadinessProbe.HTTPGet.Path != "/healthz" {
		return false
	}
	return quantityEquals(c.Resources.Requests.Cpu(), agentCatalogueCPURequest) &&
		quantityEquals(c.Resources.Limits.Cpu(), agentCatalogueCPULimit) &&
		quantityEquals(c.Resources.Requests.Memory(), agentCatalogueMemoryRequest) &&
		quantityEquals(c.Resources.Limits.Memory(), agentCatalogueMemoryLimit)
}

func quantityEquals(actual *resource.Quantity, expected string) bool {
	if actual == nil {
		return false
	}
	want := resource.MustParse(expected)
	return actual.Cmp(want) == 0
}

func (k *kubernetesAgentCatalogueCluster) preflightAuthority(ctx context.Context, p identityAgentServerProfile) error {
	checks := []authorizationv1.ResourceAttributes{
		{Verb: "get", Resource: "namespaces", Name: p.Namespace},
		{Namespace: p.Namespace, Verb: "get", Group: appsv1.GroupName, Resource: "deployments", Name: agentCatalogueDeployment},
		{Namespace: p.Namespace, Verb: "get", Resource: "pods"}, {Namespace: p.Namespace, Verb: "list", Resource: "pods"},
		{Namespace: p.Namespace, Verb: "get", Resource: "services", Name: p.Service},
		{Namespace: p.Namespace, Verb: "get", Resource: "serviceaccounts", Name: agentCatalogueServiceAccount},
		{Namespace: p.Namespace, Verb: "get", Resource: "configmaps", Name: p.GuardConfigMap},
		{Namespace: p.Namespace, Verb: "update", Resource: "configmaps", Name: p.GuardConfigMap},
		{Namespace: p.Namespace, Verb: "list", Group: discoveryv1.GroupName, Resource: "endpointslices"},
		{Namespace: p.Namespace, Verb: "get", Group: "phorvex.ai", Resource: "phorvexpolicies", Name: p.PolicyName},
		{Verb: "get", Group: "amtd.r6security.com", Resource: "securityevents"},
		{Verb: "create", Group: "amtd.r6security.com", Resource: "securityevents"},
		{Verb: "delete", Group: "amtd.r6security.com", Resource: "securityevents"},
		{Verb: "create", Group: authorizationv1.GroupName, Resource: "selfsubjectaccessreviews"},
		{Verb: "create", Group: authorizationv1.GroupName, Resource: "subjectaccessreviews"},
	}
	for _, attrs := range checks {
		review, err := k.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx,
			&authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &attrs}}, metav1.CreateOptions{})
		if err != nil || !review.Status.Allowed {
			return errors.New("agent catalogue attacks service lacks exact fixture lifecycle authority")
		}
	}
	principalChecks := map[string][]authorizationv1.ResourceAttributes{
		k.cfg.AttackCatalogAgentManagerPrincipal: {
			{Namespace: p.Namespace, Verb: "get", Resource: "configmaps", Name: p.GuardConfigMap},
			{Namespace: p.Namespace, Verb: "update", Resource: "configmaps", Name: p.GuardConfigMap},
			{Namespace: p.Namespace, Verb: "get", Resource: "pods"}, {Namespace: p.Namespace, Verb: "list", Resource: "pods"},
			{Namespace: p.Namespace, Verb: "get", Resource: "services", Name: p.Service},
		},
		k.cfg.AttackCatalogAgentActuatorPrincipal: {
			{Namespace: p.Namespace, Verb: "get", Resource: "configmaps", Name: p.GuardConfigMap},
			{Namespace: p.Namespace, Verb: "update", Resource: "configmaps", Name: p.GuardConfigMap},
			{Namespace: p.Namespace, Verb: "get", Resource: "pods"}, {Namespace: p.Namespace, Verb: "list", Resource: "pods"},
			{Namespace: p.Namespace, Verb: "get", Resource: "services", Name: p.Service},
		},
		k.cfg.AttackCatalogAgentSensorPrincipal: {
			{Namespace: p.Namespace, Verb: "get", Resource: "pods"}, {Namespace: p.Namespace, Verb: "list", Resource: "pods"},
			{Namespace: p.Namespace, Verb: "get", Resource: "services", Name: p.Service},
			{Namespace: p.Namespace, Verb: "get", Resource: "configmaps", Name: p.GuardConfigMap},
			{Namespace: p.Namespace, Verb: "list", Group: discoveryv1.GroupName, Resource: "endpointslices"},
			{Namespace: p.Namespace, Verb: "get", Group: "phorvex.ai", Resource: "phorvexpolicies", Name: p.PolicyName},
		},
	}
	for principal, required := range principalChecks {
		for _, attrs := range required {
			review, err := k.kube.AuthorizationV1().SubjectAccessReviews().Create(ctx,
				&authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: principal, ResourceAttributes: &attrs}}, metav1.CreateOptions{})
			if err != nil || !review.Status.Allowed {
				return errors.New("agent catalogue manager, sensor, or actuator fixture RBAC is incomplete")
			}
		}
	}
	return nil
}

func (k *kubernetesAgentCatalogueCluster) Launch(ctx context.Context, profile identityCatalogueProfile, f identityAgentCatalogueFixture, runID string, state *identityAgentCatalogueRunState) (identityCatalogueBindingSignal, bool, error) {
	entry, ok := attackcatalog.Lookup(profile.ID)
	if !ok || state == nil || strings.TrimSpace(runID) == "" || entry.ID != f.Profile.CatalogueID ||
		entry.EventType != model.AttackVectorAgentActionAbuse || entry.ExpectedAction != string(model.ActionAgentActionDeny) {
		return identityCatalogueBindingSignal{}, false, errors.New("agent-action launch profile changed")
	}
	current, err := k.Prepare(ctx, f.Profile)
	if err != nil || !sameAgentCatalogueFixture(f, current) {
		return identityCatalogueBindingSignal{}, false, errors.New("agent-action fixture changed after preflight")
	}
	observedAt := time.Now().UTC()
	assertion := agentdeny.Observation{Version: 1, Namespace: f.Profile.Namespace, AgentName: f.Profile.AgentName,
		CallerID: f.Profile.CallerID, ActionID: f.Profile.ActionID, GuardConfigMapUID: f.GuardUID,
		ServiceUID: f.ServiceUID, TargetPodUID: f.TargetPodUID, Objective: f.Profile.Objective,
		ObservedAt: observedAt, PolicyName: f.Profile.PolicyName, PolicyUID: f.PolicyUID, PolicyGeneration: f.PolicyGeneration}
	annotation, err := json.Marshal(assertion)
	if err != nil {
		return identityCatalogueBindingSignal{}, false, errors.New("agent-action observation encoding failed")
	}
	random := make([]byte, 6)
	if _, err = cryptorand.Read(random); err != nil {
		return identityCatalogueBindingSignal{}, false, errors.New("agent-action signal identity generation failed")
	}
	name := "catalog-agent-" + hex.EncodeToString(random)
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": name,
			"labels": map[string]any{"phorvex.ai/redteam": "true", "phorvex.ai/catalogue-id": profile.ID},
			"annotations": map[string]any{model.ConsoleTargetPodUIDAnnotation: f.TargetPodUID,
				attackCatalogCorrelationAnnotation: runID, agentdeny.ObservationAnnotation: string(annotation)}},
		"spec": map[string]any{"description": entry.Description, "targets": []any{f.Profile.Namespace + "/" + f.TargetPodName},
			"rule": map[string]any{"type": entry.EventType, "threatLevel": "critical", "source": "console-catalogue"}},
	}}
	created, err := k.dynamic.Resource(securityEventGVR).Create(ctx, object, metav1.CreateOptions{})
	if err != nil {
		return identityCatalogueBindingSignal{Name: name}, true, errors.New("agent-action signal admission failed")
	}
	signal := identityCatalogueBindingSignal{Name: name, UID: string(created.GetUID()),
		Creator: created.GetAnnotations()["phorvex.ai/creator-identity"], CreatedAt: created.GetCreationTimestamp().Time}
	targets, _, _ := unstructured.NestedStringSlice(created.Object, "spec", "targets")
	ruleType, _, _ := unstructured.NestedString(created.Object, "spec", "rule", "type")
	annotations := created.GetAnnotations()
	if signal.UID == "" || signal.CreatedAt.IsZero() || signal.Creator != eventtrust.Injector() ||
		created.GetName() != name || annotations[attackCatalogCorrelationAnnotation] != runID ||
		annotations[model.ConsoleTargetPodUIDAnnotation] != f.TargetPodUID || annotations[agentdeny.ObservationAnnotation] != string(annotation) ||
		!slices.Equal(targets, []string{f.Profile.Namespace + "/" + f.TargetPodName}) || ruleType != entry.EventType {
		uid := created.GetUID()
		_ = k.dynamic.Resource(securityEventGVR).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		return signal, true, errors.New("agent-action signal identity or admitted observation differs")
	}
	state.runID, state.signal = runID, signal
	return signal, true, nil
}

func sameAgentCatalogueFixture(left, right identityAgentCatalogueFixture) bool {
	return left.Profile == right.Profile && left.DeploymentUID == right.DeploymentUID && left.PolicyUID == right.PolicyUID &&
		left.PolicyGeneration == right.PolicyGeneration && left.TargetPodName == right.TargetPodName &&
		left.TargetPodUID == right.TargetPodUID && left.ServiceUID == right.ServiceUID && left.GuardUID == right.GuardUID &&
		slices.Equal(left.PodUIDs, right.PodUIDs) && left.ReactiveOnly == right.ReactiveOnly
}

func (k *kubernetesAgentCatalogueCluster) BindAcceptedReceipt(f identityAgentCatalogueFixture, state *identityAgentCatalogueRunState, signal identityCatalogueBindingSignal, decisionID string) error {
	if state == nil || signal != state.signal || signal.UID == "" || !identityCatalogueSafeOpaqueID(decisionID) || f.Profile.CatalogueID == "" {
		return errors.New("agent-action accepted receipt identity is invalid")
	}
	if state.acceptedDecisionID != "" && state.acceptedDecisionID != decisionID {
		return errors.New("agent-action accepted receipt changed decisions")
	}
	state.acceptedDecisionID = decisionID
	return nil
}

func (k *kubernetesAgentCatalogueCluster) Physical(ctx context.Context, f identityAgentCatalogueFixture, state *identityAgentCatalogueRunState) (identityCataloguePhysicalObservation, error) {
	result := identityCataloguePhysicalObservation{PodUID: f.TargetPodUID, GuardUID: f.GuardUID, ServiceUID: f.ServiceUID}
	if state == nil || state.signal.UID == "" || state.acceptedDecisionID == "" {
		return result, errors.New("agent-action accepted decision receipt is not bound")
	}
	deployment, err := k.kube.AppsV1().Deployments(f.Profile.Namespace).Get(ctx, agentCatalogueDeployment, metav1.GetOptions{})
	if err != nil || string(deployment.UID) != f.DeploymentUID || !k.validDeployment(deployment, f.Profile) {
		return result, errors.New("agent-action immutable deployment changed")
	}
	var policy v1alpha1.PhorvexPolicy
	if err = k.client.Get(ctx, ctrlclient.ObjectKey{Namespace: f.Profile.Namespace, Name: f.Profile.PolicyName}, &policy); err != nil ||
		string(policy.UID) != f.PolicyUID || policy.Generation != f.PolicyGeneration || !validAgentCataloguePolicy(&policy, f.Profile) {
		return result, errors.New("agent-action policy epoch changed")
	}
	live, err := agentdeny.ValidateLive(ctx, k.client, f.Profile.Namespace, f.TargetPodUID)
	if err != nil || live.ServiceUID != f.ServiceUID || live.GuardUID != f.GuardUID || !slices.Equal(agentCataloguePodUIDs(live), f.PodUIDs) ||
		!k.exactServingEndpoints(ctx, f.Profile.Namespace, f.PodUIDs) {
		return result, errors.New("agent-action serving identities changed")
	}
	key := agentdeny.ActionKey(f.Profile.CallerID, f.Profile.ActionID)
	entry, exists := live.State.Entry(key)
	if !exists || len(live.State.Entries) != 1 || !entry.Active || entry.OperationID != state.acceptedDecisionID {
		return result, errors.New("agent-action guard ledger is not the accepted decision receipt")
	}
	result.DeniedAfter, result.BenignAllowedAfter, result.SurgicalAllowedAfter = true, true, true
	for _, pod := range live.Pods {
		result.DeniedAfter = result.DeniedAfter && k.probePod(ctx, pod.IP, f.Profile.CallerID, f.Profile.ActionID, http.StatusForbidden, "deny")
		result.BenignAllowedAfter = result.BenignAllowedAfter && k.probePod(ctx, pod.IP, agentCatalogueBenignCaller, agentCatalogueBenignAction, http.StatusOK, "allow")
		result.SurgicalAllowedAfter = result.SurgicalAllowedAfter && k.probePod(ctx, pod.IP, f.Profile.CallerID, agentCatalogueSurgicalAction, http.StatusOK, "allow")
		if !k.probeGuard(ctx, pod.IP, []string{key}) {
			result.DeniedAfter = false
		}
	}
	result.ServingSetRetained = true
	return result, nil
}

func (k *kubernetesAgentCatalogueCluster) Cleanup(ctx context.Context, f identityAgentCatalogueFixture, state *identityAgentCatalogueRunState) (identityCatalogueCleanupObservation, error) {
	result := identityCatalogueCleanupObservation{Attempted: true}
	if state == nil {
		return result, errors.New("agent-action cleanup state is absent")
	}
	result.EventAbsent = k.deleteExactSignal(ctx, f, state)
	if !result.EventAbsent {
		return result, errors.New("agent-action exact SecurityEvent absence is unverified")
	}
	cm, err := k.kube.CoreV1().ConfigMaps(f.Profile.Namespace).Get(ctx, f.Profile.GuardConfigMap, metav1.GetOptions{})
	if err != nil || string(cm.UID) != f.GuardUID {
		return result, errors.New("agent-action cleanup guard identity changed")
	}
	key := agentdeny.ActionKey(f.Profile.CallerID, f.Profile.ActionID)
	nextData, changed, err := agentCatalogueCleanGuardData(cm.Data, key, state.acceptedDecisionID)
	if err != nil {
		return result, err
	}
	if changed {
		cm.Data = nextData
		if _, err = k.kube.CoreV1().ConfigMaps(f.Profile.Namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			return result, errors.New("agent-action cleanup guard compare-and-swap failed")
		}
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		live, liveErr := agentdeny.ValidateLive(ctx, k.client, f.Profile.Namespace, f.TargetPodUID)
		if liveErr == nil && live.GuardUID == f.GuardUID && live.ServiceUID == f.ServiceUID && len(live.State.Entries) == 0 &&
			slices.Equal(agentCataloguePodUIDs(live), f.PodUIDs) && k.exactServingEndpoints(ctx, f.Profile.Namespace, f.PodUIDs) {
			clean := true
			for _, pod := range live.Pods {
				clean = clean && k.probeGuard(ctx, pod.IP, nil) &&
					k.probePod(ctx, pod.IP, f.Profile.CallerID, f.Profile.ActionID, http.StatusOK, "allow") &&
					k.probePod(ctx, pod.IP, agentCatalogueBenignCaller, agentCatalogueBenignAction, http.StatusOK, "allow") &&
					k.probePod(ctx, pod.IP, f.Profile.CallerID, agentCatalogueSurgicalAction, http.StatusOK, "allow")
			}
			if clean {
				result.FixtureRestored = true
				return result, nil
			}
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-ticker.C:
		}
	}
}

func agentCatalogueCleanGuardData(data map[string]string, actionKey, acceptedDecisionID string) (map[string]string, bool, error) {
	current := agentdeny.Guard{Version: 2, Entries: []agentdeny.Entry{}}
	if raw := data[agentdeny.StateKey]; raw != "" {
		parsed, err := agentdeny.ParseState(raw)
		if err != nil {
			return nil, false, errors.New("agent-action cleanup guard ledger is malformed")
		}
		current = parsed
	}
	if len(current.Entries) == 0 {
		if !agentdeny.AppGuardMatches(data[agentdeny.GuardKey], current) {
			return nil, false, errors.New("agent-action cleanup empty ledger disagrees with the app guard")
		}
		return data, false, nil
	}
	entry, exists := current.Entry(actionKey)
	if !exists || len(current.Entries) != 1 || acceptedDecisionID == "" || entry.OperationID != acceptedDecisionID {
		return nil, false, errors.New("agent-action cleanup refuses a foreign or cross-run guard entry")
	}
	next := make(map[string]string, len(data))
	for key, value := range data {
		next[key] = value
	}
	next[agentdeny.GuardKey] = (agentdeny.Guard{Version: 2, Entries: []agentdeny.Entry{}}).EncodeAppGuard()
	delete(next, agentdeny.StateKey)
	return next, true, nil
}

func (k *kubernetesAgentCatalogueCluster) deleteExactSignal(ctx context.Context, f identityAgentCatalogueFixture, state *identityAgentCatalogueRunState) bool {
	if state.signal.Name == "" {
		return true
	}
	object, err := k.dynamic.Resource(securityEventGVR).Get(ctx, state.signal.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true
	}
	if err != nil || object.GetUID() == "" || (state.signal.UID != "" && string(object.GetUID()) != state.signal.UID) ||
		object.GetAnnotations()[attackCatalogCorrelationAnnotation] != state.runID ||
		object.GetLabels()["phorvex.ai/catalogue-id"] != f.Profile.CatalogueID {
		return false
	}
	uid := object.GetUID()
	if err = k.dynamic.Resource(securityEventGVR).Delete(ctx, state.signal.Name,
		metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
		return false
	}
	_, err = k.dynamic.Resource(securityEventGVR).Get(ctx, state.signal.Name, metav1.GetOptions{})
	return apierrors.IsNotFound(err)
}

func agentCataloguePodUIDs(live agentdeny.Live) []string {
	result := make([]string, 0, len(live.Pods))
	for _, pod := range live.Pods {
		result = append(result, pod.UID)
	}
	sort.Strings(result)
	return result
}

func (k *kubernetesAgentCatalogueCluster) exactServingEndpoints(ctx context.Context, namespace string, want []string) bool {
	slicesList, err := k.kube.DiscoveryV1().EndpointSlices(namespace).List(ctx,
		metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + agentdeny.ServiceName})
	if err != nil || len(slicesList.Items) == 0 {
		return false
	}
	seen := []string{}
	for _, slice := range slicesList.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef != nil && endpoint.TargetRef.Kind == "Pod" && endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready {
				seen = append(seen, string(endpoint.TargetRef.UID))
			}
		}
	}
	sort.Strings(seen)
	return slices.Equal(seen, want)
}

func (k *kubernetesAgentCatalogueCluster) probePod(ctx context.Context, ip, caller, action string, status int, decision string) bool {
	if net.ParseIP(ip) == nil || !agentdeny.ValidID(caller) || !agentdeny.ValidID(action) {
		return false
	}
	query := url.Values{"caller": []string{caller}, "action": []string{action}}.Encode()
	target := "http://" + net.JoinHostPort(ip, strconv.Itoa(agentdeny.ServingPort)) + "/act?" + query
	raw, responseStatus, err := k.fixtureGET(ctx, target)
	if err != nil || responseStatus != status {
		return false
	}
	var response struct {
		Decision string `json:"decision"`
		Caller   string `json:"caller"`
		Action   string `json:"action"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&response) == nil && decoder.Decode(new(any)) == io.EOF &&
		response.Decision == decision && response.Caller == caller && response.Action == action
}

func (k *kubernetesAgentCatalogueCluster) probeGuard(ctx context.Context, ip string, want []string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}
	target := "http://" + net.JoinHostPort(ip, strconv.Itoa(agentdeny.ServingPort)) + agentdeny.ReadbackPath
	raw, status, err := k.fixtureGET(ctx, target)
	if err != nil || status != http.StatusOK {
		return false
	}
	var response struct {
		Denied []string `json:"denied_agent_actions"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || decoder.Decode(new(any)) != io.EOF || response.Denied == nil {
		return false
	}
	sort.Strings(response.Denied)
	expected := slices.Clone(want)
	if expected == nil {
		expected = []string{}
	}
	sort.Strings(expected)
	return slices.Equal(response.Denied, expected)
}

func (k *kubernetesAgentCatalogueCluster) fixtureGET(ctx context.Context, target string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := k.http.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return nil, response.StatusCode, err
	}
	return raw, response.StatusCode, nil
}

var _ identityAgentCatalogueCluster = (*kubernetesAgentCatalogueCluster)(nil)
var _ identityCatalogueAcceptedReceiptBinder = (*identityAgentCatalogueBinding)(nil)
