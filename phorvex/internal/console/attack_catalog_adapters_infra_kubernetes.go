package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/datastore"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/retry"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	infraTrustedImageRefAnnotation = "phorvex.ai/trusted-image-ref"
	infraRunningImageAnnotation    = "phorvex.ai/running-image-digest"
	infraTrustedImageAnnotation    = "phorvex.ai/trusted-image-digest"
	infraTargetPodUIDAnnotation    = "phorvex.ai/target-pod-uid"
	infraNetworkObservation        = "phorvex.ai/network-edge-observation-v1"
	infraNodeObservation           = "phorvex.ai/node-escape-observation-v1"
	infraNetworkIsolatedLabel      = "phorvex.ai/network-isolated"
	infraNetworkPolicyOfLabel      = "phorvex.ai/network-isolate-of"
	infraNetworkSnapshotAnnotation = "phorvex.ai/network-isolate-snapshot"
	infraNetworkEpochAnnotation    = "phorvex.ai/network-isolate-epoch"
	infraNodeSnapshotAnnotation    = "phorvex.ai/node-recycle-snapshot"
	infraNodeEpochAnnotation       = "phorvex.ai/node-recycle-epoch"
	infraNodeTargetAnnotation      = "phorvex.ai/node-recycle-of"
	infraNodeReplacementLabel      = "phorvex.ai/replacement-for"
)

type kubernetesInfraCatalogueRuntime struct {
	profile infraCatalogueProfile
	rest    *rest.Config
	kube    kubernetes.Interface
	dynamic dynamic.Interface
	reader  ctrlclient.Client
}

func newKubernetesInfraCatalogueRuntime(cfg Config, profile infraCatalogueProfile) (infraCatalogueRuntime, error) {
	var rc *rest.Config
	if cfg.ExperimentRESTConfig != nil {
		rc = rest.CopyConfig(cfg.ExperimentRESTConfig)
	} else {
		var err error
		rc, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.New("in-cluster infra catalogue authority unavailable")
		}
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, errors.New("infra catalogue Kubernetes client unavailable")
	}
	creatorConfig := rest.CopyConfig(rc)
	creatorConfig.Impersonate = rest.ImpersonationConfig{UserName: profile.creator()}
	dyn, err := dynamic.NewForConfig(creatorConfig)
	if err != nil {
		return nil, errors.New("infra catalogue trusted-event client unavailable")
	}
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, discoveryv1.AddToScheme, networkingv1.AddToScheme, v1alpha1.AddToScheme,
	} {
		if err = add(s); err != nil {
			return nil, errors.New("infra catalogue scheme unavailable")
		}
	}
	reader, err := ctrlclient.New(rc, ctrlclient.Options{Scheme: s})
	if err != nil {
		return nil, errors.New("infra catalogue authoritative reader unavailable")
	}
	return &kubernetesInfraCatalogueRuntime{profile: profile, rest: rc, kube: kube, dynamic: dyn, reader: reader}, nil
}

type infraNetworkEdge struct {
	Token, CIDR, URL string
	Insecure         bool
}

type infraNetworkState struct {
	Edges               []infraNetworkEdge
	ForbiddenBefore     map[string]bool
	LegitimateBefore    bool
	PeerForbiddenBefore map[string]bool
	LegitimateURL       string
	MinimumAvailable    int
}

type infraDatastoreState struct {
	Live           datastore.Live
	TrustedContent []byte
	TrustedSHA     string
	BenignID       string
	PoisonedSHA    string
}

type infraImageState struct {
	DeploymentUID string
	Pin           string
	PinDigest     string
	OriginalImage string
}

type infraNodeState struct {
	CompromisedNodeUID string
	HealthyNodeUID     string
	HealthyNodePods    map[string]string
	BaselinePodUIDs    map[string]bool
	MinimumAvailable   int
}

type infraNodeActuatorSnapshot struct {
	Version         int    `json:"version"`
	NodeName        string `json:"nodeName"`
	NodeUID         string `json:"nodeUID"`
	UnschedulBefore bool   `json:"unschedulableBefore"`
	TargetPodUID    string `json:"targetPodUID"`
}

func (k *kubernetesInfraCatalogueRuntime) Prepare(ctx context.Context, profile infraCatalogueProfile) (infraCatalogueFixture, error) {
	if profile.ID != k.profile.ID || profile.Namespace != k.profile.Namespace {
		return infraCatalogueFixture{}, errors.New("infra Kubernetes runtime profile binding changed")
	}
	switch profile.Family {
	case infraFamilyNetworkEdge:
		return k.prepareNetwork(ctx, profile)
	case infraFamilyDatastore:
		return k.prepareDatastore(ctx, profile)
	case infraFamilyImage:
		return k.prepareImage(ctx, profile)
	case infraFamilyNodeRecycle:
		return k.prepareNode(ctx, profile)
	default:
		return infraCatalogueFixture{}, errors.New("unreviewed infra catalogue family")
	}
}

func (k *kubernetesInfraCatalogueRuntime) Arm(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture) (infraCatalogueArm, error) {
	switch profile.Family {
	case infraFamilyNetworkEdge, infraFamilyNodeRecycle:
		return infraCatalogueArm{TargetName: fixture.TargetName, TargetUID: fixture.TargetUID}, nil
	case infraFamilyDatastore:
		return k.armDatastore(ctx, profile, fixture)
	case infraFamilyImage:
		return k.armImage(ctx, profile, fixture)
	default:
		return infraCatalogueArm{}, errors.New("unreviewed infra catalogue family")
	}
}

func (k *kubernetesInfraCatalogueRuntime) Physical(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture, arm infraCatalogueArm) (AttackCatalogPhysicalResult, error) {
	switch profile.Family {
	case infraFamilyNetworkEdge:
		return k.physicalNetwork(ctx, profile, fixture, arm)
	case infraFamilyDatastore:
		return k.physicalDatastore(ctx, profile, fixture, arm)
	case infraFamilyImage:
		return k.physicalImage(ctx, profile, fixture)
	case infraFamilyNodeRecycle:
		return k.physicalNode(ctx, profile, fixture, arm)
	default:
		return AttackCatalogPhysicalResult{}, errors.New("unreviewed infra catalogue family")
	}
}

func (k *kubernetesInfraCatalogueRuntime) Cleanup(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture, arm infraCatalogueArm, signal infraCatalogueSignal) AttackCatalogCleanupResult {
	result := AttackCatalogCleanupResult{Attempted: true}
	problems := []string{}
	result.EventDeleted = k.cleanupEvent(ctx, profile, fixture, arm, signal)
	if !result.EventDeleted {
		problems = append(problems, "exact SecurityEvent absence unverified")
	}
	var clean bool
	var err error
	switch profile.Family {
	case infraFamilyNetworkEdge:
		clean, err = k.cleanupNetwork(ctx, profile, fixture, arm)
	case infraFamilyDatastore:
		clean, err = k.cleanupDatastore(ctx, profile, fixture)
	case infraFamilyImage:
		clean, err = k.cleanupImage(ctx, profile, fixture)
	case infraFamilyNodeRecycle:
		clean, err = k.cleanupNode(ctx, profile, fixture)
	default:
		err = errors.New("unreviewed infra catalogue family")
	}
	result.MarkerDeleted = clean
	if err != nil {
		problems = append(problems, err.Error())
	} else if !clean {
		problems = append(problems, "family mutation residue absence unverified")
	}
	result.Verified = result.EventDeleted && result.MarkerDeleted
	result.Reason = strings.Join(problems, "; ")
	result.Evidence = marshalInfraEvidence(map[string]any{"eventDeleted": result.EventDeleted, "familyResidueRemoved": result.MarkerDeleted})
	return result
}

func (k *kubernetesInfraCatalogueRuntime) policyForPod(ctx context.Context, profile infraCatalogueProfile, pod *corev1.Pod) (*v1alpha1.PhorvexPolicy, error) {
	if pod == nil || pod.UID == "" {
		return nil, errors.New("infra target Pod identity absent")
	}
	var policies v1alpha1.PhorvexPolicyList
	if err := k.reader.List(ctx, &policies, ctrlclient.InNamespace(profile.Namespace)); err != nil {
		return nil, err
	}
	matches := make([]*v1alpha1.PhorvexPolicy, 0, 1)
	for i := range policies.Items {
		policy := &policies.Items[i]
		if profile.PolicyName != "" && policy.Name != profile.PolicyName {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
		if err != nil || selector.Empty() || !selector.Matches(labels.Set(pod.Labels)) ||
			policy.Spec.EffectiveMode() != v1alpha1.ModeActive || !policy.Spec.Triggers.EventDriven ||
			!policy.Spec.ActionEnabled(v1alpha1.ActionType(profile.ExpectedAction)) || policy.UID == "" || policy.Generation < 1 {
			continue
		}
		matches = append(matches, policy)
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("%s fixture must have exactly one matching active event-driven policy enabling %s", profile.ID, profile.ExpectedAction)
	}
	return matches[0].DeepCopy(), nil
}

func (k *kubernetesInfraCatalogueRuntime) readyPods(ctx context.Context, profile infraCatalogueProfile) ([]corev1.Pod, error) {
	selector, err := labels.Parse(profile.Selector)
	if err != nil || selector.Empty() {
		return nil, errors.New("reviewed infra selector is invalid")
	}
	pods, err := k.kube.CoreV1().Pods(profile.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, err
	}
	ready := make([]corev1.Pod, 0, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp == nil && pod.Status.Phase == corev1.PodRunning && podReady(pod) && pod.UID != "" {
			ready = append(ready, *pod.DeepCopy())
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].Name < ready[j].Name })
	return ready, nil
}

func (k *kubernetesInfraCatalogueRuntime) prepareNetwork(ctx context.Context, profile infraCatalogueProfile) (infraCatalogueFixture, error) {
	pods, err := k.readyPods(ctx, profile)
	if err != nil || len(pods) < 2 {
		return infraCatalogueFixture{}, errors.New("network-edge fixture requires at least two Ready demo-api Pods")
	}
	target, peer := &pods[0], &pods[1]
	if !networkMarkersAbsent(target) || !networkMarkersAbsent(peer) {
		return infraCatalogueFixture{}, errors.New("network-edge fixture contains residue from another isolation lifetime")
	}
	policy, err := k.policyForPod(ctx, profile, target)
	if err != nil {
		return infraCatalogueFixture{}, err
	}
	deployment, err := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
	if err != nil || deployment.UID == "" || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas < 2 ||
		policy.Spec.SLO.MinAvailableReplicas != int(*deployment.Spec.Replicas) {
		return infraCatalogueFixture{}, errors.New("network-edge policy must pin minAvailableReplicas to the reviewed Deployment replica count")
	}
	edges, err := k.resolveNetworkEdges(ctx, profile, target)
	if err != nil {
		return infraCatalogueFixture{}, err
	}
	before := make(map[string]bool, len(edges))
	peerBefore := make(map[string]bool, len(edges))
	for _, edge := range edges {
		before[edge.CIDR] = k.probeFromPod(ctx, profile.Namespace, target.Name, profile.Container, edge.URL, edge.Insecure)
		peerBefore[edge.CIDR] = k.probeFromPod(ctx, profile.Namespace, peer.Name, profile.Container, edge.URL, edge.Insecure)
	}
	legitimateURL := "http://" + profile.Deployment + "." + profile.Namespace + ".svc.cluster.local/"
	legitimate := k.probeFromPod(ctx, profile.Namespace, target.Name, profile.Container, legitimateURL, false)
	if !allMapValues(before, true) || !allMapValues(peerBefore, true) || !legitimate {
		return infraCatalogueFixture{}, errors.New("network-edge baseline must prove target and peer forbidden edges plus legitimate/DNS egress are reachable")
	}
	receipt := networkPolicyObject(profile.Namespace, string(target.UID))
	return infraCatalogueFixture{Namespace: profile.Namespace, TargetName: target.Name, TargetUID: string(target.UID), TargetNode: target.Spec.NodeName,
		PeerName: peer.Name, PeerUID: string(peer.UID), PolicyName: policy.Name, PolicyUID: string(policy.UID),
		PolicyGeneration: policy.Generation, ReactiveOnly: policy.Spec.Triggers.ReactiveOnly, ReceiptObjects: []string{receipt},
		State: &infraNetworkState{Edges: edges, ForbiddenBefore: before, PeerForbiddenBefore: peerBefore,
			LegitimateBefore: legitimate, LegitimateURL: legitimateURL, MinimumAvailable: policy.Spec.SLO.MinAvailableReplicas}}, nil
}

func (k *kubernetesInfraCatalogueRuntime) resolveNetworkEdges(ctx context.Context, profile infraCatalogueProfile, target *corev1.Pod) ([]infraNetworkEdge, error) {
	var c2IP, nodeIP string
	if slicesContain(profile.ForbiddenEdges, "c2") {
		c2, err := k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, "c2-sink", metav1.GetOptions{})
		if err != nil || c2.DeletionTimestamp != nil || c2.Status.Phase != corev1.PodRunning || net.ParseIP(c2.Status.PodIP) == nil {
			return nil, errors.New("reviewed c2-sink egress target is unavailable")
		}
		c2IP = c2.Status.PodIP
	}
	if slicesContain(profile.ForbiddenEdges, "kubelet") {
		node, err := k.kube.CoreV1().Nodes().Get(ctx, target.Spec.NodeName, metav1.GetOptions{})
		if err != nil {
			return nil, errors.New("target node is unavailable for the kubelet edge")
		}
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeInternalIP && net.ParseIP(address.Address) != nil {
				nodeIP = address.Address
				break
			}
		}
		if nodeIP == "" {
			return nil, errors.New("target node InternalIP is unavailable for the kubelet edge")
		}
	}
	edges := make([]infraNetworkEdge, 0, len(profile.ForbiddenEdges))
	for _, token := range profile.ForbiddenEdges {
		switch token {
		case "c2":
			edges = append(edges, infraNetworkEdge{Token: token, CIDR: c2IP + "/32", URL: "http://" + net.JoinHostPort(c2IP, "8080") + "/"})
		case "imds":
			edges = append(edges, infraNetworkEdge{Token: token, CIDR: "169.254.169.254/32", URL: "http://169.254.169.254/"})
		case "kubelet":
			edges = append(edges, infraNetworkEdge{Token: token, CIDR: nodeIP + "/32", URL: "https://" + net.JoinHostPort(nodeIP, "10250") + "/healthz", Insecure: true})
		}
	}
	if len(edges) != len(profile.ForbiddenEdges) {
		return nil, errors.New("reviewed forbidden edge resolution changed")
	}
	return edges, nil
}

func (k *kubernetesInfraCatalogueRuntime) probeFromPod(ctx context.Context, namespace, pod, container, endpoint string, insecure bool) bool {
	command := []string{"curl", "-sS", "-m", "4", "-o", "/dev/null"}
	if insecure {
		command = append(command, "-k")
	}
	command = append(command, endpoint)
	req := k.kube.CoreV1().RESTClient().Post().Resource("pods").Name(pod).Namespace(namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: container, Command: command, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(k.rest, http.MethodPost, req.URL())
	if err != nil {
		return false
	}
	var output bytes.Buffer
	return executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &output, Stderr: &output}) == nil
}

func (k *kubernetesInfraCatalogueRuntime) physicalNetwork(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture, arm infraCatalogueArm) (AttackCatalogPhysicalResult, error) {
	state, ok := fixture.State.(*infraNetworkState)
	if !ok || state == nil {
		return AttackCatalogPhysicalResult{}, errors.New("network-edge preparation state changed")
	}
	result := infraNetworkEvidence{ForbiddenBefore: copyBoolMap(state.ForbiddenBefore), ForbiddenAfter: map[string]bool{},
		LegitimateBefore: state.LegitimateBefore, MinimumAvailable: state.MinimumAvailable}
	target, targetErr := k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, arm.TargetName, metav1.GetOptions{})
	peer, peerErr := k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, fixture.PeerName, metav1.GetOptions{})
	result.TargetSameUIDReady = targetErr == nil && string(target.UID) == arm.TargetUID && target.DeletionTimestamp == nil &&
		podReady(target) && target.Labels[infraNetworkIsolatedLabel] == arm.TargetUID
	result.PeerSameUIDUntouched = peerErr == nil && string(peer.UID) == fixture.PeerUID && peer.DeletionTimestamp == nil && podReady(peer) &&
		networkMarkersAbsent(peer)
	if result.TargetSameUIDReady {
		result.LegitimateAfter = k.probeFromPod(ctx, profile.Namespace, target.Name, profile.Container, state.LegitimateURL, false)
		for _, edge := range state.Edges {
			result.ForbiddenAfter[edge.CIDR] = k.probeFromPod(ctx, profile.Namespace, target.Name, profile.Container, edge.URL, edge.Insecure)
		}
	}
	peerEdges := map[string]bool{}
	if result.PeerSameUIDUntouched {
		for _, edge := range state.Edges {
			peerEdges[edge.CIDR] = k.probeFromPod(ctx, profile.Namespace, peer.Name, profile.Container, edge.URL, edge.Insecure)
		}
	}
	result.PeerEdgesReachable = allMapValues(peerEdges, true)
	pods, err := k.readyPods(ctx, profile)
	if err == nil {
		result.Available = len(pods)
	}
	policyOK := k.networkPolicyExact(ctx, profile.Namespace, arm.TargetName, arm.TargetUID, state.Edges)
	validated := policyOK && allMapValues(result.ForbiddenBefore, true) && allMapValues(result.ForbiddenAfter, false) &&
		result.LegitimateBefore && result.LegitimateAfter && result.TargetSameUIDReady && result.PeerSameUIDUntouched &&
		result.PeerEdgesReachable && result.Available >= result.MinimumAvailable
	return AttackCatalogPhysicalResult{Validated: validated, Oracle: infraNetworkOracle, Evidence: marshalInfraEvidence(result), PodRetained: result.TargetSameUIDReady, PodUID: arm.TargetUID}, nil
}

func (k *kubernetesInfraCatalogueRuntime) networkPolicyExact(ctx context.Context, namespace, podName, podUID string, edges []infraNetworkEdge) bool {
	name := strings.TrimPrefix(networkPolicyObject(namespace, podUID), "NetworkPolicy/"+namespace+"/")
	policy, err := k.kube.NetworkingV1().NetworkPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || policy.Labels[infraNetworkPolicyOfLabel] != podName || policy.Labels["app.kubernetes.io/managed-by"] != "phorvex" ||
		len(policy.OwnerReferences) != 1 || policy.OwnerReferences[0].APIVersion != "v1" || policy.OwnerReferences[0].Kind != "Pod" ||
		policy.OwnerReferences[0].Name != podName || string(policy.OwnerReferences[0].UID) != podUID ||
		len(policy.Spec.PodSelector.MatchLabels) != 1 || policy.Spec.PodSelector.MatchLabels[infraNetworkIsolatedLabel] != podUID ||
		len(policy.Spec.PodSelector.MatchExpressions) != 0 ||
		!slicesEqual(policy.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}) || len(policy.Spec.Egress) != 2 {
		return false
	}
	want := make([]string, 0, len(edges))
	for _, edge := range edges {
		want = append(want, edge.CIDR)
	}
	sort.Strings(want)
	dnsOK, edgeOK := false, false
	for _, rule := range policy.Spec.Egress {
		if len(rule.To) == 0 && len(rule.Ports) == 2 {
			udp, tcp := false, false
			for _, port := range rule.Ports {
				if port.Port == nil || port.Port.IntVal != 53 || port.EndPort != nil || port.Protocol == nil {
					continue
				}
				udp = udp || *port.Protocol == corev1.ProtocolUDP
				tcp = tcp || *port.Protocol == corev1.ProtocolTCP
			}
			dnsOK = udp && tcp
		}
		if len(rule.Ports) == 0 && len(rule.To) == 1 && rule.To[0].IPBlock != nil &&
			rule.To[0].PodSelector == nil && rule.To[0].NamespaceSelector == nil && rule.To[0].IPBlock.CIDR == "0.0.0.0/0" {
			got := append([]string(nil), rule.To[0].IPBlock.Except...)
			sort.Strings(got)
			edgeOK = slicesEqual(got, want)
		}
	}
	return dnsOK && edgeOK
}

func (k *kubernetesInfraCatalogueRuntime) cleanupNetwork(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture, arm infraCatalogueArm) (bool, error) {
	if arm.TargetName == "" || arm.TargetUID == "" {
		return true, nil
	}
	name := strings.TrimPrefix(networkPolicyObject(profile.Namespace, arm.TargetUID), "NetworkPolicy/"+profile.Namespace+"/")
	np, err := k.kube.NetworkingV1().NetworkPolicies(profile.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		owned := len(np.OwnerReferences) == 1 && string(np.OwnerReferences[0].UID) == arm.TargetUID && np.Labels[infraNetworkPolicyOfLabel] == arm.TargetName
		if !owned {
			return false, errors.New("network-edge cleanup refused an unbound NetworkPolicy")
		}
		uid := np.UID
		if err = k.kube.NetworkingV1().NetworkPolicies(profile.Namespace).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
			return false, err
		}
	} else if !apierrors.IsNotFound(err) {
		return false, err
	}
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		pod, getErr := k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, arm.TargetName, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			return nil
		}
		if getErr != nil {
			return getErr
		}
		if string(pod.UID) != arm.TargetUID {
			return nil
		}
		if networkMarkersAbsent(pod) {
			return nil
		}
		delete(pod.Labels, infraNetworkIsolatedLabel)
		delete(pod.Annotations, infraNetworkSnapshotAnnotation)
		delete(pod.Annotations, infraNetworkEpochAnnotation)
		_, updateErr := k.kube.CoreV1().Pods(profile.Namespace).Update(ctx, pod, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		return false, err
	}
	_, err = k.kube.NetworkingV1().NetworkPolicies(profile.Namespace).Get(ctx, name, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		if err == nil {
			return false, nil
		}
		return false, err
	}
	pod, err := k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, arm.TargetName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) || (err == nil && string(pod.UID) != arm.TargetUID) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return networkMarkersAbsent(pod), nil
}

func networkMarkersAbsent(pod *corev1.Pod) bool {
	return pod != nil && pod.Labels[infraNetworkIsolatedLabel] == "" &&
		pod.Annotations[infraNetworkSnapshotAnnotation] == "" && pod.Annotations[infraNetworkEpochAnnotation] == ""
}

func (k *kubernetesInfraCatalogueRuntime) prepareDatastore(ctx context.Context, profile infraCatalogueProfile) (infraCatalogueFixture, error) {
	pods, err := k.readyPods(ctx, profile)
	if err != nil || len(pods) == 0 {
		return infraCatalogueFixture{}, errors.New("datastore fixture has no Ready serving Pod")
	}
	target := &pods[0]
	policy, err := k.policyForPod(ctx, profile, target)
	if err != nil {
		return infraCatalogueFixture{}, err
	}
	live, err := datastore.ValidateLive(ctx, k.reader, profile.Namespace, string(target.UID))
	if err != nil || live.CurrentSHA != live.TrustedSHA {
		return infraCatalogueFixture{}, errors.New("datastore baseline must match the operator trusted snapshot")
	}
	store, err := datastore.ParseStore(live.TrustedContent)
	if err != nil || len(store.Records) == 0 {
		return infraCatalogueFixture{}, errors.New("datastore trusted snapshot has no benign control record")
	}
	for _, record := range store.Records {
		if record.ID == profile.PoisonID {
			return infraCatalogueFixture{}, errors.New("datastore poison record is already present at baseline")
		}
	}
	if !k.datastorePodsServe(ctx, live, live.TrustedSHA, store.Records[0].ID, profile.PoisonID, false) {
		return infraCatalogueFixture{}, errors.New("datastore baseline serving readback did not prove trusted content and benign control")
	}
	return infraCatalogueFixture{Namespace: profile.Namespace, TargetName: target.Name, TargetUID: string(target.UID),
		PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation,
		ReactiveOnly: policy.Spec.Triggers.ReactiveOnly, ReceiptObjects: []string{profile.Namespace + "/" + datastore.StoreConfigMapName},
		State: &infraDatastoreState{Live: live, TrustedContent: append([]byte(nil), live.TrustedContent...), TrustedSHA: live.TrustedSHA,
			BenignID: store.Records[0].ID}}, nil
}

func (k *kubernetesInfraCatalogueRuntime) armDatastore(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture) (infraCatalogueArm, error) {
	state, ok := fixture.State.(*infraDatastoreState)
	if !ok || state == nil {
		return infraCatalogueArm{}, errors.New("datastore preparation state changed")
	}
	store, err := datastore.ParseStore(state.TrustedContent)
	if err != nil {
		return infraCatalogueArm{}, err
	}
	store.Records = append(store.Records, datastore.Record{ID: profile.PoisonID, Content: profile.PoisonContent})
	poisoned := store.Canonical()
	poisonedSHA, err := datastore.CanonicalSHA(poisoned)
	if err != nil || poisonedSHA == state.TrustedSHA {
		return infraCatalogueArm{}, errors.New("datastore poison mutation has no distinct canonical identity")
	}
	cm, err := k.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, datastore.StoreConfigMapName, metav1.GetOptions{})
	if err != nil || string(cm.UID) != state.Live.StoreUID || cm.ResourceVersion != state.Live.StoreRV {
		return infraCatalogueArm{}, errors.New("datastore store changed after preflight")
	}
	cm.Data[datastore.StoreKey] = string(poisoned)
	// Record the exact intended hash before the CAS so cleanup can reconcile a
	// server-accepted update whose response was lost.
	state.PoisonedSHA = poisonedSHA
	if _, err = k.kube.CoreV1().ConfigMaps(profile.Namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		return infraCatalogueArm{TargetName: fixture.TargetName, TargetUID: fixture.TargetUID, Mutated: true}, err
	}
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = wait.PollUntilContextTimeout(deadline, 2*time.Second, 30*time.Second, true, func(probeCtx context.Context) (bool, error) {
		live, liveErr := datastore.ValidateLive(probeCtx, k.reader, profile.Namespace, fixture.TargetUID)
		if liveErr != nil || live.CurrentSHA != poisonedSHA {
			return false, nil
		}
		return k.datastorePodsServe(probeCtx, live, poisonedSHA, state.BenignID, profile.PoisonID, true), nil
	})
	if err != nil {
		return infraCatalogueArm{TargetName: fixture.TargetName, TargetUID: fixture.TargetUID, Mutated: true}, errors.New("datastore poison did not reach every serving Pod")
	}
	return infraCatalogueArm{TargetName: fixture.TargetName, TargetUID: fixture.TargetUID, Mutated: true}, nil
}

func (k *kubernetesInfraCatalogueRuntime) datastorePodsServe(ctx context.Context, live datastore.Live, wantSHA, benignID, poisonID string, poisonPresent bool) bool {
	for _, pod := range live.Pods {
		if net.ParseIP(pod.IP) == nil {
			return false
		}
		base := "http://" + net.JoinHostPort(pod.IP, strconv.Itoa(datastore.ServingPort))
		status, raw, err := boundedInfraGET(ctx, base+datastore.ReadbackPath)
		if err != nil || status != http.StatusOK {
			return false
		}
		var hash struct {
			SHA256 string `json:"sha256"`
		}
		if strictJSON(raw, &hash) != nil || hash.SHA256 != wantSHA {
			return false
		}
		status, _, err = boundedInfraGET(ctx, base+datastore.GetPath+"?id="+url.QueryEscape(benignID))
		if err != nil || status != http.StatusOK {
			return false
		}
		status, _, err = boundedInfraGET(ctx, base+datastore.GetPath+"?id="+url.QueryEscape(poisonID))
		if err != nil || (poisonPresent && status != http.StatusOK) || (!poisonPresent && status != http.StatusNotFound) {
			return false
		}
	}
	return len(live.Pods) > 0
}

func (k *kubernetesInfraCatalogueRuntime) physicalDatastore(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture, arm infraCatalogueArm) (AttackCatalogPhysicalResult, error) {
	state, ok := fixture.State.(*infraDatastoreState)
	if !ok || state == nil {
		return AttackCatalogPhysicalResult{}, errors.New("datastore preparation state changed")
	}
	live, err := datastore.ValidateLive(ctx, k.reader, profile.Namespace, arm.TargetUID)
	e := infraDatastoreEvidence{TrustedSHA: state.TrustedSHA, PoisonedSHA: state.PoisonedSHA}
	if err == nil {
		e.FinalSHA = live.CurrentSHA
		storeCM, getErr := k.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, datastore.StoreConfigMapName, metav1.GetOptions{})
		if getErr == nil {
			store, parseErr := datastore.ParseStore([]byte(storeCM.Data[datastore.StoreKey]))
			e.PoisonAbsent = parseErr == nil && !slicesContain(store.IDs(), profile.PoisonID)
		}
		e.AllPodsServed = k.datastorePodsServe(ctx, live, state.TrustedSHA, state.BenignID, profile.PoisonID, false)
		e.BenignServed = e.AllPodsServed
		for _, pod := range live.Pods {
			if pod.UID == arm.TargetUID {
				e.TargetSameUID = true
			}
		}
	}
	validated := err == nil && e.FinalSHA == e.TrustedSHA && e.PoisonAbsent && e.BenignServed && e.AllPodsServed && e.TargetSameUID
	return AttackCatalogPhysicalResult{Validated: validated, Oracle: infraDatastoreOracle, Evidence: marshalInfraEvidence(e), PodRetained: e.TargetSameUID, PodUID: arm.TargetUID}, nil
}

func (k *kubernetesInfraCatalogueRuntime) cleanupDatastore(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture) (bool, error) {
	state, ok := fixture.State.(*infraDatastoreState)
	if !ok || state == nil {
		return false, errors.New("datastore cleanup state changed")
	}
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		cm, getErr := k.kube.CoreV1().ConfigMaps(profile.Namespace).Get(ctx, datastore.StoreConfigMapName, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if string(cm.UID) != state.Live.StoreUID {
			return errors.New("datastore cleanup refused a changed store identity")
		}
		sha, shaErr := datastore.CanonicalSHA([]byte(cm.Data[datastore.StoreKey]))
		if shaErr != nil {
			return shaErr
		}
		if sha == state.TrustedSHA {
			return nil
		}
		if state.PoisonedSHA == "" || sha != state.PoisonedSHA {
			return errors.New("datastore cleanup refused content not written by this run")
		}
		cm.Data[datastore.StoreKey] = string(state.TrustedContent)
		_, updateErr := k.kube.CoreV1().ConfigMaps(profile.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		return false, err
	}
	err = wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(probeCtx context.Context) (bool, error) {
		live, liveErr := datastore.ValidateLive(probeCtx, k.reader, profile.Namespace, fixture.TargetUID)
		if liveErr != nil || live.StoreUID != state.Live.StoreUID || live.TrustedUID != state.Live.TrustedUID ||
			live.ServiceUID != state.Live.ServiceUID || live.CurrentSHA != state.TrustedSHA {
			return false, nil
		}
		return k.datastorePodsServe(probeCtx, live, state.TrustedSHA, state.BenignID, profile.PoisonID, false), nil
	})
	if err != nil {
		return false, fmt.Errorf("datastore cleanup trusted serving readback: %w", err)
	}
	return true, nil
}

func (k *kubernetesInfraCatalogueRuntime) prepareImage(ctx context.Context, profile infraCatalogueProfile) (infraCatalogueFixture, error) {
	deployment, err := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
	if err != nil || deployment.UID == "" || deployment.DeletionTimestamp != nil {
		return infraCatalogueFixture{}, errors.New("image fixture Deployment is unavailable")
	}
	pin := deployment.Annotations[infraTrustedImageRefAnnotation]
	pinDigest := imageDigest(pin)
	if pinDigest == "" {
		return infraCatalogueFixture{}, errors.New("image fixture has no operator-trusted digest pin")
	}
	image, ok := deploymentContainerImage(deployment, profile.Container)
	if !ok || image != pin {
		return infraCatalogueFixture{}, errors.New("image baseline Deployment is not on its operator-trusted pin")
	}
	pods, err := k.readyPods(ctx, profile)
	if err != nil || len(pods) == 0 {
		return infraCatalogueFixture{}, errors.New("image fixture has no Ready Pod")
	}
	for i := range pods {
		if podContainerDigest(&pods[i], profile.Container) != pinDigest {
			return infraCatalogueFixture{}, errors.New("image baseline running digest differs from the operator pin")
		}
	}
	target := &pods[0]
	policy, err := k.policyForPod(ctx, profile, target)
	if err != nil {
		return infraCatalogueFixture{}, err
	}
	return infraCatalogueFixture{Namespace: profile.Namespace, TargetName: target.Name, TargetUID: string(target.UID),
		PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation,
		ReactiveOnly: policy.Spec.Triggers.ReactiveOnly, ReceiptObjects: []string{"Deployment/" + profile.Namespace + "/" + profile.Deployment},
		State: &infraImageState{DeploymentUID: string(deployment.UID), Pin: pin, PinDigest: pinDigest, OriginalImage: image}}, nil
}

func (k *kubernetesInfraCatalogueRuntime) armImage(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture) (infraCatalogueArm, error) {
	state, ok := fixture.State.(*infraImageState)
	if !ok || state == nil {
		return infraCatalogueArm{}, errors.New("image preparation state changed")
	}
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		deployment, getErr := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if string(deployment.UID) != state.DeploymentUID || deployment.Annotations[infraTrustedImageRefAnnotation] != state.Pin {
			return errors.New("image fixture identity or trusted pin changed after preflight")
		}
		current, found := deploymentContainerImage(deployment, profile.Container)
		if !found || current != state.OriginalImage {
			return errors.New("image fixture container changed after preflight")
		}
		for i := range deployment.Spec.Template.Spec.Containers {
			if deployment.Spec.Template.Spec.Containers[i].Name == profile.Container {
				deployment.Spec.Template.Spec.Containers[i].Image = profile.PoisonImage
			}
		}
		_, updateErr := k.kube.AppsV1().Deployments(profile.Namespace).Update(ctx, deployment, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		return infraCatalogueArm{Mutated: true}, err
	}
	var targetName, targetUID string
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 2*time.Minute, true, func(probeCtx context.Context) (bool, error) {
		pods, listErr := k.readyPods(probeCtx, profile)
		if listErr != nil {
			return false, nil
		}
		for i := range pods {
			digest := podContainerDigest(&pods[i], profile.Container)
			if digest != "" && digest != state.PinDigest && podContainerImage(&pods[i], profile.Container) == profile.PoisonImage {
				targetName, targetUID = pods[i].Name, string(pods[i].UID)
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return infraCatalogueArm{TargetName: targetName, TargetUID: targetUID, Mutated: true}, errors.New("image poison rollout did not produce a Ready drifted Pod")
	}
	// The selecting policy must still match the new drifted Pod lifetime.
	pod, err := k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, targetName, metav1.GetOptions{})
	if err != nil {
		return infraCatalogueArm{TargetName: targetName, TargetUID: targetUID, Mutated: true}, err
	}
	policy, err := k.policyForPod(ctx, profile, pod)
	if err != nil || policy.Name != fixture.PolicyName || string(policy.UID) != fixture.PolicyUID || policy.Generation != fixture.PolicyGeneration {
		return infraCatalogueArm{TargetName: targetName, TargetUID: targetUID, Mutated: true}, errors.New("image selecting policy changed during poison rollout")
	}
	return infraCatalogueArm{TargetName: targetName, TargetUID: targetUID, Mutated: true}, nil
}

func (k *kubernetesInfraCatalogueRuntime) physicalImage(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture) (AttackCatalogPhysicalResult, error) {
	state, ok := fixture.State.(*infraImageState)
	if !ok || state == nil {
		return AttackCatalogPhysicalResult{}, errors.New("image preparation state changed")
	}
	e := infraImageEvidence{TrustedDigest: state.PinDigest, PoisonImage: profile.PoisonImage, PoisonImageAbsent: true}
	deployment, err := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
	if err == nil && string(deployment.UID) == state.DeploymentUID && deployment.Annotations[infraTrustedImageRefAnnotation] == state.Pin {
		e.DeploymentImage, _ = deploymentContainerImage(deployment, profile.Container)
		e.PoisonImageAbsent = e.DeploymentImage != profile.PoisonImage
	}
	pods, listErr := k.readyPods(ctx, profile)
	if listErr == nil {
		for i := range pods {
			digest := podContainerDigest(&pods[i], profile.Container)
			if digest != "" {
				e.ReadyPods++
				e.RunningDigests = append(e.RunningDigests, digest)
			}
			if podContainerImage(&pods[i], profile.Container) == profile.PoisonImage {
				e.PoisonImageAbsent = false
			}
		}
	}
	validated := err == nil && e.DeploymentImage == state.Pin && e.ReadyPods > 0 && len(e.RunningDigests) == e.ReadyPods && e.PoisonImageAbsent
	for _, digest := range e.RunningDigests {
		validated = validated && digest == state.PinDigest
	}
	return AttackCatalogPhysicalResult{Validated: validated, Oracle: infraImageOracle, Evidence: marshalInfraEvidence(e)}, nil
}

func (k *kubernetesInfraCatalogueRuntime) cleanupImage(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture) (bool, error) {
	state, ok := fixture.State.(*infraImageState)
	if !ok || state == nil {
		return false, errors.New("image cleanup state changed")
	}
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		deployment, getErr := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if string(deployment.UID) != state.DeploymentUID || deployment.Annotations[infraTrustedImageRefAnnotation] != state.Pin {
			return errors.New("image cleanup refused a changed Deployment identity or pin")
		}
		current, found := deploymentContainerImage(deployment, profile.Container)
		if !found {
			return errors.New("image cleanup target container disappeared")
		}
		if current == state.Pin {
			return nil
		}
		if current != profile.PoisonImage {
			return errors.New("image cleanup refused an image not written by this run")
		}
		for i := range deployment.Spec.Template.Spec.Containers {
			if deployment.Spec.Template.Spec.Containers[i].Name == profile.Container {
				deployment.Spec.Template.Spec.Containers[i].Image = state.Pin
			}
		}
		_, updateErr := k.kube.AppsV1().Deployments(profile.Namespace).Update(ctx, deployment, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		return false, err
	}
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 30*time.Second, true, func(probeCtx context.Context) (bool, error) {
		return k.imageResidueAbsent(probeCtx, profile, state)
	})
	if err != nil {
		return false, fmt.Errorf("image cleanup trusted rollout: %w", err)
	}
	return true, nil
}

func (k *kubernetesInfraCatalogueRuntime) imageResidueAbsent(ctx context.Context, profile infraCatalogueProfile, state *infraImageState) (bool, error) {
	deployment, err := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, profile.Deployment, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	current, found := deploymentContainerImage(deployment, profile.Container)
	if string(deployment.UID) != state.DeploymentUID || deployment.Annotations[infraTrustedImageRefAnnotation] != state.Pin ||
		!found || current != state.Pin {
		return false, errors.New("image cleanup Deployment identity or trusted pin changed")
	}
	selector, err := labels.Parse(profile.Selector)
	if err != nil || selector.Empty() {
		return false, errors.New("reviewed image cleanup selector is invalid")
	}
	pods, err := k.kube.CoreV1().Pods(profile.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return false, err
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || !podReady(pod) ||
			podContainerImage(pod, profile.Container) != state.Pin || podContainerDigest(pod, profile.Container) != state.PinDigest {
			return false, nil
		}
	}
	return len(pods.Items) > 0, nil
}

func (k *kubernetesInfraCatalogueRuntime) prepareNode(ctx context.Context, profile infraCatalogueProfile) (infraCatalogueFixture, error) {
	nodeAName, nodeBName := profile.Lane+"-node-a", profile.Lane+"-node-b"
	controller, controllerErr := k.kube.AppsV1().Deployments(profile.Namespace).Get(ctx, "kwok-controller-"+profile.Lane, metav1.GetOptions{})
	if controllerErr != nil || controller.UID == "" || controller.DeletionTimestamp != nil || controller.Status.AvailableReplicas < 1 {
		return infraCatalogueFixture{}, errors.New("node-recycle reviewed kwok controller is unavailable")
	}
	nodeA, errA := k.kube.CoreV1().Nodes().Get(ctx, nodeAName, metav1.GetOptions{})
	nodeB, errB := k.kube.CoreV1().Nodes().Get(ctx, nodeBName, metav1.GetOptions{})
	if errA != nil || errB != nil || !reviewedKWOKNode(nodeA, profile.Lane) || !reviewedKWOKNode(nodeB, profile.Lane) ||
		!nodeReady(nodeA) || !nodeReady(nodeB) || nodeA.Spec.Unschedulable || nodeB.Spec.Unschedulable ||
		!nodeRecycleMarkersAbsent(nodeA) || !nodeRecycleMarkersAbsent(nodeB) {
		return infraCatalogueFixture{}, errors.New("node-recycle requires the two clean reviewed Ready kwok lane nodes")
	}
	pods, err := k.readyPods(ctx, profile)
	if err != nil {
		return infraCatalogueFixture{}, err
	}
	var target *corev1.Pod
	baselineUIDs := map[string]bool{}
	healthyPods := map[string]string{}
	for i := range pods {
		pod := &pods[i]
		baselineUIDs[string(pod.UID)] = true
		if pod.Spec.NodeName == nodeAName && target == nil {
			target = pod
		}
		if pod.Spec.NodeName == nodeBName {
			healthyPods[pod.Name] = string(pod.UID)
		}
	}
	if target == nil || len(healthyPods) == 0 {
		return infraCatalogueFixture{}, errors.New("node-recycle requires a Ready target on node-a and a Ready control on node-b")
	}
	policy, err := k.policyForPod(ctx, profile, target)
	if err != nil || policy.Spec.SLO.MinAvailableReplicas != 2 || len(pods) < policy.Spec.SLO.MinAvailableReplicas {
		return infraCatalogueFixture{}, errors.New("node-recycle policy or availability floor differs from the reviewed profile")
	}
	return infraCatalogueFixture{Namespace: profile.Namespace, TargetName: target.Name, TargetUID: string(target.UID), TargetNode: nodeAName,
		PeerName: nodeBName, PeerUID: string(nodeB.UID), PolicyName: policy.Name, PolicyUID: string(policy.UID),
		PolicyGeneration: policy.Generation, ReactiveOnly: policy.Spec.Triggers.ReactiveOnly,
		ReceiptObjects: []string{"Node//" + nodeAName}, State: &infraNodeState{CompromisedNodeUID: string(nodeA.UID),
			HealthyNodeUID: string(nodeB.UID), HealthyNodePods: healthyPods, BaselinePodUIDs: baselineUIDs,
			MinimumAvailable: policy.Spec.SLO.MinAvailableReplicas}}, nil
}

func (k *kubernetesInfraCatalogueRuntime) physicalNode(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture, arm infraCatalogueArm) (AttackCatalogPhysicalResult, error) {
	state, ok := fixture.State.(*infraNodeState)
	if !ok || state == nil {
		return AttackCatalogPhysicalResult{}, errors.New("node-recycle preparation state changed")
	}
	e := infraNodeEvidence{TargetPodUID: arm.TargetUID, HealthyNodeUID: state.HealthyNodeUID,
		MinimumAvailable: state.MinimumAvailable, HealthyPodsSameUID: true}
	_, err := k.kube.CoreV1().Nodes().Get(ctx, fixture.TargetNode, metav1.GetOptions{})
	e.CompromisedNodeGone = apierrors.IsNotFound(err)
	_, err = k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, arm.TargetName, metav1.GetOptions{})
	e.TargetPodGone = apierrors.IsNotFound(err)
	nodeB, nodeErr := k.kube.CoreV1().Nodes().Get(ctx, fixture.PeerName, metav1.GetOptions{})
	e.HealthyNodeSameUID = nodeErr == nil && string(nodeB.UID) == state.HealthyNodeUID && nodeReady(nodeB) &&
		!nodeB.Spec.Unschedulable && nodeRecycleMarkersAbsent(nodeB)
	pods, listErr := k.readyPods(ctx, profile)
	if listErr == nil {
		e.Available = len(pods)
		for i := range pods {
			pod := &pods[i]
			if !state.BaselinePodUIDs[string(pod.UID)] {
				e.ReplacementReady = true
				if e.ReplacementPodUID == "" {
					e.ReplacementPodUID = string(pod.UID)
				}
			}
		}
		current := map[string]string{}
		for i := range pods {
			if pods[i].Spec.NodeName == fixture.PeerName {
				current[pods[i].Name] = string(pods[i].UID)
			}
		}
		for name, uid := range state.HealthyNodePods {
			if current[name] != uid {
				e.HealthyPodsSameUID = false
			}
		}
	}
	validated := e.CompromisedNodeGone && e.TargetPodGone && e.ReplacementReady && e.HealthyNodeSameUID &&
		e.HealthyPodsSameUID && e.Available >= e.MinimumAvailable
	return AttackCatalogPhysicalResult{Validated: validated, Oracle: infraNodeOracle, Evidence: marshalInfraEvidence(e)}, nil
}

func (k *kubernetesInfraCatalogueRuntime) cleanupNode(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture) (bool, error) {
	state, ok := fixture.State.(*infraNodeState)
	if !ok || state == nil {
		return false, errors.New("node-recycle cleanup state changed")
	}
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		node, getErr := k.kube.CoreV1().Nodes().Get(ctx, fixture.TargetNode, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			_, createErr := k.kube.CoreV1().Nodes().Create(ctx, reviewedKWOKReplacementNode(profile.Lane), metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(createErr) {
				return apierrors.NewConflict(corev1.Resource("nodes"), fixture.TargetNode, createErr)
			}
			return createErr
		}
		if getErr != nil {
			return getErr
		}
		if !reviewedKWOKNode(node, profile.Lane) {
			return errors.New("node-recycle cleanup refused an unexpected node-a identity")
		}
		if string(node.UID) != state.CompromisedNodeUID {
			if node.Spec.Unschedulable || !nodeRecycleMarkersAbsent(node) {
				return errors.New("node-recycle cleanup refused residue on an unbound replacement node")
			}
			return nil
		}
		if !node.Spec.Unschedulable && nodeRecycleMarkersAbsent(node) {
			return nil
		}
		var snapshot infraNodeActuatorSnapshot
		if json.Unmarshal([]byte(node.Annotations[infraNodeSnapshotAnnotation]), &snapshot) != nil ||
			snapshot.Version != 1 || snapshot.NodeName != fixture.TargetNode || snapshot.NodeUID != state.CompromisedNodeUID ||
			snapshot.UnschedulBefore || snapshot.TargetPodUID != fixture.TargetUID {
			return errors.New("node-recycle cleanup refused an unbound cordon snapshot")
		}
		node.Spec.Unschedulable = false
		delete(node.Annotations, infraNodeSnapshotAnnotation)
		delete(node.Annotations, infraNodeEpochAnnotation)
		delete(node.Annotations, infraNodeTargetAnnotation)
		_, updateErr := k.kube.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		return false, err
	}
	err = wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(probeCtx context.Context) (bool, error) {
		restored, restoredErr := k.kube.CoreV1().Nodes().Get(probeCtx, fixture.TargetNode, metav1.GetOptions{})
		healthy, healthyErr := k.kube.CoreV1().Nodes().Get(probeCtx, fixture.PeerName, metav1.GetOptions{})
		if restoredErr != nil || healthyErr != nil {
			return false, nil
		}
		return reviewedKWOKNode(restored, profile.Lane) && nodeReady(restored) && !restored.Spec.Unschedulable &&
			nodeRecycleMarkersAbsent(restored) && string(healthy.UID) == state.HealthyNodeUID &&
			reviewedKWOKNode(healthy, profile.Lane) && nodeReady(healthy) && !healthy.Spec.Unschedulable &&
			nodeRecycleMarkersAbsent(healthy), nil
	})
	if err != nil {
		return false, fmt.Errorf("node-recycle cleanup substrate restoration: %w", err)
	}
	return true, nil
}

func nodeRecycleMarkersAbsent(node *corev1.Node) bool {
	return node != nil && node.Annotations[infraNodeSnapshotAnnotation] == "" &&
		node.Annotations[infraNodeEpochAnnotation] == "" && node.Annotations[infraNodeTargetAnnotation] == ""
}

func (k *kubernetesInfraCatalogueRuntime) CreateSignal(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture, arm infraCatalogueArm, runID string) (infraCatalogueSignal, error) {
	annotations := map[string]any{attackCatalogCorrelationAnnotation: runID, model.ConsoleTargetPodUIDAnnotation: arm.TargetUID, infraTargetPodUIDAnnotation: arm.TargetUID}
	switch profile.Family {
	case infraFamilyNetworkEdge:
		state, ok := fixture.State.(*infraNetworkState)
		if !ok || state == nil {
			return infraCatalogueSignal{}, errors.New("network-edge signal state changed")
		}
		edges := make([]string, 0, len(state.Edges))
		for _, edge := range state.Edges {
			edges = append(edges, edge.CIDR)
		}
		raw, _ := json.Marshal(map[string]any{"targetPodUID": arm.TargetUID, "policyName": fixture.PolicyName,
			"policyUID": fixture.PolicyUID, "policyGeneration": fixture.PolicyGeneration, "forbiddenEdges": edges})
		annotations[infraNetworkObservation] = string(raw)
	case infraFamilyDatastore:
		state, ok := fixture.State.(*infraDatastoreState)
		if !ok || state == nil || state.PoisonedSHA == "" {
			return infraCatalogueSignal{}, errors.New("datastore signal state changed")
		}
		observation := datastore.Observation{Version: 1, Namespace: profile.Namespace, StoreName: datastore.StoreConfigMapName,
			StoreConfigMapUID: state.Live.StoreUID, TrustedSnapshotConfigMapUID: state.Live.TrustedUID,
			ServiceUID: state.Live.ServiceUID, TargetPodUID: arm.TargetUID, PoisonedSHA256: state.PoisonedSHA,
			TrustedSHA256: state.TrustedSHA, Objective: datastore.Objective, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
			PolicyName: fixture.PolicyName, PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGeneration}
		raw, _ := json.Marshal(observation)
		annotations[datastore.ObservationAnnotation] = string(raw)
	case infraFamilyImage:
		state, ok := fixture.State.(*infraImageState)
		if !ok || state == nil {
			return infraCatalogueSignal{}, errors.New("image signal state changed")
		}
		pod, err := k.kube.CoreV1().Pods(profile.Namespace).Get(ctx, arm.TargetName, metav1.GetOptions{})
		if err != nil || string(pod.UID) != arm.TargetUID {
			return infraCatalogueSignal{}, errors.New("image drifted target lifetime changed before signal")
		}
		running := podContainerDigest(pod, profile.Container)
		if running == "" || running == state.PinDigest {
			return infraCatalogueSignal{}, errors.New("image drift evidence disappeared before signal")
		}
		annotations[infraRunningImageAnnotation] = running
		annotations[infraTrustedImageAnnotation] = state.PinDigest
	case infraFamilyNodeRecycle:
		raw, _ := json.Marshal(map[string]any{"targetPodUID": arm.TargetUID, "nodeName": fixture.TargetNode,
			"escapeEvidence": profile.EscapeEvidence, "policyName": fixture.PolicyName,
			"policyUID": fixture.PolicyUID, "policyGeneration": fixture.PolicyGeneration})
		annotations[infraNodeObservation] = string(raw)
	default:
		return infraCatalogueSignal{}, errors.New("unreviewed infra catalogue family")
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return infraCatalogueSignal{}, errors.New("infra signal identity generation failed")
	}
	name := uniqueInfraSignalName(profile.ID, random)
	object := map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]any{"name": name, "labels": map[string]any{"phorvex.ai/redteam": "true", "phorvex.ai/catalogue-id": profile.ID}, "annotations": annotations},
		"spec": map[string]any{"description": "Authorized Console catalogue validation: " + profile.ID,
			"targets": []any{profile.Namespace + "/" + arm.TargetName},
			"rule":    map[string]any{"type": profile.EventType, "threatLevel": "critical", "source": profile.Lane + "-attacks"}},
	}
	u := &unstructured.Unstructured{Object: object}
	created, err := k.dynamic.Resource(securityEventGVR).Create(ctx, u, metav1.CreateOptions{})
	if err != nil {
		return infraCatalogueSignal{Name: name, RunID: runID}, errors.New("infra catalogue signal admission failed")
	}
	signal := infraCatalogueSignal{Name: name, UID: string(created.GetUID()), Creator: created.GetAnnotations()["phorvex.ai/creator-identity"],
		RunID: runID, CreatedAt: created.GetCreationTimestamp().Time}
	targets, _, _ := unstructured.NestedStringSlice(created.Object, "spec", "targets")
	eventType, _, _ := unstructured.NestedString(created.Object, "spec", "rule", "type")
	if signal.UID == "" || signal.CreatedAt.IsZero() || signal.Creator != profile.creator() || created.GetName() != name ||
		created.GetAnnotations()[attackCatalogCorrelationAnnotation] != runID ||
		created.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != arm.TargetUID ||
		!slicesEqual(targets, []string{profile.Namespace + "/" + arm.TargetName}) || eventType != profile.EventType {
		uid := created.GetUID()
		_ = k.dynamic.Resource(securityEventGVR).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		return signal, errors.New("infra catalogue signal identity, target or correlation differs")
	}
	return signal, nil
}

func (k *kubernetesInfraCatalogueRuntime) cleanupEvent(ctx context.Context, profile infraCatalogueProfile, fixture infraCatalogueFixture, arm infraCatalogueArm, signal infraCatalogueSignal) bool {
	if signal.Name == "" {
		return true
	}
	resource := k.dynamic.Resource(securityEventGVR)
	uid := types.UID(signal.UID)
	if uid == "" {
		candidate, err := resource.Get(ctx, signal.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true
		}
		if err != nil || candidate.GetUID() == "" || candidate.GetLabels()["phorvex.ai/redteam"] != "true" ||
			candidate.GetLabels()["phorvex.ai/catalogue-id"] != profile.ID ||
			candidate.GetAnnotations()["phorvex.ai/creator-identity"] != profile.creator() ||
			candidate.GetAnnotations()[attackCatalogCorrelationAnnotation] != signal.RunID ||
			candidate.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != arm.TargetUID {
			return false
		}
		targets, _, _ := unstructured.NestedStringSlice(candidate.Object, "spec", "targets")
		eventType, _, _ := unstructured.NestedString(candidate.Object, "spec", "rule", "type")
		if !slicesEqual(targets, []string{fixture.Namespace + "/" + arm.TargetName}) || eventType != profile.EventType {
			return false
		}
		uid = candidate.GetUID()
	}
	err := resource.Delete(ctx, signal.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if err != nil && !apierrors.IsNotFound(err) {
		return false
	}
	_, err = resource.Get(ctx, signal.Name, metav1.GetOptions{})
	return apierrors.IsNotFound(err)
}

func reviewedKWOKNode(node *corev1.Node, lane string) bool {
	if node == nil || (node.Name != lane+"-node-a" && node.Name != lane+"-node-b") ||
		node.Labels["type"] != "kwok" || node.Labels["phorvex.ai/lane"] != lane ||
		node.Annotations["kwok.x-k8s.io/node"] != "fake" || node.Annotations["phorvex.ai/kwok-lane"] != lane {
		return false
	}
	for _, taint := range node.Spec.Taints {
		if taint.Key == "phorvex.ai/kwok" && taint.Value == "true" && taint.Effect == corev1.TaintEffectNoSchedule {
			return true
		}
	}
	return false
}

func reviewedKWOKReplacementNode(lane string) *corev1.Node {
	name := lane + "-node-a"
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name,
		Annotations: map[string]string{"node.alpha.kubernetes.io/ttl": "0", "kwok.x-k8s.io/node": "fake", "phorvex.ai/kwok-lane": lane, infraNodeReplacementLabel: name},
		Labels: map[string]string{"type": "kwok", "phorvex.ai/lane": lane, "kubernetes.io/hostname": name,
			"kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux", "node-role.kubernetes.io/agent": ""}},
		Spec: corev1.NodeSpec{Taints: []corev1.Taint{{Key: "phorvex.ai/kwok", Value: "true", Effect: corev1.TaintEffectNoSchedule}}}}
}

func nodeReady(node *corev1.Node) bool {
	if node == nil || node.DeletionTimestamp != nil {
		return false
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func deploymentContainerImage(deployment *appsv1.Deployment, container string) (string, bool) {
	for _, current := range deployment.Spec.Template.Spec.Containers {
		if current.Name == container {
			return current.Image, true
		}
	}
	return "", false
}

func podContainerImage(pod *corev1.Pod, container string) string {
	for _, current := range pod.Spec.Containers {
		if current.Name == container {
			return current.Image
		}
	}
	return ""
}

func podContainerDigest(pod *corev1.Pod, container string) string {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == container && status.Ready {
			return imageDigest(status.ImageID)
		}
	}
	return ""
}

func imageDigest(value string) string {
	index := strings.LastIndex(value, "sha256:")
	if index < 0 || len(value[index:]) != len("sha256:")+64 {
		return ""
	}
	digest := value[index:]
	if _, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:")); err != nil {
		return ""
	}
	return digest
}

func networkPolicyObject(namespace, targetUID string) string {
	sum := sha256.Sum256([]byte(targetUID))
	return "NetworkPolicy/" + namespace + "/phorvex-netisolate-" + hex.EncodeToString(sum[:])
}

func boundedInfraGET(ctx context.Context, endpoint string) (int, []byte, error) {
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("infra oracle redirect refused") }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	return response.StatusCode, raw, err
}

func strictJSON(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("JSON response has trailing content")
	}
	return nil
}

func copyBoolMap(input map[string]bool) map[string]bool {
	out := make(map[string]bool, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func slicesContain[T comparable](values []T, want T) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func slicesEqual[T comparable](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

var _ infraCatalogueRuntime = (*kubernetesInfraCatalogueRuntime)(nil)
