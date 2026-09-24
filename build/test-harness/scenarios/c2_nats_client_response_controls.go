package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

type natsResponseCurrentControl struct {
	ServiceIP        string
	EndpointSliceUID types.UID
	// Members is the exact Ready, serving set from the authoritative Service
	// EndpointSlices at this snapshot. A Service HTTP response is accepted only
	// when its Pod UID belongs to this set; direct peer health is separate.
	Members       map[types.UID]bool
	MemberDetails map[types.UID]natsResponseServiceMember
}

func natsResponseMemberProof(p *corev1.Pod, expected types.UID) (natsResponseServiceMember, error) {
	var proof natsResponseServiceMember
	if p == nil || p.UID != expected || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning ||
		p.Status.PodIP == "" || len(p.OwnerReferences) != 1 || p.OwnerReferences[0].Controller == nil ||
		!*p.OwnerReferences[0].Controller || p.OwnerReferences[0].UID == "" || len(p.Status.ContainerStatuses) != 1 ||
		!p.Status.ContainerStatuses[0].Ready || p.Status.ContainerStatuses[0].RestartCount != 0 ||
		p.Status.ContainerStatuses[0].ContainerID == "" || p.Status.ContainerStatuses[0].ImageID == "" {
		return proof, errors.New("NATS response Service member process identity unavailable")
	}
	ready := false
	for _, condition := range p.Status.Conditions {
		ready = ready || condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue
	}
	if !ready {
		return proof, errors.New("NATS response Service member not API Ready")
	}
	owner := p.OwnerReferences[0]
	return natsResponseServiceMember{PodUID: p.UID, PodName: p.Name, PodIP: p.Status.PodIP,
		OwnerKind: owner.Kind, OwnerUID: owner.UID, ContainerID: p.Status.ContainerStatuses[0].ContainerID,
		ImageID: p.Status.ContainerStatuses[0].ImageID, Ready: true, RestartCount: 0}, nil
}

// EndpointSlice targets are not accepted merely because their UIDs appear in
// the Service. Every additional member is a fresh first-incarnation Pod of the
// exact admitted ReplicaSet, with the original immutable observer source.
func natsResponseReplacementMembers(ctx context.Context, env *core.Env, fixture natsResponseFixture,
	slices []discoveryv1.EndpointSlice, rsName string) ([]natsResponsePodIdentity, map[types.UID]*corev1.Pod, error) {
	var replacements []natsResponsePodIdentity
	pods := map[types.UID]*corev1.Pod{}
	for _, slice := range slices {
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef == nil || endpoint.TargetRef.UID == fixture.Client.UID || endpoint.TargetRef.UID == fixture.Peer.UID {
				continue
			}
			if len(replacements) >= 1 || endpoint.TargetRef.Name == "" {
				return nil, nil, errors.New("NATS response Service replacement count or identity invalid")
			}
			pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, endpoint.TargetRef.Name, metav1.GetOptions{})
			if err != nil || pod.UID != endpoint.TargetRef.UID || pod.Labels[natsResponseRoleLabel] != "" ||
				!strings.HasPrefix(pod.Name, fixture.Name+"-") || pod.Status.PodIP == fixture.Client.IP ||
				pod.Status.PodIP == fixture.Peer.IP || len(pod.Status.ContainerStatuses) != 1 ||
				pod.Status.ContainerStatuses[0].ContainerID == fixture.Client.ContainerID ||
				pod.Status.ContainerStatuses[0].ContainerID == fixture.Peer.ContainerID {
				return nil, nil, errors.New("NATS response Service replacement API identity differs")
			}
			id, err := natsResponseReadyPod(pod, fixture.ReplicaSetUID, rsName,
				env.Config.NATSExposureFixture.Nonce, env.Config.NATSExposureFixture.NodeName, env.Config.NATSExposureFixture.ObserverImage)
			if err != nil {
				return nil, nil, err
			}
			replacements = append(replacements, id)
			pods[id.UID] = pod
		}
	}
	return replacements, pods, nil
}

func natsResponseAwaitInitialControls(ctx context.Context, env *core.Env, fixture natsResponseFixture,
	admittedPolicySpec map[string]any) (natsResponseCurrentControl, error) {
	deadline, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		control, err := natsResponseCurrentControls(deadline, env, fixture, admittedPolicySpec, true)
		if err == nil {
			return control, nil
		}
		select {
		case <-deadline.Done():
			return natsResponseCurrentControl{}, errors.New("NATS response initial Service/PDB/EndpointSlice admission absent or changed")
		case <-ticker.C:
		}
	}
}

// A reusable exact-current snapshot for the initial and post-response service
// controls. The source can be reparented/quarantined after M0; the legitimate
// peer must remain the same Ready ReplicaSet-owned first container throughout.
func natsResponseCurrentControls(ctx context.Context, env *core.Env, fixture natsResponseFixture, admittedPolicySpec map[string]any, requireSourceReady bool) (natsResponseCurrentControl, error) {
	unknown := natsResponseCurrentControl{}
	if env.NamespaceUID() == "" || env.NamespaceUID() != fixture.NamespaceUID || fixture.Client.UID == "" || fixture.Peer.UID == "" ||
		fixture.Client.UID == fixture.Peer.UID || fixture.ReplicaSetUID == "" || fixture.ServiceUID == "" || len(admittedPolicySpec) == 0 {
		return unknown, errors.New("NATS response current-control identities incomplete")
	}
	specRaw, err := json.Marshal(admittedPolicySpec)
	if err != nil || natsSHA(specRaw) != fixture.PolicySpecSHA256 {
		return unknown, errors.New("NATS response admitted policy spec baseline changed")
	}
	ns, err := env.Kube.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{})
	if err != nil || ns.UID != fixture.NamespaceUID || ns.DeletionTimestamp != nil || ns.Labels["phorvex.ai/nats-exposure-fixture"] != "true" {
		return unknown, errors.New("NATS response fixture namespace identity changed")
	}
	cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, fixture.Name, metav1.GetOptions{})
	if err != nil || cm.UID != fixture.ConfigMapUID || cm.Immutable == nil || !*cm.Immutable ||
		cm.DeletionTimestamp != nil || len(cm.Data) != 1 || natsSHA([]byte(cm.Data["observer.json"])) != fixture.ConfigSHA256 ||
		cm.Labels[natsResponseOwnerLabel] != env.Config.NATSExposureFixture.Nonce {
		return unknown, errors.New("NATS response immutable observer source changed")
	}
	if err := natsResponseCurrentPolicy(ctx, env, fixture.Name, fixture.PolicyUID, fixture.PolicyGen, admittedPolicySpec); err != nil {
		return unknown, err
	}
	service, err := env.Kube.CoreV1().Services(env.Config.Namespace).Get(ctx, fixture.Name, metav1.GetOptions{})
	if err != nil || service.UID != fixture.ServiceUID || service.DeletionTimestamp != nil ||
		service.Spec.Type != corev1.ServiceTypeClusterIP || net.ParseIP(service.Spec.ClusterIP) == nil ||
		!reflect.DeepEqual(service.Spec.Selector, map[string]string{natsResponseOwnerLabel: env.Config.NATSExposureFixture.Nonce, natsResponseComponentLabel: "consumer"}) ||
		len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Name != "ready" || service.Spec.Ports[0].Port != 8080 ||
		service.Spec.Ports[0].Protocol != corev1.ProtocolTCP || service.Spec.Ports[0].TargetPort.StrVal != "ready" {
		return unknown, errors.New("NATS response Service identity or exact route changed")
	}
	pdb, err := env.Kube.PolicyV1().PodDisruptionBudgets(env.Config.Namespace).Get(ctx, fixture.Name, metav1.GetOptions{})
	if err != nil || pdb.UID != fixture.PDBUID || pdb.DeletionTimestamp != nil || pdb.Spec.MinAvailable == nil ||
		pdb.Spec.MinAvailable.IntValue() != 1 || pdb.Spec.Selector == nil ||
		!reflect.DeepEqual(pdb.Spec.Selector.MatchLabels, service.Spec.Selector) {
		return unknown, errors.New("NATS response PDB identity or capacity floor changed")
	}
	dep, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Get(ctx, fixture.Name, metav1.GetOptions{})
	if err != nil || dep.UID != fixture.DeploymentUID || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil ||
		*dep.Spec.Replicas != 2 || dep.Spec.Selector == nil || !reflect.DeepEqual(dep.Spec.Selector.MatchLabels, service.Spec.Selector) {
		return unknown, errors.New("NATS response Deployment identity or desired capacity changed")
	}
	peer, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, fixture.Peer.Name, metav1.GetOptions{})
	if err != nil || peer.UID != fixture.Peer.UID || peer.Labels[natsResponseRoleLabel] != "" {
		return unknown, errors.New("NATS response original legitimate peer changed")
	}
	if len(peer.OwnerReferences) != 1 {
		return unknown, errors.New("NATS response peer ReplicaSet owner absent")
	}
	peerNow, err := natsResponseReadyPod(peer, fixture.ReplicaSetUID, peer.OwnerReferences[0].Name,
		env.Config.NATSExposureFixture.Nonce, env.Config.NATSExposureFixture.NodeName, env.Config.NATSExposureFixture.ObserverImage)
	if err != nil || peerNow != fixture.Peer {
		return unknown, errors.New("NATS response original peer no longer healthy in same container")
	}
	source, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, fixture.Client.Name, metav1.GetOptions{})
	if err != nil || source.UID != fixture.Client.UID || source.Labels[natsResponseRoleLabel] != "source" {
		return unknown, errors.New("NATS response original source Pod changed")
	}
	if requireSourceReady {
		if len(source.OwnerReferences) != 1 {
			return unknown, errors.New("NATS response original source ReplicaSet owner absent")
		}
		sourceNow, err := natsResponseReadyPod(source, fixture.ReplicaSetUID, source.OwnerReferences[0].Name,
			env.Config.NATSExposureFixture.Nonce, env.Config.NATSExposureFixture.NodeName, env.Config.NATSExposureFixture.ObserverImage)
		if err != nil || sourceNow != fixture.Client {
			return unknown, errors.New("NATS response original source not healthy before M0")
		}
	}
	selector := labels.SelectorFromSet(map[string]string{natsResponseOwnerLabel: env.Config.NATSExposureFixture.Nonce,
		natsResponseRoleLabel: "source"}).String()
	targets, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 10})
	if err != nil || targets.Continue != "" || targets.RemainingItemCount != nil || len(targets.Items) != 1 || targets.Items[0].UID != fixture.Client.UID {
		return unknown, errors.New("NATS response policy target no longer unique original source")
	}
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + fixture.Name, Limit: 10})
	if err != nil || slices.Continue != "" || slices.RemainingItemCount != nil {
		return unknown, errors.New("NATS response Service EndpointSlice inventory incomplete")
	}
	var replacements []natsResponsePodIdentity
	memberPods := map[types.UID]*corev1.Pod{fixture.Client.UID: source, fixture.Peer.UID: peer}
	if !requireSourceReady {
		replacements, replacementPods, err := natsResponseReplacementMembers(ctx, env, fixture, slices.Items, peer.OwnerReferences[0].Name)
		if err != nil {
			return unknown, err
		}
		for uid, pod := range replacementPods {
			memberPods[uid] = pod
		}
		if len(replacements) > 0 && source.Labels[natsResponseComponentLabel] == "consumer" {
			return unknown, errors.New("NATS response replacement appeared before original source left Service selector")
		}
	}
	if requireSourceReady {
		err = natsResponseEndpointMembers(slices.Items, fixture.Name, fixture.ServiceUID, fixture.Client, fixture.Peer)
	} else {
		err = natsResponseEndpointMembersAfterWithReplacements(slices.Items, fixture.Name, fixture.ServiceUID, fixture.Client, fixture.Peer, replacements)
	}
	if err != nil {
		return unknown, err
	}
	members := make(map[types.UID]bool, 2)
	details := make(map[types.UID]natsResponseServiceMember, 3)
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			uid := endpoint.TargetRef.UID // validated above
			if uid == fixture.Client.UID && !requireSourceReady {
				if err := natsResponseClientIncarnation(ctx, env, fixture, true); err != nil {
					return unknown, err
				}
			}
			proof, err := natsResponseMemberProof(memberPods[uid], uid)
			if err != nil {
				return unknown, err
			}
			if uid != fixture.Client.UID {
				if proof.OwnerKind != "ReplicaSet" || proof.OwnerUID != fixture.ReplicaSetUID {
					return unknown, errors.New("NATS response Service member ReplicaSet owner changed")
				}
			} else if proof.OwnerKind == "ReplicaSet" {
				if proof.OwnerUID != fixture.ReplicaSetUID {
					return unknown, errors.New("NATS response original source ReplicaSet changed")
				}
			} else if requireSourceReady || proof.OwnerKind != "AdaptiveMovingTargetDefense" ||
				proof.OwnerUID == "" || memberPods[uid].OwnerReferences[0].APIVersion != "amtd.r6security.com/v1beta1" {
				return unknown, errors.New("NATS response original source Service owner changed")
			}
			members[uid], details[uid] = true, proof
		}
	}
	return natsResponseCurrentControl{ServiceIP: service.Spec.ClusterIP,
		EndpointSliceUID: slices.Items[0].UID, Members: members, MemberDetails: details}, nil
}
