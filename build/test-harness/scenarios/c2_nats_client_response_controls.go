package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
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
	Members map[types.UID]bool
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
	if requireSourceReady {
		err = natsResponseEndpointMembers(slices.Items, fixture.Name, fixture.ServiceUID, fixture.Client, fixture.Peer)
	} else {
		err = natsResponseEndpointMembersAfter(slices.Items, fixture.Name, fixture.ServiceUID, fixture.Client, fixture.Peer)
	}
	if err != nil {
		return unknown, err
	}
	members := make(map[types.UID]bool, 2)
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			members[endpoint.TargetRef.UID] = true // validated above
		}
	}
	return natsResponseCurrentControl{ServiceIP: service.Spec.ClusterIP,
		EndpointSliceUID: slices.Items[0].UID, Members: members}, nil
}
