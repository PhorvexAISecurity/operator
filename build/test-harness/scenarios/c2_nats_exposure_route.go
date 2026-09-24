package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	transportspdy "k8s.io/client-go/transport/spdy"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// These names are a server-owned profile, not request parameters. Runtime UIDs
// are captured from authoritative API objects and compared again at the barrier.
const natsExposureNamespace = "nats"
const natsExposureService = "nats"
const natsExposureStatefulSet = "nats"
const natsExposureConfigMap = "nats-config"

var natsExposureServerIdentity = regexp.MustCompile(`^N[A-Z2-7]{55}$`)

type natsBrokerIdentity struct {
	Name        string    `json:"name"`
	UID         types.UID `json:"uid"`
	IP          string    `json:"ip"`
	ImageID     string    `json:"imageID"`
	ContainerID string    `json:"containerID"`
	ServerID    string    `json:"serverID"`
}

type natsRouteIdentity struct {
	ClusterUID                   types.UID            `json:"clusterUID"`
	ServiceUID                   types.UID            `json:"serviceUID"`
	StatefulSetUID               types.UID            `json:"statefulSetUID"`
	StatefulRevision             string               `json:"statefulRevision"`
	ConfigMapUID                 types.UID            `json:"configMapUID"`
	ConfigMapResourceVersion     string               `json:"configMapResourceVersion"`
	ConfigSHA256                 string               `json:"configSHA256"`
	ConfigSourceAttestation      string               `json:"configSourceAttestation"`
	EndpointSliceUID             types.UID            `json:"endpointSliceUID"`
	EndpointSliceResourceVersion string               `json:"endpointSliceResourceVersion"`
	NodeUID                      types.UID            `json:"nodeUID"`
	Brokers                      []natsBrokerIdentity `json:"brokers"`
}

func natsReady(p *corev1.Pod, stsUID types.UID, revision, imageID string) (natsBrokerIdentity, error) {
	if p == nil || p.UID == "" || p.Namespace != natsExposureNamespace || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || p.Labels["app"] != "nats" || p.Labels["controller-revision-hash"] != revision {
		return natsBrokerIdentity{}, errors.New("broker Pod source/revision is not current")
	}
	owner := 0
	for _, o := range p.OwnerReferences {
		if o.Controller != nil && *o.Controller && o.Kind == "StatefulSet" && o.Name == natsExposureStatefulSet && o.UID == stsUID {
			owner++
		}
	}
	if owner != 1 {
		return natsBrokerIdentity{}, errors.New("broker StatefulSet owner differs")
	}
	ready := false
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready || len(p.Status.ContainerStatuses) != 1 {
		return natsBrokerIdentity{}, errors.New("broker Pod/container is not Ready")
	}
	c := p.Status.ContainerStatuses[0]
	if c.Name != "nats" || !c.Ready || c.ImageID != imageID || c.ContainerID == "" {
		return natsBrokerIdentity{}, errors.New("broker container identity differs")
	}
	if len(p.Spec.Containers) != 1 || p.Spec.Containers[0].Name != "nats" || len(p.Spec.Containers[0].Args) != 2 || p.Spec.Containers[0].Args[0] != "--config" || p.Spec.Containers[0].Args[1] != "/etc/nats/nats.conf" {
		return natsBrokerIdentity{}, errors.New("broker process arguments differ")
	}
	mounted, volume := false, false
	for _, m := range p.Spec.Containers[0].VolumeMounts {
		if m.Name == "config" && m.MountPath == "/etc/nats" && m.SubPath == "" && m.SubPathExpr == "" {
			mounted = true
		}
	}
	for _, v := range p.Spec.Volumes {
		if v.Name == "config" && v.ConfigMap != nil && v.ConfigMap.Name == natsExposureConfigMap {
			volume = true
		}
	}
	if !mounted || !volume {
		return natsBrokerIdentity{}, errors.New("broker selected config mount differs")
	}
	return natsBrokerIdentity{Name: p.Name, UID: p.UID, IP: p.Status.PodIP, ImageID: c.ImageID, ContainerID: c.ContainerID}, nil
}

func forwardNATSPod(ctx context.Context, cfg *rest.Config, namespace, pod string, remote int) (int, func() error, error) {
	if cfg == nil {
		return 0, nil, errors.New("NATS Pod port-forward requires authenticated REST transport")
	}
	transport, upgrader, err := transportspdy.RoundTripperFor(cfg)
	if err != nil {
		return 0, nil, err
	}
	u, err := url.Parse(cfg.Host)
	if err != nil {
		return 0, nil, err
	}
	u.Path = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", namespace, pod)
	u.RawQuery = ""
	u.Fragment = ""
	dialer := transportspdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, u)
	stop, ready, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var out, errOut bytes.Buffer
	pf, err := portforward.New(dialer, []string{fmt.Sprintf("0:%d", remote)}, stop, ready, &out, &errOut)
	if err != nil {
		return 0, nil, err
	}
	go func() { done <- pf.ForwardPorts() }()
	select {
	case <-ctx.Done():
		close(stop)
		return 0, nil, ctx.Err()
	case <-time.After(6 * time.Second):
		close(stop)
		return 0, nil, errors.New("NATS Pod port-forward readiness timed out")
	case <-done:
		close(stop)
		return 0, nil, errors.New("NATS Pod port-forward ended before ready")
	case <-ready:
	}
	ports, err := pf.GetPorts()
	if err != nil || len(ports) != 1 {
		close(stop)
		return 0, nil, errors.New("NATS Pod forwarded port ambiguous")
	}
	closeFn := func() error {
		close(stop)
		select {
		case err := <-done:
			return err
		case <-time.After(3 * time.Second):
			return errors.New("NATS Pod port-forward stop unconfirmed")
		}
	}
	return int(ports[0].Local), closeFn, nil
}

type natsExposureVarzResponse struct {
	ServerID     string          `json:"server_id"`
	Version      string          `json:"version"`
	Jetstream    json.RawMessage `json:"jetstream"`
	AuthRequired *bool           `json:"-"`
	AuthPresent  bool            `json:"-"`
}

func decodeNATSExposureVarz(raw []byte) (natsExposureVarzResponse, error) {
	var response natsExposureVarzResponse
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return response, errors.New("NATS monitor JSON object required")
	}
	seen := map[string]bool{}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return response, errors.New("NATS monitor key invalid")
		}
		key, ok := keyToken.(string)
		if !ok || seen[key] {
			return response, errors.New("NATS monitor duplicate/invalid key")
		}
		seen[key] = true
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return response, errors.New("NATS monitor value invalid")
		}
		fields[key] = value
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
		return response, errors.New("NATS monitor closing delimiter invalid")
	}
	if _, err = dec.Token(); err != io.EOF {
		return response, errors.New("NATS monitor trailing JSON")
	}
	if json.Unmarshal(fields["server_id"], &response.ServerID) != nil || json.Unmarshal(fields["version"], &response.Version) != nil {
		return response, errors.New("NATS monitor ID/version invalid")
	}
	response.Jetstream = fields["jetstream"]
	var jetstream map[string]json.RawMessage
	if json.Unmarshal(response.Jetstream, &jetstream) != nil || len(jetstream) == 0 {
		return response, errors.New("NATS monitor JetStream object invalid")
	}
	if !natsExposureServerIdentity.MatchString(response.ServerID) {
		return response, errors.New("NATS monitor server ID invalid")
	}
	if value, ok := fields["auth_required"]; ok {
		response.AuthPresent = true
		literal := string(value)
		if literal != "true" && literal != "false" {
			return response, errors.New("NATS monitor auth flag invalid")
		}
		enabled := literal == "true"
		response.AuthRequired = &enabled
	}
	return response, nil
}

func natsExposureVarz(ctx context.Context, env *core.Env, pod string) (response natsExposureVarzResponse, retErr error) {
	port, closeFn, err := forwardNATSPod(ctx, env.Rest, natsExposureNamespace, pod, 8222)
	if err != nil {
		return response, err
	}
	defer func() {
		if err := closeFn(); err != nil {
			retErr = errors.Join(retErr, errors.New("NATS monitor port-forward close unconfirmed"))
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/varz", port), nil)
	if err != nil {
		return response, err
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil}}
	reply, err := client.Do(req)
	if err != nil {
		return response, err
	}
	defer reply.Body.Close()
	if reply.StatusCode != 200 || reply.ContentLength > 4096 {
		return response, errors.New("NATS monitor status/size differed")
	}
	raw, err := io.ReadAll(io.LimitReader(reply.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return response, errors.New("NATS monitor body exceeded bound")
	}
	return decodeNATSExposureVarz(raw)
}

func captureNATSRoute(ctx context.Context, env *core.Env) (natsRouteIdentity, error) {
	f := env.Config.NATSExposureFixture
	if f == nil {
		return natsRouteIdentity{}, errors.New("NATS baseline fixture absent")
	}
	var route natsRouteIdentity
	cluster, err := env.Kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID == "" || string(cluster.UID) != f.ClusterUID {
		return route, errors.New("cluster identity unavailable")
	}
	route.ClusterUID = cluster.UID
	node, err := env.Kube.CoreV1().Nodes().Get(ctx, f.NodeName, metav1.GetOptions{})
	if err != nil || node.UID == "" || node.Spec.Unschedulable || !nodeReady(node) {
		return route, errors.New("reviewed fixture node unavailable")
	}
	route.NodeUID = node.UID
	service, err := env.Kube.CoreV1().Services(natsExposureNamespace).Get(ctx, natsExposureService, metav1.GetOptions{})
	if err != nil || service.UID == "" || len(service.Spec.Selector) != 1 || service.Spec.Selector["app"] != "nats" || len(service.Spec.Ports) != 1 {
		return route, errors.New("NATS Service identity/selector differs")
	}
	port := service.Spec.Ports[0]
	if port.Name != "client" || port.Port != 4222 || port.TargetPort.IntValue() != 4222 || port.Protocol != corev1.ProtocolTCP {
		return route, errors.New("NATS client Service port differs")
	}
	route.ServiceUID = service.UID
	sts, err := env.Kube.AppsV1().StatefulSets(natsExposureNamespace).Get(ctx, natsExposureStatefulSet, metav1.GetOptions{})
	if err != nil || sts.UID == "" || sts.Generation != sts.Status.ObservedGeneration || sts.Status.CurrentRevision == "" || sts.Status.CurrentRevision != sts.Status.UpdateRevision {
		return route, errors.New("NATS StatefulSet source is unavailable or rolling")
	}
	route.StatefulSetUID, route.StatefulRevision = sts.UID, sts.Status.CurrentRevision
	cm, err := env.Kube.CoreV1().ConfigMaps(natsExposureNamespace).Get(ctx, natsExposureConfigMap, metav1.GetOptions{})
	if err != nil || cm.UID == "" || len(cm.Data) != 1 {
		return route, errors.New("NATS config source unavailable")
	}
	source, ok := cm.Data["nats.conf"]
	sourceHash := sha256.Sum256([]byte(source))
	if !ok || hex.EncodeToString(sourceHash[:]) != f.ConfigSHA256 {
		return route, errors.New("NATS config bytes differ from reviewed no-auth contract")
	}
	route.ConfigMapUID, route.ConfigMapResourceVersion = cm.UID, cm.ResourceVersion
	route.ConfigSHA256, route.ConfigSourceAttestation = f.ConfigSHA256, "DECLARED_CM_ONLY"
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(natsExposureNamespace).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=nats"})
	if err != nil || len(slices.Items) != 1 {
		return route, errors.New("NATS client EndpointSlice membership ambiguous")
	}
	sl := slices.Items[0]
	if sl.UID == "" || sl.Labels["kubernetes.io/service-name"] != natsExposureService || !natsSliceOwned(&sl, service.UID) || len(sl.Ports) != 1 || sl.Ports[0].Name == nil || *sl.Ports[0].Name != "client" || sl.Ports[0].Port == nil || *sl.Ports[0].Port != 4222 {
		return route, errors.New("NATS EndpointSlice owner/port differs")
	}
	route.EndpointSliceUID, route.EndpointSliceResourceVersion = sl.UID, sl.ResourceVersion
	if len(sl.Endpoints) < 1 || len(sl.Endpoints) > 3 {
		return route, errors.New("NATS serving endpoint count outside reviewed bound")
	}
	for _, ep := range sl.Endpoints {
		if ep.Conditions.Ready == nil || !*ep.Conditions.Ready || ep.Conditions.Serving == nil || !*ep.Conditions.Serving || ep.Conditions.Terminating == nil || *ep.Conditions.Terminating || ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || ep.TargetRef.Namespace != natsExposureNamespace || ep.TargetRef.UID == "" || len(ep.Addresses) != 1 {
			return route, errors.New("NATS endpoint is not an exact serving Pod")
		}
		pod, err := env.Kube.CoreV1().Pods(natsExposureNamespace).Get(ctx, ep.TargetRef.Name, metav1.GetOptions{})
		if err != nil || pod.UID != ep.TargetRef.UID {
			return route, errors.New("NATS endpoint Pod UID differs")
		}
		b, err := natsReady(pod, sts.UID, sts.Status.CurrentRevision, f.BrokerImageID)
		if err != nil || b.IP != ep.Addresses[0] {
			return route, errors.New("NATS endpoint Pod source/IP differs")
		}
		varz, err := natsExposureVarz(ctx, env, b.Name)
		if err != nil || varz.ServerID == "" || varz.Version != f.BrokerVersion || len(varz.Jetstream) == 0 || string(varz.Jetstream) == "null" || (varz.AuthRequired != nil && *varz.AuthRequired) {
			return route, errors.New("NATS serving process version/auth/JetStream differs")
		}
		if !varz.AuthPresent && f.BrokerVersion != "2.10.29" {
			return route, errors.New("omitted auth flag only admitted for reviewed NATS version")
		}
		b.ServerID = varz.ServerID
		route.Brokers = append(route.Brokers, b)
	}
	sort.Slice(route.Brokers, func(i, j int) bool { return route.Brokers[i].Name < route.Brokers[j].Name })
	for i := 1; i < len(route.Brokers); i++ {
		if route.Brokers[i].UID == route.Brokers[i-1].UID || route.Brokers[i].ServerID == route.Brokers[i-1].ServerID {
			return route, errors.New("duplicate serving broker identity")
		}
	}
	return route, nil
}

func natsSliceOwned(sl *discoveryv1.EndpointSlice, uid types.UID) bool {
	matches := 0
	for _, o := range sl.OwnerReferences {
		if o.Kind == "Service" && o.Name == natsExposureService && o.UID == uid && o.Controller != nil && *o.Controller {
			matches++
		}
	}
	return matches == 1
}
func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func routeEqual(a, b natsRouteIdentity) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func brokerForServer(route natsRouteIdentity, id string) (natsBrokerIdentity, bool) {
	for _, b := range route.Brokers {
		if b.ServerID == id {
			return b, true
		}
	}
	return natsBrokerIdentity{}, false
}
func requireNATSRoute(ctx context.Context, env *core.Env, before natsRouteIdentity) error {
	after, err := captureNATSRoute(ctx, env)
	if err != nil {
		return err
	}
	if !routeEqual(before, after) {
		return fmt.Errorf("NATS route/source identity changed before publication")
	}
	return nil
}
