package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

const (
	natsResponseConfig   = "nats-client-response"
	natsFixtureNamespace = "phorvex-nats-exposure-fixture"
	natsResponseSchema   = "nats-client-response-v1"
)

type natsResponseRequest struct {
	Schema, RunID, Nonce, Namespace, NamespaceUID string
	ClientPod, ClientPodUID, PeerPodUID           string
	PolicyName, PolicyUID                         string
	PolicyGeneration                              int64
	ManagerPodUID, ManagerContainerID             string
	M0ReceiptSHA256, PeerM0ReceiptSHA256          string
}

// The wire object is deliberately separate from the request used for authority.
// Every field is checked against fresh Kubernetes data before the event path.
type natsResponseRequestWire struct {
	Schema              string `json:"schema"`
	RunID               string `json:"runId"`
	Nonce               string `json:"nonce"`
	Namespace           string `json:"namespace"`
	NamespaceUID        string `json:"namespaceUID"`
	ClientPod           string `json:"clientPod"`
	ClientPodUID        string `json:"clientPodUID"`
	PeerPodUID          string `json:"peerPodUID"`
	PolicyName          string `json:"policyName"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	ManagerPodUID       string `json:"managerPodUID"`
	ManagerContainerID  string `json:"managerContainerID"`
	M0ReceiptSHA256     string `json:"m0ReceiptSHA256"`
	PeerM0ReceiptSHA256 string `json:"peerM0ReceiptSHA256"`
}

func (w natsResponseRequestWire) request() natsResponseRequest {
	return natsResponseRequest{Schema: w.Schema, RunID: w.RunID, Nonce: w.Nonce, Namespace: w.Namespace,
		NamespaceUID: w.NamespaceUID, ClientPod: w.ClientPod, ClientPodUID: w.ClientPodUID,
		PeerPodUID: w.PeerPodUID, PolicyName: w.PolicyName, PolicyUID: w.PolicyUID,
		PolicyGeneration: w.PolicyGeneration, ManagerPodUID: w.ManagerPodUID,
		ManagerContainerID: w.ManagerContainerID, M0ReceiptSHA256: w.M0ReceiptSHA256,
		PeerM0ReceiptSHA256: w.PeerM0ReceiptSHA256}
}

var natsResponseRequestKeys = map[string]bool{
	"schema": true, "runId": true, "nonce": true, "namespace": true,
	"namespaceUID": true, "clientPod": true, "clientPodUID": true,
	"peerPodUID": true, "policyName": true, "policyUID": true,
	"policyGeneration": true, "managerPodUID": true,
	"managerContainerID": true, "m0ReceiptSHA256": true, "peerM0ReceiptSHA256": true,
}

func strictNATSResponseJSON(raw []byte, keys map[string]bool) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("one JSON object required")
	}
	seen := map[string]bool{}
	for d.More() {
		keyToken, err := d.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || !keys[key] || seen[key] {
			return errors.New("ambiguous or unknown JSON field")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("invalid JSON value")
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(keys) {
		return errors.New("incomplete JSON object")
	}
	if _, err = d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func natsResponseRoot(out string) (*os.Root, error) {
	if !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return nil, errors.New("run directory is not exact absolute path")
	}
	resolved, err := filepath.EvalSymlinks(out)
	if err != nil || resolved != out {
		return nil, errors.New("run directory is linked or absent")
	}
	return os.OpenRoot(out)
}

func readNATSResponseFile(out, name string) ([]byte, error) {
	return readNATSResponseSizedFile(out, name, 4096)
}

func readNATSResponseSizedFile(out, name string, limit int64) ([]byte, error) {
	root, err := natsResponseRoot(out)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	st, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > limit {
		return nil, errors.New("response file invalid")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameNATSResponseFileState(st, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("response file changed during read")
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, errors.New("response file has another hard link")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) != int(st.Size()) {
		return nil, errors.New("response file exceeded bound or changed")
	}
	endedFD, fdErr := f.Stat()
	endedPath, pathErr := root.Lstat(name)
	if fdErr != nil || pathErr != nil || !sameNATSResponseFileState(st, endedFD) || !sameNATSResponseFileState(st, endedPath) {
		return nil, errors.New("response file changed during read")
	}
	return raw, nil
}

func sameNATSResponseFileState(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	sa, aok := a.Sys().(*syscall.Stat_t)
	sb, bok := b.Sys().(*syscall.Stat_t)
	return aok && bok && sa.Ctim == sb.Ctim && sa.Nlink == 1 && sb.Nlink == 1
}

func readNATSResponseRequest(out, id string) (natsResponseRequest, error) {
	var wire natsResponseRequestWire
	raw, err := readNATSResponseFile(out, "nats-response-signal-request.json")
	if err != nil {
		return natsResponseRequest{}, err
	}
	if err := strictNATSResponseJSON(raw, natsResponseRequestKeys); err != nil {
		return natsResponseRequest{}, err
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return natsResponseRequest{}, err
	}
	r := wire.request()
	if r.Schema != natsResponseSchema || r.RunID != id || len(r.Nonce) != 24 ||
		r.Namespace != natsFixtureNamespace || r.NamespaceUID == "" || r.ClientPodUID == "" ||
		r.PeerPodUID == "" || r.ClientPodUID == r.PeerPodUID ||
		r.PolicyName != "nats-response-"+r.Nonce || r.PolicyUID == "" || r.PolicyGeneration < 1 ||
		r.ManagerPodUID == "" || r.ManagerContainerID == "" || len(r.M0ReceiptSHA256) != 64 ||
		!natsHex64.MatchString(r.PeerM0ReceiptSHA256) ||
		!nsRe.MatchString(r.ClientPod) {
		return natsResponseRequest{}, errors.New("response request identity incomplete")
	}
	for _, c := range r.Nonce {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return natsResponseRequest{}, errors.New("response nonce invalid")
		}
	}
	if b, err := hex.DecodeString(r.M0ReceiptSHA256); err != nil || len(b) != 32 || strings.ToLower(r.M0ReceiptSHA256) != r.M0ReceiptSHA256 {
		return natsResponseRequest{}, errors.New("response M0 digest invalid")
	}
	return r, nil
}

func (s *Server) currentNATSResponseGrant(id string) (*Principal, error) {
	s.runs.mu.Lock()
	launched, ok := s.runs.natsPrincipals[id]
	statusPtr := s.runs.runs[id]
	var status RunStatus
	if statusPtr != nil {
		status = *statusPtr
	}
	s.runs.mu.Unlock()
	if !ok || statusPtr == nil || status.Config != natsResponseConfig || status.State != "running" ||
		principalKey(&launched) != status.Owner || s.auth == nil {
		return nil, errors.New("response run owner unavailable")
	}
	grants := s.auth.grants
	if s.auth.grantsPath != "" {
		var err error
		grants, err = LoadGrantFile(s.auth.grantsPath)
		if err != nil {
			return nil, errors.New("current response grant unavailable")
		}
	}
	p, found := grants.Lookup(launched.Issuer, launched.Subject)
	if !found || !p.HasRole(RoleOperator) || !p.AllowsTenant("nats") || !p.AllowsTenant(natsFixtureNamespace) ||
		!p.AllowsTarget(hostTargetID) || !p.AllowsTarget(status.ScopeTarget) ||
		status.ScopeTenant != "nats" || status.FixtureTenant != natsFixtureNamespace {
		return nil, errors.New("response dual destination grant changed")
	}
	return p, nil
}

type natsResponseConfigPin struct {
	Context   string `json:"context"`
	Namespace string `json:"namespace"`
	Fixture   struct {
		RunID             string `json:"runID"`
		Nonce             string `json:"nonce"`
		ManagerNamespace  string `json:"managerNamespace"`
		ManagerDeployment string `json:"managerDeployment"`
		ObserverImage     string `json:"observerImage"`
		ManagerImageID    string `json:"managerImageID"`
	} `json:"natsExposureFixture"`
}

func (s *Server) natsResponseConfigPin(id string) (natsResponseConfigPin, error) {
	var pin natsResponseConfigPin
	path := filepath.Join(s.cfg.runsDir(), "configs", id+".yaml")
	raw, err := readBoundedFile(path, 32<<10)
	if err != nil || yaml.Unmarshal(raw, &pin) != nil || pin.Namespace != natsFixtureNamespace ||
		pin.Fixture.RunID != id || len(pin.Fixture.Nonce) != 24 || pin.Fixture.ManagerNamespace != "phorvex-system" ||
		pin.Fixture.ManagerDeployment == "" || pin.Fixture.ObserverImage == "" || pin.Fixture.ManagerImageID == "" {
		return pin, errors.New("response owned config pin unavailable")
	}
	return pin, nil
}

func natsResponseClient(cfg *rest.Config) (kubernetes.Interface, error) {
	if cfg == nil {
		var err error
		cfg, err = restConfigFor("")
		if err != nil {
			return nil, err
		}
	}
	return kubernetes.NewForConfig(cfg)
}

type natsM0Proof struct {
	client, peer               corev1.Pod
	prefix                     []byte
	configSHA                  string
	subjects, digests, servers []string
}

func (s *Server) verifyNATSResponseM0(ctx context.Context, kc kubernetes.Interface, r natsResponseRequest, pin natsResponseConfigPin) (natsM0Proof, error) {
	var proof natsM0Proof
	ns, err := kc.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.NamespaceUID || ns.DeletionTimestamp != nil {
		return proof, errors.New("response namespace identity changed")
	}
	client, err := kc.CoreV1().Pods(r.Namespace).Get(ctx, r.ClientPod, metav1.GetOptions{})
	if err != nil || string(client.UID) != r.ClientPodUID {
		return proof, errors.New("response client Pod identity changed")
	}
	// Phoenix writes its generated NetworkPolicy name into a Pod label value.
	// Bind this check to the shared producer contract before creating an event.
	if !natsPhoenixLabelFits(r.Namespace, r.ClientPod) {
		return proof, errors.New("response Phoenix label value would exceed admission bound")
	}
	pods, err := kc.CoreV1().Pods(r.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "fixture.phorvex.ai/owner-nonce=" + r.Nonce, Limit: 16})
	if err != nil || pods.Continue != "" || pods.RemainingItemCount != nil {
		return proof, errors.New("response owned Pod inventory incomplete")
	}
	peers := 0
	for i := range pods.Items {
		p := pods.Items[i]
		if p.UID == types.UID(r.PeerPodUID) {
			proof.peer = p
			peers++
		}
	}
	if peers != 1 || proof.peer.UID == client.UID || proof.peer.Name == client.Name {
		return proof, errors.New("response peer Pod identity unavailable")
	}
	if len(pods.Items) != 2 || client.Labels["fixture.phorvex.ai/role"] != "source" || proof.peer.Labels["fixture.phorvex.ai/role"] != "" ||
		client.Labels["fixture.phorvex.ai/component"] != "consumer" || proof.peer.Labels["fixture.phorvex.ai/component"] != "consumer" {
		return proof, errors.New("response exact two-Pod population differs")
	}
	if err := verifyNATSResponseService(ctx, kc, r, *client, proof.peer); err != nil {
		return proof, err
	}
	for _, p := range []*corev1.Pod{client, &proof.peer} {
		if p.Namespace != r.Namespace || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning ||
			p.Labels["fixture.phorvex.ai/owner-nonce"] != r.Nonce || !podReady(p) ||
			p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken ||
			len(p.Spec.Containers) != 1 || len(p.Status.ContainerStatuses) != 1 ||
			p.Status.ContainerStatuses[0].RestartCount != 0 || p.Status.ContainerStatuses[0].ContainerID == "" ||
			!sameNATSImageDigest(p.Status.ContainerStatuses[0].ImageID, pin.Fixture.ObserverImage) {
			return proof, errors.New("response Pod incarnation or image changed")
		}
		c := p.Spec.Containers[0]
		if len(c.Command) != 3 || c.Command[0] != "/app/nats-owned-observer" || c.Command[1] != "--response-config" || c.Command[2] != "/config/observer.json" ||
			len(c.Args) != 0 || len(c.VolumeMounts) != 1 || c.VolumeMounts[0].MountPath != "/config" || !c.VolumeMounts[0].ReadOnly ||
			len(p.Spec.Volumes) != 1 || p.Spec.Volumes[0].ConfigMap == nil || p.Spec.Volumes[0].ConfigMap.Name != r.PolicyName ||
			!responsePodUIDEnv(c.Env, string(p.UID)) {
			return proof, errors.New("response Pod process or Downward API contract changed")
		}
	}
	cm, err := kc.CoreV1().ConfigMaps(r.Namespace).Get(ctx, r.PolicyName, metav1.GetOptions{})
	if err != nil || cm.UID == "" || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable ||
		cm.Labels["fixture.phorvex.ai/owner-nonce"] != r.Nonce || len(cm.Data) != 1 {
		return proof, errors.New("response observer ConfigMap changed")
	}
	configRaw := []byte(cm.Data["observer.json"])
	if len(configRaw) == 0 || len(configRaw) > 2048 {
		return proof, errors.New("response observer config unavailable")
	}
	var obs struct {
		Nonce                 string   `json:"nonce"`
		Subjects              []string `json:"subjects"`
		ExpectedPayloadSHA256 []string `json:"expectedPayloadSHA256"`
		AllowedServerIDs      []string `json:"allowedServerIDs"`
	}
	if json.Unmarshal(configRaw, &obs) != nil || obs.Nonce != r.Nonce || len(obs.Subjects) != 2 ||
		obs.Subjects[0] != "cat.response."+r.Nonce+".m0" || obs.Subjects[1] != "cat.response."+r.Nonce+".m1" ||
		len(obs.ExpectedPayloadSHA256) != 2 || len(obs.AllowedServerIDs) == 0 || len(obs.AllowedServerIDs) > 3 {
		return proof, errors.New("response observer config differs")
	}
	for _, digest := range obs.ExpectedPayloadSHA256 {
		if len(digest) != 64 {
			return proof, errors.New("response payload digest invalid")
		}
	}
	stream, err := kc.CoreV1().Pods(r.Namespace).GetLogs(r.ClientPod, &corev1.PodLogOptions{Container: client.Spec.Containers[0].Name, LimitBytes: ptrInt64(4096)}).Stream(ctx)
	if err != nil {
		return proof, errors.New("response client log unavailable")
	}
	defer stream.Close()
	logRaw, err := io.ReadAll(io.LimitReader(stream, 4097))
	if err != nil || len(logRaw) < 1 || len(logRaw) > 4096 {
		return proof, errors.New("response client log exceeded bound")
	}
	if err := validateNATSResponseM0(logRaw, r, obs.Subjects, obs.ExpectedPayloadSHA256, obs.AllowedServerIDs); err != nil {
		return proof, err
	}
	if natsSHA(logRaw) != r.M0ReceiptSHA256 {
		return proof, errors.New("response M0 prefix differs from independent Pod log")
	}
	proof.client, proof.prefix, proof.configSHA = *client, logRaw, natsSHA(configRaw)
	proof.subjects, proof.digests, proof.servers = obs.Subjects, obs.ExpectedPayloadSHA256, obs.AllowedServerIDs
	return proof, nil
}

func verifyNATSResponsePeerM0(ctx context.Context, kc kubernetes.Interface, r natsResponseRequest, proof natsM0Proof) error {
	check := func() error {
		peer, err := kc.CoreV1().Pods(r.Namespace).Get(ctx, proof.peer.Name, metav1.GetOptions{})
		if err != nil || string(peer.UID) != r.PeerPodUID || peer.DeletionTimestamp != nil || !podReady(peer) ||
			len(peer.Status.ContainerStatuses) != 1 || len(proof.peer.Status.ContainerStatuses) != 1 ||
			peer.Status.ContainerStatuses[0].RestartCount != 0 ||
			peer.Status.ContainerStatuses[0].ContainerID != proof.peer.Status.ContainerStatuses[0].ContainerID ||
			!sameNATSImageDigest(peer.Status.ContainerStatuses[0].ImageID, proof.peer.Status.ContainerStatuses[0].ImageID) ||
			len(peer.OwnerReferences) != 1 || !reflect.DeepEqual(peer.OwnerReferences, proof.peer.OwnerReferences) {
			return errors.New("response original peer incarnation changed")
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	if len(proof.peer.Spec.Containers) != 1 {
		return errors.New("response original peer container unavailable")
	}
	stream, err := kc.CoreV1().Pods(r.Namespace).GetLogs(proof.peer.Name,
		&corev1.PodLogOptions{Container: proof.peer.Spec.Containers[0].Name, LimitBytes: ptrInt64(4096)}).Stream(ctx)
	if err != nil {
		return errors.New("response peer M0 log unavailable")
	}
	defer stream.Close()
	raw, err := io.ReadAll(io.LimitReader(stream, 4097))
	if err != nil || len(raw) < 1 || len(raw) > 4096 {
		return errors.New("response peer M0 log exceeded bound")
	}
	peerRequest := r
	peerRequest.ClientPodUID = r.PeerPodUID
	if err := validateNATSResponseM0(raw, peerRequest, proof.subjects, proof.digests, proof.servers); err != nil {
		return err
	}
	if natsSHA(raw) != r.PeerM0ReceiptSHA256 {
		return errors.New("response peer M0 prefix differs")
	}
	return check()
}

func ptrInt64(v int64) *int64 { return &v }

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func responsePodUIDEnv(env []corev1.EnvVar, uid string) bool {
	uidRefs, health := 0, 0
	for _, e := range env {
		if e.Name == "POD_UID" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil && e.ValueFrom.FieldRef.FieldPath == "metadata.uid" && e.Value == "" {
			uidRefs++
		}
		if e.Name == "NATS_RESPONSE_SERVICE" && e.Value == "1" && e.ValueFrom == nil {
			health++
		}
	}
	return uid != "" && uidRefs == 1 && health == 1
}

func verifyNATSResponsePeerOwner(source, peer corev1.Pod) error {
	if len(source.OwnerReferences) != 1 || len(peer.OwnerReferences) != 1 ||
		source.OwnerReferences[0].Kind != "ReplicaSet" ||
		peer.OwnerReferences[0].Kind != "ReplicaSet" ||
		source.OwnerReferences[0].UID == "" ||
		peer.OwnerReferences[0].UID != source.OwnerReferences[0].UID ||
		peer.OwnerReferences[0].Name != source.OwnerReferences[0].Name ||
		peer.Labels["fixture.phorvex.ai/role"] != "" ||
		source.Labels["fixture.phorvex.ai/role"] != "source" {
		return errors.New("response peer controller or role differs")
	}
	return nil
}

func verifyNATSResponseService(ctx context.Context, kc kubernetes.Interface, r natsResponseRequest, source, peer corev1.Pod) error {
	service, err := kc.CoreV1().Services(r.Namespace).Get(ctx, r.PolicyName, metav1.GetOptions{})
	if err != nil || service.UID == "" || service.DeletionTimestamp != nil ||
		service.Labels["fixture.phorvex.ai/owner-nonce"] != r.Nonce ||
		service.Spec.Type != corev1.ServiceTypeClusterIP ||
		len(service.Spec.Selector) != 2 || service.Spec.Selector["fixture.phorvex.ai/owner-nonce"] != r.Nonce || service.Spec.Selector["fixture.phorvex.ai/component"] != "consumer" ||
		len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 8080 || service.Spec.Ports[0].TargetPort != intstr.FromString("ready") {
		return errors.New("response client Service authority changed")
	}
	slices, err := kc.DiscoveryV1().EndpointSlices(r.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + r.PolicyName, Limit: 16})
	if err != nil || slices.Continue != "" || slices.RemainingItemCount != nil || len(slices.Items) == 0 {
		return errors.New("response Service endpoints unavailable")
	}
	seen := map[types.UID]bool{}
	for _, slice := range slices.Items {
		if slice.DeletionTimestamp != nil || slice.Labels["kubernetes.io/service-name"] != r.PolicyName || len(slice.OwnerReferences) != 1 || slice.OwnerReferences[0].UID != service.UID {
			return errors.New("response EndpointSlice owner differs")
		}
		for _, ep := range slice.Endpoints {
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || ep.TargetRef.Namespace != r.Namespace || ep.Conditions.Ready == nil || !*ep.Conditions.Ready ||
				ep.Conditions.Serving == nil || !*ep.Conditions.Serving || ep.Conditions.Terminating == nil || *ep.Conditions.Terminating || len(ep.Addresses) != 1 {
				return errors.New("response endpoint identity incomplete")
			}
			uid := ep.TargetRef.UID
			if seen[uid] || (uid != source.UID && uid != peer.UID) ||
				(uid == source.UID && ep.Addresses[0] != source.Status.PodIP) ||
				(uid == peer.UID && ep.Addresses[0] != peer.Status.PodIP) {
				return errors.New("response endpoint target differs")
			}
			seen[uid] = true
		}
	}
	if !seen[source.UID] || !seen[peer.UID] || len(seen) != 2 {
		return errors.New("response Service lacks exact two Ready endpoints")
	}
	pdb, err := kc.PolicyV1().PodDisruptionBudgets(r.Namespace).Get(ctx, r.PolicyName, metav1.GetOptions{})
	if err != nil || pdb.UID == "" || pdb.DeletionTimestamp != nil || pdb.Labels["fixture.phorvex.ai/owner-nonce"] != r.Nonce ||
		pdb.Spec.MinAvailable == nil || *pdb.Spec.MinAvailable != intstr.FromInt(1) || pdb.Spec.Selector == nil ||
		len(pdb.Spec.Selector.MatchLabels) != 2 || len(pdb.Spec.Selector.MatchExpressions) != 0 ||
		pdb.Spec.Selector.MatchLabels["fixture.phorvex.ai/owner-nonce"] != r.Nonce || pdb.Spec.Selector.MatchLabels["fixture.phorvex.ai/component"] != "consumer" ||
		pdb.Status.DisruptionsAllowed < 1 {
		return errors.New("response PDB headroom unavailable")
	}
	return nil
}

func (s *Server) verifyNATSResponsePolicy(r natsResponseRequest) error {
	var policy v1alpha1.PhorvexPolicy
	if err := s.scenarioObject(r.Namespace, "phorvexpolicy", r.PolicyName, &policy); err != nil {
		return err
	}
	if policy.Name != r.PolicyName || policy.Namespace != r.Namespace || string(policy.UID) != r.PolicyUID ||
		policy.Generation != r.PolicyGeneration || policy.ResourceVersion == "" || policy.DeletionTimestamp != nil ||
		policy.Spec.Tenant != r.Nonce || policy.Spec.EffectiveMode() != v1alpha1.ModeActive ||
		len(policy.Spec.Selector.MatchLabels) != 2 ||
		policy.Spec.Selector.MatchLabels["fixture.phorvex.ai/owner-nonce"] != r.Nonce ||
		policy.Spec.Selector.MatchLabels["fixture.phorvex.ai/role"] != "source" ||
		len(policy.Spec.Selector.MatchExpressions) != 0 ||
		!policy.Spec.Triggers.EventDriven || !policy.Spec.Triggers.ReactiveOnly ||
		len(policy.Spec.Actions.Enabled) != 2 || policy.Spec.Actions.Enabled[0] != v1alpha1.ActionRotate ||
		policy.Spec.Actions.Enabled[1] != v1alpha1.ActionQuarantine {
		return errors.New("response named policy contract changed")
	}
	return nil
}

type natsResponseReceipt struct {
	Kind, Phase, Status, Subject, Nonce, PodUID, ServerID string
	Flushed                                               bool
	PayloadBytes                                          int
	PayloadSHA256                                         string
	NonceHeaderMatches, PayloadHashMatches                bool
}

func validateNATSResponseM0(raw []byte, r natsResponseRequest, subjects, digests, servers []string) error {
	if len(raw) == 0 || len(raw) > 4096 || raw[len(raw)-1] != '\n' || len(subjects) != 2 || len(digests) != 2 {
		return errors.New("M0 log shape invalid")
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 3 {
		return errors.New("M0 prefix must contain exactly three receipts")
	}
	keys := map[string]bool{"kind": true, "phase": true, "status": true, "subject": true, "nonce": true, "podUID": true, "serverID": true, "flushed": true, "payloadBytes": true, "payloadSHA256": true, "nonceHeaderMatches": true, "payloadHashMatches": true}
	server := ""
	for i, line := range lines {
		if len(line) == 0 || len(line) > 1024 {
			return errors.New("M0 receipt line invalid")
		}
		// Receipt fields with omitempty are optional, but their spelled keys are never ambiguous.
		if err := strictNATSResponseSubset(line, keys); err != nil {
			return err
		}
		var row struct {
			Kind               string `json:"kind"`
			Phase              string `json:"phase"`
			Status             string `json:"status"`
			Subject            string `json:"subject"`
			Nonce              string `json:"nonce"`
			PodUID             string `json:"podUID"`
			ServerID           string `json:"serverID"`
			Flushed            bool   `json:"flushed"`
			PayloadBytes       int    `json:"payloadBytes"`
			PayloadSHA256      string `json:"payloadSHA256"`
			NonceHeaderMatches bool   `json:"nonceHeaderMatches"`
			PayloadHashMatches bool   `json:"payloadHashMatches"`
		}
		if json.Unmarshal(line, &row) != nil || row.Nonce != r.Nonce || row.PodUID != r.ClientPodUID || row.ServerID == "" {
			return errors.New("M0 receipt target identity differs")
		}
		admitted := false
		for _, id := range servers {
			admitted = admitted || row.ServerID == id
		}
		if !admitted {
			return errors.New("M0 broker ID unadmitted")
		}
		if i == 0 {
			server = row.ServerID
		}
		if row.ServerID != server {
			return errors.New("M0 broker changed")
		}
		if i < 2 {
			phase := []string{"M0", "M1"}[i]
			if row.Kind != "subscription" || row.Phase != phase || row.Subject != subjects[i] || row.Status != "READY" || !row.Flushed || row.PayloadBytes != 0 || row.PayloadSHA256 != "" || row.NonceHeaderMatches || row.PayloadHashMatches {
				return errors.New("M0 subscription barrier invalid")
			}
		} else if row.Kind != "observation" || row.Phase != "M0" || row.Subject != subjects[0] || row.Status != "EXACT_PAYLOAD_RECEIVED" || row.Flushed || row.PayloadBytes < 1 || row.PayloadBytes > 256 || row.PayloadSHA256 != digests[0] || !row.NonceHeaderMatches || !row.PayloadHashMatches {
			return errors.New("M0 disclosure receipt invalid")
		}
	}
	return nil
}

func strictNATSResponseSubset(raw []byte, keys map[string]bool) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("receipt object invalid")
	}
	seen := map[string]bool{}
	for d.More() {
		keyTok, err := d.Token()
		key, ok := keyTok.(string)
		if err != nil || !ok || !keys[key] || seen[key] {
			return errors.New("receipt key ambiguous")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("receipt value invalid")
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) < 7 {
		return errors.New("receipt incomplete")
	}
	if _, err = d.Token(); err != io.EOF {
		return errors.New("receipt trailing data")
	}
	return nil
}

type natsResponseDecision struct {
	Schema                 string `json:"schema"`
	RunID                  string `json:"runId"`
	Nonce                  string `json:"nonce"`
	NamespaceUID           string `json:"namespaceUID"`
	ClientPodUID           string `json:"clientPodUID"`
	PeerPodUID             string `json:"peerPodUID"`
	PolicyUID              string `json:"policyUID"`
	PolicyGeneration       int64  `json:"policyGeneration"`
	ManagerPodUID          string `json:"managerPodUID"`
	ManagerContainerID     string `json:"managerContainerID"`
	M0ReceiptSHA256        string `json:"m0ReceiptSHA256"`
	PeerM0ReceiptSHA256    string `json:"peerM0ReceiptSHA256"`
	EventName              string `json:"eventName"`
	EventUID               string `json:"eventUID"`
	AttackID               string `json:"attackId"`
	DecisionID             string `json:"decisionId"`
	DecisionTraceSHA256    string `json:"decisionTraceSHA256"`
	DecisionEvidenceSHA256 string `json:"decisionEvidenceSHA256"`
	SelectedAction         string `json:"selectedAction"`
	DispatchOutcome        string `json:"dispatchOutcome"`
	EffectStatus           string `json:"effectStatus"`
	EventCleanupStatus     string `json:"eventCleanupStatus"`
}

var natsGeneratedEventPattern = regexp.MustCompile(`^phorvex-quarantine-[a-z0-9]{5,20}$`)
var natsOperationPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// The capacity wrapper replaces the optimizer's decision ID with this durable
// operation identity before Phoenix emits the controlled event.
func natsQuarantineOperationID(policyUID, namespace, targetUID string) string {
	sum := sha256.Sum256([]byte(policyUID + "\x00" + namespace + "\x00" + targetUID + "\x00quarantine"))
	return hex.EncodeToString(sum[:20])
}

func natsPhoenixLabelFits(namespace, pod string) bool {
	return namespace != "" && pod != "" && len(amtdv1beta1.QuarantineNetworkPolicyName(namespace, pod)) <= 63
}

type natsQuarantineEffect struct {
	GeneratedEventName       string `json:"generatedEventName"`
	GeneratedEventUID        string `json:"generatedEventUID"`
	OperationID              string `json:"operationID"`
	AMTDName                 string `json:"amtdName"`
	AMTDUID                  string `json:"amtdUID"`
	PhoenixNetworkPolicyName string `json:"phoenixNetworkPolicyName"`
	PhoenixNetworkPolicyUID  string `json:"phoenixNetworkPolicyUID"`
	SourcePodUID             string `json:"sourcePodUID"`
	PeerPodUID               string `json:"peerPodUID"`
}

func natsQuarantineEffectMatches(e *natsQuarantineEffect, r natsResponseRequest) bool {
	return e != nil && natsGeneratedEventPattern.MatchString(e.GeneratedEventName) && e.GeneratedEventUID != "" &&
		e.OperationID == natsQuarantineOperationID(r.PolicyUID, r.Namespace, r.ClientPodUID) &&
		e.AMTDName == "phorvex-"+r.Namespace+"-"+r.Nonce && e.AMTDUID != "" &&
		e.PhoenixNetworkPolicyName == amtdv1beta1.QuarantineNetworkPolicyName(r.Namespace, r.ClientPod) && e.PhoenixNetworkPolicyUID != "" &&
		e.SourcePodUID == r.ClientPodUID && e.PeerPodUID == r.PeerPodUID
}

func natsAMTDController(ref metav1.OwnerReference, name string, uid types.UID) bool {
	return ref.APIVersion == "amtd.r6security.com/v1beta1" && ref.Kind == "AdaptiveMovingTargetDefense" &&
		ref.Name == name && ref.UID == uid && ref.Controller != nil && *ref.Controller
}

// natsDecisionEvidence is an exact-run projection of a validated manager audit
// record. No full audit row, unrelated tenant, or request-supplied WHY is copied.
type natsDecisionEvidence struct {
	Schema                  string                     `json:"schema"`
	RunID                   string                     `json:"runId"`
	NamespaceUID            string                     `json:"namespaceUID"`
	ClientPodUID            string                     `json:"clientPodUID"`
	PolicyUID               string                     `json:"policyUID"`
	PolicyGeneration        int64                      `json:"policyGeneration"`
	ManagerPodUID           string                     `json:"managerPodUID"`
	ManagerContainerID      string                     `json:"managerContainerID"`
	M0ReceiptSHA256         string                     `json:"m0ReceiptSHA256"`
	PeerM0ReceiptSHA256     string                     `json:"peerM0ReceiptSHA256"`
	EventName               string                     `json:"eventName"`
	EventUID                string                     `json:"eventUID"`
	DecisionID              string                     `json:"decisionId"`
	TickID                  string                     `json:"tickId"`
	DecisionTraceSHA256     string                     `json:"decisionTraceSHA256"`
	BrainImage              string                     `json:"brainImage"`
	BrainImageSHA256        string                     `json:"brainImageSHA256"`
	GitSHA                  string                     `json:"gitSHA"`
	InputPhase              string                     `json:"inputPhase"`
	InputStage              string                     `json:"inputStage"`
	PHold                   model.OptionalFloat        `json:"pHold"`
	ThreatPosture           model.OptionalFloat        `json:"threatPosture"`
	SLOHeadroom             model.OptionalFloat        `json:"sloHeadroom"`
	Facts                   []natsDecisionFact         `json:"facts"`
	Candidates              []natsDecisionCandidate    `json:"candidates"`
	ActionVocabularyVersion string                     `json:"actionVocabularyVersion,omitempty"`
	ActionStatus            []natsDecisionActionStatus `json:"actionStatus"`
	SelectedAction          string                     `json:"selectedAction"`
	NoopReason              string                     `json:"noopReason"`
	DispatchOutcome         string                     `json:"dispatchOutcome"`
	DispatchReason          string                     `json:"dispatchReason"`
	ObjectEffect            *natsQuarantineEffect      `json:"objectEffect,omitempty"`
	Claim                   string                     `json:"claim"`
}

type natsDecisionFact struct {
	Type          string  `json:"type"`
	Weight        float64 `json:"weight"`
	Source        string  `json:"source"`
	CoveredBefore bool    `json:"coveredBefore"`
}

type natsDecisionCandidate struct {
	Action           string              `json:"action"`
	MarginalCoverage model.OptionalFloat `json:"marginalCoverage"`
	ExpectedCost     model.OptionalFloat `json:"expectedCost"`
	NetGain          model.OptionalFloat `json:"netGain"`
	Feasible         model.OptionalBool  `json:"feasible"`
	Selected         bool                `json:"selected"`
	Exclusion        string              `json:"exclusion"`
}

type natsDecisionActionStatus struct {
	Action        string `json:"action"`
	Status        string `json:"status"`
	ExclusionKind string `json:"exclusionKind"`
	Reason        string `json:"reason"`
	Scored        bool   `json:"scored"`
	RBACUnknown   bool   `json:"rbacUnknown"`
}

// A retained WHY receipt predating the output action has no vocabulary marker
// and carries the frozen 15-action accounting. Newly produced receipts copy
// the trace's named 16-action vocabulary. Never infer a new action from count.
func natsDecisionVocabularyValid(version string, rows []natsDecisionActionStatus, candidates []natsDecisionCandidate, selected string) bool {
	actions, err := model.DecisionTraceActions(version)
	if err != nil || len(rows) != len(actions) {
		return false
	}
	allowed := make(map[string]bool, len(actions))
	for i, action := range actions {
		name := string(action)
		if rows[i].Action != name {
			return false
		}
		allowed[name] = true
	}
	if selected != "" && selected != string(model.ActionNoop) && !allowed[selected] {
		return false
	}
	for _, candidate := range candidates {
		if !allowed[candidate.Action] {
			return false
		}
	}
	return true
}

var natsWhyText = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9 ._,:;()/-]{0,159}$`)

func safeNATSWhy(s string) string {
	if s == "" {
		return ""
	}
	if !natsWhyText.MatchString(s) {
		return "[REDACTED_OR_UNAVAILABLE]"
	}
	return s
}

func publishNATSDecisionEvidence(out string, r natsResponseRequest, rec *audit.Record, traceSHA string, created *attackStimulusEvidence, effect *natsQuarantineEffect) (string, error) {
	if rec == nil || rec.DecisionTrace == nil || created == nil {
		return "", errors.New("exact decision unavailable")
	}
	if rec.DecisionTrace.Validate() != nil {
		return "", errors.New("decision trace invalid")
	}
	t := rec.DecisionTrace.Canonical()
	if t.AssetNamespace != r.Namespace || t.AssetName != r.ClientPod || t.AssetUID != r.ClientPodUID ||
		t.PolicyNamespace != r.Namespace || t.PolicyName != r.PolicyName || t.PolicyUID != r.PolicyUID ||
		len(t.Facts) > 32 || len(t.Candidates) > 32 ||
		rec.Action != t.SelectedAction || rec.DispatchOutcome != t.DispatchOutcome {
		return "", errors.New("decision projection authority or bound differs")
	}
	e := natsDecisionEvidence{Schema: "nats-client-response-decision-evidence-v1", RunID: r.RunID, NamespaceUID: r.NamespaceUID,
		ClientPodUID: r.ClientPodUID, PolicyUID: r.PolicyUID, PolicyGeneration: r.PolicyGeneration, ManagerPodUID: r.ManagerPodUID,
		ManagerContainerID: r.ManagerContainerID, M0ReceiptSHA256: r.M0ReceiptSHA256,
		PeerM0ReceiptSHA256: r.PeerM0ReceiptSHA256, EventName: created.EventName, EventUID: created.EventUID,
		DecisionID: t.DecisionID, TickID: t.TickID, DecisionTraceSHA256: traceSHA, BrainImage: safeNATSWhy(t.BrainImage), BrainImageSHA256: natsSHA([]byte(t.BrainImage)), GitSHA: safeNATSWhy(t.GitSHA),
		InputPhase: safeNATSWhy(t.Inputs.Phase), InputStage: safeNATSWhy(t.Inputs.Stage), PHold: t.Inputs.PHold,
		ThreatPosture: t.Inputs.ThreatPosture, SLOHeadroom: t.Inputs.SLOHeadroom,
		ActionVocabularyVersion: t.ActionVocabularyVersion,
		SelectedAction:          safeNATSWhy(t.SelectedAction), NoopReason: safeNATSWhy(t.NoopReason),
		DispatchOutcome: safeNATSWhy(t.DispatchOutcome), DispatchReason: safeNATSWhy(t.DispatchReason), ObjectEffect: effect,
		Claim: "OBJECT_EFFECT_AND_PACKET_OUTCOME_SEPARATE_SECURITY_NOT_EVALUATED"}
	for _, fact := range t.Facts {
		if math.IsNaN(fact.FinalWeight) || math.IsInf(fact.FinalWeight, 0) {
			return "", errors.New("decision fact weight invalid")
		}
		e.Facts = append(e.Facts, natsDecisionFact{Type: safeNATSWhy(fact.FactType), Weight: fact.FinalWeight,
			Source: safeNATSWhy(fact.SourceComponent), CoveredBefore: fact.CoveredBeforeDecision})
	}
	for _, c := range t.Candidates {
		e.Candidates = append(e.Candidates, natsDecisionCandidate{Action: safeNATSWhy(c.Action), MarginalCoverage: c.MarginalCoverage,
			ExpectedCost: c.ExpectedCost, NetGain: c.NetGain, Feasible: c.Feasible, Selected: c.Selected,
			Exclusion: safeNATSWhy(c.ExistingExclusionReason)})
	}
	for _, a := range t.ActionStatus {
		e.ActionStatus = append(e.ActionStatus, natsDecisionActionStatus{Action: safeNATSWhy(a.Action), Status: safeNATSWhy(a.Status),
			ExclusionKind: safeNATSWhy(a.ExclusionKind), Reason: safeNATSWhy(a.Reason), Scored: a.Scored, RBACUnknown: a.RBACUnknown})
	}
	if !natsDecisionVocabularyValid(e.ActionVocabularyVersion, e.ActionStatus, e.Candidates, e.SelectedAction) {
		return "", errors.New("decision projection action vocabulary invalid")
	}
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > 32<<10 {
		return "", errors.New("decision projection exceeds bound")
	}
	if err := publishNATSOwnedFile(out, "nats-response-decision-evidence.json", raw); err != nil {
		return "", err
	}
	return natsSHA(raw), nil
}

// The selected path admits only the source-object effect that round 20
// established for this installed Phoenix route. It does not decide the M1
// packet result; the independent observer must measure that later.
func (s *Server) natsQuarantineEffectOnce(ctx context.Context, kc kubernetes.Interface, r natsResponseRequest, prior natsM0Proof, rec *audit.Record) (natsQuarantineEffect, bool, error) {
	var out natsQuarantineEffect
	if rec == nil || rec.Phoenix == nil || !rec.Selected || !rec.Actuated || rec.Action != "quarantine" || rec.DispatchOutcome != model.DispatchEmitted {
		return out, false, errors.New("quarantine selection or dispatch unavailable")
	}
	amtdName := "phorvex-" + r.Namespace + "-" + r.Nonce
	forensics := rec.Phoenix
	if !natsGeneratedEventPattern.MatchString(forensics.EventName) || forensics.EventUID == "" ||
		forensics.AMTDName != amtdName || forensics.AMTDNamespace != r.Namespace ||
		forensics.RuleType != "phorvex.quarantine" || forensics.RuleSource != "PhorvexController" ||
		forensics.RuleThreatLevel != "high" {
		return out, false, errors.New("generated quarantine event audit identity differs")
	}
	cfg := s.cfg.ExperimentRESTConfig
	var err error
	if cfg == nil {
		cfg, err = restConfigFor("")
		if err != nil {
			return out, false, err
		}
	}
	dc, err := (dynamicExperimentCluster{cfg: cfg}).client()
	if err != nil {
		return out, false, err
	}
	event, err := dc.Resource(securityEventGVR).Get(ctx, forensics.EventName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	labels, ann := event.GetLabels(), event.GetAnnotations()
	targets, _, targetsErr := unstructured.NestedStringSlice(event.Object, "spec", "targets")
	ruleType, _, typeErr := unstructured.NestedString(event.Object, "spec", "rule", "type")
	ruleSource, _, sourceErr := unstructured.NestedString(event.Object, "spec", "rule", "source")
	ruleThreat, _, threatErr := unstructured.NestedString(event.Object, "spec", "rule", "threatLevel")
	if string(event.GetUID()) != forensics.EventUID || event.GetNamespace() != "" ||
		labels["app.kubernetes.io/managed-by"] != "phorvex" || labels["phorvex.ai/tenant"] != r.Nonce ||
		labels["phorvex.ai/action"] != "quarantine" || ann["phorvex.ai/identity-version"] != "v1" ||
		ann["phorvex.ai/namespace-raw"] != r.Namespace || ann["phorvex.ai/tenant-raw"] != r.Nonce ||
		ann["phorvex.ai/quarantine-target-uid"] != r.ClientPodUID ||
		ann["phorvex.ai/quarantine-namespace-uid"] != r.NamespaceUID ||
		!natsOperationPattern.MatchString(ann["phorvex.ai/quarantine-operation"]) ||
		ann["phorvex.ai/quarantine-operation"] != natsQuarantineOperationID(r.PolicyUID, r.Namespace, r.ClientPodUID) ||
		targetsErr != nil || len(targets) != 1 || targets[0] != r.Namespace+"/"+r.ClientPod ||
		typeErr != nil || ruleType != "phorvex.quarantine" || sourceErr != nil || ruleSource != "PhorvexController" || threatErr != nil || ruleThreat != "high" {
		return out, false, errors.New("generated quarantine event API identity differs")
	}
	amtdGVR := schema.GroupVersionResource{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "adaptivemovingtargetdefenses"}
	amtd, err := dc.Resource(amtdGVR).Namespace(r.Namespace).Get(ctx, amtdName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	amtdLabels, amtdAnn := amtd.GetLabels(), amtd.GetAnnotations()
	if amtd.GetUID() == "" || amtd.GetDeletionTimestamp() != nil || amtd.GetNamespace() != r.Namespace ||
		amtdLabels["app.kubernetes.io/managed-by"] != "phorvex" || amtdLabels["phorvex.ai/tenant"] != r.Nonce ||
		amtdAnn["phorvex.ai/identity-version"] != "v1" || amtdAnn["phorvex.ai/namespace-raw"] != r.Namespace ||
		amtdAnn["phorvex.ai/tenant-raw"] != r.Nonce || amtdAnn["phorvex.ai/policy-name"] != r.PolicyName ||
		amtdAnn["phorvex.ai/policy-uid"] != r.PolicyUID || amtdAnn["phorvex.ai/policy-generation"] != fmt.Sprint(r.PolicyGeneration) {
		return out, false, errors.New("owned AMTD identity differs")
	}
	var typedAMTD amtdv1beta1.AdaptiveMovingTargetDefense
	if runtime.DefaultUnstructuredConverter.FromUnstructured(amtd.Object, &typedAMTD) != nil ||
		!reflect.DeepEqual(typedAMTD.Spec.PodSelector, map[string]string{"fixture.phorvex.ai/owner-nonce": r.Nonce, "fixture.phorvex.ai/role": "source"}) ||
		typedAMTD.Spec.MatcherMode != amtdv1beta1.MatcherModeExact || len(typedAMTD.Spec.Strategy) != 2 ||
		!reflect.DeepEqual(typedAMTD.Spec.Strategy[0].Rule, amtdv1beta1.Rule{Type: "phorvex.rotate", ThreatLevel: "high", Source: "PhorvexController"}) ||
		!reflect.DeepEqual(typedAMTD.Spec.Strategy[0].Action, amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}}) ||
		!reflect.DeepEqual(typedAMTD.Spec.Strategy[1].Rule, amtdv1beta1.Rule{Type: "phorvex.quarantine", ThreatLevel: "high", Source: "PhorvexController"}) ||
		!reflect.DeepEqual(typedAMTD.Spec.Strategy[1].Action, amtdv1beta1.AMTDAction{Quarantine: &amtdv1beta1.QuarantineAction{}}) {
		return out, false, errors.New("owned AMTD selector or strategy differs")
	}
	pod, err := kc.CoreV1().Pods(r.Namespace).Get(ctx, r.ClientPod, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return out, false, errors.New("quarantine source Pod absent; packet branch unobserved")
	}
	if err != nil {
		return out, false, err
	}
	phoenixName := amtdv1beta1.QuarantineNetworkPolicyName(r.Namespace, r.ClientPod)
	if string(pod.UID) != r.ClientPodUID || pod.DeletionTimestamp != nil ||
		len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].ContainerID != prior.client.Status.ContainerStatuses[0].ContainerID ||
		pod.Status.ContainerStatuses[0].RestartCount != 0 || !sameNATSImageDigest(pod.Status.ContainerStatuses[0].ImageID, prior.client.Status.ContainerStatuses[0].ImageID) ||
		len(pod.OwnerReferences) != 1 || !natsAMTDController(pod.OwnerReferences[0], amtdName, amtd.GetUID()) ||
		pod.Labels["amtd.r6security.com/network-policy"] != phoenixName {
		return out, false, nil
	}
	phoenixNP, err := kc.NetworkingV1().NetworkPolicies(r.Namespace).Get(ctx, phoenixName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if phoenixNP.UID == "" || phoenixNP.DeletionTimestamp != nil || len(phoenixNP.OwnerReferences) != 1 ||
		!natsAMTDController(phoenixNP.OwnerReferences[0], amtdName, amtd.GetUID()) ||
		len(phoenixNP.Spec.PodSelector.MatchLabels) != 1 || len(phoenixNP.Spec.PodSelector.MatchExpressions) != 0 || phoenixNP.Spec.PodSelector.MatchLabels["amtd.r6security.com/network-policy"] != phoenixName ||
		len(phoenixNP.Spec.Ingress) != 0 || len(phoenixNP.Spec.Egress) != 0 || !bothNPTypes(phoenixNP.Spec.PolicyTypes) {
		return out, false, errors.New("Phoenix quarantine policy ownership or deny-all shape differs")
	}
	peer, err := kc.CoreV1().Pods(r.Namespace).Get(ctx, prior.peer.Name, metav1.GetOptions{})
	if err != nil || string(peer.UID) != r.PeerPodUID || peer.DeletionTimestamp != nil || !podReady(peer) ||
		len(peer.Status.ContainerStatuses) != 1 || peer.Status.ContainerStatuses[0].ContainerID != prior.peer.Status.ContainerStatuses[0].ContainerID ||
		peer.Status.ContainerStatuses[0].RestartCount != 0 || !sameNATSImageDigest(peer.Status.ContainerStatuses[0].ImageID, prior.peer.Status.ContainerStatuses[0].ImageID) {
		return out, false, errors.New("legitimate peer incarnation changed")
	}
	if err := verifyNATSResponsePeerOwner(prior.client, *peer); err != nil {
		return out, false, err
	}
	if err := s.verifyNATSResponsePolicy(r); err != nil {
		return out, false, err
	}
	out = natsQuarantineEffect{GeneratedEventName: forensics.EventName, GeneratedEventUID: forensics.EventUID,
		OperationID: ann["phorvex.ai/quarantine-operation"], AMTDName: amtdName, AMTDUID: string(amtd.GetUID()),
		PhoenixNetworkPolicyName: phoenixName, PhoenixNetworkPolicyUID: string(phoenixNP.UID),
		SourcePodUID: r.ClientPodUID, PeerPodUID: r.PeerPodUID}
	return out, true, nil
}

func bothNPTypes(types []networkingv1.PolicyType) bool {
	return len(types) == 2 && ((types[0] == networkingv1.PolicyTypeIngress && types[1] == networkingv1.PolicyTypeEgress) ||
		(types[0] == networkingv1.PolicyTypeEgress && types[1] == networkingv1.PolicyTypeIngress))
}

func publishNATSResponseDecision(out string, d natsResponseDecision) error {
	if d.Schema != natsResponseSchema || d.RunID == "" || d.EventUID == "" || d.DecisionID == "" || d.EventCleanupStatus != "CONFIRMED_ABSENT" ||
		len(d.DecisionEvidenceSHA256) != 64 || !natsHex64.MatchString(d.DecisionEvidenceSHA256) ||
		!natsHex64.MatchString(d.PeerM0ReceiptSHA256) {
		return errors.New("response decision incomplete")
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > 4096 {
		return errors.New("response decision oversized")
	}
	return publishNATSOwnedFile(out, "nats-response-signal-decision.json", raw)
}

var natsHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func publishNATSOwnedFile(out, name string, raw []byte) error {
	if !regexp.MustCompile(`^nats-response-[a-z0-9-]+\.json$`).MatchString(name) {
		return errors.New("response output name invalid")
	}
	root, err := natsResponseRoot(out)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(name); err == nil {
		return errors.New("response output already published")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile(name+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = root.Link(name+".tmp", name); err != nil {
		return err
	}
	if err = root.Remove(name + ".tmp"); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type natsAuditCursor struct {
	segment   audittransport.Segment
	offset    int64
	pending   []byte
	readBytes int64
}

func (s *Server) startNATSAudit(ctx context.Context) (natsAuditCursor, error) {
	if s.cfg.AuditSource == nil {
		return natsAuditCursor{}, errors.New("authenticated manager audit source required")
	}
	m, err := s.cfg.AuditSource.Manifest(ctx)
	if err != nil || len(m.Segments) == 0 || m.Segments[0].ID != "live" {
		return natsAuditCursor{}, errors.New("manager audit manifest unavailable")
	}
	seg := m.Segments[0]
	if seg.Size > 0 {
		b, err := s.cfg.AuditSource.Chunk(ctx, seg, seg.Size-1)
		if err != nil || len(b) != 1 || b[0] != '\n' {
			return natsAuditCursor{}, errors.New("manager audit boundary is incomplete")
		}
	}
	return natsAuditCursor{segment: seg, offset: seg.Size}, nil
}

// Each poll reads only appended bytes from the same authenticated generation.
// A rotation or a gap makes the exact event decision UNKNOWN, never a tail guess.
func (s *Server) advanceNATSAudit(ctx context.Context, cursor *natsAuditCursor, eventName, eventUID, ns, pod, podUID, policyUID string) (*audit.Record, string, error) {
	m, err := s.cfg.AuditSource.Manifest(ctx)
	if err != nil || len(m.Segments) == 0 {
		return nil, "", errors.New("manager audit manifest unavailable")
	}
	seg := m.Segments[0]
	if seg.ID != "live" || seg.Generation != cursor.segment.Generation || seg.Anchor != cursor.segment.Anchor || seg.Size < cursor.offset || seg.Size-cursor.segment.Size > 64<<20 {
		return nil, "", errors.New("manager audit generation changed or window exceeded")
	}
	if seg.Size == cursor.offset {
		return nil, "", nil
	}
	reader := s.cfg.AuditSource.Open(ctx, seg)
	defer reader.Close()
	var found *audit.Record
	var foundSHA string
	for at := cursor.offset; at < seg.Size; {
		chunk := make([]byte, min(int64(1<<20), seg.Size-at))
		if _, err := reader.ReadAt(chunk, at); err != nil {
			return nil, "", errors.New("manager audit contiguous read failed")
		}
		at += int64(len(chunk))
		cursor.readBytes += int64(len(chunk))
		if cursor.readBytes > 64<<20 {
			return nil, "", errors.New("manager audit total window exceeded")
		}
		cursor.pending = append(cursor.pending, chunk...)
		for {
			i := bytes.IndexByte(cursor.pending, '\n')
			if i < 0 {
				break
			}
			line := cursor.pending[:i]
			if len(line) == 0 || len(line) > 4<<20 {
				return nil, "", errors.New("manager audit line invalid")
			}
			var envelope struct {
				Kind string `json:"kind"`
			}
			if json.Unmarshal(line, &envelope) != nil || envelope.Kind == "" {
				return nil, "", errors.New("manager audit row invalid")
			}
			if envelope.Kind == "phorvex.decision" && found == nil {
				var rec audit.Record
				if json.Unmarshal(line, &rec) == nil && rec.DecisionTrace != nil && rec.Namespace == ns && rec.Pod == pod &&
					rec.DecisionTrace.AssetUID == podUID && rec.DecisionTrace.PolicyUID == policyUID && rec.DecisionTrace.Validate() == nil {
					for _, ev := range rec.Events {
						if ev.Name == eventName && ev.EventUID == eventUID && ev.TargetPodUID == podUID && ev.TargetsPod && ev.TrustVerdict == "trusted" && ev.Type == "Panic" {
							traceRaw, err := json.Marshal(rec.DecisionTrace)
							if err != nil {
								return nil, "", err
							}
							found = &rec
							foundSHA = natsSHA(traceRaw)
							break
						}
					}
				}
			}
			cursor.pending = cursor.pending[i+1:]
		}
		if len(cursor.pending) > 4<<20 {
			return nil, "", errors.New("manager audit incomplete line exceeded bound")
		}
		cursor.pending = append([]byte(nil), cursor.pending...)
	}
	cursor.offset = seg.Size
	return found, foundSHA, nil
}

func (s *Server) verifyNATSManager(ctx context.Context, kc kubernetes.Interface, r natsResponseRequest, pin natsResponseConfigPin) error {
	dep, err := kc.AppsV1().Deployments(pin.Fixture.ManagerNamespace).Get(ctx, pin.Fixture.ManagerDeployment, metav1.GetOptions{})
	if err != nil || dep.UID == "" || dep.DeletionTimestamp != nil || dep.Spec.Selector == nil ||
		dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 || dep.Status.ObservedGeneration < dep.Generation || dep.Status.ReadyReplicas != 1 {
		return errors.New("manager Deployment unavailable")
	}
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || selector.Empty() {
		return errors.New("manager selector unavailable")
	}
	sets, err := kc.AppsV1().ReplicaSets(pin.Fixture.ManagerNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 20})
	if err != nil || sets.Continue != "" || sets.RemainingItemCount != nil {
		return errors.New("manager ReplicaSet inventory incomplete")
	}
	var active *appsv1.ReplicaSet
	for i := range sets.Items {
		rs := &sets.Items[i]
		if rs.Spec.Replicas == nil || *rs.Spec.Replicas == 0 {
			continue
		}
		if active != nil || *rs.Spec.Replicas != 1 || rs.Status.ReadyReplicas != 1 || rs.UID == "" || rs.DeletionTimestamp != nil || !selector.Matches(labels.Set(rs.Labels)) ||
			len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].APIVersion != "apps/v1" || rs.OwnerReferences[0].Kind != "Deployment" ||
			rs.OwnerReferences[0].Name != dep.Name || rs.OwnerReferences[0].UID != dep.UID ||
			rs.OwnerReferences[0].Controller == nil || !*rs.OwnerReferences[0].Controller {
			return errors.New("manager active ReplicaSet differs")
		}
		active = rs
	}
	if active == nil {
		return errors.New("manager active ReplicaSet absent")
	}
	pods, err := kc.CoreV1().Pods(pin.Fixture.ManagerNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 10})
	if err != nil || pods.Continue != "" || pods.RemainingItemCount != nil || len(pods.Items) != 1 {
		return errors.New("manager Pod inventory incomplete")
	}
	p := &pods.Items[0]
	if string(p.UID) != r.ManagerPodUID || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || !podReady(p) || !selector.Matches(labels.Set(p.Labels)) ||
		p.Labels["app.kubernetes.io/component"] != "manager" || len(p.OwnerReferences) != 1 ||
		p.OwnerReferences[0].APIVersion != "apps/v1" || p.OwnerReferences[0].Kind != "ReplicaSet" ||
		p.OwnerReferences[0].Name != active.Name || p.OwnerReferences[0].UID != active.UID ||
		p.OwnerReferences[0].Controller == nil || !*p.OwnerReferences[0].Controller ||
		len(p.Spec.Containers) != 1 || p.Spec.Containers[0].Name != "manager" ||
		len(p.Status.ContainerStatuses) != 1 || p.Status.ContainerStatuses[0].Name != "manager" ||
		!p.Status.ContainerStatuses[0].Ready || p.Status.ContainerStatuses[0].ContainerID != r.ManagerContainerID ||
		p.Status.ContainerStatuses[0].RestartCount != 0 || p.Status.ContainerStatuses[0].ImageID != pin.Fixture.ManagerImageID {
		return errors.New("manager Pod incarnation changed")
	}
	return nil
}

func (s *Server) coordinateNATSResponse(parent context.Context, id, out string) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	var r natsResponseRequest
	for {
		var err error
		r, err = readNATSResponseRequest(out, id)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("response request did not arrive within bound")
		case <-time.After(200 * time.Millisecond):
		}
	}
	if _, err := s.currentNATSResponseGrant(id); err != nil {
		return err
	}
	pin, err := s.natsResponseConfigPin(id)
	if err != nil || pin.Fixture.Nonce != r.Nonce {
		return errors.New("response source config changed")
	}
	s.runs.mu.Lock()
	status := s.runs.runs[id]
	contextMatches := status != nil && pin.Context != "" && pin.Context == status.ScopeTarget &&
		pin.Namespace == status.FixtureTenant && status.FixtureTenant == r.Namespace
	s.runs.mu.Unlock()
	if !contextMatches {
		return errors.New("response context or destination changed")
	}
	kc, err := natsResponseClient(s.cfg.ExperimentRESTConfig)
	if err != nil {
		return err
	}
	proof, err := s.verifyNATSResponseM0(ctx, kc, r, pin)
	if err != nil {
		return err
	}
	if err := verifyNATSResponsePeerM0(ctx, kc, r, proof); err != nil {
		return err
	}
	if err := s.verifyNATSManager(ctx, kc, r, pin); err != nil {
		return err
	}
	target, err := s.resolveScenarioExactTargetForTenant(r.Namespace, r.ClientPod, r.ClientPodUID, r.Nonce)
	if err != nil || target.policyName != r.PolicyName || target.policyUID != r.PolicyUID || target.policyGen != r.PolicyGeneration {
		return errors.New("response exact policy authority changed")
	}
	if err := s.verifyNATSResponsePolicy(r); err != nil {
		return err
	}
	if err := verifyNATSResponsePeerOwner(target.pod, proof.peer); err != nil {
		return err
	}
	cursor, err := s.startNATSAudit(ctx)
	if err != nil {
		return err
	}
	// No hint, forced action or browser-supplied event body is accepted. The
	// existing reviewed producer creates a target-UID-bound Panic signal once.
	candidate, err := s.prepareSecurityEventAt(r.ClientPodUID, "nats-response-"+r.Nonce, "Panic")
	if err != nil {
		return err
	}
	if _, err := s.currentNATSResponseGrant(id); err != nil {
		return err
	}
	if err := s.recheckScenarioExactTargetForTenant(r.Namespace, r.ClientPod, r.ClientPodUID, r.Nonce, target); err != nil {
		return err
	}
	if err := s.verifyNATSResponsePolicy(r); err != nil {
		return err
	}
	if err := s.verifyNATSManager(ctx, kc, r, pin); err != nil {
		return err
	}
	if err := verifyNATSResponsePeerM0(ctx, kc, r, proof); err != nil {
		return err
	}
	if err := s.persistCatalogueSignalIntent("/api/workload/fire-scenario", "nats-client-response", r.Namespace, natsResponseConfig, r.ClientPodUID, candidate); err != nil {
		return err
	}
	created, err := s.firePreparedSecurityEventAt(r.Namespace, r.ClientPod, "synthetic NATS client response observation", candidate)
	if err != nil {
		return err
	}
	accepted := s.cfg.now()
	base := defenseBaseline{uid: r.ClientPodUID, deploy: target.ownerName, ownerKind: target.ownerKind, ownerUID: target.ownerUID, uptime: -1,
		stimulus: created, outcomeClass: "behavioral-oracle-unsupported", producerRoute: "named-suite-nats-response", resultSchema: natsResponseSchema}
	attackID := s.startAttackRecordAtKind("", r.Namespace, r.Namespace, r.ClientPod, "NATS client response signal", natsResponseConfig, "T1565", "none", false, base, accepted, accepted.Add(75*time.Second), "synthetic-detector-signal", accepted)
	var decision *audit.Record
	var traceSHA string
	window, end := time.NewTicker(500*time.Millisecond), time.NewTimer(75*time.Second)
	defer window.Stop()
	defer end.Stop()
	for decision == nil {
		decision, traceSHA, err = s.advanceNATSAudit(ctx, &cursor, created.EventName, created.EventUID, r.Namespace, r.ClientPod, r.ClientPodUID, r.PolicyUID)
		if err != nil {
			return err
		}
		if decision != nil {
			break
		}
		select {
		case <-ctx.Done():
			return errors.New("response manager observation interrupted")
		case <-end.C:
			return errors.New("response exact event decision absent")
		case <-window.C:
		}
	}
	if decision.DecisionTrace == nil || decision.DecisionTrace.DecisionID == "" {
		return errors.New("response exact decision identity unavailable")
	}
	retainPartialWHY := func(effect *natsQuarantineEffect) {
		// Failure-only diagnostic publication. It is never the harness decision
		// barrier, and cannot release M1 without exact event cleanup.
		_, _ = publishNATSDecisionEvidence(out, r, decision, traceSHA, created, effect)
	}
	effectStatus := "NOT_DISPATCHED"
	var effect *natsQuarantineEffect
	switch {
	case decision.Action == string(model.ActionNoop) && !decision.Selected && !decision.Actuated && decision.DispatchOutcome == model.DispatchNotAttempted:
		// An exact no-op is an observed decision, not a response or defense.
	case decision.Action == "quarantine" && decision.Selected && decision.Actuated && decision.DispatchOutcome == model.DispatchEmitted:
		effectTimer, effectTick := time.NewTimer(60*time.Second), time.NewTicker(2*time.Second)
		defer effectTimer.Stop()
		defer effectTick.Stop()
		for {
			observed, ready, effectErr := s.natsQuarantineEffectOnce(ctx, kc, r, proof, decision)
			if effectErr != nil {
				retainPartialWHY(nil)
				return effectErr
			}
			if ready {
				effect = &observed
				effectStatus = "OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED"
				break
			}
			select {
			case <-ctx.Done():
				retainPartialWHY(nil)
				return errors.New("quarantine object effect observation interrupted")
			case <-effectTimer.C:
				retainPartialWHY(nil)
				return errors.New("quarantine object effect unconfirmed; event retained")
			case <-effectTick.C:
			}
		}
	default:
		retainPartialWHY(nil)
		return errors.New("response decision or dispatch is nonterminal; event retained")
	}
	if _, err := s.currentNATSResponseGrant(id); err != nil {
		retainPartialWHY(effect)
		return err
	}
	if err := s.verifyNATSManager(ctx, kc, r, pin); err != nil {
		retainPartialWHY(effect)
		return err
	}
	if err := s.verifyNATSResponsePolicy(r); err != nil {
		retainPartialWHY(effect)
		return err
	}
	evidenceSHA, err := publishNATSDecisionEvidence(out, r, decision, traceSHA, created, effect)
	if err != nil {
		return err
	}
	// The event may be removed only after its exact decision and, for selected
	// quarantine, the separately observed owned Kubernetes object effect.
	if err := s.cleanupNATSResponseEvent(ctx, kc, created, r); err != nil {
		return err
	}
	decisionWire := natsResponseDecision{Schema: natsResponseSchema, RunID: id, Nonce: r.Nonce, NamespaceUID: r.NamespaceUID,
		ClientPodUID: r.ClientPodUID, PeerPodUID: r.PeerPodUID, PolicyUID: r.PolicyUID, PolicyGeneration: r.PolicyGeneration,
		ManagerPodUID: r.ManagerPodUID, ManagerContainerID: r.ManagerContainerID, M0ReceiptSHA256: r.M0ReceiptSHA256,
		PeerM0ReceiptSHA256: r.PeerM0ReceiptSHA256,
		EventName:           created.EventName, EventUID: created.EventUID, AttackID: attackID,
		DecisionID: decision.DecisionTrace.DecisionID, DecisionTraceSHA256: traceSHA, DecisionEvidenceSHA256: evidenceSHA,
		SelectedAction: decision.Action, DispatchOutcome: decision.DispatchOutcome,
		EffectStatus: effectStatus, EventCleanupStatus: "CONFIRMED_ABSENT"}
	return publishNATSResponseDecision(out, decisionWire)
}

func (s *Server) cleanupNATSResponseEvent(ctx context.Context, kc kubernetes.Interface, created *attackStimulusEvidence, r natsResponseRequest) error {
	// The SecurityEvent is cluster-scoped; the only authorized delete is its
	// exact API UID after the event body is re-read through the dynamic client.
	cfg := s.cfg.ExperimentRESTConfig
	var err error
	if cfg == nil {
		cfg, err = restConfigFor("")
		if err != nil {
			return err
		}
	}
	d := dynamicExperimentCluster{cfg: cfg}
	dc, err := d.client()
	if err != nil {
		return err
	}
	u, err := dc.Resource(securityEventGVR).Get(ctx, created.EventName, metav1.GetOptions{})
	if err != nil || string(u.GetUID()) != created.EventUID || u.GetAnnotations()[model.ConsoleTargetPodUIDAnnotation] != r.ClientPodUID {
		return errors.New("response event identity changed before cleanup")
	}
	targets, _, err := unstructured.NestedStringSlice(u.Object, "spec", "targets")
	if err != nil || len(targets) != 1 || targets[0] != r.Namespace+"/"+r.ClientPod {
		return errors.New("response event target changed before cleanup")
	}
	uid := types.UID(created.EventUID)
	if err := dc.Resource(securityEventGVR).Delete(ctx, created.EventName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil {
		return errors.New("response exact event delete unconfirmed")
	}
	for i := 0; i < 10; i++ {
		_, err := dc.Resource(securityEventGVR).Get(ctx, created.EventName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return errors.New("response event absence unverified")
		}
		select {
		case <-ctx.Done():
			return errors.New("response event cleanup expired")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("response event remains after delete acknowledgement")
}

type NATSResponseResult struct {
	Accepted                  bool                  `json:"accepted"`
	CleanupVerified           bool                  `json:"cleanupVerified"`
	M0Status                  string                `json:"m0Status"`
	SignalStatus              string                `json:"signalStatus"`
	DecisionStatus            string                `json:"decisionStatus"`
	SelectedAction            string                `json:"selectedAction"`
	DispatchOutcome           string                `json:"dispatchOutcome"`
	EffectStatus              string                `json:"effectStatus"`
	M1Status                  string                `json:"m1Status"`
	PeerStatus                string                `json:"peerStatus"`
	CleanupStatus             string                `json:"cleanupStatus"`
	CapacityReservationStatus string                `json:"capacityReservationStatus"`
	Repeatability             string                `json:"repeatability"`
	SecurityEfficacy          string                `json:"securityEfficacy"`
	DecisionTrace             *natsDecisionEvidence `json:"decisionTrace,omitempty"`
	Issues                    []string              `json:"issues"`
}

type natsResultPod struct {
	Name        string `json:"name"`
	UID         string `json:"uid"`
	IP          string `json:"ip"`
	ContainerID string `json:"containerID"`
	ImageID     string `json:"imageID"`
}
type natsResultFixture struct {
	Name             string        `json:"name"`
	NamespaceUID     string        `json:"namespaceUID"`
	ConfigMapUID     string        `json:"configMapUID"`
	ConfigSHA256     string        `json:"configSHA256"`
	DeploymentUID    string        `json:"deploymentUID"`
	ReplicaSetUID    string        `json:"replicaSetUID"`
	ServiceUID       string        `json:"serviceUID"`
	PDBUID           string        `json:"pdbUID"`
	PolicyUID        string        `json:"policyUID"`
	PolicyGeneration int64         `json:"policyGeneration"`
	PolicySpecSHA256 string        `json:"policySpecSHA256"`
	Client           natsResultPod `json:"client"`
	Peer             natsResultPod `json:"peer"`
}
type natsResultProtocol struct {
	Stream                  string `json:"stream"`
	Subject                 string `json:"subject"`
	Consumer                string `json:"consumer"`
	Nonce                   string `json:"nonce"`
	WriterServerID          string `json:"writerServerID"`
	AdversaryServerID       string `json:"adversaryServerID"`
	SubscriptionFlushed     bool   `json:"subscriptionFlushed"`
	PayloadSHA256           string `json:"payloadSHA256"`
	PubAckSequence          uint64 `json:"pubAckSequence"`
	PublishAttempted        bool   `json:"publishAttempted"`
	LegitimateAcked         bool   `json:"legitimateAcked"`
	LegitimatePayloadSHA256 string `json:"legitimatePayloadSHA256"`
	StoredPayloadSHA256     string `json:"storedPayloadSHA256"`
	AdversaryPayloadSHA256  string `json:"adversaryPayloadSHA256"`
	AdversaryObservation    string `json:"adversaryObservation"`
	Objective               string `json:"objective"`
	Validity                string `json:"validity"`
	Cleanup                 string `json:"cleanup"`
	Phase                   string `json:"phase"`
}
type natsResultPhase struct {
	Stream        string                `json:"stream"`
	Subject       string                `json:"subject"`
	PayloadSHA256 string                `json:"payloadSHA256"`
	Protocol      natsResultProtocol    `json:"protocol"`
	Observer      []natsResponseReceipt `json:"observer"`
	PeerObserver  []natsResponseReceipt `json:"peerObserver"`
}
type natsResultServiceReceipt struct {
	AddressKind        string                    `json:"addressKind"`
	ServiceUID         string                    `json:"serviceUID"`
	PodUID             string                    `json:"podUID"`
	ServerID           string                    `json:"serverID"`
	Status             string                    `json:"status"`
	EndpointSliceUID   string                    `json:"endpointSliceUID,omitempty"`
	EndpointMemberUIDs []string                  `json:"endpointMemberUIDs,omitempty"`
	EndpointMembers    []natsResultServiceMember `json:"endpointMembers,omitempty"`
	ObservedAt         string                    `json:"observedAt"`
}
type natsResultServiceMember struct {
	PodUID       string `json:"podUID"`
	PodName      string `json:"podName"`
	PodIP        string `json:"podIP"`
	OwnerKind    string `json:"ownerKind"`
	OwnerUID     string `json:"ownerUID"`
	ContainerID  string `json:"containerID"`
	ImageID      string `json:"imageID"`
	Ready        bool   `json:"ready"`
	RestartCount int32  `json:"restartCount"`
}
type natsResponseArtifact struct {
	Schema                    string                   `json:"schema"`
	RunID                     string                   `json:"runId"`
	Nonce                     string                   `json:"nonce"`
	Namespace                 string                   `json:"namespace"`
	NamespaceUID              string                   `json:"namespaceUID"`
	ClusterUID                string                   `json:"clusterUID"`
	Fixture                   natsResultFixture        `json:"fixture"`
	Route                     json.RawMessage          `json:"route"`
	ManagerPodUID             string                   `json:"managerPodUID"`
	ManagerContainerID        string                   `json:"managerContainerID"`
	ManagerImageID            string                   `json:"managerImageID"`
	M0                        natsResultPhase          `json:"m0"`
	SignalRequestSHA256       string                   `json:"signalRequestSHA256"`
	Decision                  *natsResponseDecision    `json:"decision,omitempty"`
	M1                        natsResultPhase          `json:"m1"`
	ServiceBefore             natsResultServiceReceipt `json:"serviceBefore"`
	PeerBefore                natsResultServiceReceipt `json:"peerBefore"`
	ServiceAfter              natsResultServiceReceipt `json:"serviceAfter"`
	PeerAfter                 natsResultServiceReceipt `json:"peerAfter"`
	InitialDisclosure         string                   `json:"initialDisclosure"`
	OngoingAccess             string                   `json:"ongoingAccess"`
	LegitimateService         string                   `json:"legitimateService"`
	SecurityOutcome           string                   `json:"securityOutcome"`
	Validity                  string                   `json:"validity"`
	Cleanup                   string                   `json:"cleanup"`
	CapacityReservationStatus string                   `json:"capacityReservationStatus"`
	Repeatability             string                   `json:"repeatability"`
	ObservedAt                string                   `json:"observedAt"`
}
type natsResultCleanupChecks struct {
	NamespacePreserved    bool `json:"namespacePreserved"`
	ConfigMapAbsent       bool `json:"configMapAbsent"`
	DeploymentAbsent      bool `json:"deploymentAbsent"`
	ReplicaSetAbsent      bool `json:"replicaSetAbsent"`
	ServiceAbsent         bool `json:"serviceAbsent"`
	PDBAbsent             bool `json:"pdbAbsent"`
	PolicyAbsent          bool `json:"policyAbsent"`
	OriginalPodsAbsent    bool `json:"originalPodsAbsent"`
	StreamsAbsent         bool `json:"streamsAbsent"`
	SecurityEventAbsent   bool `json:"securityEventAbsent"`
	PhoenixChildrenAbsent bool `json:"phoenixChildrenAbsent"`
}

func (c natsResultCleanupChecks) all() bool {
	return c.NamespacePreserved && c.ConfigMapAbsent && c.DeploymentAbsent && c.ReplicaSetAbsent && c.ServiceAbsent && c.PDBAbsent && c.PolicyAbsent && c.OriginalPodsAbsent && c.StreamsAbsent && c.SecurityEventAbsent && c.PhoenixChildrenAbsent
}

type natsResponseTerminal struct {
	Schema                    string                  `json:"schema"`
	RunID                     string                  `json:"runId"`
	Nonce                     string                  `json:"nonce"`
	NamespaceUID              string                  `json:"namespaceUID"`
	ArtifactSHA256            string                  `json:"artifactSHA256"`
	Cleanup                   string                  `json:"cleanup"`
	CapacityReservationStatus string                  `json:"capacityReservationStatus"`
	Repeatability             string                  `json:"repeatability"`
	Checks                    natsResultCleanupChecks `json:"checks"`
	ObservedAt                string                  `json:"observedAt"`
}

var natsResponseArtifactKeys = map[string]bool{"schema": true, "runId": true, "nonce": true, "namespace": true, "namespaceUID": true, "clusterUID": true, "fixture": true, "route": true, "managerPodUID": true, "managerContainerID": true, "managerImageID": true, "m0": true, "signalRequestSHA256": true, "decision": true, "m1": true, "serviceBefore": true, "peerBefore": true, "serviceAfter": true, "peerAfter": true, "initialDisclosure": true, "ongoingAccess": true, "legitimateService": true, "securityOutcome": true, "validity": true, "cleanup": true, "capacityReservationStatus": true, "repeatability": true, "observedAt": true}
var natsResponseTerminalKeys = map[string]bool{"schema": true, "runId": true, "nonce": true, "namespaceUID": true, "artifactSHA256": true, "cleanup": true, "capacityReservationStatus": true, "repeatability": true, "checks": true, "observedAt": true}

func decodeNATSResult(raw []byte, keys map[string]bool, out any) error {
	if err := rejectNATSNestedDuplicates(raw); err != nil {
		return err
	}
	if err := strictNATSResponseJSON(raw, keys); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("response result trailing data")
	}
	return nil
}

func rejectNATSNestedDuplicates(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("response JSON nesting exceeded")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyTok, err := d.Token()
				key, ok := keyTok.(string)
				if err != nil || !ok || seen[key] {
					return errors.New("response JSON key ambiguous")
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("response JSON object incomplete")
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("response JSON array incomplete")
			}
		default:
			return errors.New("response JSON delimiter invalid")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("response JSON trailing data")
	}
	return nil
}

func natsResultServiceGood(x natsResultServiceReceipt, kind, serviceUID, podUID string, serverIDs map[string]bool) bool {
	if x.AddressKind != kind || x.ServiceUID != serviceUID || x.PodUID != podUID || x.Status != "HTTP_200" || !serverIDs[x.ServerID] {
		return false
	}
	if kind == "SERVICE" {
		if x.EndpointSliceUID == "" || len(x.EndpointMemberUIDs) < 1 || len(x.EndpointMemberUIDs) > 3 ||
			!sort.StringsAreSorted(x.EndpointMemberUIDs) {
			return false
		}
		found := false
		for i, uid := range x.EndpointMemberUIDs {
			if uid == "" || (i > 0 && uid == x.EndpointMemberUIDs[i-1]) {
				return false
			}
			found = found || uid == podUID
		}
		if !found {
			return false
		}
	} else if x.EndpointSliceUID != "" || len(x.EndpointMemberUIDs) != 0 || len(x.EndpointMembers) != 0 {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, x.ObservedAt)
	return err == nil
}

func natsServiceReceiptOwned(x natsResultServiceReceipt, a natsResponseArtifact, r natsResponseRequest,
	before bool, effect *natsQuarantineEffect) bool {
	if len(x.EndpointMembers) != len(x.EndpointMemberUIDs) || len(x.EndpointMembers) < 1 || len(x.EndpointMembers) > 2 {
		return false
	}
	seenSource, seenPeer, seenReplacement := false, false, false
	for i, m := range x.EndpointMembers {
		if m.PodUID == "" || m.PodUID != x.EndpointMemberUIDs[i] || m.PodName == "" || net.ParseIP(m.PodIP) == nil ||
			m.ContainerID == "" || m.ImageID == "" || !m.Ready || m.RestartCount != 0 {
			return false
		}
		switch m.PodUID {
		case r.ClientPodUID:
			seenSource = true
			if m.PodName != a.Fixture.Client.Name || m.PodIP != a.Fixture.Client.IP ||
				m.ContainerID != a.Fixture.Client.ContainerID || m.ImageID != a.Fixture.Client.ImageID {
				return false
			}
			if before || effect == nil {
				if m.OwnerKind != "ReplicaSet" || m.OwnerUID != a.Fixture.ReplicaSetUID {
					return false
				}
			} else if m.OwnerKind != "AdaptiveMovingTargetDefense" || m.OwnerUID != effect.AMTDUID {
				return false
			}
		case r.PeerPodUID:
			seenPeer = true
			if m.PodName != a.Fixture.Peer.Name || m.PodIP != a.Fixture.Peer.IP ||
				m.ContainerID != a.Fixture.Peer.ContainerID || m.ImageID != a.Fixture.Peer.ImageID ||
				m.OwnerKind != "ReplicaSet" || m.OwnerUID != a.Fixture.ReplicaSetUID {
				return false
			}
		default:
			if before || effect == nil || seenReplacement || !strings.HasPrefix(m.PodName, a.Fixture.Name+"-") ||
				m.PodIP == a.Fixture.Client.IP || m.PodIP == a.Fixture.Peer.IP ||
				m.ContainerID == a.Fixture.Client.ContainerID || m.ContainerID == a.Fixture.Peer.ContainerID ||
				m.ImageID != a.Fixture.Client.ImageID || m.OwnerKind != "ReplicaSet" || m.OwnerUID != a.Fixture.ReplicaSetUID {
				return false
			}
			seenReplacement = true
		}
	}
	if !seenPeer || (before && !seenSource) || (seenSource && seenReplacement) {
		return false
	}
	return true
}

// A stopped run can retain a server-written decision projection even when the
// harness never reaches M1 or terminal cleanup. This is a diagnostic only:
// the local file cannot replace the exact decision barrier and terminal join.
func projectNATSPartialWHY(out, id, ns, nonce, namespaceUID string, result NATSResponseResult) NATSResponseResult {
	r, err := readNATSResponseRequest(out, id)
	if err != nil || r.Namespace != ns || r.Nonce != nonce || r.NamespaceUID != namespaceUID {
		return result
	}
	raw, err := readNATSResponseSizedFile(out, "nats-response-decision-evidence.json", 32<<10)
	if err != nil || rejectNATSNestedDuplicates(raw) != nil {
		return result
	}
	var why natsDecisionEvidence
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&why) != nil || d.Decode(new(any)) != io.EOF ||
		why.Schema != "nats-client-response-decision-evidence-v1" || why.RunID != id ||
		why.NamespaceUID != r.NamespaceUID || why.ClientPodUID != r.ClientPodUID ||
		why.PolicyUID != r.PolicyUID || why.PolicyGeneration != r.PolicyGeneration ||
		why.ManagerPodUID != r.ManagerPodUID || why.ManagerContainerID != r.ManagerContainerID ||
		why.M0ReceiptSHA256 != r.M0ReceiptSHA256 || why.PeerM0ReceiptSHA256 != r.PeerM0ReceiptSHA256 || why.EventName == "" || why.EventUID == "" ||
		why.DecisionID == "" || !natsHex64.MatchString(why.DecisionTraceSHA256) ||
		!natsHex64.MatchString(why.BrainImageSHA256) || len(why.Facts) > 32 || len(why.Candidates) > 32 ||
		!natsDecisionVocabularyValid(why.ActionVocabularyVersion, why.ActionStatus, why.Candidates, why.SelectedAction) ||
		why.Claim != "OBJECT_EFFECT_AND_PACKET_OUTCOME_SEPARATE_SECURITY_NOT_EVALUATED" {
		return result
	}
	// Only closed, already-sanitized text can enter the public projection.
	for _, field := range []string{why.BrainImage, why.GitSHA, why.InputPhase, why.InputStage,
		why.SelectedAction, why.NoopReason, why.DispatchOutcome, why.DispatchReason} {
		if field != "[REDACTED_OR_UNAVAILABLE]" && safeNATSWhy(field) != field {
			return result
		}
	}
	for _, f := range why.Facts {
		if safeNATSWhy(f.Type) != f.Type || safeNATSWhy(f.Source) != f.Source || math.IsNaN(f.Weight) || math.IsInf(f.Weight, 0) {
			return result
		}
	}
	for _, c := range why.Candidates {
		if safeNATSWhy(c.Action) != c.Action || safeNATSWhy(c.Exclusion) != c.Exclusion {
			return result
		}
	}
	for _, a := range why.ActionStatus {
		if safeNATSWhy(a.Action) != a.Action || safeNATSWhy(a.Status) != a.Status ||
			safeNATSWhy(a.ExclusionKind) != a.ExclusionKind || safeNATSWhy(a.Reason) != a.Reason {
			return result
		}
	}
	if why.ObjectEffect != nil && !natsQuarantineEffectMatches(why.ObjectEffect, r) {
		return result
	}
	result.DecisionTrace = &why
	result.DecisionStatus = "RUN_OWNED_WHY_BARRIER_UNVERIFIED"
	result.SelectedAction = why.SelectedAction
	result.DispatchOutcome = why.DispatchOutcome
	result.Issues = append(result.Issues, "Run-owned decision projection retained; exact terminal barrier unverified")
	return result
}

func readNATSResponseResult(out, id, ns string) (NATSResponseResult, error) {
	result := NATSResponseResult{M0Status: "UNKNOWN", SignalStatus: "UNKNOWN", DecisionStatus: "UNKNOWN", M1Status: "UNKNOWN", PeerStatus: "UNKNOWN", CleanupStatus: "UNVERIFIED", CapacityReservationStatus: "UNKNOWN", Repeatability: "UNKNOWN", SecurityEfficacy: "NOT_EVALUATED", Issues: []string{}}
	artifactRaw, err := readNATSResponseSizedFile(out, "nats-response.json", 64<<10)
	if err != nil {
		return result, errors.New("response artifact missing or unsafe")
	}
	terminalRaw, err := readNATSResponseFile(out, "nats-response-terminal.json")
	if err != nil {
		return result, errors.New("response terminal receipt missing or unsafe")
	}
	var a natsResponseArtifact
	keys := natsResponseArtifactKeys
	var probe map[string]json.RawMessage
	if json.Unmarshal(artifactRaw, &probe) != nil {
		return result, errors.New("response artifact malformed")
	}
	if _, ok := probe["decision"]; !ok {
		keys = make(map[string]bool, len(natsResponseArtifactKeys)-1)
		for k, v := range natsResponseArtifactKeys {
			if k != "decision" {
				keys[k] = v
			}
		}
	}
	if decodeNATSResult(artifactRaw, keys, &a) != nil {
		return result, errors.New("response artifact schema ambiguous")
	}
	var term natsResponseTerminal
	if decodeNATSResult(terminalRaw, natsResponseTerminalKeys, &term) != nil {
		return result, errors.New("response terminal schema ambiguous")
	}
	if a.Schema != "nats-client-response-artifact-v1" || term.Schema != "nats-client-response-terminal-v1" ||
		a.RunID != id || term.RunID != id || a.Namespace != ns || ns != natsFixtureNamespace ||
		a.Nonce == "" || term.Nonce != a.Nonce || a.NamespaceUID == "" || term.NamespaceUID != a.NamespaceUID ||
		a.ClusterUID == "" || !natsHex64.MatchString(term.ArtifactSHA256) || term.ArtifactSHA256 != natsSHA(artifactRaw) ||
		a.Cleanup != term.Cleanup || a.CapacityReservationStatus != term.CapacityReservationStatus || a.Repeatability != term.Repeatability ||
		!((a.CapacityReservationStatus == "UNRECONCILED_POSSIBLE" && a.Repeatability == "UNKNOWN") ||
			(a.CapacityReservationStatus == "NOT_APPLICABLE" && a.Repeatability == "NOT_EVALUATED") ||
			(a.CapacityReservationStatus == "UNKNOWN" && a.Repeatability == "UNKNOWN")) ||
		(term.Cleanup == "CONFIRMED_ABSENT") != term.Checks.all() {
		return result, errors.New("response artifact or cleanup identity differs")
	}
	if _, err := time.Parse(time.RFC3339Nano, a.ObservedAt); err != nil {
		return result, errors.New("response observation time invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, term.ObservedAt); err != nil {
		return result, errors.New("response terminal time invalid")
	}
	result.CleanupVerified = term.Cleanup == "CONFIRMED_ABSENT" && term.Checks.all()
	result.CleanupStatus = term.Cleanup
	result.CapacityReservationStatus = term.CapacityReservationStatus
	result.Repeatability = term.Repeatability
	if a.Decision == nil || a.Validity != "MEASUREMENT_COMPLETE" || !result.CleanupVerified {
		result = projectNATSPartialWHY(out, id, ns, a.Nonce, a.NamespaceUID, result)
		result.Issues = append(result.Issues, "Exact response measurement or owned cleanup incomplete")
		return result, nil
	}
	if a.Fixture.NamespaceUID != a.NamespaceUID || a.Fixture.Name != "nats-response-"+a.Nonce ||
		a.Fixture.PolicyUID == "" || a.Fixture.PolicyGeneration < 1 || !natsHex64.MatchString(a.Fixture.PolicySpecSHA256) ||
		a.Fixture.Client.Name == "" || a.Fixture.Client.UID == "" || a.Fixture.Peer.UID == "" ||
		a.Fixture.Client.UID == a.Fixture.Peer.UID || a.ManagerPodUID == "" || a.ManagerContainerID == "" || a.ManagerImageID == "" ||
		len(a.Route) < 2 || !natsHex64.MatchString(a.SignalRequestSHA256) {
		return result, errors.New("response complete artifact identity differs")
	}
	requestRaw, err := readNATSResponseFile(out, "nats-response-signal-request.json")
	if err != nil || natsSHA(requestRaw) != a.SignalRequestSHA256 {
		return result, errors.New("response request digest differs")
	}
	r, err := readNATSResponseRequest(out, id)
	if err != nil || r.Nonce != a.Nonce || r.NamespaceUID != a.NamespaceUID || r.ClientPod != a.Fixture.Client.Name || r.ClientPodUID != a.Fixture.Client.UID ||
		r.PeerPodUID != a.Fixture.Peer.UID || r.PolicyUID != a.Fixture.PolicyUID || r.PolicyGeneration != a.Fixture.PolicyGeneration ||
		r.ManagerPodUID != a.ManagerPodUID || r.ManagerContainerID != a.ManagerContainerID {
		return result, errors.New("response request authority differs")
	}
	decisionRaw, err := readNATSResponseFile(out, "nats-response-signal-decision.json")
	if err != nil {
		return result, errors.New("response decision barrier missing")
	}
	var d natsResponseDecision
	decisionKeys := map[string]bool{"schema": true, "runId": true, "nonce": true, "namespaceUID": true, "clientPodUID": true, "peerPodUID": true, "policyUID": true, "policyGeneration": true, "managerPodUID": true, "managerContainerID": true, "m0ReceiptSHA256": true, "peerM0ReceiptSHA256": true, "eventName": true, "eventUID": true, "attackId": true, "decisionId": true, "decisionTraceSHA256": true, "decisionEvidenceSHA256": true, "selectedAction": true, "dispatchOutcome": true, "effectStatus": true, "eventCleanupStatus": true}
	if decodeNATSResult(decisionRaw, decisionKeys, &d) != nil || !reflect.DeepEqual(&d, a.Decision) ||
		d.Schema != natsResponseSchema || d.RunID != id || d.Nonce != r.Nonce || d.NamespaceUID != r.NamespaceUID ||
		d.ClientPodUID != r.ClientPodUID || d.PeerPodUID != r.PeerPodUID || d.PolicyUID != r.PolicyUID || d.PolicyGeneration != r.PolicyGeneration ||
		d.ManagerPodUID != r.ManagerPodUID || d.ManagerContainerID != r.ManagerContainerID || d.M0ReceiptSHA256 != r.M0ReceiptSHA256 ||
		d.PeerM0ReceiptSHA256 != r.PeerM0ReceiptSHA256 ||
		d.EventCleanupStatus != "CONFIRMED_ABSENT" || !natsHex64.MatchString(d.DecisionTraceSHA256) || !natsHex64.MatchString(d.DecisionEvidenceSHA256) {
		return result, errors.New("response decision exact joins differ")
	}
	if !((d.SelectedAction == "noop" && d.DispatchOutcome == model.DispatchNotAttempted && d.EffectStatus == "NOT_DISPATCHED") ||
		(d.SelectedAction == "quarantine" && d.DispatchOutcome == model.DispatchEmitted && d.EffectStatus == "OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED")) {
		return result, errors.New("response decision outside terminal barrier")
	}
	if (d.SelectedAction == "noop" && a.CapacityReservationStatus != "NOT_APPLICABLE") ||
		(d.SelectedAction == "quarantine" && a.CapacityReservationStatus != "UNRECONCILED_POSSIBLE") {
		return result, errors.New("response protected-capacity debt differs")
	}
	evidenceRaw, err := readNATSResponseSizedFile(out, "nats-response-decision-evidence.json", 32<<10)
	if err != nil || natsSHA(evidenceRaw) != d.DecisionEvidenceSHA256 {
		return result, errors.New("response decision evidence digest differs")
	}
	var why natsDecisionEvidence
	if rejectNATSNestedDuplicates(evidenceRaw) != nil || json.Unmarshal(evidenceRaw, &why) != nil || why.Schema != "nats-client-response-decision-evidence-v1" ||
		why.RunID != id || why.NamespaceUID != r.NamespaceUID || why.ClientPodUID != r.ClientPodUID || why.PolicyUID != r.PolicyUID ||
		why.PolicyGeneration != r.PolicyGeneration || why.ManagerPodUID != r.ManagerPodUID || why.ManagerContainerID != r.ManagerContainerID ||
		why.M0ReceiptSHA256 != r.M0ReceiptSHA256 || why.PeerM0ReceiptSHA256 != r.PeerM0ReceiptSHA256 || why.EventName != d.EventName || why.EventUID != d.EventUID ||
		why.DecisionID != d.DecisionID || why.DecisionTraceSHA256 != d.DecisionTraceSHA256 || why.SelectedAction != d.SelectedAction ||
		why.DispatchOutcome != d.DispatchOutcome || !natsHex64.MatchString(why.BrainImageSHA256) || why.Claim != "OBJECT_EFFECT_AND_PACKET_OUTCOME_SEPARATE_SECURITY_NOT_EVALUATED" ||
		len(why.Facts) > 32 || len(why.Candidates) > 32 || !natsDecisionVocabularyValid(why.ActionVocabularyVersion, why.ActionStatus, why.Candidates, why.SelectedAction) ||
		(d.SelectedAction == "quarantine") != (why.ObjectEffect != nil) {
		return result, errors.New("response decision WHY differs")
	}
	if e := why.ObjectEffect; e != nil {
		if !natsQuarantineEffectMatches(e, r) {
			return result, errors.New("response owned object-effect identity differs")
		}
	}
	if a.InitialDisclosure != "EXPOSED" || a.LegitimateService != "AVAILABLE" || a.OngoingAccess != "CONTINUING_EXPOSURE" ||
		len(a.M0.Observer) != 3 || len(a.M1.Observer) != 4 || len(a.M0.PeerObserver) != 3 || len(a.M1.PeerObserver) != 4 ||
		a.M0.Observer[2].Status != "EXACT_PAYLOAD_RECEIVED" || a.M0.PeerObserver[2].Status != "EXACT_PAYLOAD_RECEIVED" ||
		a.M1.Observer[3].Status != "EXACT_PAYLOAD_RECEIVED" || a.M0.Observer[2].PodUID != r.ClientPodUID ||
		a.M1.PeerObserver[3].Status != "EXACT_PAYLOAD_RECEIVED" || a.M1.Observer[3].PodUID != r.ClientPodUID ||
		a.M0.PeerObserver[2].PodUID != r.PeerPodUID || a.M1.PeerObserver[3].PodUID != r.PeerPodUID ||
		a.M0.Protocol.PubAckSequence != 1 || a.M1.Protocol.PubAckSequence != 1 ||
		!a.M0.Protocol.SubscriptionFlushed || !a.M1.Protocol.SubscriptionFlushed ||
		!a.M0.Protocol.PublishAttempted || !a.M1.Protocol.PublishAttempted || !a.M0.Protocol.LegitimateAcked || !a.M1.Protocol.LegitimateAcked {
		return result, errors.New("response packet or legitimate control incomplete")
	}
	wantM0Subject, wantM1Subject := "cat.response."+a.Nonce+".m0", "cat.response."+a.Nonce+".m1"
	wantM0Payload, wantM1Payload := natsSHA([]byte("phorvex-owned-nats-response:"+a.Nonce+":M0")), natsSHA([]byte("phorvex-owned-nats-response:"+a.Nonce+":M1"))
	if a.M0.Stream == "" || a.M1.Stream == "" || a.M0.Stream == a.M1.Stream ||
		a.M0.Subject != wantM0Subject || a.M1.Subject != wantM1Subject ||
		a.M0.PayloadSHA256 != wantM0Payload || a.M1.PayloadSHA256 != wantM1Payload ||
		a.M0.Protocol.Stream != a.M0.Stream || a.M1.Protocol.Stream != a.M1.Stream ||
		a.M0.Protocol.Subject != wantM0Subject || a.M1.Protocol.Subject != wantM1Subject ||
		a.M0.Protocol.Nonce != a.Nonce || a.M1.Protocol.Nonce != a.Nonce ||
		a.M0.Protocol.PayloadSHA256 != wantM0Payload || a.M1.Protocol.PayloadSHA256 != wantM1Payload ||
		a.M0.Protocol.LegitimatePayloadSHA256 != wantM0Payload || a.M1.Protocol.LegitimatePayloadSHA256 != wantM1Payload ||
		a.M0.Protocol.StoredPayloadSHA256 != wantM0Payload || a.M1.Protocol.StoredPayloadSHA256 != wantM1Payload ||
		a.M0.Protocol.AdversaryPayloadSHA256 != wantM0Payload || a.M1.Protocol.AdversaryPayloadSHA256 != wantM1Payload ||
		a.M0.Protocol.AdversaryObservation != "EXACT_PAYLOAD_RECEIVED" || a.M1.Protocol.AdversaryObservation != "EXACT_PAYLOAD_RECEIVED" ||
		a.M0.Protocol.Objective != "REACHED" || a.M1.Protocol.Objective != "REACHED" ||
		a.M0.Protocol.Validity != "VALID" || a.M1.Protocol.Validity != "VALID" ||
		a.M0.Protocol.Cleanup != "CONFIRMED_ABSENT" || a.M1.Protocol.Cleanup != "CONFIRMED_ABSENT" ||
		a.M0.Observer[2].PayloadSHA256 != wantM0Payload || a.M1.Observer[3].PayloadSHA256 != wantM1Payload ||
		a.M0.PeerObserver[2].PayloadSHA256 != wantM0Payload || a.M1.PeerObserver[3].PayloadSHA256 != wantM1Payload {
		return result, errors.New("response subject or synthetic payload differs")
	}
	var route struct {
		ClusterUID string `json:"clusterUID"`
		Brokers    []struct {
			ServerID string `json:"serverID"`
		} `json:"brokers"`
	}
	if json.Unmarshal(a.Route, &route) != nil || route.ClusterUID != a.ClusterUID || len(route.Brokers) < 1 || len(route.Brokers) > 3 {
		return result, errors.New("response broker route differs")
	}
	serverIDs := map[string]bool{}
	serverList := make([]string, 0, len(route.Brokers))
	for _, b := range route.Brokers {
		if b.ServerID == "" || serverIDs[b.ServerID] {
			return result, errors.New("response broker identity ambiguous")
		}
		serverIDs[b.ServerID] = true
		serverList = append(serverList, b.ServerID)
	}
	peerRequest := r
	peerRequest.ClientPodUID = r.PeerPodUID
	if !natsM0PrefixJoined(out, "nats-response-m0-prefix.jsonl", r.M0ReceiptSHA256, r,
		[]string{wantM0Subject, wantM1Subject}, []string{wantM0Payload, wantM1Payload}, serverList, a.M0.Observer) ||
		!natsM0PrefixJoined(out, "nats-response-peer-m0-prefix.jsonl", r.PeerM0ReceiptSHA256, peerRequest,
			[]string{wantM0Subject, wantM1Subject}, []string{wantM0Payload, wantM1Payload}, serverList, a.M0.PeerObserver) {
		return result, errors.New("response original source or peer M0 prefix differs")
	}
	if !natsObservedM1Joined(a.M0.Observer, a.M1.Observer, r, wantM1Subject, wantM1Payload, serverIDs) ||
		!natsObservedM1Joined(a.M0.PeerObserver, a.M1.PeerObserver, peerRequest, wantM1Subject, wantM1Payload, serverIDs) {
		return result, errors.New("response original source or peer M1 receipt differs")
	}
	if a.M0.Protocol.Phase != "M0" || a.M1.Protocol.Phase != "M1" ||
		a.M0.Protocol.Consumer == "" || a.M1.Protocol.Consumer == "" ||
		!strings.Contains(a.M0.Protocol.Consumer, a.Nonce) || !strings.Contains(a.M1.Protocol.Consumer, a.Nonce) ||
		a.M0.Protocol.Consumer == a.M1.Protocol.Consumer ||
		!serverIDs[a.M0.Protocol.WriterServerID] || !serverIDs[a.M1.Protocol.WriterServerID] ||
		!serverIDs[a.M0.Protocol.AdversaryServerID] || !serverIDs[a.M1.Protocol.AdversaryServerID] {
		return result, errors.New("response local actor or broker identity differs")
	}
	if !natsResultServiceGood(a.PeerBefore, "PEER_DIRECT", a.Fixture.ServiceUID, r.PeerPodUID, serverIDs) ||
		!natsResultServiceGood(a.PeerAfter, "PEER_DIRECT", a.Fixture.ServiceUID, r.PeerPodUID, serverIDs) ||
		!natsResultServiceGood(a.ServiceAfter, "SERVICE", a.Fixture.ServiceUID, a.ServiceAfter.PodUID, serverIDs) ||
		!natsResultServiceGood(a.ServiceBefore, "SERVICE", a.Fixture.ServiceUID, a.ServiceBefore.PodUID, serverIDs) ||
		!natsServiceReceiptOwned(a.ServiceBefore, a, r, true, nil) ||
		!natsServiceReceiptOwned(a.ServiceAfter, a, r, false, why.ObjectEffect) {
		return result, errors.New("response exact legitimate HTTP route unavailable")
	}
	if a.SecurityOutcome == "CONTAINMENT_NOT_ACHIEVED" {
		if d.SelectedAction != "quarantine" {
			return result, errors.New("negative security conclusion lacks selected response")
		}
		result.SecurityEfficacy = "CONTAINMENT_NOT_ACHIEVED"
	} else if a.SecurityOutcome != "NOT_EVALUATED" {
		return result, errors.New("response security outcome invalid")
	}
	result.SignalStatus = "TRUSTED_EVENT_OBSERVED"
	result.DecisionStatus = "EXACT_DECISION_OBSERVED"
	result.M0Status = "EXPOSED"
	result.M1Status = "CONTINUING_EXPOSURE"
	result.PeerStatus = "AVAILABLE"
	result.SelectedAction = d.SelectedAction
	result.DispatchOutcome = d.DispatchOutcome
	result.EffectStatus = d.EffectStatus
	result.DecisionTrace = &why
	result.Accepted = true
	return result, nil
}

func natsServiceMembersOwned(members []string, sourceUID, peerUID string) bool {
	peerPresent := false
	for _, uid := range members {
		if uid != sourceUID && uid != peerUID {
			return false
		}
		peerPresent = peerPresent || uid == peerUID
	}
	return peerPresent
}

func natsM0PrefixJoined(out, filename, expectedSHA string, r natsResponseRequest,
	subjects, digests, servers []string, artifactRows []natsResponseReceipt) bool {
	raw, err := readNATSResponseSizedFile(out, filename, 4096)
	if err != nil || natsSHA(raw) != expectedSHA || validateNATSResponseM0(raw, r, subjects, digests, servers) != nil {
		return false
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 3 || len(artifactRows) != 3 {
		return false
	}
	for i, line := range lines {
		var observed natsResponseReceipt
		if json.Unmarshal(line, &observed) != nil || !reflect.DeepEqual(observed, artifactRows[i]) {
			return false
		}
	}
	return true
}

func natsObservedM1Joined(m0, m1 []natsResponseReceipt, r natsResponseRequest, subject, digest string, servers map[string]bool) bool {
	if len(m0) != 3 || len(m1) != 4 || !reflect.DeepEqual(m0, m1[:3]) {
		return false
	}
	last := m1[3]
	return last.Kind == "observation" && last.Phase == "M1" && last.Status == "EXACT_PAYLOAD_RECEIVED" &&
		last.Subject == subject && last.Nonce == r.Nonce && last.PodUID == r.ClientPodUID && servers[last.ServerID] &&
		last.ServerID == m0[0].ServerID && !last.Flushed && last.PayloadBytes > 0 && last.PayloadBytes <= 256 &&
		last.PayloadSHA256 == digest && last.NonceHeaderMatches && last.PayloadHashMatches
}

func (rm *RunManager) NATSResponseResult(id string) (*NATSResponseResult, error) {
	rm.mu.Lock()
	st := rm.runs[id]
	out := rm.runOut[id]
	if st == nil || st.Config != natsResponseConfig {
		rm.mu.Unlock()
		return nil, nil
	}
	ns, state := st.Namespace, st.State
	rm.mu.Unlock()
	if state != "done" && state != "partial" && state != "error" && state != "stopped" {
		return nil, errors.New("response run has no terminal result yet")
	}
	if out == "" || strings.Contains(out, "..") {
		return nil, errors.New("response output path unavailable")
	}
	result, err := readNATSResponseResult(rm.cfg.runOutputPath(out), id, ns)
	if err != nil {
		// A partial run may have stopped before the harness could publish its
		// artifact/terminal pair. Preserve bounded run-owned WHY, explicitly
		// unverified, without converting it into an accepted decision or cleanup.
		partial := NATSResponseResult{M0Status: "UNKNOWN", SignalStatus: "UNKNOWN", DecisionStatus: "UNKNOWN",
			M1Status: "UNKNOWN", PeerStatus: "UNKNOWN", CleanupStatus: "UNVERIFIED", CapacityReservationStatus: "UNKNOWN", Repeatability: "UNKNOWN", SecurityEfficacy: "NOT_EVALUATED",
			Issues: []string{"Response artifact or terminal join unavailable"}}
		root := rm.cfg.runOutputPath(out)
		if r, requestErr := readNATSResponseRequest(root, id); requestErr == nil && r.Namespace == ns {
			partial = projectNATSPartialWHY(root, id, ns, r.Nonce, r.NamespaceUID, partial)
		}
		return &partial, nil
	}
	if state != "done" {
		result.Accepted = false
		result.Issues = append(result.Issues, "run terminal state is not done")
	}
	return &result, nil
}

func natsSHA(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func sameNATSImageDigest(observed, admitted string) bool {
	const marker = "@sha256:"
	a, b := strings.LastIndex(observed, marker), strings.LastIndex(admitted, marker)
	return a >= 0 && b >= 0 && len(observed[a+len(marker):]) == 64 && observed[a:] == admitted[b:]
}
