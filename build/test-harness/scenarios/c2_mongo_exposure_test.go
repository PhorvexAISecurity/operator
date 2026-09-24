package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"go.mongodb.org/mongo-driver/v2/bson"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestMongoExposureExactClientAndOriginalReply(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	pod := mongoExposureClientPod(nonce, "cpu-node")
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken ||
		len(pod.Spec.ImagePullSecrets) != 0 || len(pod.Spec.Containers) != 1 || len(pod.Spec.Containers[0].EnvFrom) != 0 ||
		!strings.Contains(pod.Spec.Containers[0].Args[0], "retryReads=false&retryWrites=false") ||
		pod.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields[0].Key != "metadata.name" {
		t.Fatal("producer gave the separate client credentials, retries, or an unpinned scheduler path")
	}
	pod.UID = "pod-uid"
	want := pod.DeepCopy()
	if err := mongoExposureClientIdentity(pod, want, pod.UID); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"envFrom secret": func(p *corev1.Pod) {
			p.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "secret"}}}}
		},
		"pull secret": func(p *corev1.Pod) { p.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "pull"}} },
		"token":       func(p *corev1.Pod) { v := true; p.Spec.AutomountServiceAccountToken = &v },
		"dns override": func(p *corev1.Pod) {
			p.Spec.DNSPolicy = corev1.DNSNone
			p.Spec.DNSConfig = &corev1.PodDNSConfig{Nameservers: []string{"127.0.0.1"}}
		},
		"command": func(p *corev1.Pod) { p.Spec.Containers[0].Command = []string{"sh"} },
		"node": func(p *corev1.Pod) {
			p.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchFields[0].Values[0] = "other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := want.DeepCopy()
			mutate(got)
			if mongoExposureClientIdentity(got, want, want.UID) == nil {
				t.Fatal("admission-mutated client accepted")
			}
		})
	}
	doc := mongoExposureDoc(nonce)
	row, _ := json.Marshal([]mongoExposureDocument{doc})
	raw := []byte(`CAT_MONGO_JSON={"ok":true,"code":0,"codeName":"","rows":` + string(row) + `}` + "\n")
	status, hash, err := mongoExposureReply(raw, nonce)
	if err != nil || status != "UNAUTHENTICATED_EXACT_READ" || hash != mongoExposureDocumentSHA(nonce) {
		t.Fatalf("exact original reply not recognized: %q %q %v", status, hash, err)
	}
	for name, bad := range map[string][]byte{
		"outer duplicate":  []byte(`CAT_MONGO_JSON={"ok":true,"ok":true,"code":0,"codeName":"","rows":` + string(row) + `}`),
		"inner duplicate":  []byte(`CAT_MONGO_JSON={"ok":true,"code":0,"codeName":"","rows":[{"_id":"` + nonce + `","nonce":"` + nonce + `","state":"initial","payload":"synthetic-mongo-exposure-v1","payload":"synthetic-mongo-exposure-v1"}]}`),
		"inner case alias": []byte(`CAT_MONGO_JSON={"ok":true,"code":0,"codeName":"","rows":[{"_id":"` + nonce + `","nonce":"` + nonce + `","state":"initial","Payload":"synthetic-mongo-exposure-v1"}]}`),
		"other document":   []byte(strings.Replace(string(raw), "synthetic-mongo-exposure-v1", "customer", 1)),
		"second line":      append(append([]byte{}, raw...), raw...),
	} {
		t.Run(name, func(t *testing.T) {
			if status, _, err := mongoExposureReply(bad, nonce); err == nil && status == "UNAUTHENTICATED_EXACT_READ" {
				t.Fatal("non-owned or ambiguous reply credited")
			}
		})
	}
	denied := []byte(`CAT_MONGO_JSON={"ok":false,"code":13,"codeName":"Unauthorized","rows":[]}`)
	if status, _, err := mongoExposureReply(denied, nonce); err != nil || status != "MONGO_AUTH_DENIED" {
		t.Fatalf("closed denial lost: %q %v", status, err)
	}
	if !strings.Contains(mongoExposureReadScript(nonce), "catch(e)") {
		t.Fatal("mongosh thrown denial would not produce closed reply")
	}
}

func TestMongoExposureLogBracketsExactClientIncarnation(t *testing.T) {
	nonce := strings.Repeat("d", 32)
	want := mongoExposureClientPod(nonce, "cpu-node")
	pre := want.DeepCopy()
	pre.UID = "original-uid"
	pre.Spec.NodeName = "cpu-node"
	pre.Status.Phase, pre.Status.PodIP, pre.Status.HostIP = corev1.PodSucceeded, "10.0.0.8", "10.0.0.9"
	completed := metav1.Now()
	pre.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "read-once", ImageID: mongoExposureClientImage, ContainerID: "containerd://exact", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, StartedAt: completed, FinishedAt: completed}}}}
	if err := mongoExposureStableClientLogSource(pre, pre.DeepCopy(), want, pre.UID); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"same-name replacement": func(p *corev1.Pod) { p.UID = "replacement" },
		"container replacement": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID = "containerd://other" },
		"image replacement":     func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "other" },
		"changed command":       func(p *corev1.Pod) { p.Spec.Containers[0].Args = []string{"other"} },
		"changed node":          func(p *corev1.Pod) { p.Spec.NodeName = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			after := pre.DeepCopy()
			mutate(after)
			if mongoExposureStableClientLogSource(pre, after, want, pre.UID) == nil {
				t.Fatal("name-addressed log could be misattributed")
			}
		})
	}
}

type mongoExposureFakeStore struct {
	uuid  string
	doc   mongoExposureDocument
	count int64
	drops int
}

func (s *mongoExposureFakeStore) ServerVersion(context.Context) (string, error) { return "7.0.40", nil }
func (s *mongoExposureFakeStore) SourceConfiguration(context.Context) error     { return nil }

func (s *mongoExposureFakeStore) CollectionUUID(context.Context, string, string) (string, error) {
	return s.uuid, nil
}
func (s *mongoExposureFakeStore) CreateCollection(context.Context, string, string) error { return nil }
func (s *mongoExposureFakeStore) Insert(context.Context, string, string, mongoExposureDocument) (any, error) {
	return nil, nil
}
func (s *mongoExposureFakeStore) Read(context.Context, string, string, string) (mongoExposureDocument, error) {
	return s.doc, nil
}
func (s *mongoExposureFakeStore) Count(context.Context, string, string) (int64, error) {
	return s.count, nil
}
func (s *mongoExposureFakeStore) Drop(_ context.Context, _, _, expectedUUID string) error {
	if s.uuid != expectedUUID {
		return errors.New("collectionUUID mismatch")
	}
	s.drops++
	s.uuid = ""
	return nil
}

func TestMongoExposureDropCommandCarriesBinaryUUID(t *testing.T) {
	uuid := strings.Repeat("ab", 16)
	cmd, err := mongoExposureDropCommand("owned_"+strings.Repeat("a", 32), uuid)
	if err != nil || len(cmd) != 2 || cmd[0].Key != "drop" || cmd[1].Key != "collectionUUID" {
		t.Fatalf("UUID drop command malformed: %#v %v", cmd, err)
	}
	bin, ok := cmd[1].Value.(bson.Binary)
	if !ok || bin.Subtype != 4 || len(bin.Data) != 16 || bin.Data[0] != 0xab {
		t.Fatal("collectionUUID is not BSON subtype-4 binary")
	}
	for _, bad := range []string{"", strings.Repeat("a", 31), strings.Repeat("z", 32)} {
		if _, err := mongoExposureDropCommand("owned_"+strings.Repeat("a", 32), bad); err == nil {
			t.Fatal("invalid UUID admitted")
		}
	}
	s := &mongoExposureFakeStore{uuid: uuid, doc: mongoExposureDoc(strings.Repeat("a", 32)), count: 1}
	if err := s.Drop(context.Background(), "db", "coll", strings.Repeat("cd", 16)); err == nil || s.drops != 0 {
		t.Fatal("wrong UUID caused deletion")
	}
}

func TestMongoExposureReviewedProcessConfiguration(t *testing.T) {
	row := bson.M{"ok": float64(1), "parsed": bson.M{"net": bson.M{"bindIp": "*"}}}
	if err := mongoExposureSourceConfiguration(row); err != nil {
		t.Fatal(err)
	}
	wire, err := bson.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bson.M
	if err = bson.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if err = mongoExposureSourceConfiguration(decoded); err != nil {
		t.Fatalf("driver-decoded BSON object rejected: %v", err)
	}
	for name, mutate := range map[string]func(bson.M){
		"authorization enabled":           func(r bson.M) { r["parsed"].(bson.M)["security"] = bson.M{"authorization": "enabled"} },
		"authorization disabled declared": func(r bson.M) { r["parsed"].(bson.M)["security"] = bson.M{"authorization": "disabled"} },
		"bind changed":                    func(r bson.M) { r["parsed"].(bson.M)["net"].(bson.M)["bindIp"] = "127.0.0.1" },
		"missing parsed":                  func(r bson.M) { delete(r, "parsed") },
	} {
		t.Run(name, func(t *testing.T) {
			copy := bson.M{"ok": float64(1), "parsed": bson.M{"net": bson.M{"bindIp": "*"}}}
			mutate(copy)
			if mongoExposureSourceConfiguration(copy) == nil {
				t.Fatal("unreviewed process shape admitted")
			}
		})
	}
}
func (s *mongoExposureFakeStore) Close(context.Context) error { return nil }

func TestMongoExposureDropRequiresUUIDAndSingletonOwnedRecord(t *testing.T) {
	nonce := strings.Repeat("b", 32)
	db, coll, _ := mongoExposureNames(nonce)
	for name, makeStore := range map[string]func() *mongoExposureFakeStore{
		"replaced collection": func() *mongoExposureFakeStore {
			return &mongoExposureFakeStore{uuid: strings.Repeat("c", 32), doc: mongoExposureDoc(nonce), count: 1}
		},
		"changed document": func() *mongoExposureFakeStore {
			d := mongoExposureDoc(nonce)
			d.Payload = "foreign"
			return &mongoExposureFakeStore{uuid: strings.Repeat("a", 32), doc: d, count: 1}
		},
		"extra record": func() *mongoExposureFakeStore {
			return &mongoExposureFakeStore{uuid: strings.Repeat("a", 32), doc: mongoExposureDoc(nonce), count: 2}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := makeStore()
			if mongoExposureDropOwned(context.Background(), s, t.TempDir(), "run-1", nonce, db, coll, strings.Repeat("a", 32)) == nil || s.drops != 0 {
				t.Fatal("non-owned collection was dropped")
			}
		})
	}
	out := t.TempDir()
	s := &mongoExposureFakeStore{uuid: strings.Repeat("a", 32), doc: mongoExposureDoc(nonce), count: 1}
	if err := mongoExposureDropOwned(context.Background(), s, out, "run-1", nonce, db, coll, s.uuid); err != nil || s.drops != 1 {
		t.Fatalf("owned exact collection not cleaned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "mongo-exposure-phases.jsonl")); err != nil {
		t.Fatal("durable cleanup phases absent", err)
	}
}

func TestMongoExposureRunClaimIsOneUse(t *testing.T) {
	out := t.TempDir()
	nonce := strings.Repeat("c", 32)
	if err := ClaimMongoExposureRun(out, "run-1", nonce); err != nil {
		t.Fatal(err)
	}
	if err := ClaimMongoExposureRun(out, "run-1", nonce); err == nil {
		t.Fatal("second invocation could overwrite first-run ledger")
	}
}

func TestMongoExposureServiceRouteBindsActualPodAndEndpoint(t *testing.T) {
	yes := true
	port := int32(27017)
	proto := corev1.ProtocolTCP
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mongo-rs-pod", Namespace: "document-store", UID: "pod-uid", Labels: map[string]string{"app": "mongo", "tier": "db"}}, Status: corev1.PodStatus{PodIP: "10.0.0.4"}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "mongo", Namespace: "document-store", UID: "service-uid"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{"app": "mongo"}, Ports: []corev1.ServicePort{{Port: port, Protocol: proto}}}}
	es := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "mongo-slice", Namespace: "document-store", UID: "slice-uid", Labels: map[string]string{discoveryv1.LabelServiceName: "mongo"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: "mongo", UID: svc.UID, Controller: &yes}}}, AddressType: discoveryv1.AddressTypeIPv4, Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: &proto}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{pod.Status.PodIP}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}, Conditions: discoveryv1.EndpointConditions{Ready: &yes}}}}
	if err := mongoExposureServiceRoute(svc, es, pod); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*corev1.Service, *discoveryv1.EndpointSlice, *corev1.Pod){
		"extra selector excludes": func(s *corev1.Service, _ *discoveryv1.EndpointSlice, _ *corev1.Pod) {
			s.Spec.Selector["other"] = "excluded"
		},
		"wrong address": func(_ *corev1.Service, e *discoveryv1.EndpointSlice, _ *corev1.Pod) {
			e.Endpoints[0].Addresses[0] = "10.0.0.8"
		},
		"wrong target kind": func(_ *corev1.Service, e *discoveryv1.EndpointSlice, _ *corev1.Pod) {
			e.Endpoints[0].TargetRef.Kind = "Service"
		},
		"wrong target name": func(_ *corev1.Service, e *discoveryv1.EndpointSlice, _ *corev1.Pod) {
			e.Endpoints[0].TargetRef.Name = "other"
		},
		"wrong target namespace": func(_ *corev1.Service, e *discoveryv1.EndpointSlice, _ *corev1.Pod) {
			e.Endpoints[0].TargetRef.Namespace = "other"
		},
		"wrong target uid": func(_ *corev1.Service, e *discoveryv1.EndpointSlice, _ *corev1.Pod) {
			e.Endpoints[0].TargetRef.UID = types.UID("other")
		},
		"terminating": func(_ *corev1.Service, e *discoveryv1.EndpointSlice, _ *corev1.Pod) {
			e.Endpoints[0].Conditions.Terminating = &yes
		},
		"wrong port": func(s *corev1.Service, _ *discoveryv1.EndpointSlice, _ *corev1.Pod) {
			s.Spec.Ports[0].TargetPort = intstr.FromInt32(27018)
		},
		"wrong endpoint port name": func(_ *corev1.Service, e *discoveryv1.EndpointSlice, _ *corev1.Pod) {
			name := "foreign"
			e.Ports[0].Name = &name
		},
	} {
		t.Run(name, func(t *testing.T) {
			ss := svc.DeepCopy()
			ee := es.DeepCopy()
			pp := pod.DeepCopy()
			mutate(ss, ee, pp)
			if mongoExposureServiceRoute(ss, ee, pp) == nil {
				t.Fatal("unrouted or replaced endpoint accepted")
			}
		})
	}
}

func TestMongoExposurePolicySelectsCurrentExactPod(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mongo-0", Namespace: "document-store", Labels: map[string]string{"app": "mongo", "role": "db"}}}
	policy := &unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"name": "mongo-defense", "uid": "policy-uid", "generation": int64(7)}, "spec": map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "mongo"}, "matchExpressions": []any{map[string]any{"key": "role", "operator": "In", "values": []any{"db"}}}}}, "status": map[string]any{"observedGeneration": int64(7)}}}
	if err := mongoExposurePolicySelectsPod(policy, pod); err != nil {
		t.Fatal(err)
	}
	if err := mongoExposurePolicyCurrent(policy); err != nil {
		t.Fatal(err)
	}
	bad := policy.DeepCopy()
	// A second selector label must not be ignored merely because app=mongo.
	_ = unstructured.SetNestedField(bad.Object, "excluded", "spec", "selector", "matchLabels", "extra")
	if mongoExposurePolicySelectsPod(bad, pod) == nil {
		t.Fatal("policy with excluding selector admitted")
	}
	stale := policy.DeepCopy()
	_ = unstructured.SetNestedField(stale.Object, int64(6), "status", "observedGeneration")
	if mongoExposurePolicyCurrent(stale) == nil {
		t.Fatal("stale policy status admitted")
	}
}

func TestMongoExposurePinsMountedBoundPVC(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mongo-pod", Namespace: "document-store"}, Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "mongo", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data/db"}}}},
		Volumes:    []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "mongo-data"}}}},
	}}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "mongo-data", Namespace: "document-store", UID: "pvc-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv-owned"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	env := &core.Env{Kube: fake.NewSimpleClientset(pvc)}
	if uid, err := mongoExposurePVC(context.Background(), env, pod); err != nil || uid != pvc.UID {
		t.Fatalf("bound source PVC lost: %s %v", uid, err)
	}
	bad := pod.DeepCopy()
	bad.Spec.Containers[0].VolumeMounts = nil
	if _, err := mongoExposurePVC(context.Background(), env, bad); err == nil {
		t.Fatal("unmounted claim credited")
	}
	bad = pod.DeepCopy()
	bad.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = "foreign"
	if _, err := mongoExposurePVC(context.Background(), env, bad); err == nil {
		t.Fatal("foreign claim credited")
	}
	bad = pod.DeepCopy()
	bad.Spec.Containers[0].VolumeMounts[0].MountPath = "/tmp"
	if _, err := mongoExposurePVC(context.Background(), env, bad); err == nil {
		t.Fatal("PVC mounted away from Mongo data path credited")
	}
	bad = pod.DeepCopy()
	bad.Spec.Containers[0].VolumeMounts[0].SubPath = "other"
	if _, err := mongoExposurePVC(context.Background(), env, bad); err == nil {
		t.Fatal("PVC subPath credited as exact data path")
	}
}
