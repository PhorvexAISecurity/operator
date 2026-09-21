package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/portforward"
	transportspdy "k8s.io/client-go/transport/spdy"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/jetstreamprobe"
)

func init() { core.RegisterScenario(&c2NATSJetStreamDurability{}) }

const (
	natsDurabilityScenario = "c2-nats-jetstream-durability"
	natsDurabilitySuite    = "post25-nats-jetstream-durability-v1"
	natsFixtureName        = "c2-nats-js"
	natsHeadlessService    = "c2-nats-js-headless"
	natsClientService      = "c2-nats-js-client"
	natsImage              = "docker.io/library/nats@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927"
	natsStorageCapacity    = "64Mi"
	natsClientPort         = 4222
	natsClusterPort        = 6222
	natsMonitorPort        = 8222
	natsEvidenceMaxItems   = 64
	natsEvidenceMaxKey     = 128
	natsEvidenceMaxValue   = 16 << 10
	natsEvidenceMaxTotal   = 32 << 10
)

const natsSupervisorScript = `set -eu
generation=0
mkdir -p /control /data/jetstream
while true; do
  generation=$((generation+1))
  rc=0
  rm -f /control/restart
  nats-server --name "$POD_NAME" --jetstream --store_dir /data/jetstream --port 4222 --http_port 8222 --cluster_name post25-nats-js --cluster nats://0.0.0.0:6222 --routes nats://c2-nats-js-0.c2-nats-js-headless:6222,nats://c2-nats-js-1.c2-nats-js-headless:6222,nats://c2-nats-js-2.c2-nats-js-headless:6222 &
  child=$!
  printf '%s\n' "$child" > /control/pid
  printf '%s\n' "$generation" > /control/generation
  wait "$child" || rc=$?
  if [ -f /control/restart ]; then continue; fi
  exit "${rc:-0}"
done`

type natsStorageIdentity struct {
	PVCName  string
	PVCUID   types.UID
	PVName   string
	PVUID    types.UID
	Slot     int
	PathHash string
}

type c2NATSJetStreamDurability struct {
	unavailable                            string
	mode                                   string
	statefulSetUID, headlessUID, clientUID types.UID
	storage                                [3]natsStorageIdentity
	pods                                   map[string]types.UID
	serverIDs                              map[string]string
	connectedMember                        string
	probe                                  *jetstreamprobe.Probe
	receipt                                *jetstreamprobe.RestartOracleReceipt
	noActionReceipt                        *jetstreamprobe.NoActionOracleReceipt
	baseline                               map[string]string
	portStop                               chan struct{}
	portDone                               chan error
}

func (s *c2NATSJetStreamDurability) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{Name: natsDurabilityScenario, Category: core.CategoryR6Claimed, Source: "Post25 NATS 2.10.29 JetStream durability catalogue", R6ResponseTag: core.R6Partial, BenignControl: true, Realism: core.RealismExecutable,
		Mechanism:          "fresh owned three-member NATS 2.10.29 file-backed JetStream fixture; official nats.go PubAck/consumer ACK/stored-message protocol and exact child-process restart boundary",
		ClaimLimits:        "functional state/availability benchmark; no CVE, detection, containment, NetworkPolicy enforcement, node/zone/disk failure, installed dispatch, security efficacy, or monetary claim",
		OracleDescription:  "requires exact three-member stream and consumer replication, A acknowledgement and independent storage, unchanged Pod/PVC/PV/store identity across one child restart, replica recovery, then B at the exact next sequence with no unexpected redelivery",
		CleanupDescription: "close the probe and delete only create-response StatefulSet, Services and PVC UIDs; externally owned Retain PVs, holder and StorageClass are never deleted",
		R6Justification:    "Supplies a real protocol and state oracle for later matched actuator and brain comparisons while keeping resilience separate from security outcome."}
}

func natsLocalPath(holderUID string, slot int) string {
	return fmt.Sprintf("/var/lib/kubelet/pods/%s/volumes/kubernetes.io~empty-dir/slot-%d", holderUID, slot)
}

func natsPathHash(path string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(path))) }
func validateNATSStorageClass(sc *storagev1.StorageClass, fixture *config.NATSJetStreamFixtureConfig) error {
	if sc == nil || sc.Name != fixture.StorageClass || string(sc.UID) != fixture.StorageClassUID || sc.DeletionTimestamp != nil || sc.Provisioner != "kubernetes.io/no-provisioner" || sc.VolumeBindingMode == nil || *sc.VolumeBindingMode != storagev1.VolumeBindingImmediate || sc.ReclaimPolicy == nil || *sc.ReclaimPolicy != corev1.PersistentVolumeReclaimRetain || sc.AllowVolumeExpansion != nil && *sc.AllowVolumeExpansion || sc.Annotations["fixture.phorvex.ai/nonce"] != fixture.Nonce {
		return errors.New("NATS fixture StorageClass identity or no-provisioner Immediate Retain contract differs")
	}
	return nil
}

func validateNATSLocalPV(pv *corev1.PersistentVolume, authority config.NATSJetStreamLocalPV, fixture *config.NATSJetStreamFixtureConfig, requireAvailable bool) error {
	path := natsLocalPath(fixture.HolderUID, authority.Slot)
	if pv == nil {
		return errors.New("NATS local PV is absent")
	}
	capacity := pv.Spec.Capacity.Storage()
	if pv.Name != authority.Name || string(pv.UID) != authority.UID || pv.DeletionTimestamp != nil || pv.Spec.StorageClassName != fixture.StorageClass || pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimRetain || pv.Spec.Local == nil || pv.Spec.Local.Path != path || natsPathHash(path) != authority.PathSHA256 || capacity == nil || capacity.Cmp(resource.MustParse(natsStorageCapacity)) != 0 || len(pv.Spec.AccessModes) != 1 || pv.Spec.AccessModes[0] != corev1.ReadWriteOnce || pv.Spec.ClaimRef != nil && requireAvailable {
		return errors.New("NATS local PV exact identity, path, capacity or availability differs")
	}
	if pv.Spec.VolumeMode == nil || *pv.Spec.VolumeMode != corev1.PersistentVolumeFilesystem || !checkpointLocalNodeAffinityMatches(pv, fixture.NodeName) {
		return errors.New("NATS local PV filesystem mode or exact node affinity differs")
	}
	if requireAvailable && pv.Status.Phase != corev1.VolumeAvailable || !requireAvailable && pv.Status.Phase != corev1.VolumeBound {
		return errors.New("NATS local PV phase differs")
	}
	if pv.Annotations["fixture.phorvex.ai/holder-uid"] != fixture.HolderUID || pv.Annotations["fixture.phorvex.ai/node-uid"] != fixture.NodeUID || pv.Annotations["fixture.phorvex.ai/nonce"] != fixture.Nonce || pv.Annotations["fixture.phorvex.ai/slot"] != strconv.Itoa(authority.Slot) || pv.Annotations["fixture.phorvex.ai/local-path-sha256"] != authority.PathSHA256 {
		return errors.New("NATS local PV provenance differs")
	}
	return nil
}

func (s *c2NATSJetStreamDurability) Setup(ctx context.Context, env *core.Env) error {
	*s = c2NATSJetStreamDurability{pods: map[string]types.UID{}, serverIDs: map[string]string{}}
	fixture := env.Config.NATSJetStreamFixture
	if fixture == nil {
		s.unavailable = "NATS JetStream fixture authority is not configured"
		return nil
	}
	s.mode = fixture.Mode
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	if err := s.validateAuthority(ctx, env, fixture); err != nil {
		return err
	}
	if err := s.createClaims(ctx, env, fixture); err != nil {
		return err
	}
	if err := s.createWorkload(ctx, env, fixture); err != nil {
		return err
	}
	return s.waitAndBindPods(ctx, env, fixture)
}

func (s *c2NATSJetStreamDurability) validateAuthority(ctx context.Context, env *core.Env, fixture *config.NATSJetStreamFixtureConfig) error {
	node, err := env.Kube.CoreV1().Nodes().Get(ctx, fixture.NodeName, metav1.GetOptions{})
	if err != nil || string(node.UID) != fixture.NodeUID || !checkpointNodeReady(node) {
		return fmt.Errorf("NATS fixture node identity/readiness differs: %w", err)
	}
	holder, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, fixture.HolderName, metav1.GetOptions{})
	if err != nil || string(holder.UID) != fixture.HolderUID || holder.Spec.NodeName != fixture.NodeName || holder.DeletionTimestamp != nil || !podReady(holder) || holder.Annotations["fixture.phorvex.ai/nonce"] != fixture.Nonce {
		return fmt.Errorf("NATS fixture holder identity/readiness differs: %w", err)
	}
	volumes, mounts := map[string]bool{}, map[string]string{}
	for _, volume := range holder.Spec.Volumes {
		if volume.EmptyDir != nil && volume.EmptyDir.SizeLimit != nil && volume.EmptyDir.SizeLimit.Cmp(resource.MustParse(natsStorageCapacity)) == 0 {
			volumes[volume.Name] = true
		}
	}
	if len(holder.Spec.Containers) != 1 {
		return errors.New("NATS fixture holder must have exactly one container")
	}
	for _, mount := range holder.Spec.Containers[0].VolumeMounts {
		mounts[mount.Name] = mount.MountPath
	}
	if len(holder.Spec.Volumes) != len(fixture.PVs) || len(volumes) != len(fixture.PVs) || len(mounts) != len(fixture.PVs) {
		return errors.New("NATS fixture holder contains volumes or mounts outside its exact three-slot authority")
	}
	for _, authority := range fixture.PVs {
		name := fmt.Sprintf("slot-%d", authority.Slot)
		if !volumes[name] || mounts[name] != fmt.Sprintf("/nats/slot-%d", authority.Slot) {
			return fmt.Errorf("NATS holder slot %d differs", authority.Slot)
		}
	}
	sc, err := env.Kube.StorageV1().StorageClasses().Get(ctx, fixture.StorageClass, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if err := validateNATSStorageClass(sc, fixture); err != nil {
		return err
	}
	for _, authority := range fixture.PVs {
		pv, err := env.Kube.CoreV1().PersistentVolumes().Get(ctx, authority.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if err := validateNATSLocalPV(pv, authority, fixture, true); err != nil {
			return fmt.Errorf("PV %s: %w", authority.Name, err)
		}
	}
	return nil
}

func (s *c2NATSJetStreamDurability) createClaims(ctx context.Context, env *core.Env, fixture *config.NATSJetStreamFixtureConfig) error {
	ordered := append([]config.NATSJetStreamLocalPV(nil), fixture.PVs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Slot < ordered[j].Slot })
	for ordinal, authority := range ordered {
		name := fmt.Sprintf("store-%s-%d", natsFixtureName, ordinal)
		labels := env.OwnedLabels(map[string]string{"app": natsFixtureName, "fixture.phorvex.ai/nonce": fixture.Nonce, "fixture.phorvex.ai/member": strconv.Itoa(ordinal)})
		pvc, err := env.Kube.CoreV1().PersistentVolumeClaims(env.Config.Namespace).Create(ctx, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace, Labels: labels}, Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: &fixture.StorageClass, VolumeName: authority.Name, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(natsStorageCapacity)}}}}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create NATS PVC %s: %w", name, err)
		}
		if pvc.UID == "" {
			return errors.New("NATS PVC create returned empty UID")
		}
		s.storage[ordinal] = natsStorageIdentity{PVCName: name, PVCUID: pvc.UID, PVName: authority.Name, PVUID: types.UID(authority.UID), Slot: authority.Slot, PathHash: authority.PathSHA256}
	}
	return nil
}

func natsFixtureLabels(env *core.Env, nonce string) map[string]string {
	return env.OwnedLabels(map[string]string{"app": natsFixtureName, "fixture.phorvex.ai/nonce": nonce})
}

func (s *c2NATSJetStreamDurability) createWorkload(ctx context.Context, env *core.Env, fixture *config.NATSJetStreamFixtureConfig) error {
	ns := env.Config.Namespace
	labels := natsFixtureLabels(env, fixture.Nonce)
	noToken := false
	nonroot := true
	uid := int64(1000)
	noEsc := false
	ro := true
	three := int32(3)
	headless, err := env.Kube.CoreV1().Services(ns).Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: natsHeadlessService, Namespace: ns, Labels: labels}, Spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone, PublishNotReadyAddresses: true, Selector: map[string]string{"app": natsFixtureName}, Ports: []corev1.ServicePort{{Name: "client", Port: natsClientPort}, {Name: "cluster", Port: natsClusterPort}, {Name: "monitor", Port: natsMonitorPort}}}}, metav1.CreateOptions{})
	if err != nil || headless.UID == "" {
		return fmt.Errorf("create NATS headless Service: %w", err)
	}
	s.headlessUID = headless.UID
	client, err := env.Kube.CoreV1().Services(ns).Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: natsClientService, Namespace: ns, Labels: labels}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": natsFixtureName}, Ports: []corev1.ServicePort{{Name: "client", Port: natsClientPort, TargetPort: intstr.FromInt(natsClientPort)}}}}, metav1.CreateOptions{})
	if err != nil || client.UID == "" {
		return fmt.Errorf("create NATS client Service: %w", err)
	}
	s.clientUID = client.UID
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: natsFixtureName, Namespace: ns, Labels: labels}, Spec: appsv1.StatefulSetSpec{ServiceName: natsHeadlessService, Replicas: &three, PodManagementPolicy: appsv1.ParallelPodManagement, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": natsFixtureName}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &noToken, NodeSelector: map[string]string{"kubernetes.io/hostname": fixture.NodeName}, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid, RunAsGroup: &uid, FSGroup: &uid}, Containers: []corev1.Container{{Name: "nats", Image: natsImage, Command: []string{"/bin/sh", "-ec", natsSupervisorScript}, Env: []corev1.EnvVar{{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}}}, Ports: []corev1.ContainerPort{{Name: "client", ContainerPort: natsClientPort}, {Name: "cluster", ContainerPort: natsClusterPort}, {Name: "monitor", ContainerPort: natsMonitorPort}}, ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz?js-enabled-only=true", Port: intstr.FromInt(natsMonitorPort)}}, PeriodSeconds: 1, TimeoutSeconds: 2, FailureThreshold: 30}, SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid, RunAsGroup: &uid, AllowPrivilegeEscalation: &noEsc, ReadOnlyRootFilesystem: &ro, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("32Mi")}, Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("128Mi")}}, VolumeMounts: []corev1.VolumeMount{{Name: "store", MountPath: "/data"}, {Name: "control", MountPath: "/control"}}}}, Volumes: []corev1.Volume{{Name: "control", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}}}, VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "store"}, Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: &fixture.StorageClass, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(natsStorageCapacity)}}}}}}}
	created, err := env.Kube.AppsV1().StatefulSets(ns).Create(ctx, sts, metav1.CreateOptions{})
	if err != nil || created.UID == "" {
		return fmt.Errorf("create NATS StatefulSet: %w", err)
	}
	s.statefulSetUID = created.UID
	return nil
}

func (s *c2NATSJetStreamDurability) waitAndBindPods(ctx context.Context, env *core.Env, fixture *config.NATSJetStreamFixtureConfig) error {
	seenIDs := map[string]bool{}
	for ordinal := range 3 {
		name := fmt.Sprintf("%s-%d", natsFixtureName, ordinal)
		if err := env.WaitForPodRunning(ctx, name, 120*time.Second); err != nil {
			return err
		}
		pod, value, _, err := s.validateCurrentMember(ctx, env, fixture, ordinal, "", "")
		if err != nil {
			return err
		}
		if seenIDs[value.ServerID] {
			return errors.New("NATS fixture server ID is duplicated")
		}
		seenIDs[value.ServerID] = true
		s.pods[name] = pod.UID
		s.serverIDs[name] = value.ServerID
	}
	return s.openProbe(ctx, env)
}

func natsControllerOwner(pod *corev1.Pod, statefulSetUID types.UID) bool {
	if pod == nil || statefulSetUID == "" {
		return false
	}
	for _, owner := range pod.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && owner.APIVersion == "apps/v1" && owner.Kind == "StatefulSet" && owner.Name == natsFixtureName && owner.UID == statefulSetUID {
			return true
		}
	}
	return false
}

func validateNATSMemberPod(pod *corev1.Pod, fixture *config.NATSJetStreamFixtureConfig, statefulSetUID, expectedUID types.UID, ordinal int, storage natsStorageIdentity) error {
	name := fmt.Sprintf("%s-%d", natsFixtureName, ordinal)
	if pod == nil || pod.Name != name || pod.Namespace == "" || pod.UID == "" || expectedUID != "" && pod.UID != expectedUID || pod.DeletionTimestamp != nil || pod.Spec.NodeName != fixture.NodeName || !podReady(pod) || !natsControllerOwner(pod, statefulSetUID) {
		return fmt.Errorf("NATS member %s Pod identity, readiness, node or StatefulSet owner differs", name)
	}
	if pod.Labels["app"] != natsFixtureName || pod.Labels["fixture.phorvex.ai/nonce"] != fixture.Nonce {
		return fmt.Errorf("NATS member %s labels/nonce differ", name)
	}
	if len(pod.Spec.Containers) != 1 {
		return fmt.Errorf("NATS member %s must have exactly one container", name)
	}
	c := pod.Spec.Containers[0]
	if c.Name != "nats" || c.Image != natsImage || len(c.Command) != 3 || c.Command[0] != "/bin/sh" || c.Command[1] != "-ec" || c.Command[2] != natsSupervisorScript {
		return fmt.Errorf("NATS member %s pinned container/process contract differs", name)
	}
	mounts := map[string]string{}
	for _, mount := range c.VolumeMounts {
		mounts[mount.Name] = mount.MountPath
	}
	if len(mounts) != 2 || mounts["store"] != "/data" || mounts["control"] != "/control" {
		return fmt.Errorf("NATS member %s exact volume mounts differ", name)
	}
	volumes := map[string]corev1.VolumeSource{}
	for _, volume := range pod.Spec.Volumes {
		volumes[volume.Name] = volume.VolumeSource
	}
	if len(volumes) != 2 || volumes["store"].PersistentVolumeClaim == nil || volumes["store"].PersistentVolumeClaim.ClaimName != storage.PVCName || volumes["control"].EmptyDir == nil {
		return fmt.Errorf("NATS member %s exact PVC/control volumes differ", name)
	}
	return nil
}

func (s *c2NATSJetStreamDurability) validateCurrentMember(ctx context.Context, env *core.Env, fixture *config.NATSJetStreamFixtureConfig, ordinal int, expectedUID types.UID, expectedServerID string) (*corev1.Pod, natsVarz, string, error) {
	name := fmt.Sprintf("%s-%d", natsFixtureName, ordinal)
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, natsVarz{}, "", fmt.Errorf("read NATS member %s: %w", name, err)
	}
	storage := s.storage[ordinal]
	if err := validateNATSMemberPod(pod, fixture, s.statefulSetUID, expectedUID, ordinal, storage); err != nil {
		return nil, natsVarz{}, "", err
	}
	volume, err := s.requireStorageBinding(ctx, env, fixture, storage)
	if err != nil {
		return nil, natsVarz{}, "", err
	}
	value, err := natsPodVarz(ctx, env, name)
	if err != nil {
		return nil, natsVarz{}, "", err
	}
	if expectedServerID != "" && value.ServerID != expectedServerID {
		return nil, value, volume, fmt.Errorf("NATS member %s server identity drifted from %s to %s before action", name, expectedServerID, value.ServerID)
	}
	return pod, value, volume, nil
}

func (s *c2NATSJetStreamDurability) openProbe(ctx context.Context, env *core.Env) error {
	if env.Rest == nil {
		return errors.New("NATS fixture requires live REST config for exact Pod port-forward")
	}
	transport, upgrader, err := transportspdy.RoundTripperFor(env.Rest)
	if err != nil {
		return err
	}
	u, err := url.Parse(env.Rest.Host)
	if err != nil {
		return fmt.Errorf("parse REST host for NATS port-forward: %w", err)
	}
	u.Path = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s-0/portforward", env.Config.Namespace, natsFixtureName)
	u.RawQuery, u.Fragment = "", ""
	dialer := transportspdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, u)
	s.portStop = make(chan struct{})
	ready := make(chan struct{})
	s.portDone = make(chan error, 1)
	var out, errOut bytes.Buffer
	pf, err := portforward.New(dialer, []string{"0:4222"}, s.portStop, ready, &out, &errOut)
	if err != nil {
		return err
	}
	go func() { s.portDone <- pf.ForwardPorts() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-s.portDone:
		return fmt.Errorf("NATS port-forward stopped before ready: %v %s", err, errOut.String())
	case <-ready:
	}
	ports, err := pf.GetPorts()
	if err != nil || len(ports) != 1 {
		return fmt.Errorf("NATS forwarded port identity differs: %v", err)
	}
	nonce := env.Config.NATSJetStreamFixture.Nonce
	cfg := jetstreamprobe.Config{URL: fmt.Sprintf("nats://127.0.0.1:%d", ports[0].Local), Stream: "DURABILITY_" + strings.ToUpper(strings.ReplaceAll(nonce, "-", "_")), Subject: "durability." + nonce, Consumer: "durability-main", OwnerNonce: nonce, Replicas: 3, ConnectTimeout: 3 * time.Second, RequestTimeout: 3 * time.Second, FetchTimeout: 500 * time.Millisecond, AckWait: 2 * time.Second, DuplicateWindow: 2 * time.Minute}
	s.probe, err = jetstreamprobe.Open(ctx, cfg)
	if err != nil {
		return err
	}
	connectedID := s.probe.ConnectedServerID()
	pod0 := natsFixtureName + "-0"
	if connectedID == "" || connectedID != s.serverIDs[pod0] {
		s.probe.Close()
		s.probe = nil
		return fmt.Errorf("NATS probe connection identity %q differs from exact port-forward member %s/%s", connectedID, pod0, s.serverIDs[pod0])
	}
	s.connectedMember = pod0
	return nil
}

type natsVarz struct {
	ServerID   string `json:"server_id"`
	ServerName string `json:"server_name"`
	Version    string `json:"version"`
	JetStream  struct {
		Config json.RawMessage `json:"config"`
	} `json:"jetstream"`
}

func natsPodVarz(ctx context.Context, env *core.Env, pod string) (natsVarz, error) {
	raw, err := env.Kube.CoreV1().RESTClient().Get().AbsPath(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s:%d/proxy/varz", env.Config.Namespace, pod, natsMonitorPort)).DoRaw(ctx)
	if err != nil {
		return natsVarz{}, err
	}
	return decodeNATSVarz(raw, pod)
}

func decodeNATSVarz(raw []byte, pod string) (natsVarz, error) {
	var value natsVarz
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, err
	}
	config := bytes.TrimSpace(value.JetStream.Config)
	if value.ServerID == "" || value.ServerName != pod || value.Version != "2.10.29" || len(config) == 0 || bytes.Equal(config, []byte("null")) {
		return value, errors.New("NATS varz identity/version/JetStream differs")
	}
	return value, nil
}

func (s *c2NATSJetStreamDurability) restartMember(ctx context.Context, env *core.Env, ordinal int) (jetstreamprobe.RestartBoundaryReceipt, error) {
	podName := fmt.Sprintf("%s-%d", natsFixtureName, ordinal)
	if ordinal != 2 || podName == s.connectedMember {
		return jetstreamprobe.RestartBoundaryReceipt{}, errors.New("restart must target exact non-client fixture member c2-nats-js-2")
	}
	uid := s.pods[podName]
	if uid == "" {
		return jetstreamprobe.RestartBoundaryReceipt{}, errors.New("restart Pod UID missing")
	}
	fixture := env.Config.NATSJetStreamFixture
	if fixture == nil {
		return jetstreamprobe.RestartBoundaryReceipt{}, errors.New("restart fixture authority missing")
	}
	_, before, volume, err := s.validateCurrentMember(ctx, env, fixture, ordinal, uid, s.serverIDs[podName])
	if err != nil {
		return jetstreamprobe.RestartBoundaryReceipt{}, err
	}
	gen := env.Exec(ctx, podName, "nats", []string{"/bin/sh", "-ec", "cat /control/generation"})
	if gen.Err != nil || gen.ExitCode != 0 {
		return jetstreamprobe.RestartBoundaryReceipt{}, fmt.Errorf("read old generation: %v", gen.Err)
	}
	oldGeneration := strings.TrimSpace(gen.Stdout)
	storage := s.storage[ordinal]
	_, beforeAction, volume, err := s.validateCurrentMember(ctx, env, fixture, ordinal, uid, before.ServerID)
	if err != nil {
		return jetstreamprobe.RestartBoundaryReceipt{}, err
	}
	before = beforeAction
	boundary := jetstreamprobe.RestartBoundaryReceipt{Member: podName, OldProcessID: before.ServerID, WorkloadUIDBefore: string(uid), VolumeUIDBefore: volume, StorePathHashBefore: storage.PathHash}
	boundary.ActionAttempted = true
	started := time.Now()
	action := env.Exec(ctx, podName, "nats", []string{"/bin/sh", "-ec", "touch /control/restart && kill -TERM \"$(cat /control/pid)\""})
	if action.Err != nil || action.ExitCode != 0 {
		boundary.ElapsedNanos = time.Since(started).Nanoseconds()
		return boundary, fmt.Errorf("one-send child restart: exit=%d err=%v stderr=%s", action.ExitCode, action.Err, action.Stderr)
	}
	boundary.ActionSent = true
	boundary.ActionCompleted = true
	deadline := time.Now().Add(30 * time.Second)
	var after natsVarz
	for time.Now().Before(deadline) {
		newGen := env.Exec(ctx, podName, "nats", []string{"/bin/sh", "-ec", "cat /control/generation"})
		_, candidate, _, readErr := s.validateCurrentMember(ctx, env, fixture, ordinal, uid, "")
		if newGen.Err == nil && newGen.ExitCode == 0 && strings.TrimSpace(newGen.Stdout) != oldGeneration && readErr == nil && candidate.ServerID != before.ServerID {
			after = candidate
			break
		}
		select {
		case <-ctx.Done():
			boundary.ElapsedNanos = time.Since(started).Nanoseconds()
			return boundary, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if after.ServerID == "" || after.ServerID == before.ServerID {
		boundary.ElapsedNanos = time.Since(started).Nanoseconds()
		return boundary, errors.New("NATS child process identity did not change")
	}
	_, confirmed, afterVolume, err := s.validateCurrentMember(ctx, env, fixture, ordinal, uid, after.ServerID)
	boundary.ElapsedNanos = time.Since(started).Nanoseconds()
	boundary.NewProcessID = after.ServerID
	boundary.WorkloadUIDAfter = string(uid)
	boundary.VolumeUIDAfter = afterVolume
	boundary.StorePathHashAfter = storage.PathHash
	if err != nil {
		return boundary, err
	}
	s.serverIDs[podName] = confirmed.ServerID
	return boundary, nil
}

func (s *c2NATSJetStreamDurability) requireStorageBinding(ctx context.Context, env *core.Env, fixture *config.NATSJetStreamFixtureConfig, storage natsStorageIdentity) (string, error) {
	pvc, err := env.Kube.CoreV1().PersistentVolumeClaims(env.Config.Namespace).Get(ctx, storage.PVCName, metav1.GetOptions{})
	if err != nil || pvc.UID != storage.PVCUID || pvc.DeletionTimestamp != nil || pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != fixture.StorageClass || pvc.Spec.VolumeName != storage.PVName || pvc.Status.Phase != corev1.ClaimBound || pvc.Labels["fixture.phorvex.ai/nonce"] != fixture.Nonce {
		return "", fmt.Errorf("NATS PVC %s binding differs: %v", storage.PVCName, err)
	}
	pv, err := env.Kube.CoreV1().PersistentVolumes().Get(ctx, storage.PVName, metav1.GetOptions{})
	if err != nil || pv.UID != storage.PVUID || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != storage.PVCUID || pv.Status.Phase != corev1.VolumeBound {
		return "", fmt.Errorf("NATS PV %s binding differs: %v", storage.PVName, err)
	}
	var authority *config.NATSJetStreamLocalPV
	for i := range fixture.PVs {
		if fixture.PVs[i].Name == storage.PVName && fixture.PVs[i].UID == string(storage.PVUID) && fixture.PVs[i].Slot == storage.Slot && fixture.PVs[i].PathSHA256 == storage.PathHash {
			authority = &fixture.PVs[i]
			break
		}
	}
	if authority == nil {
		return "", fmt.Errorf("NATS PV %s is outside configured storage authority", storage.PVName)
	}
	if err := validateNATSLocalPV(pv, *authority, fixture, false); err != nil {
		return "", fmt.Errorf("NATS PV %s current authority differs: %w", storage.PVName, err)
	}
	return string(storage.PVCUID) + "/" + string(storage.PVUID), nil
}

func (s *c2NATSJetStreamDurability) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	started := time.Now()
	if s.unavailable != "" {
		return core.AttackResult{Skipped: true, SkipReason: s.unavailable}, nil
	}
	if s.probe == nil {
		return core.AttackResult{}, errors.New("NATS probe missing")
	}
	a := jetstreamprobe.Message{ID: env.Config.NATSJetStreamFixture.Nonce + "-a", Payload: []byte("synthetic-nats-durability-a")}
	b := jetstreamprobe.Message{ID: env.Config.NATSJetStreamFixture.Nonce + "-b", Payload: []byte("synthetic-nats-durability-b")}
	evidence := s.identityEvidence(env)
	if s.mode == "no-action" {
		receipt, err := s.probe.RunNoActionOracle(ctx, a, b, 45*time.Second)
		s.noActionReceipt = &receipt
		raw, marshalErr := json.Marshal(receipt)
		for key, value := range map[string]string{"securityOutcome": "not-measured", "availabilityOutcome": "protocol-available", "stateOutcome": "acknowledged-A-and-B-contiguous", "oracleStatus": "complete", "oracleReceiptJSON": string(raw), "protocolReceiptSHA256": fmt.Sprintf("%x", sha256.Sum256(raw)), "messageASequence": strconv.FormatUint(receipt.MessageA.Sequence, 10), "messageBSequence": strconv.FormatUint(receipt.MessageB.Sequence, 10), "actionAttempted": "false", "actionCompleted": "false", "actionCount": "0", "elapsedMillis": strconv.FormatInt(time.Since(started).Milliseconds(), 10)} {
			evidence[key] = value
		}
		if err != nil {
			evidence["oracleStatus"] = "incomplete"
			evidence["availabilityOutcome"] = "incomplete"
			evidence["stateOutcome"] = "partial-receipt-retained"
		}
		s.baseline = evidence
		result, evidenceErr := natsBenchmarkResult(noActionStages(receipt), evidence)
		return result, errors.Join(err, marshalErr, evidenceErr)
	}
	receipt, err := s.probe.RunRestartOracle(ctx, a, b, func(callCtx context.Context) (jetstreamprobe.RestartBoundaryReceipt, error) {
		return s.restartMember(callCtx, env, 2)
	}, 45*time.Second)
	s.receipt = &receipt
	raw, marshalErr := json.Marshal(receipt)
	actionCount := "0"
	if receipt.Restart.ActionSent {
		actionCount = "1"
	} else if receipt.Restart.ActionAttempted {
		actionCount = "unobserved"
	}
	for key, value := range map[string]string{"securityOutcome": "not-measured", "availabilityOutcome": "protocol-restored-after-one-non-client-member-child-restart", "availabilityDuringRestart": "unobserved", "clientFailoverOutcome": "not-measured", "leaderFailoverOutcome": "not-measured", "stateOutcome": "acknowledged-A-stored-across-restart-and-B-contiguous", "oracleStatus": "complete", "oracleReceiptJSON": string(raw), "restartReceiptSHA256": fmt.Sprintf("%x", sha256.Sum256(raw)), "messageASequence": strconv.FormatUint(receipt.MessageA.Sequence, 10), "messageBSequence": strconv.FormatUint(receipt.MessageB.Sequence, 10), "member": receipt.Restart.Member, "oldServerID": receipt.Restart.OldProcessID, "newServerID": receipt.Restart.NewProcessID, "actionAttempted": strconv.FormatBool(receipt.Restart.ActionAttempted), "actionCompleted": strconv.FormatBool(receipt.Restart.ActionCompleted), "actionCount": actionCount, "podReplacementCount": observedIdentityChanges(receipt.Restart.WorkloadUIDBefore, receipt.Restart.WorkloadUIDAfter), "volumeChangeCount": observedIdentityChanges(receipt.Restart.VolumeUIDBefore, receipt.Restart.VolumeUIDAfter), "restartBoundaryElapsedNanos": strconv.FormatInt(receipt.Restart.ElapsedNanos, 10), "replicaRecoveryElapsedNanos": strconv.FormatInt(receipt.RecoveryElapsedNanos, 10), "elapsedMillis": strconv.FormatInt(time.Since(started).Milliseconds(), 10)} {
		evidence[key] = value
	}
	if err != nil {
		evidence["oracleStatus"] = "incomplete"
		evidence["availabilityOutcome"] = "incomplete"
		evidence["stateOutcome"] = "partial-receipt-retained"
	}
	s.baseline = evidence
	result, evidenceErr := natsBenchmarkResult(restartStages(receipt), evidence)
	return result, errors.Join(err, marshalErr, evidenceErr)
}

func (s *c2NATSJetStreamDurability) identityEvidence(env *core.Env) map[string]string {
	revision, modified := harnessVCSIdentity()
	out := map[string]string{"suiteVersion": natsDurabilitySuite, "mode": s.mode, "fixtureImage": natsImage, "fixtureNATSVersion": "2.10.29", "probeLibrary": "github.com/nats-io/nats.go@v1.47.0", "fixtureNonce": env.Config.NATSJetStreamFixture.Nonce, "nodeName": env.Config.NATSJetStreamFixture.NodeName, "nodeUID": env.Config.NATSJetStreamFixture.NodeUID, "storageClass": env.Config.NATSJetStreamFixture.StorageClass, "storageClassUID": env.Config.NATSJetStreamFixture.StorageClassUID, "connectedMember": s.connectedMember, "restartScope": "exact-non-client-member-c2-nats-js-2", "natsReconnectPolicy": "MaxReconnects(0)", "harnessVCSRevision": revision, "harnessVCSModified": modified, "installedDispatchProven": "false", "directNativeActuatorProven": "false", "cveOutcome": "not-measured", "costObservation": "resource-requests-only", "cpuRequestMillicores": "75", "memoryRequestBytes": "100663296"}
	for ordinal := range 3 {
		name := fmt.Sprintf("%s-%d", natsFixtureName, ordinal)
		out[fmt.Sprintf("pod%dUID", ordinal)] = string(s.pods[name])
		out[fmt.Sprintf("server%dID", ordinal)] = s.serverIDs[name]
		out[fmt.Sprintf("pvc%dUID", ordinal)] = string(s.storage[ordinal].PVCUID)
		out[fmt.Sprintf("pv%dUID", ordinal)] = string(s.storage[ordinal].PVUID)
		out[fmt.Sprintf("store%dPathSHA256", ordinal)] = s.storage[ordinal].PathHash
	}
	return out
}

func harnessVCSIdentity() (string, string) {
	revision, modified := "unavailable", "unavailable"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value
			}
		}
	}
	return revision, modified
}

func observedIdentityChanges(before, after string) string {
	if before == "" || after == "" {
		return "unobserved"
	}
	if before == after {
		return "0"
	}
	return "1"
}

func natsBenchmarkResult(stages []string, evidence map[string]string) (core.AttackResult, error) {
	if err := validateNATSBenchmarkEvidence(evidence); err != nil {
		return core.AttackResult{Stages: stages}, err
	}
	return core.AttackResult{Stages: stages, BenchmarkEvidence: evidence}, nil
}

func noActionStages(receipt jetstreamprobe.NoActionOracleReceipt) []string {
	stages := []string{}
	if len(receipt.Baseline.Stream.Members) == 3 && len(receipt.Baseline.Consumer.Members) == 3 {
		stages = append(stages, "establish exact three-replica JetStream protocol state")
	}
	if receipt.MessageA.Sequence != 0 {
		stages = append(stages, "publish synthetic message A with a real PubAck")
	}
	if receipt.DeliveryA.StreamSequence != 0 {
		stages = append(stages, "consume and acknowledge synthetic message A")
	}
	if receipt.StoredA.StreamSequence != 0 {
		stages = append(stages, "read message A independently from stream storage")
	}
	if receipt.MessageB.Sequence != 0 {
		stages = append(stages, "publish contiguous synthetic message B with a real PubAck")
	}
	if receipt.DeliveryB.StreamSequence != 0 {
		stages = append(stages, "consume and acknowledge synthetic message B")
	}
	if receipt.FinalState.LastSequence != 0 {
		stages = append(stages, "confirm final stream and consumer state")
	}
	return stages
}

func restartStages(receipt jetstreamprobe.RestartOracleReceipt) []string {
	stages := []string{}
	if len(receipt.Baseline.Stream.Members) == 3 && len(receipt.Baseline.Consumer.Members) == 3 {
		stages = append(stages, "establish exact three-replica JetStream protocol state")
	}
	if receipt.MessageA.Sequence != 0 {
		stages = append(stages, "publish synthetic message A with a real PubAck")
	}
	if receipt.DeliveryA.StreamSequence != 0 {
		stages = append(stages, "consume and acknowledge synthetic message A")
	}
	if receipt.StoredBefore.StreamSequence != 0 {
		stages = append(stages, "read message A independently before restart")
	}
	if receipt.Restart.ActionAttempted {
		stages = append(stages, "attempt one restart action on exact non-client fixture member")
	}
	if receipt.Restart.ActionSent {
		stages = append(stages, "confirm one restart action completed")
	}
	if receipt.Restart.NewProcessID != "" && receipt.Restart.WorkloadUIDBefore == receipt.Restart.WorkloadUIDAfter && receipt.Restart.VolumeUIDBefore == receipt.Restart.VolumeUIDAfter && receipt.Restart.StorePathHashBefore == receipt.Restart.StorePathHashAfter {
		stages = append(stages, "bind changed child process to unchanged Pod and local volume")
	}
	if len(receipt.Recovered.Stream.Members) == 3 && len(receipt.Recovered.Consumer.Members) == 3 {
		stages = append(stages, "confirm exact replica recovery")
	}
	if receipt.StoredAfter.StreamSequence != 0 {
		stages = append(stages, "read message A independently after recovery")
	}
	if receipt.MessageB.Sequence != 0 {
		stages = append(stages, "publish contiguous synthetic message B with a real PubAck")
	}
	if receipt.DeliveryB.StreamSequence != 0 {
		stages = append(stages, "consume and acknowledge synthetic message B")
	}
	if receipt.FinalState.LastSequence != 0 {
		stages = append(stages, "confirm final stream and consumer state")
	}
	return stages
}

func validateNATSBenchmarkEvidence(evidence map[string]string) error {
	if len(evidence) == 0 || len(evidence) > natsEvidenceMaxItems {
		return fmt.Errorf("NATS benchmark evidence item count %d exceeds bound", len(evidence))
	}
	total := 0
	for key, value := range evidence {
		if key == "" || len(key) > natsEvidenceMaxKey || len(value) > natsEvidenceMaxValue {
			return fmt.Errorf("NATS benchmark evidence field %q exceeds key/value bound", key)
		}
		total += len(key) + len(value)
	}
	if total > natsEvidenceMaxTotal {
		return fmt.Errorf("NATS benchmark evidence size %d exceeds bound", total)
	}
	return nil
}

func (s *c2NATSJetStreamDurability) SuccessOracle(context.Context, *core.Env) (core.OracleResult, error) {
	if s.receipt == nil && s.noActionReceipt == nil {
		return core.OracleResult{}, errors.New("NATS protocol receipt missing")
	}
	state := "functional NATS no-action control: acknowledged A and B retained exact contiguous state; security outcome not measured"
	if s.receipt != nil {
		state = "functional NATS durability control: exact stored A survived one child restart and acknowledged B used the next stream sequence; security outcome not measured"
	}
	return core.OracleResult{Achieved: true, ObservedState: state, Evidence: s.baseline}, nil
}

func natsFixturePodName(name string) bool {
	for ordinal := range 3 {
		if name == fmt.Sprintf("%s-%d", natsFixtureName, ordinal) {
			return true
		}
	}
	return false
}

func natsOwnedDescendants(pods []corev1.Pod, statefulSetUID types.UID, bound map[string]types.UID) (int, error) {
	remaining := 0
	for i := range pods {
		pod := &pods[i]
		owned := natsControllerOwner(pod, statefulSetUID)
		if natsFixturePodName(pod.Name) && !owned {
			return remaining, fmt.Errorf("NATS Pod %s is a foreign same-name object UID=%s; PVC cleanup withheld", pod.Name, pod.UID)
		}
		if !owned {
			continue
		}
		if expected := bound[pod.Name]; expected != "" && pod.UID != expected {
			return remaining, fmt.Errorf("NATS Pod %s changed from bound UID %s to %s; PVC cleanup withheld", pod.Name, expected, pod.UID)
		}
		if !natsFixturePodName(pod.Name) {
			return remaining, fmt.Errorf("StatefulSet UID %s has unexpected descendant Pod %s; PVC cleanup withheld", statefulSetUID, pod.Name)
		}
		remaining++
	}
	return remaining, nil
}

func (s *c2NATSJetStreamDurability) Teardown(ctx context.Context, env *core.Env) error {
	if s.probe != nil {
		s.probe.Close()
		s.probe = nil
	}
	if s.portStop != nil {
		close(s.portStop)
		s.portStop = nil
		select {
		case <-s.portDone:
		case <-time.After(3 * time.Second):
		}
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	ns := env.Config.Namespace
	var errs []error
	deleteOne := func(kind, name string, uid types.UID, fn func(metav1.DeleteOptions) error) {
		if uid == "" {
			return
		}
		opts := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}
		if err := fn(opts); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete %s %s uid=%s: %w", kind, name, uid, err))
		}
	}
	deleteOne("StatefulSet", natsFixtureName, s.statefulSetUID, func(o metav1.DeleteOptions) error {
		return env.Kube.AppsV1().StatefulSets(ns).Delete(ctx, natsFixtureName, o)
	})
	if s.statefulSetUID != "" {
		deadline := time.Now().Add(60 * time.Second)
		podsGone := false
		for time.Now().Before(deadline) {
			pods, err := env.Kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				errs = append(errs, fmt.Errorf("list NATS Pods during cleanup: %w", err))
				return errors.Join(errs...)
			}
			remaining, err := natsOwnedDescendants(pods.Items, s.statefulSetUID, s.pods)
			if err != nil {
				errs = append(errs, err)
				return errors.Join(errs...)
			}
			if remaining == 0 {
				podsGone = true
				break
			}
			select {
			case <-ctx.Done():
				errs = append(errs, ctx.Err())
				return errors.Join(errs...)
			case <-time.After(250 * time.Millisecond):
			}
		}
		if !podsGone {
			errs = append(errs, errors.New("NATS fixture Pods remain; PVC cleanup withheld"))
			return errors.Join(errs...)
		}
	}
	deleteOne("Service", natsClientService, s.clientUID, func(o metav1.DeleteOptions) error {
		return env.Kube.CoreV1().Services(ns).Delete(ctx, natsClientService, o)
	})
	deleteOne("Service", natsHeadlessService, s.headlessUID, func(o metav1.DeleteOptions) error {
		return env.Kube.CoreV1().Services(ns).Delete(ctx, natsHeadlessService, o)
	})
	for _, storage := range s.storage {
		storage := storage
		deleteOne("PVC", storage.PVCName, storage.PVCUID, func(o metav1.DeleteOptions) error {
			return env.Kube.CoreV1().PersistentVolumeClaims(ns).Delete(ctx, storage.PVCName, o)
		})
	}
	for _, storage := range s.storage {
		if storage.PVCUID == "" {
			continue
		}
		deadline := time.Now().Add(60 * time.Second)
		for {
			pvc, err := env.Kube.CoreV1().PersistentVolumeClaims(ns).Get(ctx, storage.PVCName, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				break
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("verify NATS PVC %s retirement: %w", storage.PVCName, err))
				break
			}
			if pvc.UID != storage.PVCUID {
				errs = append(errs, fmt.Errorf("NATS PVC %s was replaced by foreign UID %s", storage.PVCName, pvc.UID))
				break
			}
			if time.Now().After(deadline) {
				errs = append(errs, fmt.Errorf("NATS PVC %s remains after bounded cleanup", storage.PVCName))
				break
			}
			select {
			case <-ctx.Done():
				errs = append(errs, ctx.Err())
				return errors.Join(errs...)
			case <-time.After(250 * time.Millisecond):
			}
		}
		deadline = time.Now().Add(60 * time.Second)
		retired := false
		for time.Now().Before(deadline) {
			pv, err := env.Kube.CoreV1().PersistentVolumes().Get(ctx, storage.PVName, metav1.GetOptions{})
			if err != nil || pv.UID != storage.PVUID || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != storage.PVCUID {
				errs = append(errs, fmt.Errorf("NATS retained PV %s retirement identity differs: %v", storage.PVName, err))
				break
			}
			if pv.Status.Phase == corev1.VolumeReleased {
				retired = true
				break
			}
			select {
			case <-ctx.Done():
				errs = append(errs, ctx.Err())
				return errors.Join(errs...)
			case <-time.After(250 * time.Millisecond):
			}
		}
		if !retired {
			errs = append(errs, fmt.Errorf("NATS retained PV %s did not reach exact Released binding", storage.PVName))
		}
	}
	return errors.Join(errs...)
}
