package scenarios

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

func TestNATSDurabilityMetadataKeepsFunctionalAndSecurityOutcomesSeparate(t *testing.T) {
	meta := (&c2NATSJetStreamDurability{}).Metadata()
	if !meta.BenignControl || meta.EffectiveRealism() != core.RealismExecutable || len(meta.AttackTechniqueIDs) != 0 || len(meta.ExercisedTechniqueIDs) != 0 {
		t.Fatalf("metadata=%+v", meta)
	}
	for _, limit := range []string{"no CVE", "installed dispatch", "security efficacy", "node/zone/disk failure"} {
		if !strings.Contains(meta.ClaimLimits, limit) {
			t.Errorf("missing claim limit %q", limit)
		}
	}
}

func TestNATSLocalPVAuthorityRefusesIdentityPathAndForeignClaim(t *testing.T) {
	fixture := &config.NATSJetStreamFixtureConfig{StorageClass: "nats-local", NodeUID: "node-uid", HolderUID: "holder-uid", Nonce: "nonce"}
	path := natsLocalPath(fixture.HolderUID, 7)
	authority := config.NATSJetStreamLocalPV{Name: "nats-pv-7", UID: "pv-uid", Slot: 7, PathSHA256: natsPathHash(path)}
	reclaim := corev1.PersistentVolumeReclaimRetain
	mode := corev1.PersistentVolumeFilesystem
	fixture.NodeName = "reviewed-node"
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: authority.Name, UID: types.UID(authority.UID), Annotations: map[string]string{"fixture.phorvex.ai/holder-uid": fixture.HolderUID, "fixture.phorvex.ai/node-uid": fixture.NodeUID, "fixture.phorvex.ai/nonce": fixture.Nonce, "fixture.phorvex.ai/slot": "7", "fixture.phorvex.ai/local-path-sha256": authority.PathSHA256}}, Spec: corev1.PersistentVolumeSpec{Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(natsStorageCapacity)}, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, PersistentVolumeReclaimPolicy: reclaim, StorageClassName: fixture.StorageClass, VolumeMode: &mode, NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{fixture.NodeName}}}}}}}, PersistentVolumeSource: corev1.PersistentVolumeSource{Local: &corev1.LocalVolumeSource{Path: path}}}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeAvailable}}
	if err := validateNATSLocalPV(pv, authority, fixture, true); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*corev1.PersistentVolume){
		"replacement uid": func(p *corev1.PersistentVolume) { p.UID = "replacement" },
		"foreign path":    func(p *corev1.PersistentVolume) { p.Spec.Local.Path = "/foreign" },
		"foreign claim":   func(p *corev1.PersistentVolume) { p.Spec.ClaimRef = &corev1.ObjectReference{UID: "foreign"} },
		"wrong nonce":     func(p *corev1.PersistentVolume) { p.Annotations["fixture.phorvex.ai/nonce"] = "foreign" },
		"wrong slot":      func(p *corev1.PersistentVolume) { p.Annotations["fixture.phorvex.ai/slot"] = "8" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := pv.DeepCopy()
			mutate(candidate)
			if err := validateNATSLocalPV(candidate, authority, fixture, true); err == nil {
				t.Fatal("foreign PV authority accepted")
			}
		})
	}
}

func TestNATSStorageClassRequiresExactUIDAndRetainContract(t *testing.T) {
	immediate := storagev1.VolumeBindingImmediate
	retain := corev1.PersistentVolumeReclaimRetain
	fixture := &config.NATSJetStreamFixtureConfig{StorageClass: "nats-local", StorageClassUID: "11111111-2222-4333-8444-555555555555", Nonce: "nonce"}
	sc := &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: fixture.StorageClass, UID: types.UID(fixture.StorageClassUID), Annotations: map[string]string{"fixture.phorvex.ai/nonce": fixture.Nonce}}, Provisioner: "kubernetes.io/no-provisioner", ReclaimPolicy: &retain, VolumeBindingMode: &immediate}
	if err := validateNATSStorageClass(sc, fixture); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*storagev1.StorageClass){
		"replacement uid": func(value *storagev1.StorageClass) { value.UID = "replacement" },
		"wrong nonce":     func(value *storagev1.StorageClass) { value.Annotations["fixture.phorvex.ai/nonce"] = "foreign" },
		"provisioner":     func(value *storagev1.StorageClass) { value.Provisioner = "example.invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := sc.DeepCopy()
			mutate(candidate)
			if err := validateNATSStorageClass(candidate, fixture); err == nil {
				t.Fatal("foreign StorageClass authority accepted")
			}
		})
	}
}

func TestNATSSupervisorUsesPinnedImageAndChildRestartBoundary(t *testing.T) {
	if !strings.Contains(natsImage, "@sha256:") || !strings.Contains(natsSupervisorScript, "wait \"$child\"") || !strings.Contains(natsSupervisorScript, "/control/restart") || !strings.Contains(natsSupervisorScript, "--store_dir /data/jetstream") {
		t.Fatal("NATS image or supervisor persistence/restart boundary differs")
	}
}

func TestNATSVarzDecoderUsesActualServerMonitorSchema(t *testing.T) {
	start := func(t *testing.T, jetStream bool) (*server.Server, []byte) {
		t.Helper()
		opts := &server.Options{ServerName: "fixture-monitor", Host: "127.0.0.1", Port: -1, HTTPHost: "127.0.0.1", HTTPPort: -1, NoLog: true, NoSigs: true, JetStream: jetStream}
		if jetStream {
			opts.StoreDir = filepath.Join(t.TempDir(), "jetstream")
		}
		srv, err := server.NewServer(opts)
		if err != nil {
			t.Fatal(err)
		}
		go srv.Start()
		if !srv.ReadyForConnections(5 * time.Second) {
			srv.Shutdown()
			t.Fatal("embedded NATS 2.10.29 monitor producer did not become ready")
		}
		t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/varz", srv.MonitorAddr().Port))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return srv, raw
	}

	enabled, rawEnabled := start(t, true)
	value, err := decodeNATSVarz(rawEnabled, "fixture-monitor")
	if err != nil {
		t.Fatalf("actual JetStream-enabled /varz rejected: %v; body=%s", err, rawEnabled)
	}
	if value.ServerID != enabled.ID() || len(value.JetStream.Config) == 0 {
		t.Fatalf("actual /varz identity/config not retained: %+v", value)
	}
	_, rawDisabled := start(t, false)
	if _, err := decodeNATSVarz(rawDisabled, "fixture-monitor"); err == nil {
		t.Fatalf("actual JetStream-disabled /varz accepted: %s", rawDisabled)
	}
}

func TestNATSBenchmarkEvidenceIsBoundedAtProducer(t *testing.T) {
	valid := map[string]string{"oracleStatus": "incomplete"}
	if err := validateNATSBenchmarkEvidence(valid); err != nil {
		t.Fatal(err)
	}
	valid["oracleReceiptJSON"] = strings.Repeat("x", natsEvidenceMaxValue+1)
	if err := validateNATSBenchmarkEvidence(valid); err == nil {
		t.Fatal("oversized benchmark evidence value accepted")
	}
}

func TestNATSWorkloadBuilderCreatesOnlyPinnedThreeMemberFixture(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	sequence := 0
	client.Fake.PrependReactor("create", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create := action.(k8stesting.CreateAction)
		obj := create.GetObject()
		sequence++
		uid := types.UID(fmt.Sprintf("created-%d", sequence))
		switch value := obj.(type) {
		case *corev1.Service:
			value.UID = uid
		case interface{ SetUID(types.UID) }:
			value.SetUID(uid)
		}
		return false, nil, nil
	})
	env := &core.Env{Kube: client, Config: config.TargetConfig{Namespace: "sandbox"}, ScenarioName: natsDurabilityScenario, Trial: 0}
	fixture := &config.NATSJetStreamFixtureConfig{StorageClass: "nats-local", NodeName: "reviewed-node", Nonce: "nonce"}
	scenario := &c2NATSJetStreamDurability{}
	if err := scenario.createWorkload(context.Background(), env, fixture); err != nil {
		t.Fatal(err)
	}
	sts, err := client.AppsV1().StatefulSets("sandbox").Get(context.Background(), natsFixtureName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 3 || sts.Spec.ServiceName != natsHeadlessService || len(sts.Spec.VolumeClaimTemplates) != 1 || sts.Spec.VolumeClaimTemplates[0].Name != "store" {
		t.Fatalf("StatefulSet=%+v", sts.Spec)
	}
	container := sts.Spec.Template.Spec.Containers[0]
	if container.Image != natsImage || !strings.Contains(strings.Join(container.Command, " "), natsSupervisorScript) || sts.Spec.Template.Spec.NodeSelector["kubernetes.io/hostname"] != fixture.NodeName {
		t.Fatalf("container/node contract=%+v", container)
	}
	for _, name := range []string{natsHeadlessService, natsClientService} {
		if _, err := client.CoreV1().Services("sandbox").Get(context.Background(), name, metav1.GetOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}
