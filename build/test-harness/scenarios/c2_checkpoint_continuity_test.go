package scenarios

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func TestCheckpointContinuityMetadataIsBenign(t *testing.T) {
	m := (&c2CheckpointContinuity{}).Metadata()
	if !m.BenignControl || m.EffectiveRealism() != core.RealismExecutable || len(m.AttackTechniqueIDs) != 0 || len(m.ExercisedTechniqueIDs) != 0 {
		t.Fatalf("metadata=%+v", m)
	}
	for _, s := range []string{"zero ATT&CK", "continuous-availability", "GPU-training", "security-coverage"} {
		if !strings.Contains(m.ClaimLimits, s) {
			t.Errorf("missing limit %q", s)
		}
	}
}

func TestCheckpointServerActualRestartContinuity(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	first := startCheckpointServer(t, dir, port, "pod-old", "pvc-owned", "")
	one := waitCheckpointHTTP(t, port, func(b checkpointBody) bool { return b.Ready != nil && *b.Ready && b.Sequence >= 1 })
	two := waitCheckpointHTTP(t, port, func(b checkpointBody) bool { return b.Sequence > one.Sequence })
	if two.Incarnation != one.Incarnation || two.BootSequence != 0 || two.InitializedFresh == nil || !*two.InitializedFresh {
		t.Fatalf("fresh process provenance=%+v", two)
	}
	stopCheckpointServer(t, first)
	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint.json"))
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := parseCheckpointFile(raw)
	if err != nil || persisted.Sequence < two.Sequence {
		t.Fatalf("persisted=%+v err=%v acknowledged=%d", persisted, err, two.Sequence)
	}
	second := startCheckpointServer(t, dir, port, "pod-new", "pvc-owned", "")
	defer stopCheckpointServer(t, second)
	restarted := waitCheckpointHTTP(t, port, func(b checkpointBody) bool { return b.PodUID == "pod-new" && b.Sequence > b.BootSequence })
	if restarted.Incarnation == two.Incarnation || restarted.BootSequence < two.Sequence || restarted.InitializedFresh == nil || *restarted.InitializedFresh {
		t.Fatalf("restart did not load durable checkpoint: before=%+v after=%+v", two, restarted)
	}
}

func TestCheckpointServerRejectsInvalidAndFaultedStorage(t *testing.T) {
	for _, tc := range []struct{ name, contents, fault string }{{"truncated", "{", ""}, {"unsupported-version", `{"checksum":"bad","payload":"synthetic-sequence-00000000000000000001","sequence":1,"version":2}`, ""}, {"bool-version", `{"checksum":"bad","payload":"synthetic-sequence-00000000000000000001","sequence":1,"version":true}`, ""}, {"checksum", `{"checksum":"bad","payload":"synthetic-sequence-00000000000000000001","sequence":1,"version":1}`, ""}, {"duplicate-field", `{"version":1,"version":1,"sequence":0,"payload":"synthetic-sequence-00000000000000000000","checksum":"unused"}`, ""}, {"oversized", strings.Repeat("x", 8193), ""}, {"file-fsync-fault", "", "before-file-fsync"}, {"replace-fault", "", "before-replace"}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.contents != "" {
				if err := os.WriteFile(filepath.Join(dir, "checkpoint.json"), []byte(tc.contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			port := freePort(t)
			cmd := startCheckpointServer(t, dir, port, "pod", "pvc", tc.fault)
			defer stopCheckpointServer(t, cmd)
			status, b := waitCheckpointEnvelope(t, port, func(status int, b checkpointBody) bool { return status == 503 && b.Ready != nil && !*b.Ready })
			if status != 503 || b.Error == "" {
				t.Fatalf("invalid storage accepted: status=%d body=%+v", status, b)
			}
		})
	}
}

func TestCheckpointServerWritesAsActualNonRootProcess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root test process")
	}
	dir := t.TempDir()
	port := freePort(t)
	cmd := startCheckpointServer(t, dir, port, "pod", "pvc", "")
	written := waitCheckpointHTTP(t, port, func(b checkpointBody) bool { return b.Sequence >= 1 })
	stopCheckpointServer(t, cmd)
	if written.PodUID != "pod" || written.PVCUID != "pvc" {
		t.Fatalf("writer identity=%+v", written)
	}
	if _, err := os.Stat(filepath.Join(dir, "checkpoint.json")); err != nil {
		t.Fatalf("non-root writer did not create checkpoint: %v", err)
	}
}

func TestCheckpointLocalMarkerInitStrictlyBindsOpenedRegularFile(t *testing.T) {
	holderUID := "11111111-2222-4333-8444-555555555555"
	nodeName := "reviewed-node"
	nonce := "checkpoint-local-r1"
	valid := []byte(`{"campaignNonce":"checkpoint-local-r1","holderPodUID":"11111111-2222-4333-8444-555555555555","nodeName":"reviewed-node","schema":"post25-checkpoint-local-holder-marker-v1","slot":0}` + "\n")
	cases := []struct {
		name    string
		raw     []byte
		prepare func(string) error
		ok      bool
	}{
		{name: "canonical", raw: valid, ok: true},
		{name: "missing"},
		{name: "null", raw: []byte(`{"campaignNonce":null,"holderPodUID":"11111111-2222-4333-8444-555555555555","nodeName":"reviewed-node","schema":"post25-checkpoint-local-holder-marker-v1","slot":0}` + "\n")},
		{name: "duplicate", raw: []byte(`{"campaignNonce":"checkpoint-local-r1","campaignNonce":"checkpoint-local-r1","holderPodUID":"11111111-2222-4333-8444-555555555555","nodeName":"reviewed-node","schema":"post25-checkpoint-local-holder-marker-v1","slot":0}` + "\n")},
		{name: "case-variant", raw: []byte(`{"CampaignNonce":"checkpoint-local-r1","holderPodUID":"11111111-2222-4333-8444-555555555555","nodeName":"reviewed-node","schema":"post25-checkpoint-local-holder-marker-v1","slot":0}` + "\n")},
		{name: "trailing", raw: append(append([]byte{}, valid...), []byte("{}")...)},
		{name: "wrong-slot", raw: bytes.Replace(valid, []byte(`"slot":0`), []byte(`"slot":1`), 1)},
		{name: "bool-slot", raw: bytes.Replace(valid, []byte(`"slot":0`), []byte(`"slot":false`), 1)},
		{name: "oversized", raw: bytes.Repeat([]byte("x"), 1025)},
		{name: "directory", prepare: func(dir string) error { return os.Mkdir(filepath.Join(dir, checkpointLocalMarker), 0700) }},
		{name: "symlink", prepare: func(dir string) error {
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, valid, 0600); err != nil {
				return err
			}
			return os.Symlink(target, filepath.Join(dir, checkpointLocalMarker))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.prepare != nil {
				if err := tc.prepare(dir); err != nil {
					t.Fatal(err)
				}
			} else if tc.raw != nil {
				if err := os.WriteFile(filepath.Join(dir, checkpointLocalMarker), tc.raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("python3", "-B", "-c", checkpointMarkerInitSource)
			cmd.Env = append(os.Environ(), "STATE_DIR="+dir, "EXPECTED_HOLDER_UID="+holderUID, "EXPECTED_NODE_NAME="+nodeName, "EXPECTED_NONCE="+nonce, "EXPECTED_SLOT=0")
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("marker result err=%v output=%s", err, out)
			}
			if tc.ok && (!bytes.Contains(out, []byte(`"status":"VERIFIED"`)) || !bytes.Contains(out, []byte(`"markerSHA256"`))) {
				t.Fatalf("marker receipt=%s", out)
			}
		})
	}
}

func TestCheckpointParserRejectsMissingNullDuplicateAndCaseVariant(t *testing.T) {
	valid := checkpointJSON(t, checkpointFixture("pod", "pvc", "inc", 4, 1))
	for _, raw := range []string{strings.Replace(valid, `"ready":true,`, "", 1), strings.Replace(valid, `"ready":true`, `"ready":null`, 1), strings.Replace(valid, "{", `{"ready":true,`, 1), strings.Replace(valid, `"ready"`, `"Ready"`, 1), valid + " {}"} {
		if _, err := parseCheckpointBody([]byte(raw)); err == nil {
			t.Fatalf("malformed body accepted: %s", raw)
		}
	}
}

func TestCheckpointOracleIdentityAndProgressBoundaries(t *testing.T) {
	oldWait := checkpointObservationWait
	checkpointObservationWait = func(context.Context, time.Duration, time.Duration, func() (checkpointBody, error)) (time.Time, time.Time, int, int, error) {
		start := time.Now()
		return start, start.Add(checkpointObservationWindow), 1, 0, nil
	}
	t.Cleanup(func() { checkpointObservationWait = oldWait; core.SetExecer(nil) })
	cases := []struct {
		name    string
		podUID  types.UID
		reply   checkpointBody
		wantErr bool
	}{{"same-progress", "old", checkpointFixture("old", "pvc", "old-inc", 9, 0), false}, {"same-stalled", "old", checkpointFixture("old", "pvc", "old-inc", 5, 0), true}, {"replacement-continuity", "new", checkpointFixture("new", "pvc", "new-inc", 9, 7), false}, {"replacement-reset", "new", checkpointFixture("new", "pvc", "new-inc", 9, 0), true}, {"wrong-pvc", "new", checkpointFixture("new", "foreign", "new-inc", 9, 7), true}, {"same-incarnation", "new", checkpointFixture("new", "pvc", "old-inc", 9, 7), true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := checkpointRequestEnv(t, tc.podUID)
			core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
				return checkpointExecReply(t, tc.reply, 200)
			})
			s := observedCheckpointScenario()
			got, err := s.SuccessOracle(context.Background(), env)
			if (err != nil) != tc.wantErr || (!tc.wantErr && !got.Achieved) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestCheckpointReceiptPersistsRawEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.log")
	logger, err := core.NewTrialLogger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := checkpointRequestEnv(t, "old")
	env.Log = logger
	reply := checkpointFixture("old", "pvc", "inc", 3, 0)
	result := checkpointExecReply(t, reply, 200)
	core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
		return result
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := observedCheckpointScenario()
	if _, err := s.request(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := logger.(interface{ Close() error }).Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `c2-checkpoint-continuity http-receipt=`) || !strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte(checkpointJSON(t, reply)))) || !strings.Contains(string(raw), `"observedProducerUID":"producer-owned"`) {
		t.Fatalf("raw receipt incomplete: %s", raw)
	}
}

func TestCheckpointReceiptPersistsTransportFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.log")
	logger, err := core.NewTrialLogger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := checkpointRequestEnv(t, "old")
	env.Log = logger
	core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
		return core.ExecResult{Stderr: "synthetic timeout detail", ExitCode: 17, Err: context.DeadlineExceeded}
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := observedCheckpointScenario()
	if _, err := s.request(context.Background(), env); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("transport error=%v", err)
	}
	if err := logger.(interface{ Close() error }).Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"execError":"context deadline exceeded"`, `"stderr":"synthetic timeout detail"`, `"stderrBytes":24`, `"observedProducerUID":"producer-owned"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("raw transport receipt lacks %s: %s", want, raw)
		}
	}
}

func TestCheckpointOracleRejectsReplacementWhileOriginalUIDSurvives(t *testing.T) {
	env := checkpointRequestEnv(t, "new")
	original := sessionFixturePod(checkpointApp, checkpointApp, "old", false, true)
	original.Name = "original-detached-label"
	original.Labels = map[string]string{"some": "other-label"}
	createSessionFixturePod(t, env, original)
	core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
		return checkpointExecReply(t, checkpointFixture("new", "pvc", "new-inc", 9, 7), 200)
	})
	t.Cleanup(func() { core.SetExecer(nil) })
	s := observedCheckpointScenario()
	s.targetName = original.Name
	if _, err := s.SuccessOracle(context.Background(), env); err == nil {
		t.Fatalf("replacement response accepted while original UID survives: %v", err)
	}
}

func TestCheckpointExecuteRetainsSampledHighWaterAcrossReplacement(t *testing.T) {
	oldWait := checkpointObservationWait
	t.Cleanup(func() { checkpointObservationWait = oldWait; core.SetExecer(nil) })
	for _, tc := range []struct {
		name            string
		replacementBoot int64
		wantErr         bool
	}{{"replacement-loses-sampled-ack", 10, true}, {"replacement-loads-sampled-ack-and-advances", 100, false}} {
		t.Run(tc.name, func(t *testing.T) {
			env := checkpointRequestEnv(t, "old")
			s := observedCheckpointScenario()
			calls := 0
			core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
				calls++
				var body checkpointBody
				switch calls {
				case 1:
					body = checkpointFixture("old", "pvc", "old-inc", 5, 0)
				case 2:
					body = checkpointFixture("old", "pvc", "old-inc", 6, 0)
				case 3:
					body = checkpointFixture("old", "pvc", "old-inc", 100, 0)
				default:
					body = checkpointFixture("new", "pvc", "new-inc", tc.replacementBoot+1, tc.replacementBoot)
				}
				return checkpointExecReply(t, body, 200)
			})
			checkpointObservationWait = func(ctx context.Context, _, _ time.Duration, sample func() (checkpointBody, error)) (time.Time, time.Time, int, int, error) {
				start := time.Now()
				failures := 0
				if _, err := sample(); err != nil {
					failures++
				}
				if err := env.Kube.CoreV1().Pods("sandbox").Delete(ctx, "target", metav1.DeleteOptions{}); err != nil {
					return start, start.Add(checkpointObservationWindow), 1, failures, err
				}
				replacement := sessionFixturePod(checkpointApp, checkpointApp, "new", false, true)
				replacement.Name = "target"
				bindCheckpointFixturePod(replacement)
				createSessionFixturePod(t, env, replacement)
				setCheckpointFixtureEndpoint(t, env, replacement)
				if _, err := sample(); err != nil {
					failures++
				}
				return start, start.Add(checkpointObservationWindow), 2, failures, nil
			}
			_, err := s.Execute(context.Background(), env)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Execute err=%v wantErr=%v", err, tc.wantErr)
			}
			if s.lastOriginal.Sequence != 100 {
				t.Fatalf("sampled original high-water=%d", s.lastOriginal.Sequence)
			}
			if !tc.wantErr {
				got, err := s.SuccessOracle(context.Background(), env)
				if err != nil || !got.Achieved {
					t.Fatalf("continued replacement got=%+v err=%v", got, err)
				}
			}
		})
	}
}

func TestCheckpointObservedWorkloadBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *core.Env, *corev1.Pod)
		valid  bool
	}{
		{name: "exact-owned", valid: true},
		{name: "foreign-replicaset", mutate: func(_ *testing.T, _ *core.Env, pod *corev1.Pod) { pod.OwnerReferences[0].UID = "foreign-rs" }},
		{name: "foreign-deployment", mutate: func(t *testing.T, env *core.Env, _ *corev1.Pod) {
			rs, err := env.Kube.AppsV1().ReplicaSets("sandbox").Get(context.Background(), "checkpoint-rs", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			rs.OwnerReferences[0].UID = "foreign-deployment"
			if _, err := env.Kube.AppsV1().ReplicaSets("sandbox").Update(context.Background(), rs, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "replacement-service", mutate: func(t *testing.T, env *core.Env, _ *corev1.Pod) {
			svc, err := env.Kube.CoreV1().Services("sandbox").Get(context.Background(), checkpointService, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			svc.UID = "foreign-service"
			if _, err := env.Kube.CoreV1().Services("sandbox").Update(context.Background(), svc, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong-mounted-claim", mutate: func(_ *testing.T, _ *core.Env, pod *corev1.Pod) {
			pod.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = "foreign-pvc"
		}},
		{name: "foreign-endpoint-target", mutate: func(t *testing.T, env *core.Env, _ *corev1.Pod) {
			slices, err := env.Kube.DiscoveryV1().EndpointSlices("sandbox").List(context.Background(), metav1.ListOptions{})
			if err != nil {
				t.Fatal(err)
			}
			slice := &slices.Items[0]
			slice.Endpoints[0].TargetRef.UID = "foreign-pod"
			if _, err := env.Kube.DiscoveryV1().EndpointSlices("sandbox").Update(context.Background(), slice, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := checkpointRequestEnv(t, "old")
			pod, err := env.Kube.CoreV1().Pods("sandbox").Get(context.Background(), "target", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if tc.mutate != nil {
				tc.mutate(t, env, pod)
			}
			s := observedCheckpointScenario()
			err = s.validateObservedCheckpointWorkload(context.Background(), env, pod)
			if (err == nil) != tc.valid {
				t.Fatalf("binding err=%v valid=%v", err, tc.valid)
			}
		})
	}
}

func TestCheckpointSetupCollisionAndCleanupPreconditions(t *testing.T) {
	env := fixtureObservationEnv()
	env.Config.BenignCheckpointStorageClass = "reviewed-storage"
	if _, err := env.Kube.StorageV1().StorageClasses().Create(context.Background(), &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "reviewed-storage"}, Provisioner: "fixture.example/provisioner"}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	foreign := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: checkpointPVC, Namespace: "sandbox", UID: "foreign"}}
	if _, err := env.Kube.CoreV1().PersistentVolumeClaims("sandbox").Create(context.Background(), foreign, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	s := &c2CheckpointContinuity{pvcUID: "stale", deploymentUID: "stale"}
	if err := s.Setup(context.Background(), env); err == nil {
		t.Fatal("foreign PVC collision accepted")
	}
	if s.pvcUID != "" || s.deploymentUID != "" {
		t.Fatalf("stale ownership retained: %+v", s)
	}
	if err := s.Teardown(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if got, err := env.Kube.CoreV1().PersistentVolumeClaims("sandbox").Get(context.Background(), checkpointPVC, metav1.GetOptions{}); err != nil || got.UID != "foreign" {
		t.Fatalf("foreign PVC changed: %+v %v", got, err)
	}

	env = fixtureObservationEnv()
	client := env.Kube.(*k8sfake.Clientset)
	var uids []types.UID
	client.PrependReactor("delete", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		o := a.(k8stesting.DeleteAction).GetDeleteOptions()
		if o.Preconditions == nil || o.Preconditions.UID == nil {
			t.Fatal("delete lacks UID")
		}
		uids = append(uids, *o.Preconditions.UID)
		return true, nil, nil
	})
	s = &c2CheckpointContinuity{deploymentUID: "d", targetName: "p", targetUID: "puid", replicaSetName: "rs", replicaSetUID: "rsuid", serviceUID: "s", producerUID: "prod", pvcUID: "pvc"}
	if err := s.Teardown(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(uidStrings(uids), ","), "d,puid,rsuid,s,prod,pvc"; got != want {
		t.Fatalf("delete UIDs=%s", got)
	}
	client.PrependReactor("delete", "persistentvolumeclaims", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("cleanup failed") })
	s = &c2CheckpointContinuity{pvcUID: "pvc"}
	if err := s.Teardown(context.Background(), env); err == nil {
		t.Fatal("cleanup failure hidden")
	}
}

func TestCheckpointSetupCapturesExactOwnedStorageAndWorkloadIdentities(t *testing.T) {
	env := fixtureObservationEnv()
	env.Config.BenignCheckpointStorageClass = "reviewed-storage"
	env.Config.BenignSessionNodeSelector = map[string]string{"kubernetes.io/hostname": "reviewed-cpu-node"}
	client := env.Kube.(*k8sfake.Clientset)
	if _, err := client.StorageV1().StorageClasses().Create(context.Background(), &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "reviewed-storage"}, Provisioner: "fixture.example/provisioner"}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().PersistentVolumes().Create(context.Background(), &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv-owned", UID: "pv-uid"}, Spec: corev1.PersistentVolumeSpec{StorageClassName: "reviewed-storage", ClaimRef: &corev1.ObjectReference{Namespace: "sandbox", Name: checkpointPVC, UID: "pvc-uid"}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	controller := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "target-rs", Namespace: "sandbox", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: checkpointApp, UID: "deployment-uid", Controller: &controller}}}}
	if _, err := client.AppsV1().ReplicaSets("sandbox").Create(context.Background(), rs, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	target := sessionFixturePod(checkpointApp, checkpointApp, "target-uid", false, true)
	target.Name = "target-pod"
	target.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}
	createSessionFixturePod(t, env, target)
	client.PrependReactor("create", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj := a.(k8stesting.CreateAction).GetObject()
		switch v := obj.(type) {
		case *corev1.PersistentVolumeClaim:
			v.UID = "pvc-uid"
			v.Status.Phase = corev1.ClaimBound
			v.Spec.VolumeName = "pv-owned"
		case *appsv1.Deployment:
			v.UID = "deployment-uid"
		case *corev1.Service:
			v.UID = "service-uid"
		case *corev1.Pod:
			if v.Name == checkpointProducer {
				v.UID = "producer-uid"
				v.Status.Phase = corev1.PodRunning
				v.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "producer", Ready: true}}
			}
		}
		return false, nil, nil
	})
	s := &c2CheckpointContinuity{}
	if err := s.Setup(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if s.deploymentUID != "deployment-uid" || s.serviceUID != "service-uid" || s.producerUID != "producer-uid" || s.targetUID != "target-uid" || s.replicaSetUID != "rs-uid" || s.pvcUID != "pvc-uid" || s.pvUID != "pv-uid" || s.pvName != "pv-owned" || s.storageProvisioner != "fixture.example/provisioner" {
		t.Fatalf("captured identities=%+v", s)
	}
	dep, err := client.AppsV1().Deployments("sandbox").Get(context.Background(), checkpointApp, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	producer, err := client.CoreV1().Pods("sandbox").Get(context.Background(), checkpointProducer, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, selector := range map[string]map[string]string{"target": dep.Spec.Template.Spec.NodeSelector, "producer": producer.Spec.NodeSelector} {
		if selector["kubernetes.io/hostname"] != "reviewed-cpu-node" {
			t.Fatalf("%s selector=%v", name, selector)
		}
	}
	if producer.Spec.AutomountServiceAccountToken == nil || *producer.Spec.AutomountServiceAccountToken {
		t.Fatalf("producer token mount=%v", producer.Spec.AutomountServiceAccountToken)
	}
	security := dep.Spec.Template.Spec.SecurityContext
	if security == nil || security.FSGroup == nil || *security.FSGroup != 65532 || security.FSGroupChangePolicy == nil || *security.FSGroupChangePolicy != corev1.FSGroupChangeOnRootMismatch {
		t.Fatalf("target fsGroup contract=%+v", security)
	}
	probe := dep.Spec.Template.Spec.Containers[0].ReadinessProbe
	if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Path != "/progress" || probe.HTTPGet.Port.IntVal != checkpointPort {
		t.Fatalf("target HTTP readiness probe=%+v", probe)
	}
	if len(dep.Spec.Template.Spec.InitContainers) != 0 {
		t.Fatalf("ordinary provisioned storage unexpectedly gained local init: %+v", dep.Spec.Template.Spec.InitContainers)
	}
	pvc, err := client.CoreV1().PersistentVolumeClaims("sandbox").Get(context.Background(), checkpointPVC, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pvc.Spec.Selector != nil {
		t.Fatalf("ordinary provisioned storage unexpectedly gained selector: %+v", pvc.Spec.Selector)
	}
}

func TestCheckpointLocalFixturePrebindsBeforeWriterAndRepeatsMarkerInit(t *testing.T) {
	env, client, pv := checkpointLocalSetupEnv(t)
	var orderingErr error
	client.PrependReactor("create", "persistentvolumeclaims", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pvc := a.(k8stesting.CreateAction).GetObject().(*corev1.PersistentVolumeClaim).DeepCopy()
		pvc.UID = "pvc-local-uid"
		pvc.Status.Phase = corev1.ClaimPending
		boundPVC := pvc.DeepCopy()
		boundPVC.Status.Phase = corev1.ClaimBound
		if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("persistentvolumeclaims"), boundPVC, "sandbox"); err != nil {
			return true, nil, err
		}
		bound := pv.DeepCopy()
		bound.Status.Phase = corev1.VolumeBound
		bound.Spec.ClaimRef = &corev1.ObjectReference{Namespace: "sandbox", Name: checkpointPVC, UID: pvc.UID}
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("persistentvolumes"), bound, ""); err != nil {
			return true, nil, err
		}
		return true, pvc, nil
	})
	client.PrependReactor("create", "deployments", func(a k8stesting.Action) (bool, runtime.Object, error) {
		current, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("persistentvolumes"), "", pv.Name)
		if err != nil || current.(*corev1.PersistentVolume).Status.Phase != corev1.VolumeBound || current.(*corev1.PersistentVolume).Spec.ClaimRef == nil || current.(*corev1.PersistentVolume).Spec.ClaimRef.UID != "pvc-local-uid" {
			orderingErr = fmt.Errorf("deployment preceded exact Bound claimRef: pv=%v err=%v", current, err)
		}
		dep := a.(k8stesting.CreateAction).GetObject().(*appsv1.Deployment)
		dep.UID = "deployment-uid"
		return false, nil, nil
	})
	client.PrependReactor("create", "services", func(a k8stesting.Action) (bool, runtime.Object, error) {
		a.(k8stesting.CreateAction).GetObject().(*corev1.Service).UID = "service-uid"
		return false, nil, nil
	})
	client.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		if pod.Name == checkpointProducer {
			pod.UID = "producer-uid"
			pod.Status.Phase = corev1.PodRunning
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "producer", Ready: true}}
		}
		return false, nil, nil
	})
	s := &c2CheckpointContinuity{}
	if err := s.Setup(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if orderingErr != nil {
		t.Fatal(orderingErr)
	}
	if s.pvName != pv.Name || s.pvUID != pv.UID || s.storageClassUID != "storage-class-uid" || s.localSlot != 0 {
		t.Fatalf("local fixture identities=%+v", s)
	}
	dep, err := client.AppsV1().Deployments("sandbox").Get(context.Background(), checkpointApp, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(dep.Spec.Template.Spec.InitContainers) != 1 {
		t.Fatalf("marker init=%+v", dep.Spec.Template.Spec.InitContainers)
	}
	init := dep.Spec.Template.Spec.InitContainers[0]
	if init.Name != "verify-local-marker" || init.Command[len(init.Command)-1] != checkpointMarkerInitSource || len(init.VolumeMounts) != 1 || !init.VolumeMounts[0].ReadOnly {
		t.Fatalf("marker init contract=%+v", init)
	}
	if dep.Spec.Template.Spec.NodeSelector["kubernetes.io/hostname"] != "reviewed-node" {
		t.Fatalf("checkpoint target placement=%v", dep.Spec.Template.Spec.NodeSelector)
	}
	pvc, err := client.CoreV1().PersistentVolumeClaims("sandbox").Get(context.Background(), checkpointPVC, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wantSelector := checkpointLocalSelector("d-nomtd", 0, 0)
	if pvc.Spec.VolumeName != pv.Name || pvc.Spec.Selector == nil || !maps.Equal(pvc.Spec.Selector.MatchLabels, wantSelector) {
		t.Fatalf("local PVC prebinding=%+v", pvc.Spec)
	}
	if err := s.verifyStorageIdentity(context.Background(), env); err != nil {
		t.Fatalf("bound local identity rejected: %v", err)
	}
	holder, err := client.CoreV1().Pods("sandbox").Get(context.Background(), checkpointLocalHolder, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	holder.UID = "99999999-2222-4333-8444-555555555555"
	if _, err := client.CoreV1().Pods("sandbox").Update(context.Background(), holder, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyStorageIdentity(context.Background(), env); err == nil {
		t.Fatal("later holder UID replacement accepted")
	}
	holder.UID = s.localHolderUID
	if _, err := client.CoreV1().Pods("sandbox").Update(context.Background(), holder, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	boundPV, err := client.CoreV1().PersistentVolumes().Get(context.Background(), pv.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	boundPV.Spec.Local.Path += "-foreign"
	if _, err := client.CoreV1().PersistentVolumes().Update(context.Background(), boundPV, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyStorageIdentity(context.Background(), env); err == nil {
		t.Fatal("later local PV path replacement accepted")
	}
	ev := map[string]string{}
	s.addCheckpointLocalEvidence(ev)
	if ev["checkpointLocalHolderUID"] != string(s.localHolderUID) || ev["checkpointLocalNodeUID"] != string(s.localNodeUID) || ev["checkpointLocalSlot"] != "0" || ev["checkpointLocalPathSHA256"] == "" || ev["checkpointLocalMarkerInitSourceSHA256"] != checkpointMarkerInitSourceSHA256() {
		t.Fatalf("local evidence=%v", ev)
	}
}

func TestCheckpointLocalFixtureRefusesUnsafeBindingBeforeDeployment(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*storagev1.StorageClass, *corev1.PersistentVolume)
	}{
		{name: "wait-for-first-consumer", mutate: func(sc *storagev1.StorageClass, _ *corev1.PersistentVolume) {
			mode := storagev1.VolumeBindingWaitForFirstConsumer
			sc.VolumeBindingMode = &mode
		}},
		{name: "wrong-path", mutate: func(_ *storagev1.StorageClass, pv *corev1.PersistentVolume) { pv.Spec.Local.Path += "-foreign" }},
		{name: "foreign-claim", mutate: func(_ *storagev1.StorageClass, pv *corev1.PersistentVolume) {
			pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: "other", Name: "foreign", UID: "foreign"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, client, pv := checkpointLocalSetupEnv(t)
			sc, err := client.StorageV1().StorageClasses().Get(context.Background(), env.Config.BenignCheckpointStorageClass, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(sc, pv)
			if _, err := client.StorageV1().StorageClasses().Update(context.Background(), sc, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.CoreV1().PersistentVolumes().Update(context.Background(), pv, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			s := &c2CheckpointContinuity{}
			if err := s.Setup(context.Background(), env); err == nil {
				t.Fatal("unsafe local fixture accepted")
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "create" && action.GetResource().Resource == "deployments" {
					t.Fatal("writer Deployment created before local binding validation")
				}
			}
		})
	}
}

func TestCheckpointLocalFixtureRequiresOneDeterministicSlot(t *testing.T) {
	for index, tc := range []struct {
		defender string
		trial    int
	}{{"d-nomtd", 0}, {"d-nomtd", 1}, {"d-nomtd", 2}, {"d-r6blindtimer", 0}, {"d-r6blindtimer", 1}, {"d-r6blindtimer", 2}} {
		got, err := checkpointLocalAssignment(tc.defender, tc.trial)
		if err != nil || got != index {
			t.Fatalf("assignment %s/%d=%d err=%v want=%d", tc.defender, tc.trial, got, err, index)
		}
	}
	for _, tc := range []struct {
		defender string
		trial    int
	}{{"d-fullphoenix", 0}, {"d-nomtd", -1}, {"d-r6blindtimer", 3}} {
		if _, err := checkpointLocalAssignment(tc.defender, tc.trial); err == nil {
			t.Fatalf("unsupported assignment accepted: %+v", tc)
		}
	}

	env, client, pv := checkpointLocalSetupEnv(t)
	duplicate := pv.DeepCopy()
	duplicate.Name = "checkpoint-local-duplicate"
	duplicate.UID = "pv-local-duplicate-uid"
	if _, err := client.CoreV1().PersistentVolumes().Create(context.Background(), duplicate, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := (&c2CheckpointContinuity{}).Setup(context.Background(), env); err == nil {
		t.Fatal("duplicate exact slot candidates accepted")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && (action.GetResource().Resource == "persistentvolumeclaims" || action.GetResource().Resource == "deployments") {
			t.Fatalf("duplicate candidates reached writer mutation: %s", action.GetResource().Resource)
		}
	}
}

func TestCheckpointLocalFixtureRefusesBoundClaimRefMismatchBeforeWriter(t *testing.T) {
	env, client, pv := checkpointLocalSetupEnv(t)
	client.PrependReactor("create", "persistentvolumeclaims", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pvc := a.(k8stesting.CreateAction).GetObject().(*corev1.PersistentVolumeClaim)
		pvc.UID = "pvc-local-uid"
		pvc.Status.Phase = corev1.ClaimBound
		bound := pv.DeepCopy()
		bound.Status.Phase = corev1.VolumeBound
		bound.Spec.ClaimRef = &corev1.ObjectReference{Namespace: "sandbox", Name: checkpointPVC, UID: "foreign-pvc-uid"}
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("persistentvolumes"), bound, ""); err != nil {
			return true, nil, err
		}
		return false, nil, nil
	})
	if err := (&c2CheckpointContinuity{}).Setup(context.Background(), env); err == nil {
		t.Fatal("Bound PV with foreign claimRef UID accepted")
	}
	seenPVC := false
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" && action.GetResource().Resource == "persistentvolumeclaims" {
			seenPVC = true
		}
		if action.GetVerb() == "create" && action.GetResource().Resource == "deployments" {
			t.Fatal("writer Deployment created after claimRef mismatch")
		}
	}
	if !seenPVC {
		t.Fatal("test did not exercise PVC create/binding path")
	}
}

func TestCheckpointSetupWithoutPinnedStorageIsUnavailableAndReadOnly(t *testing.T) {
	env := fixtureObservationEnv()
	s := &c2CheckpointContinuity{}
	if err := s.Setup(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	result, err := s.Execute(context.Background(), env)
	if err != nil || !result.Skipped || !strings.Contains(result.SkipReason, "not explicitly pinned") {
		t.Fatalf("unavailable result=%+v err=%v", result, err)
	}
	for _, action := range env.Kube.(*k8sfake.Clientset).Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "delete" || action.GetVerb() == "patch" || action.GetVerb() == "update" {
			t.Fatalf("unpinned storage caused mutation: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
}

func checkpointLocalSetupEnv(t *testing.T) (*core.Env, *k8sfake.Clientset, *corev1.PersistentVolume) {
	t.Helper()
	env := fixtureObservationEnv()
	env.ScenarioName = "c2-checkpoint-continuity"
	env.DefenderName = "d-nomtd"
	env.Trial = 0
	env.Config.BenignCheckpointStorageClass = "checkpoint-local"
	env.Config.BenignCheckpointLocalFixture = true
	env.Config.BenignCheckpointNodeSelector = map[string]string{"kubernetes.io/hostname": "reviewed-node"}
	env.Config.BenignCheckpointLocalHolderUID = "11111111-2222-4333-8444-555555555555"
	env.Config.BenignCheckpointLocalNodeUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	env.Config.BenignCheckpointLocalNonce = "checkpoint-local-r1"
	client := env.Kube.(*k8sfake.Clientset)
	mode := storagev1.VolumeBindingImmediate
	reclaim := corev1.PersistentVolumeReclaimRetain
	expand := false
	sc := &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: env.Config.BenignCheckpointStorageClass, UID: "storage-class-uid", Labels: map[string]string{core.OwnedLabelKey: core.OwnedLabelValue, "fixture.phorvex.ai/campaign": checkpointLocalCampaign}, Annotations: map[string]string{"fixture.phorvex.ai/nonce": env.Config.BenignCheckpointLocalNonce}}, Provisioner: "kubernetes.io/no-provisioner", VolumeBindingMode: &mode, ReclaimPolicy: &reclaim, AllowVolumeExpansion: &expand}
	if _, err := client.StorageV1().StorageClasses().Create(context.Background(), sc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "reviewed-node", UID: types.UID(env.Config.BenignCheckpointLocalNodeUID)}, Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("0")}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	if _, err := client.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	noToken := false
	nonroot := true
	uid := int64(65532)
	noEsc := false
	ro := true
	volumes := make([]corev1.Volume, 0, 6)
	mounts := make([]corev1.VolumeMount, 0, 6)
	for slot := 0; slot < 6; slot++ {
		capacity := resource.MustParse(checkpointLocalCapacity)
		volumes = append(volumes, corev1.Volume{Name: fmt.Sprintf("slot-%d", slot), VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &capacity}}})
		mounts = append(mounts, corev1.VolumeMount{Name: fmt.Sprintf("slot-%d", slot), MountPath: fmt.Sprintf("/checkpoint/slot-%d", slot)})
	}
	holder := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: checkpointLocalHolder, Namespace: "sandbox", UID: types.UID(env.Config.BenignCheckpointLocalHolderUID), Labels: map[string]string{core.OwnedLabelKey: core.OwnedLabelValue, "fixture.phorvex.ai/campaign": checkpointLocalCampaign}, Annotations: map[string]string{"fixture.phorvex.ai/nonce": env.Config.BenignCheckpointLocalNonce}}, Spec: corev1.PodSpec{AutomountServiceAccountToken: &noToken, RestartPolicy: corev1.RestartPolicyNever, NodeName: "reviewed-node", NodeSelector: map[string]string{"kubernetes.io/hostname": "reviewed-node"}, SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid, RunAsGroup: &uid, FSGroup: &uid}, Volumes: volumes, Containers: []corev1.Container{{Name: "holder", Image: checkpointImage, SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &nonroot, RunAsUser: &uid, RunAsGroup: &uid, AllowPrivilegeEscalation: &noEsc, ReadOnlyRootFilesystem: &ro, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}, VolumeMounts: mounts}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "holder", Ready: true}}}}
	if _, err := client.CoreV1().Pods("sandbox").Create(context.Background(), holder, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	volumeMode := corev1.PersistentVolumeFilesystem
	selector := checkpointLocalSelector("d-nomtd", 0, 0)
	path := checkpointLocalPath(holder.UID, 0)
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "checkpoint-local-0", UID: "pv-local-uid", Labels: selector, Annotations: map[string]string{"fixture.phorvex.ai/holder-uid": string(holder.UID), "fixture.phorvex.ai/node-uid": string(node.UID), "fixture.phorvex.ai/nonce": env.Config.BenignCheckpointLocalNonce, "fixture.phorvex.ai/slot": "0", "fixture.phorvex.ai/local-path-sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(path)))}}, Spec: corev1.PersistentVolumeSpec{Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(checkpointLocalCapacity)}, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain, StorageClassName: env.Config.BenignCheckpointStorageClass, VolumeMode: &volumeMode, PersistentVolumeSource: corev1.PersistentVolumeSource{Local: &corev1.LocalVolumeSource{Path: path}}, NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{"reviewed-node"}}}}}}}}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeAvailable}}
	if _, err := client.CoreV1().PersistentVolumes().Create(context.Background(), pv, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	controller := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "checkpoint-rs", Namespace: "sandbox", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: checkpointApp, UID: "deployment-uid", Controller: &controller}}}}
	if _, err := client.AppsV1().ReplicaSets("sandbox").Create(context.Background(), rs, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	target := sessionFixturePod(checkpointApp, checkpointApp, "target-uid", false, true)
	target.Name = "target-pod"
	target.Spec.NodeName = "reviewed-node"
	target.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}
	bindCheckpointFixturePod(target)
	createSessionFixturePod(t, env, target)
	return env, client, pv
}

func startCheckpointServer(t *testing.T, dir string, port int, pod, pvc, fault string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("python3", "-B", "-c", checkpointServerSource)
	cmd.Env = append(os.Environ(), "STATE_DIR="+dir, "PORT="+strconv.Itoa(port), "POD_UID="+pod, "PVC_UID="+pvc, "INTERVAL_MS=80", "CHECKPOINT_FAULT="+fault)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}
func stopCheckpointServer(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func waitCheckpointHTTP(t *testing.T, port int, pred func(checkpointBody) bool) checkpointBody {
	t.Helper()
	_, b := waitCheckpointEnvelope(t, port, func(status int, b checkpointBody) bool { return status == 200 && pred(b) })
	return b
}
func waitCheckpointEnvelope(t *testing.T, port int, pred func(int, checkpointBody) bool) (int, checkpointBody) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		cmd := exec.Command("python3", "-B", "-c", checkpointClientSource, fmt.Sprintf("http://127.0.0.1:%d/progress", port))
		out, err := cmd.CombinedOutput()
		last = string(out)
		if err == nil {
			r, e := parseCheckpointReply(string(out))
			if e == nil && pred(r.HTTPStatus, r.Body) {
				return r.HTTPStatus, r.Body
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("checkpoint server condition timed out: %s", last)
	return 0, checkpointBody{}
}
func parseCheckpointFile(raw []byte) (checkpointBody, error) {
	var x struct {
		Version           int64 `json:"version"`
		Sequence          int64 `json:"sequence"`
		Payload, Checksum string
	}
	if err := json.Unmarshal(raw, &x); err != nil {
		return checkpointBody{}, err
	}
	return checkpointBody{Version: x.Version, Sequence: x.Sequence, Payload: x.Payload, Checksum: x.Checksum}, nil
}
func checkpointFixture(pod, pvc, inc string, seq, boot int64) checkpointBody {
	ready := true
	fresh := boot == 0
	payload := fmt.Sprintf("synthetic-sequence-%020d", seq)
	checksum := fmt.Sprintf("%x", sha256sum([]byte(fmt.Sprintf("v1\n%d\n%s", seq, payload))))
	bp := fmt.Sprintf("synthetic-sequence-%020d", boot)
	bc := fmt.Sprintf("%x", sha256sum([]byte(fmt.Sprintf("v1\n%d\n%s", boot, bp))))
	return checkpointBody{Version: 1, PodUID: pod, PVCUID: pvc, Incarnation: inc, Sequence: seq, Payload: payload, Checksum: checksum, BootSequence: boot, BootChecksum: bc, Ready: &ready, InitializedFresh: &fresh}
}
func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }
func checkpointJSON(t *testing.T, b checkpointBody) string {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func checkpointExecReply(t *testing.T, b checkpointBody, status int) core.ExecResult {
	t.Helper()
	return core.ExecResult{Stdout: strconv.Itoa(status) + "\n" + base64.StdEncoding.EncodeToString([]byte(checkpointJSON(t, b))), ExitCode: 0}
}
func checkpointRequestEnv(t *testing.T, targetUID types.UID) *core.Env {
	t.Helper()
	env := fixtureObservationEnv()
	producer := sessionFixturePod(checkpointProducer, checkpointProducer, "producer-owned", false, true)
	producer.Spec.Containers[0].Name = "producer"
	createSessionFixturePod(t, env, producer)
	storageClass := "reviewed-storage"
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: checkpointPVC, Namespace: "sandbox", UID: "pvc"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv-owned", StorageClassName: &storageClass}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	if _, err := env.Kube.CoreV1().PersistentVolumeClaims("sandbox").Create(context.Background(), pvc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv-owned", UID: "pv-uid"}, Spec: corev1.PersistentVolumeSpec{StorageClassName: storageClass, ClaimRef: &corev1.ObjectReference{Namespace: "sandbox", Name: checkpointPVC, UID: "pvc"}}}
	if _, err := env.Kube.CoreV1().PersistentVolumes().Create(context.Background(), pv, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if targetUID != "" {
		dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: checkpointApp, Namespace: "sandbox", UID: "deployment-uid"}}
		if _, err := env.Kube.AppsV1().Deployments("sandbox").Create(context.Background(), dep, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		controller := true
		rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "checkpoint-rs", Namespace: "sandbox", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: checkpointApp, UID: dep.UID, Controller: &controller}}}}
		if _, err := env.Kube.AppsV1().ReplicaSets("sandbox").Create(context.Background(), rs, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: checkpointService, Namespace: "sandbox", UID: "service-uid"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": checkpointApp}}}
		if _, err := env.Kube.CoreV1().Services("sandbox").Create(context.Background(), svc, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		target := sessionFixturePod(checkpointApp, checkpointApp, targetUID, false, true)
		target.Name = "target"
		bindCheckpointFixturePod(target)
		createSessionFixturePod(t, env, target)
		setCheckpointFixtureEndpoint(t, env, target)
	}
	return env
}

func bindCheckpointFixturePod(pod *corev1.Pod) {
	controller := true
	pod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "checkpoint-rs", UID: "rs-uid", Controller: &controller}}
	pod.Spec.Volumes = []corev1.Volume{{Name: "state", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: checkpointPVC}}}}
}

func setCheckpointFixtureEndpoint(t *testing.T, env *core.Env, pod *corev1.Pod) {
	t.Helper()
	slices, err := env.Kube.DiscoveryV1().EndpointSlices("sandbox").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range slices.Items {
		if err := env.Kube.DiscoveryV1().EndpointSlices("sandbox").Delete(context.Background(), slices.Items[i].Name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	ready := true
	controller := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "checkpoint-slice", Namespace: "sandbox", Labels: map[string]string{discoveryv1.LabelServiceName: checkpointService}, OwnerReferences: []metav1.OwnerReference{{Kind: "Service", Name: checkpointService, UID: "service-uid", Controller: &controller}}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"127.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "sandbox", Name: pod.Name, UID: pod.UID}}}}
	if _, err := env.Kube.DiscoveryV1().EndpointSlices("sandbox").Create(context.Background(), slice, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}
func observedCheckpointScenario() *c2CheckpointContinuity {
	start := time.Now().Add(-checkpointObservationWindow)
	return &c2CheckpointContinuity{deploymentUID: "deployment-uid", serviceUID: "service-uid", replicaSetName: "checkpoint-rs", replicaSetUID: "rs-uid", producerUID: "producer-owned", pvcUID: "pvc", pvName: "pv-owned", pvUID: "pv-uid", storageClassName: "reviewed-storage", targetName: "target", targetUID: "old", originalIncarnation: "old-inc", lastOriginal: checkpointFixture("old", "pvc", "old-inc", 5, 0), windowStarted: start, windowEnded: start.Add(checkpointObservationWindow)}
}
func uidStrings(in []types.UID) []string {
	out := make([]string, len(in))
	for i := range in {
		out[i] = string(in[i])
	}
	return out
}
