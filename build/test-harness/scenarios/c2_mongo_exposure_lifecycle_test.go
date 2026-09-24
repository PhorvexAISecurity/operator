package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type mongoLifecycleGuard struct{ deny bool }

func (g *mongoLifecycleGuard) AssertMutationAllowed(string) error {
	if g.deny {
		return errors.New("guard revoked")
	}
	return nil
}

type mongoLifecycleStore struct {
	uuid      string
	doc       mongoExposureDocument
	createErr error
	inserted  bool
	drops     int
}

func (*mongoLifecycleStore) ServerVersion(context.Context) (string, error) { return "7.0.40", nil }
func (*mongoLifecycleStore) SourceConfiguration(context.Context) error     { return nil }
func (s *mongoLifecycleStore) CollectionUUID(context.Context, string, string) (string, error) {
	return s.uuid, nil
}
func (s *mongoLifecycleStore) CreateCollection(context.Context, string, string) error {
	s.uuid = strings.Repeat("a", 32)
	return s.createErr
}
func (s *mongoLifecycleStore) Insert(_ context.Context, _, _ string, d mongoExposureDocument) (any, error) {
	s.doc = d
	s.inserted = true
	return d.ID, nil
}
func (s *mongoLifecycleStore) Read(context.Context, string, string, string) (mongoExposureDocument, error) {
	return s.doc, nil
}
func (s *mongoLifecycleStore) Count(context.Context, string, string) (int64, error) {
	if s.inserted {
		return 1, nil
	}
	return 0, nil
}
func (s *mongoLifecycleStore) Drop(_ context.Context, _, _, uuid string) error {
	if uuid != s.uuid {
		return errors.New("wrong UUID")
	}
	s.uuid = ""
	s.drops++
	return nil
}
func (*mongoLifecycleStore) Close(context.Context) error { return nil }

func mongoLifecycleEnv(t *testing.T, nonce string, store *mongoLifecycleStore, guard *mongoLifecycleGuard, podCreateErr error) (*core.Env, mongoExposureDependencies, *fake.Clientset) {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "document-store", UID: "ns-uid"}}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "cpu-node", UID: "node-uid"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}, Allocatable: corev1.ResourceList{corev1.ResourceCPU: mustQuantity("2"), corev1.ResourceMemory: mustQuantity("2Gi"), corev1.ResourcePods: mustQuantity("100")}}}
	kc := fake.NewSimpleClientset(ns, node)
	kc.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		created := action.(ktesting.CreateAction).GetObject().(*corev1.Pod).DeepCopy()
		created.UID = "client-uid"
		created.Spec.NodeName = "cpu-node"
		created.Status.Phase, created.Status.PodIP, created.Status.HostIP = corev1.PodSucceeded, "10.0.0.8", "10.0.0.9"
		ended := metav1.Now()
		created.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "read-once", ImageID: mongoExposureClientImage, ContainerID: "containerd://client", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, StartedAt: ended, FinishedAt: ended}}}}
		if err := kc.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), created, "document-store"); err != nil {
			return true, nil, err
		}
		if podCreateErr != nil {
			return true, nil, podCreateErr
		}
		return true, created, nil
	})
	f := &config.MongoExposureFixtureConfig{RunID: "run-1", Nonce: nonce, ClusterUID: "11111111-1111-4111-8111-111111111111"}
	env := &core.Env{Kube: kc, Ctrl: ctrlfake.NewClientBuilder().Build(), Rest: &rest.Config{Host: "https://test.invalid"}, Config: config.TargetConfig{Namespace: "document-store", ExpectedNamespaceUID: "ns-uid", OutDir: t.TempDir(), MongoExposureFixture: f}, Guard: guard}
	if err := env.EnsureNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	source := mongoExposureSource{NamespaceUID: "ns-uid", DeploymentUID: "deployment-uid", ReplicaSetUID: "replicaset-uid", PodName: "mongo-pod", PodUID: "mongo-uid", PodIP: "10.0.0.5", NodeName: "mongo-node", ContainerID: "containerd://mongo", ImageID: "mongo-image", PVCUID: "pvc-uid", ServiceUID: "service-uid", EndpointSliceUID: "endpoint-uid", PolicyUID: "policy-uid", PolicyGeneration: 3, PolicySpecSHA256: strings.Repeat("a", 64), ManagerPodUID: "manager-uid", ManagerContainerID: "containerd://manager", ManagerImageID: "manager-image"}
	deps := mongoExposureDependencies{
		captureSource: func(context.Context, *core.Env) (mongoExposureSource, error) { return source, nil },
		chooseNode: func(context.Context, *core.Env) (mongoExposureNode, error) {
			return mongoExposureNode{Name: "cpu-node", UID: "node-uid"}, nil
		},
		forward: func(context.Context, *rest.Config, string, string, int) (int, func() error, error) {
			return 27017, func() error { return nil }, nil
		},
		connect: func(context.Context, int) (mongoExposureStore, error) { return store, nil },
		clientLogs: func(context.Context, *core.Env, string, int64) ([]byte, error) {
			row, _ := json.Marshal([]mongoExposureDocument{mongoExposureDoc(nonce)})
			return []byte(`CAT_MONGO_JSON={"ok":true,"code":0,"codeName":"","rows":` + string(row) + `}` + "\n"), nil
		},
	}
	return env, deps, kc
}

func TestMongoExposureActualRunAndAmbiguousCreateNeverClaimAbsence(t *testing.T) {
	for _, tc := range []struct {
		name         string
		createErr    error
		podCreateErr error
		wantComplete bool
	}{{"exact owned run", nil, nil, true}, {"timeout after server-side collection create", context.DeadlineExceeded, nil, false}, {"timeout after server-side Pod create", nil, context.DeadlineExceeded, false}} {
		t.Run(tc.name, func(t *testing.T) {
			nonce := strings.Repeat("e", 32)
			store := &mongoLifecycleStore{createErr: tc.createErr}
			env, deps, kc := mongoLifecycleEnv(t, nonce, store, &mongoLifecycleGuard{}, tc.podCreateErr)
			err := runMongoExposureWith(context.Background(), env, deps)
			if (err == nil) != tc.wantComplete {
				t.Fatalf("run outcome %v", err)
			}
			raw, e := os.ReadFile(filepath.Join(env.Config.OutDir, "mongo-exposure.json"))
			if e != nil {
				t.Fatal(e)
			}
			var artifact mongoExposureArtifact
			if json.Unmarshal(raw, &artifact) != nil {
				t.Fatal("artifact malformed")
			}
			terminalRaw, e := os.ReadFile(filepath.Join(env.Config.OutDir, "mongo-exposure-terminal.json"))
			if e != nil {
				t.Fatal(e)
			}
			var terminal mongoExposureTerminal
			if json.Unmarshal(terminalRaw, &terminal) != nil {
				t.Fatal("terminal malformed")
			}
			if tc.podCreateErr != nil {
				if export := os.Getenv("MONGO_EXPOSURE_PARTIAL_FIXTURE_DIR"); export != "" {
					if err := os.MkdirAll(export, 0700); err != nil {
						t.Fatal(err)
					}
					for _, name := range []string{"mongo-exposure.json", "mongo-exposure-terminal.json", "mongo-exposure-phases.jsonl"} {
						content, err := os.ReadFile(filepath.Join(env.Config.OutDir, name))
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(export, name), content, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if tc.wantComplete {
				if export := os.Getenv("MONGO_EXPOSURE_PRODUCER_FIXTURE_DIR"); export != "" {
					for _, name := range []string{"mongo-exposure.json", "mongo-exposure-terminal.json", "mongo-exposure-original-reply.log", "mongo-exposure-phases.jsonl"} {
						content, err := os.ReadFile(filepath.Join(env.Config.OutDir, name))
						if err != nil {
							t.Fatal(err)
						}
						if err := os.MkdirAll(export, 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(export, name), content, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				if artifact.Validity != "MEASUREMENT_COMPLETE" || artifact.Cleanup != "CONFIRMED_ABSENT" || artifact.ObservedFinding != "EXPOSED" || !terminal.CollectionAbsent || !terminal.ClientPodAbsent || store.drops != 1 {
					t.Fatalf("actual producer chain incomplete: %#v %#v drops=%d", artifact, terminal, store.drops)
				}
				_, _, name := mongoExposureNames(nonce)
				if _, e = kc.CoreV1().Pods("document-store").Get(context.Background(), name, metav1.GetOptions{}); e == nil {
					t.Fatal("owned Pod not cleaned")
				}
			} else if tc.createErr != nil {
				if artifact.Cleanup != "UNCONFIRMED" || terminal.CollectionAbsent || store.drops != 0 || store.uuid == "" {
					t.Fatal("ambiguous collection create was adopted or declared absent")
				}
			} else if tc.podCreateErr != nil {
				if artifact.Cleanup != "UNCONFIRMED" || terminal.ClientPodAbsent || artifact.ClientPodUID != "" || store.drops != 1 {
					t.Fatal("ambiguous Pod create was adopted or credited absent")
				}
				_, _, name := mongoExposureNames(nonce)
				if _, e = kc.CoreV1().Pods("document-store").Get(context.Background(), name, metav1.GetOptions{}); e != nil {
					t.Fatal("ambiguous server-created Pod unexpectedly absent")
				}
			}
		})
	}
}

func mustQuantity(s string) resource.Quantity { return resource.MustParse(s) }
