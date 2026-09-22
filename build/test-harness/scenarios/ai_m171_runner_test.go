package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
	"github.com/r6security/phoenix-test-harness/internal/report"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

type m171Emitter struct {
	fail    bool
	mu      sync.Mutex
	emitted int
}

func (e *m171Emitter) Metadata() core.DefenderMeta             { return core.DefenderMeta{Name: "m171-emitter"} }
func (*m171Emitter) Setup(context.Context, *core.Env) error    { return nil }
func (*m171Emitter) Start(context.Context, *core.Env) error    { return nil }
func (*m171Emitter) Stop(context.Context, *core.Env) error     { return nil }
func (*m171Emitter) Teardown(context.Context, *core.Env) error { return nil }
func (*m171Emitter) DefensiveActions(context.Context, *core.Env) (int, []float64, error) {
	return 0, nil, nil
}
func (e *m171Emitter) EmitSecurityEvent(_ context.Context, _ *core.Env, _, _, _ string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.emitted++
	if e.fail {
		return errors.New("fixture event delivery failed")
	}
	return nil
}

// m171ActingDefender is test-only. Its Start worker mutates the actual fixture
// after event delivery and records the exact target and attempt. FullPhoenix
// does not have this registry or ConfigMap repair capability.
type m171ActingDefender struct {
	mu             sync.Mutex
	wrongTarget    bool
	wrongAttempt   bool
	recreateTarget bool
	requests       chan *core.Env
	done           chan error
	receipt        core.DefenseEffectReceipt
}

func (*m171ActingDefender) Metadata() core.DefenderMeta {
	return core.DefenderMeta{Name: "m171-acting-defender"}
}
func (*m171ActingDefender) Setup(context.Context, *core.Env) error { return nil }
func (a *m171ActingDefender) Start(ctx context.Context, _ *core.Env) error {
	a.mu.Lock()
	a.requests = make(chan *core.Env, 1)
	a.done = make(chan error, 1)
	a.receipt = core.DefenseEffectReceipt{}
	recreate := a.recreateTarget
	a.mu.Unlock()
	go func() {
		select {
		case env := <-a.requests:
			var targetUID string
			var err error
			if env.ScenarioName == "ai2-agent-rogue-tool-persistence" {
				cm, readErr := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, mocks.AgentToolsConfigMap, metav1.GetOptions{})
				if readErr != nil {
					err = readErr
				} else {
					targetUID = string(cm.UID)
					cm.Data["tools"] = "search,summarize"
					_, err = env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Update(ctx, cm, metav1.UpdateOptions{})
					if err == nil && recreate {
						replacement := cm.DeepCopy()
						replacement.UID = types.UID("recreated-" + targetUID)
						_ = env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Delete(ctx, cm.Name, metav1.DeleteOptions{})
						_, err = env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Create(ctx, replacement, metav1.CreateOptions{})
					}
				}
			} else {
				pod, readErr := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, "mock-model-registry-pod", metav1.GetOptions{})
				if readErr != nil {
					err = readErr
				} else {
					targetUID = string(pod.UID)
					res := env.Exec(ctx, pod.Name, "server", []string{"sh", "-c", "echo " + mocks.GoldenModelDigest + " > /tmp/served_digest"})
					err = res.Err
					if err == nil && recreate {
						replacement := pod.DeepCopy()
						replacement.UID = types.UID("recreated-" + targetUID)
						_ = env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
						_, err = env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, replacement, metav1.CreateOptions{})
					}
				}
			}
			if err == nil {
				a.mu.Lock()
				if a.wrongTarget {
					targetUID = "unmatched-target"
				}
				attemptID := env.EffectAttemptID
				if a.wrongAttempt {
					attemptID = "previous-attempt"
				}
				a.receipt = core.DefenseEffectReceipt{Objective: env.ScenarioName, TargetUID: targetUID, AttemptID: attemptID, AtUnix: float64(time.Now().UnixNano()) / float64(time.Second)}
				a.mu.Unlock()
			}
			a.done <- err
		case <-ctx.Done():
			a.done <- ctx.Err()
		}
	}()
	return nil
}
func (*m171ActingDefender) Stop(context.Context, *core.Env) error     { return nil }
func (*m171ActingDefender) Teardown(context.Context, *core.Env) error { return nil }
func (a *m171ActingDefender) EmitSecurityEvent(_ context.Context, env *core.Env, _, _, _ string) error {
	a.requests <- env
	return <-a.done
}
func (a *m171ActingDefender) DefensiveActions(context.Context, *core.Env) (int, []float64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.receipt.AtUnix == 0 {
		return 0, nil, nil
	}
	return 1, []float64{a.receipt.AtUnix}, nil
}
func (a *m171ActingDefender) DefensiveEffectReceipt(context.Context, *core.Env) (core.DefenseEffectReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.receipt.AtUnix == 0 {
		return core.DefenseEffectReceipt{}, errors.New("no action")
	}
	return a.receipt, nil
}

type m171FixtureState struct {
	mu       sync.Mutex
	digest   string
	failPost bool
	reads    int
	cmReads  int
}

// This drives registered producers and core.Runner against local API and exec
// fixtures. The emitter does nothing to the substrate: successful delivery is
// the exact baseline false-credit trigger. No final OracleAchieved flag is set.
func TestM171RunnerEmitterDeliveryCannotRepairFixture(t *testing.T) {
	oldPause := observationPause
	observationPause = func(time.Duration) {}
	t.Cleanup(func() { observationPause = oldPause; core.SetExecer(nil) })
	emitter := &m171Emitter{}
	core.RegisterDefender(emitter)
	actor := &m171ActingDefender{}
	core.RegisterDefender(actor)
	for _, name := range []string{"ai2-data-model-poisoning", "ai2-poisoned-model-registry", "ai2-agent-rogue-tool-persistence"} {
		t.Run(name, func(t *testing.T) {
			states := map[string]*m171FixtureState{}
			var statesMu sync.Mutex
			failPost := false
			core.SetExecer(func(_ context.Context, rc *rest.Config, _ kubernetes.Interface, _, _, _ string, cmd []string) core.ExecResult {
				statesMu.Lock()
				st := states[rc.Host]
				statesMu.Unlock()
				if st == nil {
					return core.ExecResult{ExitCode: -1, Err: errors.New("missing fixture state")}
				}
				st.mu.Lock()
				defer st.mu.Unlock()
				script := strings.Join(cmd, " ")
				if strings.Contains(script, "echo") && strings.Contains(script, mocks.PoisonedModelDigest) {
					st.digest = mocks.PoisonedModelDigest
					return core.ExecResult{}
				}
				if strings.Contains(script, "echo") && strings.Contains(script, mocks.GoldenModelDigest) {
					st.digest = mocks.GoldenModelDigest
					return core.ExecResult{}
				}
				if strings.Contains(script, "cat /tmp/served_digest") {
					st.reads++
					if st.failPost && st.reads > 1 {
						return core.ExecResult{ExitCode: -1, Err: errors.New("fixture read failed")}
					}
					return core.ExecResult{Stdout: st.digest + "\n"}
				}
				return core.ExecResult{}
			})
			factory := func(_, defender string, trial int, _ int64, _ string) (*core.Env, func() error, error) {
				kube := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", UID: "sandbox-uid"}})
				kube.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
					obj := action.(k8stesting.CreateAction).GetObject().(*corev1.Pod).DeepCopy()
					if obj.UID == "" {
						obj.UID = types.UID("fixture-" + defender + "-" + obj.Name)
					}
					obj.Status.Phase = corev1.PodRunning
					if err := kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), obj, obj.Namespace); err != nil {
						return true, nil, err
					}
					return true, obj, nil
				})
				kube.PrependReactor("create", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
					obj := action.(k8stesting.CreateAction).GetObject().(*corev1.ConfigMap).DeepCopy()
					if obj.UID == "" {
						obj.UID = types.UID("fixture-" + defender + "-" + obj.Name)
					}
					if err := kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("configmaps"), obj, obj.Namespace); err != nil {
						return true, nil, err
					}
					return true, obj, nil
				})
				kube.PrependReactor("create", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
					obj := action.(k8stesting.CreateAction).GetObject().(*corev1.Service).DeepCopy()
					if obj.UID == "" {
						obj.UID = types.UID("fixture-" + defender + "-" + obj.Name)
					}
					if err := kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("services"), obj, obj.Namespace); err != nil {
						return true, nil, err
					}
					return true, obj, nil
				})
				kube.PrependReactor("get", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if !failPost || action.(k8stesting.GetAction).GetName() != mocks.AgentToolsConfigMap {
						return false, nil, nil
					}
					host := "https://" + defender + ".invalid"
					statesMu.Lock()
					st := states[host]
					statesMu.Unlock()
					st.mu.Lock()
					defer st.mu.Unlock()
					st.cmReads++
					if st.cmReads > 2 {
						return true, nil, errors.New("fixture ConfigMap read failed")
					}
					return false, nil, nil
				})
				host := "https://" + defender + ".invalid"
				statesMu.Lock()
				states[host] = &m171FixtureState{digest: mocks.GoldenModelDigest, failPost: failPost}
				statesMu.Unlock()
				env := &core.Env{Kube: kube, Rest: &rest.Config{Host: host}, Config: config.TargetConfig{Namespace: "sandbox"}, Log: &dpLogger{}, Guard: dpGuard{}, Trial: trial, ScenarioName: name, DefenderName: defender}
				if err := env.EnsureNamespace(context.Background()); err != nil {
					return nil, nil, err
				}
				return env, func() error {
					// Explicit unscored fixture cleanup runs after the oracle. The
					// recorded emitter result must retain its pre-cleanup poison.
					if defender == "m171-emitter" && name != "ai2-agent-rogue-tool-persistence" {
						statesMu.Lock()
						st := states[host]
						statesMu.Unlock()
						st.mu.Lock()
						st.digest = mocks.GoldenModelDigest
						st.mu.Unlock()
					}
					pods, _ := kube.CoreV1().Pods("sandbox").List(context.Background(), metav1.ListOptions{})
					for i := range pods.Items {
						_ = kube.CoreV1().Pods("sandbox").Delete(context.Background(), pods.Items[i].Name, metav1.DeleteOptions{})
					}
					cms, _ := kube.CoreV1().ConfigMaps("sandbox").List(context.Background(), metav1.ListOptions{})
					for i := range cms.Items {
						_ = kube.CoreV1().ConfigMaps("sandbox").Delete(context.Background(), cms.Items[i].Name, metav1.DeleteOptions{})
					}
					return env.CleanupOwned(context.Background(), false)
				}, nil
			}
			writer, err := core.NewMetricWriter(filepath.Join(t.TempDir(), "metrics.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			r := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir(), ScenarioFilter: map[string]bool{name: true}, DefenderFilter: map[string]bool{"d-nomtd": true, "m171-emitter": true, "m171-acting-defender": true}, CleanupTimeout: 8 * time.Second}, factory, writer, nil)
			rows, err := r.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 3 {
				t.Fatalf("rows=%d want 3", len(rows))
			}
			for _, row := range rows {
				if row.Defender == "m171-acting-defender" {
					if row.OracleAchieved || !row.IsScored() || row.DisruptionVsOracle != 1 {
						t.Fatalf("acting test defender did not earn credit for its measured action: %+v", row)
					}
				} else {
					if !row.OracleAchieved || !row.IsScored() || row.DisruptionVsOracle != 0 {
						t.Fatalf("emitter/no-defense fixture changed or received credit: %+v", row)
					}
					if strings.Contains(row.ObservedState, "golden observed=true") {
						t.Fatalf("fixture was repaired: %+v", row)
					}
				}
				blob, err := json.Marshal(row)
				if err != nil {
					t.Fatal(err)
				}
				var restored core.Metric
				if err := json.Unmarshal(blob, &restored); err != nil {
					t.Fatal(err)
				}
				if restored.ObservedState != row.ObservedState || restored.OracleAchieved != row.OracleAchieved || restored.Validity == nil {
					t.Fatalf("raw result lost in serialization: %+v", restored)
				}
			}
			if name != "ai2-agent-rogue-tool-persistence" {
				statesMu.Lock()
				st := states["https://m171-emitter.invalid"]
				statesMu.Unlock()
				st.mu.Lock()
				cleanedDigest := st.digest
				st.mu.Unlock()
				if cleanedDigest != mocks.GoldenModelDigest {
					t.Fatalf("unscored fixture cleanup did not restore local state: %s", cleanedDigest)
				}
			}
			failPost = true
			invalidWriter, err := core.NewMetricWriter(filepath.Join(t.TempDir(), "invalid.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer invalidWriter.Close()
			invalidRunner := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir(), ScenarioFilter: map[string]bool{name: true}, DefenderFilter: map[string]bool{"d-nomtd": true, "m171-emitter": true}, CleanupTimeout: 8 * time.Second}, factory, invalidWriter, nil)
			invalidRows, err := invalidRunner.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(invalidRows) != 2 {
				t.Fatalf("invalid rows=%d", len(invalidRows))
			}
			for _, row := range invalidRows {
				if row.IsScored() || !row.Skipped || row.Validity == nil || row.Validity.Status != core.MeasurementInvalid {
					t.Fatalf("failed post-response read was scored: %+v", row)
				}
			}
			failPost = false
			actor.mu.Lock()
			actor.wrongTarget = true
			actor.mu.Unlock()
			unmatchedWriter, err := core.NewMetricWriter(filepath.Join(t.TempDir(), "unmatched.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer unmatchedWriter.Close()
			unmatchedRunner := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir(), ScenarioFilter: map[string]bool{name: true}, DefenderFilter: map[string]bool{"d-nomtd": true, "m171-acting-defender": true}, CleanupTimeout: 8 * time.Second}, factory, unmatchedWriter, nil)
			unmatchedRows, err := unmatchedRunner.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range unmatchedRows {
				if row.Defender == "m171-acting-defender" && (row.OracleAchieved || row.IsScored() || !row.Skipped || row.DisruptionVsOracle != 0) {
					t.Fatalf("unmatched acting receipt received mitigation credit: %+v", row)
				}
			}
			for _, summary := range report.Aggregate(unmatchedRows, 0.95) {
				if summary.Defender == "m171-acting-defender" && (summary.Trials != 0 || summary.Validity.Scored != 0 || !summary.Skipped) {
					t.Fatalf("report serialized unmatched receipt as scored: %+v", summary)
				}
			}
			actor.mu.Lock()
			actor.wrongTarget = false
			actor.mu.Unlock()
			actor.mu.Lock()
			actor.wrongAttempt = true
			actor.mu.Unlock()
			staleWriter, err := core.NewMetricWriter(filepath.Join(t.TempDir(), "stale-attempt.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer staleWriter.Close()
			staleRunner := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir(), ScenarioFilter: map[string]bool{name: true}, DefenderFilter: map[string]bool{"d-nomtd": true, "m171-acting-defender": true}, CleanupTimeout: 8 * time.Second}, factory, staleWriter, nil)
			staleRows, err := staleRunner.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range staleRows {
				if row.Defender == "m171-acting-defender" && (row.OracleAchieved || row.IsScored() || !row.Skipped || row.DisruptionVsOracle != 0) {
					t.Fatalf("stale action attempt received mitigation credit: %+v", row)
				}
			}
			actor.mu.Lock()
			actor.wrongAttempt = false
			actor.mu.Unlock()
			actor.mu.Lock()
			actor.recreateTarget = true
			actor.mu.Unlock()
			recreatedWriter, err := core.NewMetricWriter(filepath.Join(t.TempDir(), "recreated-target.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer recreatedWriter.Close()
			recreatedRunner := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir(), ScenarioFilter: map[string]bool{name: true}, DefenderFilter: map[string]bool{"d-nomtd": true, "m171-acting-defender": true}, CleanupTimeout: 8 * time.Second}, factory, recreatedWriter, nil)
			recreatedRows, recreatedErr := recreatedRunner.Run(context.Background())
			actor.mu.Lock()
			actor.recreateTarget = false
			actor.mu.Unlock()
			if name != "ai2-agent-rogue-tool-persistence" {
				// The actor replaced the exact Pod after setup. The scenario oracle
				// already marks the trial invalid, and ownership-safe teardown must
				// additionally refuse to delete that replacement.
				if recreatedErr == nil || !strings.Contains(recreatedErr.Error(), "refusing replacement pod") {
					t.Fatalf("same-name replacement cleanup error=%v rows=%+v", recreatedErr, recreatedRows)
				}
			} else {
				if recreatedErr != nil {
					t.Fatal(recreatedErr)
				}
				for _, row := range recreatedRows {
					if row.Defender == "m171-acting-defender" && (row.IsScored() || !row.Skipped || row.Validity == nil || row.Validity.Status != core.MeasurementInvalid) {
						t.Fatalf("same-name recreated substrate received credit: %+v", row)
					}
				}
			}
			emitter.mu.Lock()
			emitter.fail = true
			emitter.mu.Unlock()
			failedWriter, err := core.NewMetricWriter(filepath.Join(t.TempDir(), "failed-emitter.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer failedWriter.Close()
			failedRunner := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir(), ScenarioFilter: map[string]bool{name: true}, DefenderFilter: map[string]bool{"d-nomtd": true, "m171-emitter": true}, CleanupTimeout: 8 * time.Second}, factory, failedWriter, nil)
			failedRows, err := failedRunner.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range failedRows {
				if !row.OracleAchieved || !row.IsScored() || row.DisruptionVsOracle != 0 {
					t.Fatalf("failed emitter changed scored fixture state: %+v", row)
				}
				if row.Defender == "m171-emitter" && !strings.Contains(row.ObservedState, "event emitted=false") {
					t.Fatalf("failed delivery not disclosed: %+v", row)
				}
			}
			emitter.mu.Lock()
			emitter.fail = false
			emitter.mu.Unlock()
		})
	}
}

func TestM171FixtureReadsRejectMissingAndMalformedTargets(t *testing.T) {
	t.Cleanup(func() { core.SetExecer(nil) })
	env := fixtureObservationEnv()
	registry := &mocks.MockModelRegistry{MockServer: &mocks.MockServer{PodName: "mock-model-registry-pod"}}
	if _, err := registry.ObservedServedDigest(context.Background(), env); err == nil {
		t.Fatal("missing registry Pod read was accepted")
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: registry.PodName, Namespace: "sandbox", UID: "registry-uid"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	if _, err := env.Kube.CoreV1().Pods("sandbox").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		return core.ExecResult{Stdout: "truncated", ExitCode: 0}
	})
	if _, err := registry.ObservedServedDigest(context.Background(), env); err == nil {
		t.Fatal("malformed registry digest was accepted")
	}
	core.SetExecer(func(_ context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, _ []string) core.ExecResult {
		return core.ExecResult{Stdout: mocks.PoisonedModelDigest + "\n", ExitCode: 0}
	})
	if digest, err := registry.ObservedServedDigest(context.Background(), env); err != nil || digest != mocks.PoisonedModelDigest {
		t.Fatalf("valid poisoned digest lost: %q %v", digest, err)
	}
	reads := 0
	env.Kube.(*fake.Clientset).PrependReactor("get", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		reads++
		if reads == 2 {
			recreated := pod.DeepCopy()
			recreated.UID = "recreated-registry-uid"
			return true, recreated, nil
		}
		return false, nil, nil
	})
	if _, err := registry.ObservedServedDigest(context.Background(), env); err == nil {
		t.Fatal("same-name registry recreation during exec was accepted")
	}
	agent := &mocks.MockAgentRuntime{PodName: "mock-agent"}
	if _, err := agent.ObservedTools(context.Background(), env); err == nil {
		t.Fatal("missing tools ConfigMap was accepted")
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: mocks.AgentToolsConfigMap, Namespace: "sandbox", UID: "tools-uid"}, Data: map[string]string{}}
	if _, err := env.Kube.CoreV1().ConfigMaps("sandbox").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.ObservedTools(context.Background(), env); err == nil {
		t.Fatal("missing tools key was accepted")
	}
	cm.Data["tools"] = "truncated"
	if _, err := env.Kube.CoreV1().ConfigMaps("sandbox").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.ObservedTools(context.Background(), env); err == nil {
		t.Fatal("malformed tools value was accepted")
	}
	cm.Data["tools"] = "search,summarize," + mocks.RogueToolMarker
	if _, err := env.Kube.CoreV1().ConfigMaps("sandbox").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if tools, err := agent.ObservedTools(context.Background(), env); err != nil || !strings.Contains(tools, mocks.RogueToolMarker) {
		t.Fatalf("valid rogue tools lost: %q %v", tools, err)
	}
}
