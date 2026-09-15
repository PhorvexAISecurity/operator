package scenarios

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
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

type integrityDefender struct {
	name     string
	baseline bool
}

func (d integrityDefender) Metadata() core.DefenderMeta {
	return core.DefenderMeta{Name: d.name, IsNegativeControlBaseline: d.baseline}
}
func (integrityDefender) Setup(context.Context, *core.Env) error    { return nil }
func (integrityDefender) Start(context.Context, *core.Env) error    { return nil }
func (integrityDefender) Stop(context.Context, *core.Env) error     { return nil }
func (integrityDefender) Teardown(context.Context, *core.Env) error { return nil }
func (integrityDefender) DefensiveActions(context.Context, *core.Env) (int, []float64, error) {
	return 0, nil, nil
}

// The actual c1-lateral Setup→Execute→oracle runs through core.Runner. The
// defended fixture loses the measured marker with zero actions, so a raw false
// post-state must never become a disruption/ROI/report score.
func TestObservationRunnerExcludesUnattributedNegative(t *testing.T) {
	oldPause := observationPause
	observationPause = func(time.Duration) {}
	t.Cleanup(func() { observationPause = oldPause; core.SetExecer(nil) })
	core.RegisterDefender(integrityDefender{name: "m172-fixture-arm"})
	core.SetExecer(func(_ context.Context, rc *rest.Config, _ kubernetes.Interface, _, _, _ string, cmd []string) core.ExecResult {
		if len(cmd) > 2 && strings.Contains(cmd[2], "/tmp/.r6th_lateral") && strings.Contains(cmd[2], "test -f") {
			if strings.Contains(rc.Host, "fixture-arm") {
				return core.ExecResult{Stdout: observationAbsent, ExitCode: 0}
			}
			return core.ExecResult{Stdout: lateralMarker, ExitCode: 0}
		}
		return core.ExecResult{Stdout: "stimulus-ok", ExitCode: 0}
	})
	factory := func(_, defender string, trial int, _ int64, _ string) (*core.Env, func() error, error) {
		kube := fake.NewSimpleClientset()
		kube.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
			obj := action.(k8stesting.CreateAction).GetObject().(*corev1.Pod).DeepCopy()
			obj.UID = types.UID("fixture-" + defender + "-" + obj.Name)
			obj.Status.Phase = corev1.PodRunning
			if err := kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), obj, obj.Namespace); err != nil {
				return true, nil, err
			}
			return true, obj, nil
		})
		env := &core.Env{Kube: kube, Rest: &rest.Config{Host: "https://" + defender + ".invalid"}, Config: config.TargetConfig{Namespace: "sandbox"}, Log: &dpLogger{}, Guard: dpGuard{}, Trial: trial, ScenarioName: "c1-lateral", DefenderName: defender}
		return env, func() error {
			// Fake DeleteCollection may accept without removing tracker entries;
			// remove those local entries before exercising real residue verification.
			pods, err := kube.CoreV1().Pods("sandbox").List(context.Background(), metav1.ListOptions{})
			if err != nil {
				return err
			}
			for i := range pods.Items {
				if err := kube.CoreV1().Pods("sandbox").Delete(context.Background(), pods.Items[i].Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
			return env.CleanupOwned(context.Background(), false)
		}, nil
	}
	metricsPath := filepath.Join(t.TempDir(), "metrics.jsonl")
	writer, err := core.NewMetricWriter(metricsPath)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	runner := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir(), ScenarioFilter: map[string]bool{"c1-lateral": true}, DefenderFilter: map[string]bool{"d-nomtd": true, "m172-fixture-arm": true}, CleanupTimeout: 8 * time.Second}, factory, writer, nil)
	rows, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	var base, arm *core.Metric
	for i := range rows {
		switch rows[i].Defender {
		case "d-nomtd":
			base = &rows[i]
		case "m172-fixture-arm":
			arm = &rows[i]
		}
	}
	if base == nil || arm == nil {
		t.Fatalf("missing rows: %+v", rows)
	}
	if !base.IsScored() || !base.OracleAchieved {
		t.Fatalf("real positive control unavailable: %+v", *base)
	}
	if arm.OracleAchieved || arm.IsScored() || !arm.Skipped || arm.DisruptionVsOracle != 0 || arm.SecurityPerCost != 0 || arm.ROI != nil {
		t.Fatalf("unattributed false marker scored: %+v", *arm)
	}
	if arm.DefensiveActions != 0 {
		t.Fatalf("zero-action fixture relevance: got %d", arm.DefensiveActions)
	}
	foundSummary := false
	for _, summary := range report.Aggregate(rows, 0.95) {
		if summary.Defender == "m172-fixture-arm" && (summary.Trials != 0 || summary.Validity.Scored != 0 || !summary.Skipped) {
			t.Fatalf("report included unattributed disruption: %+v", summary)
		}
		if summary.Defender == "m172-fixture-arm" {
			foundSummary = true
		}
	}
	if !foundSummary {
		t.Fatal("report dropped the unscored arm instead of disclosing it")
	}
}
