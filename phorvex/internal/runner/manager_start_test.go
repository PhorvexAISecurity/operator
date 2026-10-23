package runner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	ctrlmanager "sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func TestManagerTickLoopRequiresLeaderElection(t *testing.T) {
	var runnable ctrlmanager.LeaderElectionRunnable = &Manager{Local: &inprocess.Services{}}
	if !runnable.NeedLeaderElection() {
		t.Fatal("mutating tick loop must run only in the leader-elected runnable group")
	}
}

func TestHelmChartEnablesLeaderElectionByDefault(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	valuesPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "charts", "phorvex", "values.yaml")
	raw, err := os.ReadFile(valuesPath)
	if err != nil {
		t.Fatalf("read chart values: %v", err)
	}
	if !strings.Contains(string(raw), "  leaderElect: true\n") {
		t.Fatal("phorvex chart must enable leader election by default")
	}
}

type invalidStartupRecon struct{}

func (invalidStartupRecon) Name() string { return "standard-recon" }
func (invalidStartupRecon) AssetFacts(_ *model.WorkloadView, _ recon.FactContext) recon.AssetFacts {
	return recon.AssetFacts{CoverByAction: map[model.Action][]string{
		model.ActionRotate: {"pod|shared-block|podIdentity"},
	}}
}

func TestManagerStartFailsClosedOnCrossBlockCoverKey(t *testing.T) {
	original, ok := recon.Registry.Get("standard-recon")
	if !ok {
		t.Fatal("standard-recon is not registered")
	}
	recon.Registry.Register(invalidStartupRecon{})
	t.Cleanup(func() { recon.Registry.Register(original) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (&Manager{Local: &inprocess.Services{}, Log: logr.Discard()}).Start(ctx)
	if err == nil {
		t.Fatal("manager startup accepted a cross-block cover key")
	}
	if !strings.Contains(err.Error(), "recon cover-key startup invariant failed") {
		t.Fatalf("unexpected startup error: %v", err)
	}
}
