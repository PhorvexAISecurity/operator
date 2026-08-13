package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type invalidStartupRecon struct{}

func (invalidStartupRecon) Name() string { return "standard-recon" }
func (invalidStartupRecon) AssetFacts(_ *model.WorkloadView, _ recon.FactContext) recon.AssetFacts {
	return recon.AssetFacts{CoverByAction: map[model.Action][]string{
		model.ActionRotate: {"shared-block|podIdentity"},
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
	err := (&Manager{Log: logr.Discard()}).Start(ctx)
	if err == nil {
		t.Fatal("manager startup accepted a cross-block cover key")
	}
	if !strings.Contains(err.Error(), "recon cover-key startup invariant failed") {
		t.Fatalf("unexpected startup error: %v", err)
	}
}
