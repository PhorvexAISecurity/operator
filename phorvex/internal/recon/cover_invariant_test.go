package recon

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

type sharedCoverRecon struct{}

func (sharedCoverRecon) Name() string { return "test-shared-cover" }
func (sharedCoverRecon) AssetFacts(_ *model.WorkloadView, _ FactContext) AssetFacts {
	return AssetFacts{
		CoverByAction: map[model.Action][]string{
			model.ActionRotate: {"shared-block|podIdentity"},
		},
	}
}

func TestCoverKeysAreBlockPrefixed(t *testing.T) {
	profiles := Registry.All()
	if len(profiles) == 0 {
		t.Fatal("recon registry is empty")
	}
	if err := validateCoverKeys(profiles, coverInvariantProbes()); err != nil {
		t.Fatal(err)
	}

	// Mutation proof: the same guard must reject a deliberately shared cross-block key.
	err := validateCoverKeys([]ReconProfile{sharedCoverRecon{}}, coverInvariantProbes())
	if err == nil {
		t.Fatal("deliberately shared cover key passed the block-prefix guard")
	}
	if !strings.Contains(err.Error(), "shared-block|podIdentity") {
		t.Fatalf("guard error does not identify the shared key: %v", err)
	}
}
