package killchain

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestVoiceMemoryObservedVectorUsesPersistStage(t *testing.T) {
	if got := stageFromEvent(model.SecurityEventInfo{Type: model.AttackVectorVoiceMemory}); got != StagePersist {
		t.Fatalf("observed Voice memory note stage=%v, want persist", got)
	}
}
