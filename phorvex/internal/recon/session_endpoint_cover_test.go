package recon

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestSessionErasersUseCommonEndpointPrerequisite(t *testing.T) {
	ctx := FactContext{AssetValue: 2, PHold: 1, StageUrgency: 1, HasGPU: true, Stateful: true}
	for _, ready := range []bool{false, true} {
		v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "served", ServingEndpointReady: ready}}
		standard := standardRecon{}.AssetFacts(v, ctx)
		ucw := ucwRecon{}.AssetFacts(v, ctx)
		reset := standard.CoverByAction[model.ActionKVReset]
		migrate := ucw.CoverByAction[model.ActionKVMigrateInvalidate]
		if ready {
			if len(reset) != 1 || len(migrate) != 1 || reset[0] != migrate[0] {
				t.Fatalf("ready endpoint covers differ: reset=%v migrate=%v", reset, migrate)
			}
		} else if len(reset) != 0 || len(migrate) != 0 {
			t.Fatalf("missing endpoint received session cover: reset=%v migrate=%v", reset, migrate)
		}
	}
}
