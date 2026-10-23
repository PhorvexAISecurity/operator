package runner

import (
	"context"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actuatorsvc"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/inprocess"
)

// TestCapabilityAccessIsTheActingIdentitys pins whose authorization the gate
// reviews: the identity the actuator acts as. In process that is this process's
// checker; a remote actuator answers for its own identity, and this process's
// checker is never consulted.
func TestCapabilityAccessIsTheActingIdentitys(t *testing.T) {
	ctx := context.Background()
	verbs := []authz.Verb{{Resource: "pods", Verb: "delete"}}
	own := authz.NewCheckerWithClient(runnerDenySSAR{deny: false}, time.Minute)

	m := &Manager{Local: &inprocess.Services{}, Authz: own}
	if m.access() != nil {
		t.Fatal("no actuator is wired, yet the gate has an access leg")
	}
	localServices(m).Actuator = supportsAll{}
	local, ok := m.access().(*actuatorsvc.Local)
	if !ok || local.Access != own {
		t.Fatalf("in process the gate must review this process's identity: %#v", m.access())
	}
	m.Authz = nil
	if m.access() != nil {
		t.Fatal("without a checker the in-process actuator reviews no access")
	}

	m.Authz = own
	m.ActuatorService = &actuatorsvc.Local{Actuator: supportsAll{}, Access: authz.NewCheckerWithClient(runnerDenySSAR{deny: true}, time.Minute)}
	if allowed, unknown, _ := m.access().AccessAllowed(ctx, "vllm", verbs); allowed || unknown {
		t.Fatalf("a remote actuator's denial was not the gate's answer: allowed=%v unknown=%v", allowed, unknown)
	}
	m.ActuatorService = &actuatorsvc.Local{Actuator: supportsAll{}}
	if m.access() != nil {
		t.Fatal("a remote actuator that reviews no access must leave the gate without an access leg, not fall back to this process's identity")
	}
}
