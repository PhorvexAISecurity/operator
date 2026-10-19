package actuatorpb

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/phorvex/phorvex/internal/actuatorapi"
)

// roundTrip sends m through the protobuf encoding, as the wire does.
func roundTrip[M proto.Message](t *testing.T, m M, into M) M {
	t.Helper()
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
	return into
}

func TestErrorsKeepTheIdentitiesTheDispatcherBranchesOn(t *testing.T) {
	inner := errors.New("serving receipt differs")
	for name, err := range map[string]error{
		"plain":            errors.New("amtd refused"),
		"empty text":       errors.New(""),
		"refusal":          actuatorapi.RefusedWithoutEffect(inner),
		"wrapped refusal":  fmt.Errorf("native: %w", actuatorapi.RefusedWithoutEffect(inner)),
		"deadline":         fmt.Errorf("journal read: %w", context.DeadlineExceeded),
		"canceled":         context.Canceled,
		"refused deadline": actuatorapi.RefusedWithoutEffect(fmt.Errorf("probe: %w", context.DeadlineExceeded)),
	} {
		got := DecodeError(roundTrip(t, &PendingOperationResponse{Error: EncodeError(err)}, &PendingOperationResponse{}).GetError())
		if got == nil || got.Error() != err.Error() {
			t.Fatalf("%s: %v, want %q", name, got, err)
		}
		if actuatorapi.IsNoEffectRefusal(got) != actuatorapi.IsNoEffectRefusal(err) ||
			errors.Is(got, context.DeadlineExceeded) != errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(got, context.Canceled) != errors.Is(err, context.Canceled) {
			t.Fatalf("%s: identities lost: refusal=%v deadline=%v canceled=%v", name,
				actuatorapi.IsNoEffectRefusal(got), errors.Is(got, context.DeadlineExceeded), errors.Is(got, context.Canceled))
		}
	}
	if DecodeError(roundTrip(t, &PendingOperationResponse{Error: EncodeError(nil)}, &PendingOperationResponse{}).GetError()) != nil {
		t.Fatal("a nil error came back non-nil")
	}
}

func TestRouteResultsRoundTrip(t *testing.T) {
	refusal := actuatorapi.RefusedWithoutEffect(errors.New("owner ambiguous"))
	result := actuatorapi.PolicyMaintenanceResult{
		Preparation: actuatorapi.RoutePreparation{PhoenixErr: refusal, NativeSkipped: true},
		Phoenix:     actuatorapi.PolicyRouteMaintenance{State: actuatorapi.PolicyMaintenanceOwnershipRefused, Detail: "owner ambiguous"},
		Native:      actuatorapi.PolicyRouteMaintenance{State: actuatorapi.PolicyMaintenanceNotRequired, Detail: "native route not required"},
	}
	got := DecodePolicyMaintenance(roundTrip(t, &ObserveStandingPolicyResponse{Result: EncodePolicyMaintenance(result)}, &ObserveStandingPolicyResponse{}).GetResult())
	if got.Phoenix != result.Phoenix || got.Native != result.Native || got.Preparation.NativeErr != nil ||
		!got.Preparation.NativeSkipped || got.Preparation.PhoenixSkipped || !actuatorapi.IsNoEffectRefusal(got.Preparation.PhoenixErr) {
		t.Fatalf("maintenance = %+v", got)
	}

	events := []actuatorapi.RecoveryEvent{{Receipt: "r1", Kind: "k", Phase: "p", Tenant: "t", PolicyNamespace: "ns", PolicyName: "n",
		PolicyUID: "u", TargetName: "tn", TargetUID: "tu", Outcome: "o", Effect: "e", Err: refusal}, {Receipt: "r2"}}
	back := DecodeRecoveryEvents(roundTrip(t, &RecoverOperationsResponse{Events: EncodeRecoveryEvents(events)}, &RecoverOperationsResponse{}).GetEvents())
	if len(back) != 2 || !actuatorapi.IsNoEffectRefusal(back[0].Err) || back[1].Err != nil {
		t.Fatalf("events = %+v", back)
	}
	back[0].Err, events[0].Err = nil, nil
	if back[0] != events[0] || back[1] != events[1] {
		t.Fatalf("events = %+v, want %+v", back, events)
	}
}
