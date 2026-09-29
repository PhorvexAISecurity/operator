package actuator

import (
	"errors"
	"fmt"
	"testing"
)

// A rule that is written but not yet projected into every Pod is an emitted, unconfirmed
// effect on the dispatch path; every other resume failure must stay an error.
func TestVoiceMemoryDispatchReportsPendingProjectionAsEmitted(t *testing.T) {
	pending := fmt.Errorf("%w: %w", errVoiceMemoryProjectionPending, errors.New("desired rule not yet observed"))
	res, err := voiceMemoryDispatch(HandlerResult{MutationKind: "partial"}, pending)
	if err != nil || !res.Emitted || res.MutationKind != "partial" || len(res.ObjectsTouched) != 1 || res.NoEffect != NoEffectUnknown {
		t.Fatalf("pending projection not reported as emitted-unconfirmed: %+v %v", res, err)
	}
	other := errors.New("voice memory rule superseded prepared operation")
	res, err = voiceMemoryDispatch(HandlerResult{MutationKind: "partial"}, other)
	if !errors.Is(err, other) || res.Emitted {
		t.Fatalf("a real failure was masked: %+v %v", res, err)
	}
	ok := HandlerResult{MutationKind: "forward-only", Emitted: true}
	if res, err = voiceMemoryDispatch(ok, nil); err != nil || res.MutationKind != "forward-only" {
		t.Fatalf("confirmed result changed: %+v %v", res, err)
	}
}

func TestLiteLLMReadbackDeadlineIsIdentifiable(t *testing.T) {
	wrapped := fmt.Errorf("%w: %w", errLiteLLMReadbackPending, errors.New("gateway still inactive"))
	if !errors.Is(wrapped, errLiteLLMReadbackPending) {
		t.Fatal("readback deadline lost its identity")
	}
}
