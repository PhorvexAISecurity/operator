package brainsvc

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/brainpb"
	"github.com/phorvex/phorvex/internal/model"
)

// authorityProbe records what the installed authority answers during admission and
// right after it.
type authorityProbe struct {
	brainapi.Brain
	authority model.PersistenceObservationAuthority
	during    []bool
}

func (p *authorityProbe) SetPersistenceAuthority(a model.PersistenceObservationAuthority) {
	p.authority = a
}

func (p *authorityProbe) AdmitPersistenceObservation(o model.PersistenceObservation) model.PersistenceObservationResult {
	_, exact := p.authority.AuthorizeObservation(o)
	other := o
	other.EvidenceID += "-other"
	_, foreign := p.authority.AuthorizeObservation(other)
	p.during = append(p.during, exact, foreign)
	return model.PersistenceObservationResult{Reason: p.authority.Source()}
}

func TestAuthorityAnswersOnlyForTheAdmittedObservation(t *testing.T) {
	probe := &authorityProbe{}
	s := NewServer(probe, "")
	ctx := context.Background()
	if _, err := s.SetPersistenceAuthority(ctx, &brainpb.SetPersistenceAuthorityRequest{Present: true, Source: model.ScopedSessionCapability}); err != nil {
		t.Fatal(err)
	}
	observation := model.PersistenceObservation{EvidenceID: "evidence-1", Source: model.ScopedSessionCapability}
	raw, err := brainpb.Encode(observation)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := brainpb.Encode(model.PersistenceOperationBinding{OperationID: "op-1"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.AdmitPersistenceObservation(ctx, &brainpb.AdmitPersistenceObservationRequest{Observation: raw, Resolved: true, Authorized: true, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	var result model.PersistenceObservationResult
	if err := brainpb.Decode(resp.GetResult(), &result); err != nil || result.Reason != model.ScopedSessionCapability {
		t.Fatalf("authority source not reported: %+v %v", result, err)
	}
	if probe.during[0] != true || probe.during[1] != false {
		t.Fatalf("authority answered %v for the admitted and a foreign observation", probe.during)
	}
	if _, ok := probe.authority.AuthorizeObservation(observation); ok {
		t.Fatal("authority still authorizes after the admission returned")
	}
	if _, err := s.AdmitPersistenceObservation(ctx, &brainpb.AdmitPersistenceObservationRequest{Observation: raw}); err != nil {
		t.Fatal(err)
	}
	if probe.during[2] {
		t.Fatal("an observation the dispatcher did not resolve was authorized")
	}
	if _, err := s.SetPersistenceAuthority(ctx, &brainpb.SetPersistenceAuthorityRequest{}); err != nil {
		t.Fatal(err)
	}
	if probe.authority != nil {
		t.Fatal("removing the authority left one installed")
	}
}

// brokenStream fails every receive, as a stream whose client went away does.
type brokenStream struct {
	grpc.ServerStream
	sent int
}

func (s *brokenStream) Send(*brainpb.DecideResponse) error { s.sent++; return nil }
func (s *brokenStream) Recv() (*brainpb.DecideRequest, error) {
	return nil, errors.New("client gone")
}

func TestGateQuestionsFailClosedOnceTheStreamBreaks(t *testing.T) {
	stream := &brokenStream{}
	views := []*model.WorkloadView{{Pod: model.Pod{Namespace: "ns", Name: "a"}}}
	asker := &gateAsker{stream: stream, index: viewIndex(views)}
	capability := asker.capability(false)
	for i := 0; i < 3; i++ {
		if e := capability(views[0], model.ActionRotate, nil); e == nil || !e.Excluded || e.Kind != GateUnavailable {
			t.Fatalf("question %d after a broken stream was not answered closed: %+v", i, e)
		}
		if detail, excluded := asker.failure(views[0], model.ActionRotate); !excluded || detail == "" {
			t.Fatalf("failure question %d after a broken stream was not answered closed", i)
		}
	}
	if stream.sent != 1 {
		t.Fatalf("sent %d questions after the stream broke, want only the first", stream.sent)
	}
	stranger := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "not-in-request"}}
	fresh := &gateAsker{stream: &brokenStream{}, index: viewIndex(views)}
	if e := fresh.capability(true)(stranger, model.ActionRotate, nil); e == nil || !e.Excluded {
		t.Fatal("a question about an asset outside the request was not answered closed")
	}
}

func TestEvaluationErrorKinds(t *testing.T) {
	collision := model.CrossBlockCollision{Key: "k", ExistingBlock: "a", ConflictingBlock: "b"}
	for _, tc := range []struct {
		err  error
		kind brainpb.DecideErrorKind
	}{
		{brainapi.ErrOwnerRetired, brainpb.DecideErrorKind_DECIDE_ERROR_KIND_OWNER_RETIRED},
		{brainapi.ErrShadowCapabilityUnavailable, brainpb.DecideErrorKind_DECIDE_ERROR_KIND_SHADOW_CAPABILITY_UNAVAILABLE},
		{collision, brainpb.DecideErrorKind_DECIDE_ERROR_KIND_CROSS_BLOCK_COLLISION},
		{&collision, brainpb.DecideErrorKind_DECIDE_ERROR_KIND_CROSS_BLOCK_COLLISION},
		{errors.New("other"), brainpb.DecideErrorKind_DECIDE_ERROR_KIND_OTHER},
	} {
		got := decideError(tc.err)
		if got.GetKind() != tc.kind || got.GetMessage() != tc.err.Error() {
			t.Errorf("%v: kind %v message %q", tc.err, got.GetKind(), got.GetMessage())
		}
		if tc.kind == brainpb.DecideErrorKind_DECIDE_ERROR_KIND_CROSS_BLOCK_COLLISION && got.GetCollisionKey() != "k" {
			t.Errorf("%v: collision detail lost: %+v", tc.err, got)
		}
	}
	if decideError(nil) != nil {
		t.Fatal("no error must report none")
	}
}
