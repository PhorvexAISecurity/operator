package console

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPodBoundCoordinatorRecordsRealEarlyFailure(t *testing.T) {
	out := t.TempDir()
	id := "run-1"
	req := podBoundTokenRequest{Schema: "pod-bound-token-request-v1", RunID: id,
		Nonce: strings.Repeat("a", 24), RequestedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	if _, err := writePodBoundOwnedFile(out, podBoundRequestFile, req); err != nil {
		t.Fatal(err)
	}
	s := &Server{runs: &RunManager{runs: map[string]*RunStatus{id: {Config: podBoundTokenCPUConfig}}}}
	if err := s.coordinatePodBoundTokenResponse(context.Background(), id, out); err == nil {
		t.Fatal("invalid CPU baseline accepted")
	}
	failure, err := readPodBoundCoordinatorFailure(out, id)
	if err != nil || failure.Stage != "request-validation" || failure.Reason != "REQUEST_INVALID" {
		t.Fatalf("real coordinator error not recorded: %+v, %v", failure, err)
	}
}

func TestPodBoundCoordinatorFailureIsBoundAndSafe(t *testing.T) {
	out := t.TempDir()
	req := podBoundTokenRequest{Schema: "pod-bound-token-request-v1", RunID: "run-1", Nonce: strings.Repeat("a", 24), RequestedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)}
	reqSHA, err := writePodBoundOwnedFile(out, podBoundRequestFile, req)
	if err != nil {
		t.Fatal(err)
	}
	secret := "sensitive API response body"
	if err := recordPodBoundCoordinatorFailure(out, req, reqSHA, "post-audit-disjointness", errors.New(secret)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out + "/" + podBoundCoordinatorFailureFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("raw coordinator error leaked")
	}
	failure, err := readPodBoundCoordinatorFailure(out, req.RunID)
	if err != nil || failure.Stage != "post-audit-disjointness" || failure.ErrorSHA256 != podBoundHash([]byte(secret)) {
		t.Fatalf("bound diagnostic unavailable: %+v, %v", failure, err)
	}
	if _, err := readPodBoundCoordinatorFailure(out, "run-2"); err == nil {
		t.Fatal("foreign run accepted")
	}
	for _, changed := range []podBoundCoordinatorFailure{
		{Schema: failure.Schema, RunID: failure.RunID, Nonce: strings.Repeat("b", 24), RequestSHA256: failure.RequestSHA256, Stage: failure.Stage, Reason: failure.Reason, ErrorSHA256: failure.ErrorSHA256, RecordedAt: failure.RecordedAt},
		{Schema: failure.Schema, RunID: failure.RunID, Nonce: failure.Nonce, RequestSHA256: strings.Repeat("b", 64), Stage: failure.Stage, Reason: failure.Reason, ErrorSHA256: failure.ErrorSHA256, RecordedAt: failure.RecordedAt},
	} {
		other := t.TempDir()
		if _, err := writePodBoundOwnedFile(other, podBoundRequestFile, req); err != nil {
			t.Fatal(err)
		}
		if _, err := writePodBoundOwnedFile(other, podBoundCoordinatorFailureFile, changed); err != nil {
			t.Fatal(err)
		}
		if _, err := readPodBoundCoordinatorFailure(other, req.RunID); err == nil {
			t.Fatal("foreign diagnostic accepted")
		}
	}
	status := &RunStatus{}
	finishPodBoundTokenStatus(status, out, req.RunID, true, PodBoundTokenResult{}, errors.New("result unavailable"), errors.New(secret), nil, nil, nil)
	if status.State != "partial" || status.CleanupStatus != "UNVERIFIED" || !status.UnsafeToRetry ||
		!strings.Contains(status.Error, failure.Stage) || !strings.Contains(status.Error, failure.ErrorSHA256) || strings.Contains(status.Error, secret) {
		t.Fatalf("unsafe coordinator failure was not propagated safely: %+v", status)
	}
	status = &RunStatus{}
	finishPodBoundTokenStatus(status, t.TempDir(), req.RunID, true, PodBoundTokenResult{
		TerminalStatus: "COMPLETE", Cleanup: PodBoundTokenCleanup{Status: "CONFIRMED_ABSENT", Absent: true},
	}, nil, errors.New("coordinator failed"), nil, nil, nil)
	if status.State != "partial" || !status.UnsafeToRetry || !strings.Contains(status.Error, "without a matching diagnostic") {
		t.Fatalf("response error bypassed result gate: %+v", status)
	}
}
