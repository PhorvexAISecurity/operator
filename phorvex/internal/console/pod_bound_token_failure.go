package console

import (
	"errors"
	"fmt"
	"time"
)

// This receipt contains only stable diagnostics. The original error may contain
// API response bodies or credentials and must never be copied into run output.
type podBoundCoordinatorFailure struct {
	Schema        string `json:"schema"`
	RunID         string `json:"runID"`
	Nonce         string `json:"nonce"`
	RequestSHA256 string `json:"requestSHA256"`
	Stage         string `json:"stage"`
	Reason        string `json:"reason"`
	ErrorSHA256   string `json:"errorSHA256"`
	RecordedAt    string `json:"recordedAt"`
}

func podBoundFailureReason(stage string) string {
	switch stage {
	case "request-validation":
		return "REQUEST_INVALID"
	case "authorization":
		return "AUTHORIZATION_FAILED"
	case "source-validation":
		return "SOURCE_VALIDATION_FAILED"
	case "audit-start":
		return "AUDIT_START_FAILED"
	case "post-audit-authorization":
		return "AUTHORIZATION_CHANGED"
	case "post-audit-source":
		return "SOURCE_RECHECK_FAILED"
	case "post-audit-source-manifest":
		return "SOURCE_MANIFEST_FAILED"
	case "post-audit-disjointness":
		return "DISJOINTNESS_FAILED"
	case "signal-intent":
		return "SIGNAL_INTENT_FAILED"
	case "typed-event-create":
		return "EVENT_CREATION_FAILED"
	case "decision-observation":
		return "DECISION_OBSERVATION_FAILED"
	case "observation-commit":
		return "OBSERVATION_COMMIT_FAILED"
	case "event-cleanup":
		return "EVENT_CLEANUP_FAILED"
	}
	return ""
}

func recordPodBoundCoordinatorFailure(out string, req podBoundTokenRequest, requestSHA, stage string, cause error) error {
	if cause == nil || req.RunID == "" || !podBoundTokenNonce.MatchString(req.Nonce) ||
		!mongoSHA.MatchString(requestSHA) || podBoundFailureReason(stage) == "" {
		return errors.New("Pod-bound token coordinator failure identity unavailable")
	}
	_, err := writePodBoundOwnedFile(out, podBoundCoordinatorFailureFile, podBoundCoordinatorFailure{
		Schema: "pod-bound-token-coordinator-failure-v1", RunID: req.RunID, Nonce: req.Nonce,
		RequestSHA256: requestSHA, Stage: stage, Reason: podBoundFailureReason(stage),
		ErrorSHA256: podBoundHash([]byte(cause.Error())), RecordedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	return err
}

func readPodBoundCoordinatorFailure(out, id string) (*podBoundCoordinatorFailure, error) {
	var req podBoundTokenRequest
	rawReq, err := readPodBoundJSON(out, podBoundRequestFile, &req)
	if err != nil {
		return nil, err
	}
	if req.Schema != "pod-bound-token-request-v1" || req.RunID != id || !podBoundTokenNonce.MatchString(req.Nonce) {
		return nil, errors.New("Pod-bound token coordinator request identity differs")
	}
	var failure podBoundCoordinatorFailure
	if _, err := readPodBoundJSON(out, podBoundCoordinatorFailureFile, &failure); err != nil {
		return nil, err
	}
	if failure.Schema != "pod-bound-token-coordinator-failure-v1" || failure.RunID != id ||
		failure.Nonce != req.Nonce || failure.RequestSHA256 != podBoundHash(rawReq) ||
		podBoundFailureReason(failure.Stage) == "" || failure.Reason != podBoundFailureReason(failure.Stage) ||
		!mongoSHA.MatchString(failure.ErrorSHA256) {
		return nil, errors.New("Pod-bound token coordinator failure identity differs")
	}
	requested, reqTimeErr := time.Parse(time.RFC3339Nano, req.RequestedAt)
	recorded, recordedErr := time.Parse(time.RFC3339Nano, failure.RecordedAt)
	if reqTimeErr != nil || recordedErr != nil || recorded.Before(requested) || recorded.After(time.Now().Add(2*time.Second)) {
		return nil, errors.New("Pod-bound token coordinator failure time invalid")
	}
	return &failure, nil
}

func podBoundCoordinatorStatus(out, id string, responseErr error) string {
	failure, err := readPodBoundCoordinatorFailure(out, id)
	if err == nil {
		return fmt.Sprintf("; coordinator failed at %s (%s; error SHA-256 %s)", failure.Stage, failure.Reason, failure.ErrorSHA256)
	}
	if responseErr != nil {
		return "; coordinator failed without a matching diagnostic receipt"
	}
	return ""
}

func finishPodBoundTokenStatus(st *RunStatus, out, id string, started bool, result PodBoundTokenResult,
	evidenceErr, responseErr, sealErr, processErr, contextErr error) {
	if !started {
		st.State, st.CleanupStatus, st.UnsafeToRetry = "error", "NO_EFFECT", false
		st.Error = "Pod-bound token harness process did not start"
		return
	}
	if evidenceErr == nil && responseErr == nil && sealErr == nil && processErr == nil && contextErr == nil &&
		result.TerminalStatus == "COMPLETE" && result.Cleanup.Status == "CONFIRMED_ABSENT" && result.Cleanup.Absent {
		st.State, st.CleanupStatus, st.UnsafeToRetry = "done", "VERIFIED", false
		return
	}
	st.State, st.CleanupStatus, st.UnsafeToRetry = "partial", "UNVERIFIED", true
	st.Error = podBoundUnsafeStatus(out, id) + podBoundCoordinatorStatus(out, id, responseErr)
}
