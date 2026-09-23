package cataloguev1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type authHandler struct {
	profile ProfileID
}

func NewAuthUnauthHandler() Handler { return authHandler{profile: AuthUnauth} }
func NewAuthScopeHandler() Handler  { return authHandler{profile: AuthScope} }

func (h authHandler) Definition() Definition {
	definition, _ := DefinitionFor(h.profile)
	return definition
}

func (h authHandler) Validate(runtime Runtime) error {
	if h.profile != AuthUnauth && h.profile != AuthScope {
		return errors.New("unsupported authentication profile")
	}
	if runtime.FixedLoopback == nil {
		return errors.New("fixed loopback origin is not configured")
	}
	cfg := h.config(runtime)
	if err := validateAuthHTTPConfig(cfg, h.profile == AuthScope); err != nil {
		return err
	}
	token, err := readScopedToken(runtime.ScopedTokenFile)
	if err != nil {
		return err
	}
	zeroBytes(token)
	if !filepath.IsAbs(runtime.GrantFile) || filepath.Clean(runtime.GrantFile) != runtime.GrantFile {
		return errors.New("grant file must be a clean absolute path")
	}
	if _, err := privateFileSHA256(runtime.GrantFile); err != nil {
		return fmt.Errorf("grant authority: %w", err)
	}
	return nil
}

func (h authHandler) Run(ctx context.Context, job JobContext) Result {
	started := time.Now().UTC()
	result := Result{
		Outcome:   OutcomeTestFailed,
		Summary:   "authentication control did not complete",
		Limits:    []string{h.Definition().ClaimLimits},
		Cleanup:   Cleanup{Attempted: true, Status: "REFUSED"},
		StartedAt: started,
	}
	if err := h.Validate(job.Runtime); err != nil {
		result.Outcome = OutcomeInconclusive
		result.Summary = "authentication fixture unavailable: " + err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	before, err := captureAuthState(job.Runtime)
	if err != nil {
		result.Outcome = OutcomeInconclusive
		result.Summary = "authentication state could not be fingerprinted before the control: " + err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	hooks := authRecorderHooks(job.Recorder)
	var observed authHTTPResult
	if h.profile == AuthUnauth {
		observed, err = runAuthUnauthenticatedControl(ctx, job.Runtime.HTTPClient, h.config(job.Runtime), hooks)
	} else {
		observed, err = runAuthScopedControl(ctx, job.Runtime.HTTPClient, h.config(job.Runtime), hooks)
	}
	after, afterErr := captureAuthState(job.Runtime)
	result.Evidence = authEvidence(observed, before, after)
	if afterErr != nil {
		result.Outcome = OutcomeInconclusive
		result.Summary = "authentication state could not be fingerprinted after the control: " + afterErr.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if before != after {
		result.Outcome = OutcomeInconclusive
		result.Summary = "console executable or grant authority changed during the read-only control"
		result.Cleanup = Cleanup{Attempted: true, Verified: false, Status: "STATE-CHANGED"}
		result.FinishedAt = time.Now().UTC()
		return result
	}
	result.Cleanup = Cleanup{
		Attempted: true, Verified: true, Status: "PASS",
		Details: map[string]string{"effects": "none", "stateFingerprint": before.combined()},
	}
	if err != nil {
		result.Outcome, result.Summary = classifyAuthProbeFailure(err, observed)
		result.FinishedAt = time.Now().UTC()
		return result
	}
	result.Outcome = OutcomeFunctionalPass
	if h.profile == AuthUnauth {
		result.Summary = "missing and unsigned credentials were refused while the exact scoped bearer session succeeded"
	} else {
		result.Summary = "the allowed tenant read succeeded, unrelated tenant and target reads were refused, and the allowed read remained available"
	}
	result.FinishedAt = time.Now().UTC()
	return result
}

func (h authHandler) Reconcile(_ context.Context, _ JobContext, journal Journal) Cleanup {
	for _, record := range journal.Records {
		if record.Intent != nil && record.Intent.Mutation {
			return Cleanup{Attempted: true, Verified: false, Status: "FOREIGN-MUTATION-INTENT", UnsafeToRetry: true}
		}
	}
	return Cleanup{
		Attempted: true, Verified: true, Status: "PASS-NO-EFFECT",
		Details: map[string]string{"requestsReplayed": "0", "effects": "none"},
	}
}

func (h authHandler) config(runtime Runtime) authHTTPConfig {
	origin := ""
	if runtime.FixedLoopback != nil {
		origin = runtime.FixedLoopback.String()
	}
	return authHTTPConfig{
		FixedLoopback: origin, ScopedTokenFile: runtime.ScopedTokenFile,
		ExpectedSubject: runtime.ExpectedSubject, AllowedTenant: runtime.AllowedTenant,
		DeniedTenant: runtime.DeniedTenant, DeniedTarget: runtime.DeniedTarget,
	}
}

func authRecorderHooks(recorder Recorder) authProbeHooks {
	return authProbeHooks{
		Intent: func(step, method, path string) error {
			if recorder == nil {
				return errors.New("authentication recorder is unavailable")
			}
			return recorder.Intent(Intent{
				Step: step, Mutation: false, At: time.Now().UTC(),
				Identity: map[string]string{"method": method, "path": path},
			})
		},
		Event: func(observation authHTTPObservation) error {
			if recorder == nil {
				return errors.New("authentication recorder is unavailable")
			}
			return recorder.Event(Event{
				Step: observation.Step, Status: strconv.Itoa(observation.Status), At: time.Now().UTC(),
				Identity: map[string]string{
					"method": observation.Method, "path": observation.Path,
					"bodySHA256": observation.BodySHA256,
					"schema":     strings.Join(observation.SchemaKeys, ","),
				},
			})
		},
	}
}

type authStateFingerprint struct {
	Executable string
	Grant      string
}

func captureAuthState(runtime Runtime) (authStateFingerprint, error) {
	executable, err := os.Executable()
	if err != nil {
		return authStateFingerprint{}, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return authStateFingerprint{}, err
	}
	executableSHA, err := privateFileSHA256(executable)
	if err != nil {
		return authStateFingerprint{}, err
	}
	grantSHA, err := privateFileSHA256(runtime.GrantFile)
	if err != nil {
		return authStateFingerprint{}, err
	}
	return authStateFingerprint{Executable: executableSHA, Grant: grantSHA}, nil
}

func (f authStateFingerprint) combined() string {
	sum := sha256.Sum256([]byte(f.Executable + "\x00" + f.Grant))
	return hex.EncodeToString(sum[:])
}

func privateFileSHA256(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 256<<20 {
		return "", errors.New("fingerprinted authority must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 256<<20+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func authEvidence(observed authHTTPResult, before, after authStateFingerprint) map[string]string {
	evidence := map[string]string{
		"securityOutcome": "not-measured", "readOnly": "true",
		"requestCount":       strconv.Itoa(len(observed.Observations)),
		"sourceBeforeSHA256": before.Executable, "sourceAfterSHA256": after.Executable,
		"grantBeforeSHA256": before.Grant, "grantAfterSHA256": after.Grant,
		"projectionBeforeSHA256": observed.BeforeSHA256, "projectionAfterSHA256": observed.AfterSHA256,
	}
	for i, observation := range observed.Observations {
		prefix := "request" + strconv.Itoa(i+1)
		evidence[prefix+"Status"] = strconv.Itoa(observation.Status)
		evidence[prefix+"BodySHA256"] = observation.BodySHA256
	}
	return evidence
}

func classifyAuthProbeFailure(err error, observed authHTTPResult) (Outcome, string) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return OutcomeInconclusive, "authentication control was interrupted before a complete observation"
	}
	var status authStatusError
	if errors.As(err, &status) {
		if strings.Contains(status.Step, "legitimate") || strings.Contains(status.Step, "allowed") {
			return OutcomeInconclusive, "scoped test credential, grant, or positive control was unavailable during the control"
		}
		if status.Got == http.StatusOK && authenticatedPositiveObserved(observed) && boundaryBypassShape(status.Step, observed) {
			return OutcomeFunctionalFail, "authentication or authorization boundary allowed a request that the fixed scoped control required it to refuse: " + status.Error()
		}
		switch status.Got {
		case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return OutcomeInconclusive, "console boundary endpoint was unavailable during the control: " + status.Error()
		case http.StatusNotFound, http.StatusMethodNotAllowed:
			return OutcomeTestFailed, "console boundary endpoint contract differs from the fixed control: " + status.Error()
		}
		return OutcomeTestFailed, "authentication or authorization response could not establish the fixed oracle: " + status.Error()
	}
	if strings.Contains(err.Error(), "subject authority differs") || strings.Contains(err.Error(), "changed across") {
		return OutcomeInconclusive, err.Error()
	}
	return OutcomeTestFailed, "authentication control measurement is invalid: " + err.Error()
}

func authenticatedPositiveObserved(observed authHTTPResult) bool {
	for _, observation := range observed.Observations {
		if strings.HasPrefix(observation.Step, "legitimate-session") && observation.Status == http.StatusOK && containsAll(observation.SchemaKeys, []string{"authModes", "source", "subject"}) {
			return true
		}
	}
	return false
}

func boundaryBypassShape(step string, observed authHTTPResult) bool {
	for _, observation := range observed.Observations {
		if observation.Step != step || observation.Status != http.StatusOK {
			continue
		}
		switch step {
		case "missing-credential", "unsigned-alb-identity":
			return containsAll(observation.SchemaKeys, []string{"authModes", "source", "subject"})
		case "denied-tenant":
			return containsAll(observation.SchemaKeys, []string{"events", "rollup"})
		case "denied-target":
			return containsAll(observation.SchemaKeys, []string{"context", "namespaces"})
		}
	}
	return false
}
