package cataloguev1

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phorvex/metricvalidity"
	"golang.org/x/sys/unix"
)

const (
	JobVersion     = 1
	ResultVersion  = 1
	maxRecordBytes = 64 << 10
	maxMetricBytes = 1 << 20
)

var (
	runIDPattern = regexp.MustCompile(`^v1run-[1-9][0-9]*$`)
	hex64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Runner struct {
	runtime  Runtime
	handlers map[ProfileID]Handler
}

func New(runtime Runtime, handlers ...Handler) (*Runner, error) {
	if strings.TrimSpace(runtime.StateDir) == "" || !filepath.IsAbs(runtime.StateDir) {
		return nil, errors.New("catalogue v1 state directory must be absolute")
	}
	r := &Runner{runtime: runtime, handlers: make(map[ProfileID]Handler, len(handlers))}
	for _, handler := range handlers {
		if handler == nil {
			return nil, errors.New("catalogue v1 handler is nil")
		}
		definition := handler.Definition()
		if err := validateDefinition(definition); err != nil {
			return nil, err
		}
		if _, exists := r.handlers[definition.ID]; exists {
			return nil, fmt.Errorf("catalogue v1 profile %q is registered twice", definition.ID)
		}
		r.handlers[definition.ID] = handler
	}
	return r, nil
}

func LoadJob(path, stateDir string) (Job, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Job{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maxRecordBytes {
		return Job{}, errors.New("catalogue v1 job file is not a private bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Job{}, err
	}
	var job Job
	if err = json.Unmarshal(raw, &job); err != nil {
		return Job{}, err
	}
	if err = validateJob(stateDir, job, false); err != nil {
		return Job{}, err
	}
	return job, nil
}

func WriteJob(path, stateDir string, job Job) error {
	if err := validateJob(stateDir, job, true); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(raw, '\n'))
}

// AcquireExecutionLock serializes execution and reconciliation for one job.
// The returned release function must remain held through handler cleanup.
func AcquireExecutionLock(outputDir string) (func() error, error) {
	f, err := os.OpenFile(filepath.Join(outputDir, "worker.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("catalogue v1 job is already executing or reconciling")
	}
	return func() error {
		unlockErr := unix.Flock(int(f.Fd()), unix.LOCK_UN)
		closeErr := f.Close()
		if unlockErr != nil {
			return unlockErr
		}
		return closeErr
	}, nil
}

func ExecutionLockAvailable(outputDir string) bool {
	release, err := AcquireExecutionLock(outputDir)
	if err != nil {
		return false
	}
	_ = release()
	return true
}

func (r *Runner) Definitions() []Definition {
	definitions := make([]Definition, 0, len(r.handlers))
	for _, handler := range r.handlers {
		definitions = append(definitions, handler.Definition())
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].ID < definitions[j].ID })
	return definitions
}

func DefinitionSHA256(definition Definition) (string, error) {
	if err := validateDefinition(definition); err != nil {
		return "", err
	}
	raw, err := json.Marshal(definition)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (r *Runner) Execute(ctx context.Context, job Job) Result {
	started := time.Now().UTC()
	handler, recorder, err := r.prepare(job, true)
	if err != nil {
		return failedResult(job, started, err)
	}
	result := handler.Run(ctx, JobContext{Job: job, Runtime: r.runtime, Recorder: recorder})
	result = normalizeResult(job, handler.Definition(), result, started)
	if err := ValidateResult(job, result); err != nil {
		result.Outcome = OutcomeTestFailed
		result.Summary = "handler terminal result is invalid: " + err.Error()
		result.Evidence = map[string]string{}
		result.UnsafeToRetry = true
	}
	if err := recorder.Result(result); err != nil {
		result.Outcome = OutcomeTestFailed
		result.Summary = "result persistence failed; unsafe to retry: " + err.Error()
		result.UnsafeToRetry = true
		return result
	}
	if !recorder.metricWritten {
		if err := recorder.Metric(metricFor(handler.Definition(), result)); err != nil {
			result.Outcome = OutcomeTestFailed
			result.Summary = "functional result persistence failed: " + err.Error()
			result.UnsafeToRetry = true
			_ = recorder.Result(result)
		}
	}
	return result
}

func (r *Runner) Reconcile(ctx context.Context, job Job) Result {
	started := time.Now().UTC()
	handler, recorder, err := r.prepare(job, false)
	if err != nil {
		return failedResult(job, started, err)
	}
	journal, err := loadJournal(filepath.Join(job.OutputDir, "journal.jsonl"))
	if err != nil {
		return failedResult(job, started, fmt.Errorf("load reconciliation journal: %w", err))
	}
	cleanup := handler.Reconcile(ctx, JobContext{Job: job, Runtime: r.runtime, Recorder: recorder}, journal)
	result := Result{
		Version: ResultVersion, RunID: job.RunID, Profile: job.Profile,
		Outcome: OutcomeInconclusive, Summary: "interrupted fixed suite reconciled without replay",
		Limits: []string{"interrupted execution was not resumed or retried"}, Cleanup: cleanup,
		UnsafeToRetry: cleanup.UnsafeToRetry || !cleanup.Verified,
		StartedAt:     started, FinishedAt: time.Now().UTC(),
	}
	if !cleanup.Verified {
		result.Outcome = OutcomeTestFailed
		result.Summary = "interrupted fixed suite requires reconciliation"
	}
	result = normalizeResult(job, handler.Definition(), result, started)
	if err := recorder.Result(result); err != nil {
		result.Outcome = OutcomeTestFailed
		result.Summary = "reconciliation result persistence failed; unsafe to retry: " + err.Error()
		result.UnsafeToRetry = true
	}
	return result
}

func (r *Runner) prepare(job Job, requireFresh bool) (Handler, *fileRecorder, error) {
	if err := validateJob(r.runtime.StateDir, job, requireFresh); err != nil {
		return nil, nil, err
	}
	if r.runtime.ConfigSHA256 != job.RuntimeConfigSHA256 {
		return nil, nil, errors.New("catalogue v1 runtime configuration differs from the persisted job")
	}
	handler := r.handlers[job.Profile]
	if handler == nil {
		return nil, nil, fmt.Errorf("catalogue v1 profile %q is not registered", job.Profile)
	}
	want, err := DefinitionSHA256(handler.Definition())
	if err != nil || job.DefinitionSHA256 != want {
		return nil, nil, errors.New("catalogue v1 profile definition differs from the persisted job")
	}
	if err := validateResolvedAuthority(job, handler.Definition(), r.runtime); err != nil {
		return nil, nil, err
	}
	if err := handler.Validate(r.runtime); err != nil {
		return nil, nil, fmt.Errorf("catalogue v1 profile unavailable: %w", err)
	}
	recorder, err := newFileRecorder(job.OutputDir)
	if err != nil {
		return nil, nil, err
	}
	return handler, recorder, nil
}

func validateResolvedAuthority(job Job, definition Definition, runtime Runtime) error {
	if job.ResolvedTarget != definition.FixedTarget {
		return errors.New("catalogue v1 resolved target differs from the fixed profile")
	}
	wantTenant := definition.FixedTenant
	switch job.Profile {
	case VoiceMedia, VoiceRecovery:
		wantTenant = runtime.Voice.Namespace
	case GPUDrain:
		wantTenant = runtime.GPU.Namespace
	case AuthUnauth, AuthScope:
		wantTenant = runtime.AllowedTenant
	case GuardrailCalibration:
		wantTenant = runtime.Guardrail.Namespace
	case MCPSessionBaseline:
		wantTenant = runtime.MCP.Namespace
	}
	if strings.TrimSpace(wantTenant) == "" || job.ResolvedTenant != wantTenant {
		return errors.New("catalogue v1 resolved tenant differs from the fixed runtime profile")
	}
	return nil
}

func validateDefinition(definition Definition) error {
	known := map[ProfileID]bool{VoiceMedia: true, VoiceRecovery: true, GPUDrain: true, AuthUnauth: true, AuthScope: true, GuardrailCalibration: true, MCPSessionBaseline: true}
	if !known[definition.ID] {
		return fmt.Errorf("unknown catalogue v1 profile %q", definition.ID)
	}
	if definition.Title == "" || definition.Product == "" || definition.Category == "" || definition.ClaimLimits == "" || definition.FixedTarget == "" || definition.FixedTenant == "" {
		return fmt.Errorf("catalogue v1 profile %q has incomplete metadata", definition.ID)
	}
	if definition.MaxDuration <= 0 || definition.MaxDuration > 15*time.Minute || definition.MaxMutations < 0 || definition.MaxMutations > 4 {
		return fmt.Errorf("catalogue v1 profile %q has invalid bounds", definition.ID)
	}
	return nil
}

func validateJob(stateDir string, job Job, requireFresh bool) error {
	if job.Version != JobVersion || !runIDPattern.MatchString(job.RunID) {
		return errors.New("catalogue v1 job version or run identity is invalid")
	}
	if job.Profile == "" || !hex64Pattern.MatchString(job.DefinitionSHA256) || !hex64Pattern.MatchString(job.OwnerDigest) {
		return errors.New("catalogue v1 job profile authority is invalid")
	}
	if strings.TrimSpace(job.ResolvedTarget) == "" || strings.TrimSpace(job.ResolvedTenant) == "" || !hex64Pattern.MatchString(job.RuntimeConfigSHA256) {
		return errors.New("catalogue v1 job runtime authority is invalid")
	}
	if job.CreatedAt.IsZero() || job.Deadline.IsZero() || !job.Deadline.After(job.CreatedAt) || (requireFresh && time.Now().After(job.Deadline)) {
		return errors.New("catalogue v1 job deadline is invalid or expired")
	}
	wantRoot := filepath.Join(filepath.Clean(stateDir), "runs") + string(os.PathSeparator)
	cleanOutput := filepath.Clean(job.OutputDir)
	if !filepath.IsAbs(cleanOutput) || !strings.HasPrefix(cleanOutput+string(os.PathSeparator), wantRoot) || filepath.Base(cleanOutput) != job.RunID {
		return errors.New("catalogue v1 output directory is outside the owned run root")
	}
	return nil
}

func normalizeResult(job Job, definition Definition, result Result, started time.Time) Result {
	result.Version, result.RunID, result.Profile = ResultVersion, job.RunID, job.Profile
	result.DefinitionSHA256, result.OwnerDigest = job.DefinitionSHA256, job.OwnerDigest
	result.ResolvedTarget, result.ResolvedTenant = job.ResolvedTarget, job.ResolvedTenant
	result.RuntimeConfigSHA256 = job.RuntimeConfigSHA256
	if result.StartedAt.IsZero() {
		result.StartedAt = started
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Now().UTC()
	}
	if result.Evidence == nil {
		result.Evidence = map[string]string{}
	}
	if result.Limits == nil {
		result.Limits = []string{definition.ClaimLimits}
	}
	switch result.Outcome {
	case OutcomeFunctionalPass, OutcomeFunctionalFail, OutcomeInconclusive, OutcomeTestFailed:
	default:
		result.Outcome = OutcomeTestFailed
		result.Summary = "handler returned an unsupported outcome"
		result.UnsafeToRetry = true
	}
	if !result.Cleanup.Verified && result.Outcome == OutcomeFunctionalPass {
		result.Outcome = OutcomeTestFailed
		result.Summary = "functional oracle completed but cleanup was not verified"
		result.UnsafeToRetry = true
	}
	return result
}

func metricFor(definition Definition, result Result) Metric {
	oracleStatus := "complete"
	status, phase := "valid", "oracle"
	reasons := []string{}
	oracleObserved := result.Outcome == OutcomeFunctionalPass || result.Outcome == OutcomeFunctionalFail
	if result.Outcome == OutcomeInconclusive {
		oracleStatus, status, phase = "incomplete", "invalid", "oracle"
		reasons = []string{result.Summary}
	}
	if result.Outcome == OutcomeTestFailed {
		oracleStatus, status, phase = "incomplete", "invalid", "execution"
		reasons = []string{result.Summary}
	}
	validity := &metricvalidity.Validity{
		Version: metricvalidity.Version, Kind: metricvalidity.TrialOrdinary, Status: metricvalidity.Status(status), Phase: metricvalidity.PhaseComplete,
		Reasons: reasons, AttackExecuted: true, OracleObserved: oracleObserved, ObserverPresent: true, CostObserved: false, Scored: false,
		UnscoredReason: "UNSCORED(benign-control)",
		Baseline:       metricvalidity.BaselineRef{Required: false, Defender: "d-functional", Trial: 0, Kind: metricvalidity.TrialOrdinary},
		Cleanup:        metricvalidity.CleanupRecord{Attempted: []metricvalidity.CleanupStep{{Step: "cataloguev1.cleanup"}}, Complete: result.Cleanup.Verified, Verified: result.Cleanup.Verified},
	}
	if status != string(metricvalidity.StatusValid) {
		validity.Phase = metricvalidity.Phase(phase)
	}
	return Metric{
		Scenario: string(definition.ID), Defender: "d-functional", Trial: 0,
		OracleAchieved:  result.Outcome == OutcomeFunctionalPass,
		ScenarioRealism: "executable-mechanism", ScenarioBenignControl: true,
		ScenarioClaimLimits: definition.ClaimLimits,
		BenchmarkEvidence:   map[string]string{"functionalArm": "fixed-suite", "oracleStatus": oracleStatus, "securityOutcome": "not-measured"},
		Validity:            validity,
	}
}

func failedResult(job Job, started time.Time, err error) Result {
	return Result{Version: ResultVersion, RunID: job.RunID, Profile: job.Profile, Outcome: OutcomeTestFailed,
		DefinitionSHA256: job.DefinitionSHA256, OwnerDigest: job.OwnerDigest,
		ResolvedTarget: job.ResolvedTarget, ResolvedTenant: job.ResolvedTenant, RuntimeConfigSHA256: job.RuntimeConfigSHA256,
		Summary: err.Error(), Limits: []string{}, Cleanup: Cleanup{Status: "not-started"},
		StartedAt: started, FinishedAt: time.Now().UTC()}
}

func ValidateResult(job Job, result Result) error {
	if result.Version != ResultVersion || result.RunID != job.RunID || result.Profile != job.Profile || result.DefinitionSHA256 != job.DefinitionSHA256 || result.OwnerDigest != job.OwnerDigest || result.ResolvedTarget != job.ResolvedTarget || result.ResolvedTenant != job.ResolvedTenant || result.RuntimeConfigSHA256 != job.RuntimeConfigSHA256 {
		return errors.New("catalogue v1 terminal result identity differs from the persisted job")
	}
	switch result.Outcome {
	case OutcomeFunctionalPass, OutcomeFunctionalFail, OutcomeInconclusive, OutcomeTestFailed:
	default:
		return errors.New("catalogue v1 terminal result outcome is unknown")
	}
	if result.StartedAt.IsZero() || result.FinishedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		return errors.New("catalogue v1 terminal result time authority is invalid")
	}
	if result.Outcome == OutcomeFunctionalPass && !result.Cleanup.Verified {
		return errors.New("catalogue v1 functional pass lacks verified cleanup")
	}
	for key, value := range result.Evidence {
		if err := validatePublicField(key, value); err != nil {
			return fmt.Errorf("catalogue v1 result evidence: %w", err)
		}
	}
	for key, value := range result.Cleanup.Details {
		if err := validatePublicField(key, value); err != nil {
			return fmt.Errorf("catalogue v1 cleanup details: %w", err)
		}
	}
	return nil
}

func validatePublicField(key, value string) error {
	lower := strings.ToLower(key)
	if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "authorization") || strings.Contains(lower, "credential") {
		return errors.New("contains a forbidden sensitive field")
	}
	if len(key) == 0 || len(key) > 64 || len(value) > 4096 {
		return errors.New("exceeds its bound")
	}
	return nil
}

// ValidateMetricFile proves that exactly one bounded metric was durably
// published for a terminal job. Result readers require it before marking a
// fixed suite done.
func ValidateMetricFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(raw) > maxMetricBytes+1 || raw[len(raw)-1] != '\n' || bytes.Contains(trimmed, []byte{'\n'}) {
		return errors.New("catalogue v1 metric file is empty, incomplete, multi-row, or exceeds its bound")
	}
	var projection Metric
	if err = json.Unmarshal(trimmed, &projection); err != nil {
		return err
	}
	if strings.TrimSpace(projection.Scenario) == "" || strings.TrimSpace(projection.Defender) == "" || projection.Validity == nil {
		return errors.New("catalogue v1 metric lacks required authority")
	}
	return nil
}

func ValidateTerminalArtifacts(job Job, result Result, metricPath string) error {
	if err := ValidateMetricFile(metricPath); err != nil {
		return err
	}
	raw, err := os.ReadFile(metricPath)
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(raw)
	if want := result.Evidence["metricSHA256"]; want != "" {
		sum := sha256.Sum256(trimmed)
		if hex.EncodeToString(sum[:]) != want {
			return errors.New("catalogue v1 metric digest differs from the terminal result")
		}
	}
	var metric Metric
	if err = json.Unmarshal(trimmed, &metric); err != nil {
		return err
	}
	wantScenario, wantDefender := string(job.Profile), "d-functional"
	if job.Profile == GPUDrain {
		wantScenario, wantDefender = "c2-vllm-request-drain", "d-nomtd"
	}
	if metric.Scenario != wantScenario || metric.Defender != wantDefender || metric.Trial != 0 || !metric.ScenarioBenignControl || metric.ScenarioRealism != "executable-mechanism" {
		return errors.New("catalogue v1 metric identity or benign-functional claim differs from the fixed profile")
	}
	if metric.Validity == nil || metric.Validity.Version != metricvalidity.Version || metric.Validity.Kind != metricvalidity.TrialOrdinary || metric.Validity.Scored || metric.Validity.UnscoredReason == "" {
		return errors.New("catalogue v1 metric validity is not an unscored ordinary functional measurement")
	}
	valid := metric.Validity != nil && metric.Validity.Status == metricvalidity.StatusValid && metric.Validity.Phase == metricvalidity.PhaseComplete
	if metric.Validity != nil && metric.Validity.Cleanup.Verified != result.Cleanup.Verified {
		return errors.New("catalogue v1 metric cleanup differs from the terminal result")
	}
	switch result.Outcome {
	case OutcomeFunctionalPass:
		if !valid || !metric.OracleAchieved {
			return errors.New("catalogue v1 functional pass differs from the metric oracle")
		}
	case OutcomeFunctionalFail:
		if !valid || metric.OracleAchieved {
			return errors.New("catalogue v1 functional failure differs from the metric oracle")
		}
	case OutcomeInconclusive:
		if valid {
			return errors.New("catalogue v1 inconclusive result carries a valid completed metric")
		}
	case OutcomeTestFailed:
		// A terminal execution/storage failure may legitimately demote an earlier
		// valid observation. Consumers must honor the terminal result.
	}
	return nil
}

type fileRecorder struct {
	dir           string
	mu            sync.Mutex
	metricWritten bool
}

func newFileRecorder(dir string) (*fileRecorder, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() || info.Mode().Perm()&0o027 != 0 {
		return nil, errors.New("catalogue v1 output directory is not private")
	}
	return &fileRecorder{dir: dir}, nil
}

func (r *fileRecorder) Intent(value Intent) error {
	if value.At.IsZero() {
		value.At = time.Now().UTC()
	}
	return r.append(JournalRecord{Kind: "intent", Intent: &value})
}
func (r *fileRecorder) Event(value Event) error {
	if value.At.IsZero() {
		value.At = time.Now().UTC()
	}
	return r.append(JournalRecord{Kind: "event", Event: &value})
}
func (r *fileRecorder) append(value JournalRecord) error {
	if err := validateRecord(value); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := os.OpenFile(filepath.Join(r.dir, "journal.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
func (r *fileRecorder) Metric(value Metric) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return r.MetricRaw(raw)
}
func (r *fileRecorder) MetricRaw(raw json.RawMessage) error {
	if len(raw) == 0 || len(raw) > maxMetricBytes {
		return errors.New("catalogue v1 metric exceeds bound")
	}
	var projection Metric
	if err := json.Unmarshal(raw, &projection); err != nil {
		return fmt.Errorf("catalogue v1 metric is malformed: %w", err)
	}
	if strings.TrimSpace(projection.Scenario) == "" || strings.TrimSpace(projection.Defender) == "" || projection.Validity == nil {
		return errors.New("catalogue v1 metric lacks scenario, defender, or validity authority")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.metricWritten {
		return errors.New("catalogue v1 metric already written")
	}
	if err := atomicWriteBounded(filepath.Join(r.dir, "metrics.jsonl"), append(raw, '\n'), maxMetricBytes+1); err != nil {
		return err
	}
	r.metricWritten = true
	return nil
}
func (r *fileRecorder) Result(value Result) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(r.dir, "result.json"), append(raw, '\n'))
}

func atomicWrite(path string, data []byte) error {
	return atomicWriteBounded(path, data, maxRecordBytes)
}

func atomicWriteBounded(path string, data []byte, limit int) error {
	if len(data) > limit {
		return errors.New("catalogue v1 record exceeds bound")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".catalogue-v1-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func validateRecord(record JournalRecord) error {
	var step string
	var identity map[string]string
	if record.Kind == "intent" && record.Intent != nil {
		step, identity = record.Intent.Step, record.Intent.Identity
	}
	if record.Kind == "event" && record.Event != nil {
		step, identity = record.Event.Step, record.Event.Identity
	}
	if step == "" || len(step) > 128 {
		return errors.New("catalogue v1 journal step is invalid")
	}
	for key, value := range identity {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "authorization") || strings.Contains(lower, "credential") {
			return errors.New("catalogue v1 journal contains a forbidden sensitive field")
		}
		if len(key) > 64 || len(value) > 512 {
			return errors.New("catalogue v1 journal identity exceeds bound")
		}
	}
	return nil
}

func loadJournal(path string) (Journal, error) {
	f, err := os.Open(path)
	if err != nil {
		return Journal{}, err
	}
	defer f.Close()
	journal := Journal{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), maxRecordBytes)
	for scanner.Scan() {
		if len(strings.TrimSpace(scanner.Text())) == 0 {
			continue
		}
		var record JournalRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return Journal{}, err
		}
		if err := validateRecord(record); err != nil {
			return Journal{}, err
		}
		journal.Records = append(journal.Records, record)
		if len(journal.Records) > 256 {
			return Journal{}, errors.New("catalogue v1 journal exceeds record bound")
		}
	}
	return journal, scanner.Err()
}
