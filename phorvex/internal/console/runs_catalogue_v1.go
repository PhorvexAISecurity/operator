package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func (c Config) functionalProfileAvailable(profile cataloguev1.ProfileID) (bool, string) {
	for _, item := range c.limitedV1Catalogue() {
		if item.Profile == string(profile) && item.LaunchKind == "fixed-suite" {
			return item.Available, item.UnavailableReason
		}
	}
	return false, "profile is not in the fixed limited-v1 catalogue"
}

func (rm *RunManager) FunctionalDestination(profile cataloguev1.ProfileID) (runDestination, error) {
	definition, err := cataloguev1.DefinitionFor(profile)
	if err != nil {
		return runDestination{}, err
	}
	tenant := definition.FixedTenant
	switch profile {
	case cataloguev1.VoiceMedia, cataloguev1.VoiceRecovery:
		tenant = strings.TrimSpace(rm.cfg.CatalogueV1.VoiceNamespace)
	case cataloguev1.GPUDrain:
		tenant = strings.TrimSpace(rm.cfg.CatalogueV1.GPUFixtureNamespace)
	case cataloguev1.AuthUnauth, cataloguev1.AuthScope:
		tenant = strings.TrimSpace(rm.cfg.CatalogueV1.AllowedTenant)
	case cataloguev1.GuardrailCalibration:
		tenant = strings.TrimSpace(rm.cfg.CatalogueV1.GuardrailNamespace)
	}
	if tenant == "" {
		return runDestination{}, errors.New("fixed suite resolved tenant is unavailable")
	}
	return runDestination{Targets: []string{hostTargetID, definition.FixedTarget}, Tenants: []string{tenant}, ScopeTarget: definition.FixedTarget, ScopeTenant: tenant}, nil
}

func (c Config) catalogueV1RuntimeConfig() cataloguev1.RuntimeConfig {
	runtime := cataloguev1.RuntimeConfig{Version: cataloguev1.RuntimeConfigVersion, StateDir: c.StateDir,
		KubeconfigPath: c.CatalogueV1.KubeconfigPath, KubeContext: c.CatalogueV1.KubeContext,
		FixedLoopback: c.CatalogueV1.LoopbackURL, ScopedTokenFile: c.CatalogueV1.ScopedTokenFile,
		AllowedTenant: c.CatalogueV1.AllowedTenant, DeniedTenant: c.CatalogueV1.DeniedTenant,
		DeniedTarget: c.CatalogueV1.DeniedTarget, ExpectedSubject: c.CatalogueV1.ExpectedSubject,
		GrantFile: c.CatalogueV1.GrantFile,
		Voice: cataloguev1.VoiceRuntime{Enabled: c.CatalogueV1.VoiceEnabled, Namespace: c.CatalogueV1.VoiceNamespace,
			Deployment: c.CatalogueV1.VoiceDeployment, Service: c.CatalogueV1.VoiceService,
			Container: c.CatalogueV1.VoiceContainer, ServicePort: c.CatalogueV1.VoiceServicePort,
			PDB: c.CatalogueV1.VoicePDB, TranscriptPodSelector: c.CatalogueV1.TranscriptSelector,
			TranscriptContainer: c.CatalogueV1.TranscriptContainer},
		GPU: cataloguev1.GPUFixtureRuntime{Enabled: c.CatalogueV1.GPUEnabled,
			Namespace: c.CatalogueV1.GPUFixtureNamespace, FixtureConfigFile: c.CatalogueV1.GPUFixtureConfig,
			HarnessBinary: c.HarnessBin, HarnessDir: c.HarnessDir,
			KubeconfigPath: c.CatalogueV1.GPUKubeconfigPath, KubeContext: c.CatalogueV1.GPUKubeContext}}
	if c.CatalogueV1.GuardrailCalibrationEnabled {
		runtime.Guardrail = &cataloguev1.GuardrailCalibrationRuntime{Enabled: true,
			Namespace: c.CatalogueV1.GuardrailNamespace, Service: c.CatalogueV1.GuardrailService,
			Port: c.CatalogueV1.GuardrailPort, Container: c.CatalogueV1.GuardrailContainer,
			SourceConfigMap: c.CatalogueV1.GuardrailSourceConfigMap, SourceKey: c.CatalogueV1.GuardrailSourceKey,
			ExpectedSourceSHA256: c.CatalogueV1.GuardrailSourceSHA256}
	}
	return runtime
}

func (rm *RunManager) StartFunctional(profile cataloguev1.ProfileID, startedAt, owner string) (string, error) {
	definition, err := cataloguev1.DefinitionFor(profile)
	if err != nil {
		return "", err
	}
	if available, reason := rm.cfg.functionalProfileAvailable(profile); !available {
		return "", fmt.Errorf("fixed suite %q unavailable: %s", profile, reason)
	}
	definitionHash, err := cataloguev1.DefinitionSHA256(definition)
	if err != nil {
		return "", err
	}
	destination, err := rm.FunctionalDestination(profile)
	if err != nil {
		return "", err
	}
	runtimeConfig := rm.cfg.catalogueV1RuntimeConfig()
	runtimeHash, err := runtimeConfig.SHA256()
	if err != nil {
		return "", fmt.Errorf("validate fixed-suite runtime: %w", err)
	}
	rm.mu.Lock()
	for _, existing := range rm.runs {
		if existing.ExecutionKind == "fixed-suite" && existing.UnsafeToRetry && existing.State != "done" && existing.State != "stopped" {
			rm.mu.Unlock()
			return "", errors.New("a prior fixed suite requires reconciliation before another fixed suite can start")
		}
	}
	if err = rm.guard(time.Now()); err != nil {
		rm.mu.Unlock()
		return "", err
	}
	rm.seq++
	id := fmt.Sprintf("v1run-%d", rm.seq)
	outDir := rm.cfg.runOutputPath(id)
	if err = os.MkdirAll(outDir, 0o750); err != nil {
		rm.mu.Unlock()
		return "", err
	}
	ownerSum := sha256.Sum256([]byte(owner))
	now := time.Now().UTC()
	job := cataloguev1.Job{Version: cataloguev1.JobVersion, RunID: id, Profile: profile, OutputDir: outDir,
		DefinitionSHA256: definitionHash, OwnerDigest: hex.EncodeToString(ownerSum[:]),
		ResolvedTarget: destination.ScopeTarget, ResolvedTenant: destination.ScopeTenant, RuntimeConfigSHA256: runtimeHash,
		CreatedAt: now, Deadline: now.Add(definition.MaxDuration)}
	jobPath := filepath.Join(outDir, "job.json")
	runtimePath := filepath.Join(outDir, "runtime.json")
	if err = cataloguev1.WriteRuntimeConfig(runtimePath, runtimeConfig); err != nil {
		rm.mu.Unlock()
		return "", fmt.Errorf("persist fixed-suite runtime: %w", err)
	}
	if err = cataloguev1.WriteJob(jobPath, rm.cfg.StateDir, job); err != nil {
		rm.mu.Unlock()
		return "", fmt.Errorf("persist fixed-suite job: %w", err)
	}
	claimClass := "functional"
	if profile == cataloguev1.GuardrailCalibration {
		claimClass = "calibration"
	}
	st := &RunStatus{ID: id, Config: string(profile), State: "running", Started: startedAt, Date: tsNow(),
		ExpectedTrials: 1, Owner: owner, ScopeTarget: destination.ScopeTarget, ScopeTenant: destination.ScopeTenant,
		Target: rm.cfg.catalogueV1RuntimeContext(profile), TargetLabel: rm.cfg.catalogueV1RuntimeContext(profile), Provider: "Kubernetes",
		ExecutionKind: "fixed-suite", ClaimClass: claimClass}
	rm.runs[id], rm.runOut[id], rm.functional[id] = st, id, job
	rm.active++
	rm.lastStart = time.Now()
	if err = rm.persistStatus(st, id); err != nil {
		delete(rm.runs, id)
		delete(rm.runOut, id)
		delete(rm.functional, id)
		rm.active--
		rm.mu.Unlock()
		return "", fmt.Errorf("persist fixed-suite status before effect: %w", err)
	}
	rm.mu.Unlock()
	go rm.runFunctional(id, jobPath, job)
	return id, nil
}

func (rm *RunManager) runFunctional(id, jobPath string, job cataloguev1.Job) {
	rm.mu.Lock()
	stopping := rm.stopping[id]
	rm.mu.Unlock()
	if stopping {
		rm.finishFunctional(id, job, errors.New("fixed suite stopped before worker start"), false)
		return
	}
	executable := strings.TrimSpace(rm.cfg.CatalogueV1.Executable)
	if executable == "" {
		executable, _ = os.Executable()
	}
	if executable == "" {
		rm.failRunBeforeStart(id, errors.New("console executable unavailable"))
		return
	}
	runtimePath := filepath.Join(job.OutputDir, "runtime.json")
	cmd := exec.Command(executable, "--catalogue-v1-job="+jobPath, "--catalogue-v1-runtime="+runtimePath)
	cmd.Env = envBase()
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	logFile, err := os.OpenFile(filepath.Join(job.OutputDir, "console-run.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		rm.failRunBeforeStart(id, err)
		return
	}
	defer logFile.Close()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err = cmd.Start(); err != nil {
		rm.finishFunctional(id, job, err, false)
		return
	}
	startTicks, ticksErr := processStartTicks(cmd.Process.Pid)
	worker := map[string]any{"pid": cmd.Process.Pid, "startTicks": startTicks, "recordedAt": time.Now().UTC()}
	if ticksErr != nil {
		worker["startTicksError"] = ticksErr.Error()
	}
	if raw, marshalErr := json.MarshalIndent(worker, "", "  "); marshalErr == nil {
		_ = atomicWriteState(filepath.Join(job.OutputDir, "worker.json"), append(raw, '\n'))
	}
	rm.mu.Lock()
	rm.procs[id] = cmd
	stopping = rm.stopping[id]
	rm.mu.Unlock()
	if stopping {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	timer := time.NewTimer(time.Until(job.Deadline) + 20*time.Second)
	defer timer.Stop()
	timedOut := false
	select {
	case err = <-wait:
	case <-timer.C:
		timedOut = true
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case err = <-wait:
		case <-time.After(2 * time.Minute):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			err = <-wait
		}
	}
	rm.finishFunctional(id, job, err, timedOut)
}

func (rm *RunManager) finishFunctional(id string, job cataloguev1.Job, processErr error, timedOut bool) {
	var result cataloguev1.Result
	raw, readErr := os.ReadFile(filepath.Join(job.OutputDir, "result.json"))
	if readErr == nil {
		readErr = json.Unmarshal(raw, &result)
	}
	if readErr == nil {
		readErr = cataloguev1.ValidateResult(job, result)
	}
	if readErr == nil {
		readErr = cataloguev1.ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl"))
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.procs, id)
	if rm.active > 0 {
		rm.active--
	}
	st := rm.runs[id]
	if st == nil {
		return
	}
	st.Finished = tsNow()
	if readErr == nil {
		st.UnsafeToRetry = result.UnsafeToRetry || result.Cleanup.UnsafeToRetry
		st.Outcome, st.CleanupStatus = string(result.Outcome), result.Cleanup.Status
	} else {
		st.UnsafeToRetry = true
		st.Outcome, st.CleanupStatus = "", "unverified"
	}
	stopping := rm.stopping[id]
	delete(rm.stopping, id)
	switch {
	case readErr != nil:
		st.State = "partial"
		st.UnsafeToRetry = true
		st.Error = "fixed-suite terminal result missing or malformed: " + readErr.Error()
	case timedOut:
		st.State = "partial"
		st.UnsafeToRetry = true
		st.Error = "fixed suite exceeded its bounded deadline"
	case stopping && result.Cleanup.Verified:
		st.State = "stopped"
		st.Error = "stopped by user after verified cleanup"
	case stopping:
		st.State = "partial"
		st.UnsafeToRetry = true
		st.Error = "stopped by user; cleanup unverified"
	case processErr != nil:
		st.State = "partial"
		st.UnsafeToRetry = true
		st.Error = "fixed-suite worker failed: " + processErr.Error()
	case !result.Cleanup.Verified:
		st.State = "partial"
		st.UnsafeToRetry = true
		st.Error = "fixed suite ended without verified cleanup"
	case result.Outcome == cataloguev1.OutcomeTestFailed:
		st.State = "error"
		st.Error = result.Summary
	default:
		st.State = "done"
	}
	if err := rm.persistStatus(st, id); err != nil {
		st.State = "partial"
		st.UnsafeToRetry = true
		st.Outcome = ""
		st.CleanupStatus = "unverified"
		st.Error = "fixed-suite status persistence failed; unsafe to retry: " + err.Error()
	}
	rm.dequeueNextLocked()
}

func (rm *RunManager) reconcileInterruptedFunctional() {
	time.Sleep(2 * time.Second)
	rm.mu.Lock()
	jobs := map[string]cataloguev1.Job{}
	for id, st := range rm.runs {
		if st.ExecutionKind == "fixed-suite" && st.State == "partial" && strings.Contains(st.Error, "reconciliation pending") {
			job, err := cataloguev1.LoadJob(filepath.Join(rm.cfg.runOutputPath(rm.runOut[id]), "job.json"), rm.cfg.StateDir)
			if err == nil {
				jobs[id] = job
			}
		}
	}
	rm.mu.Unlock()
	for id, job := range jobs {
		for attempt := 0; attempt < 20 && !cataloguev1.ExecutionLockAvailable(job.OutputDir); attempt++ {
			time.Sleep(3 * time.Second)
		}
		if !cataloguev1.ExecutionLockAvailable(job.OutputDir) {
			continue
		}
		executable := strings.TrimSpace(rm.cfg.CatalogueV1.Executable)
		if executable == "" {
			executable, _ = os.Executable()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, executable, "--catalogue-v1-reconcile="+filepath.Join(job.OutputDir, "job.json"), "--catalogue-v1-runtime="+filepath.Join(job.OutputDir, "runtime.json"))
		cmd.Env, cmd.Dir = envBase(), "/"
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
		err := cmd.Run()
		cancel()
		var result cataloguev1.Result
		raw, readErr := os.ReadFile(filepath.Join(job.OutputDir, "result.json"))
		if readErr == nil {
			readErr = json.Unmarshal(raw, &result)
		}
		if readErr == nil {
			readErr = cataloguev1.ValidateResult(job, result)
		}
		rm.mu.Lock()
		st := rm.runs[id]
		if st != nil {
			if err == nil && readErr == nil && result.Cleanup.Verified {
				st.State = "partial"
				st.Error = "interrupted fixed suite reconciled; original result remains incomplete"
				st.CleanupStatus = result.Cleanup.Status
				st.UnsafeToRetry = false
			} else {
				st.State = "partial"
				st.Error = "interrupted fixed suite reconciliation failed"
				st.UnsafeToRetry = true
			}
			if persistErr := rm.persistStatus(st, rm.runOut[id]); persistErr != nil {
				st.State = "partial"
				st.UnsafeToRetry = true
				st.Error = "interrupted fixed suite reconciliation status persistence failed: " + persistErr.Error()
			}
		}
		rm.mu.Unlock()
	}
}

func processStartTicks(pid int) (string, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	closeIndex := strings.LastIndexByte(string(raw), ')')
	if closeIndex < 0 {
		return "", errors.New("malformed process stat")
	}
	fields := strings.Fields(string(raw[closeIndex+1:]))
	if len(fields) <= 19 {
		return "", errors.New("process stat lacks start time")
	}
	if _, err = strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", err
	}
	return fields[19], nil
}

func (rm *RunManager) FunctionalResult(id string) (*cataloguev1.Result, error) {
	rm.mu.Lock()
	st, ok := rm.runs[id]
	out := rm.runOut[id]
	var status RunStatus
	if ok {
		status = *st
	}
	rm.mu.Unlock()
	if !ok || status.ExecutionKind != "fixed-suite" {
		return nil, nil
	}
	if status.State != "done" && status.State != "error" && status.State != "stopped" {
		return nil, errors.New("fixed-suite terminal result is not yet verified")
	}
	dir := rm.cfg.runOutputPath(out)
	job, err := cataloguev1.LoadJob(filepath.Join(dir, "job.json"), rm.cfg.StateDir)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		return nil, err
	}
	var result cataloguev1.Result
	if err = json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if err = cataloguev1.ValidateResult(job, result); err != nil {
		return nil, err
	}
	if err = cataloguev1.ValidateTerminalArtifacts(job, result, filepath.Join(dir, "metrics.jsonl")); err != nil {
		return nil, err
	}
	if string(result.Outcome) != status.Outcome || result.Cleanup.Status != status.CleanupStatus {
		return nil, errors.New("fixed-suite terminal result differs from the accepted run status")
	}
	return &result, nil
}
