package cataloguev1

import (
	"bytes"
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
)

type gpuProcessIdentity struct {
	Version             int       `json:"version"`
	RunID               string    `json:"runID"`
	PID                 int       `json:"pid"`
	PGID                int       `json:"pgid"`
	StartTicks          uint64    `json:"startTicks"`
	ExecutableSHA256    string    `json:"executableSHA256"`
	CommandLineSHA256   string    `json:"commandLineSHA256"`
	HarnessSHA256       string    `json:"harnessSHA256"`
	FixtureConfigSHA256 string    `json:"fixtureConfigSHA256"`
	CreatedAt           time.Time `json:"createdAt"`
}

func persistGPUProcessIdentity(path string, job Job, command *exec.Cmd, harnessSHA, configSHA string) error {
	if command.Process == nil || command.Process.Pid <= 1 {
		return errors.New("GPU harness process identity is unavailable")
	}
	pid := command.Process.Pid
	pgid, start, err := readLinuxProcessIdentity(pid)
	if err != nil || pgid != pid {
		return errors.New("GPU harness process group identity differs")
	}
	executableSHA, err := fileSHA256(filepath.Join("/proc", strconv.Itoa(pid), "exe"), 512<<20)
	if err != nil {
		return err
	}
	if filepath.Base(path) == "crm-process.json" && executableSHA != harnessSHA {
		return errors.New("CRM started executable SHA-256 differs from reviewed harness")
	}
	commandLine, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(commandLine) == 0 {
		return errors.New("GPU harness command-line identity is unavailable")
	}
	identity := gpuProcessIdentity{
		Version: 1, RunID: job.RunID, PID: pid, PGID: pgid, StartTicks: start,
		ExecutableSHA256: executableSHA, CommandLineSHA256: digestBytes(commandLine),
		HarnessSHA256: harnessSHA, FixtureConfigSHA256: configSHA, CreatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	return writeExclusive(path, append(raw, '\n'), 0o600)
}

func readLinuxProcessIdentity(pid int) (pgid int, start uint64, err error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, 0, err
	}
	end := bytes.LastIndex(raw, []byte(") "))
	if end < 0 {
		return 0, 0, errors.New("process stat comm terminator is absent")
	}
	fields := strings.Fields(string(raw[end+2:]))
	// fields[0] is field 3 (state), so pgrp is field 5 at index 2 and
	// starttime is field 22 at index 19.
	if len(fields) <= 19 {
		return 0, 0, errors.New("process stat is truncated")
	}
	pgid64, err := strconv.ParseInt(fields[2], 10, 32)
	if err != nil {
		return 0, 0, err
	}
	start, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return int(pgid64), start, nil
}

func reapRetainedGPUProcess(job JobContext, harnessSHA, configSHA string) string {
	return reapRetainedProcess(job, harnessSHA, configSHA, "gpu-process.json")
}

func reapRetainedProcess(job JobContext, harnessSHA, configSHA, file string) string {
	raw, err := os.ReadFile(filepath.Join(job.Job.OutputDir, file))
	if err != nil || len(raw) > maxRecordBytes {
		return "process-identity-absent"
	}
	var identity gpuProcessIdentity
	if json.Unmarshal(raw, &identity) != nil || identity.Version != 1 || identity.RunID != job.Job.RunID || identity.PID <= 1 || identity.PGID != identity.PID || identity.StartTicks == 0 || identity.HarnessSHA256 != harnessSHA || identity.FixtureConfigSHA256 != configSHA {
		return "process-identity-refused"
	}
	pgid, start, err := readLinuxProcessIdentity(identity.PID)
	if os.IsNotExist(err) {
		if linuxProcessGroupExists(identity.PGID) {
			return "leader-absent-process-group-unresolved"
		}
		return "leader-and-process-group-absent"
	}
	if err != nil || pgid != identity.PGID || start != identity.StartTicks {
		return "process-identity-drifted"
	}
	executableSHA, err := fileSHA256(filepath.Join("/proc", strconv.Itoa(identity.PID), "exe"), 512<<20)
	if err != nil || executableSHA != identity.ExecutableSHA256 {
		return "process-executable-drifted"
	}
	commandLine, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(identity.PID), "cmdline"))
	if err != nil || digestBytes(commandLine) != identity.CommandLineSHA256 {
		return "process-command-line-drifted"
	}
	return terminateRecordedGPUProcessGroup(identity.PGID, "exact-leader")
}

func terminateRecordedGPUProcessGroup(pgid int, prefix string) string {
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	if waitGPUProcessGroupGone(pgid, 3*time.Second) {
		return prefix + "-process-group-reaped"
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	if waitGPUProcessGroupGone(pgid, 3*time.Second) {
		return prefix + "-process-group-killed"
	}
	return prefix + "-process-group-still-present"
}

// gpuGroupExitGrace bounds how long a harness's process group may take to finish
// exiting after its leader has.
const gpuGroupExitGrace = time.Second

func waitGPUProcessGroupGone(pgid int, bound time.Duration) bool {
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		if !linuxProcessGroupExists(pgid) {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return !linuxProcessGroupExists(pgid)
}

func linuxProcessGroupExists(pgid int) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return true
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		current, _, err := readLinuxProcessIdentity(pid)
		if err == nil && current == pgid {
			return true
		}
	}
	return false
}

func processIdentityError(err error, command *exec.Cmd, done <-chan error) error {
	stopErr := stopProcessGroup(command, done)
	return fmt.Errorf("persist GPU process ownership: %v (forced stop: %v)", err, stopErr)
}
