package console

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const consoleStateFileLimit int64 = 48 << 20
const consoleStateRecordLimit = 4 << 20

var consoleStateMu sync.Mutex

func (c Config) statePath(name string) string {
	base := c.StateDir
	if base == "" {
		base = c.HarnessDir
	}
	if base == "" {
		return ""
	}
	return filepath.Join(base, name)
}

func (s *Server) persistEffectIntent(endpoint, actor, namespace, action string) error {
	b, err := json.Marshal(map[string]string{"kind": "phorvex.console.effect", "phase": "intent", "time": time.Now().UTC().Format(time.RFC3339Nano), "endpoint": endpoint, "actor": actor, "namespace": namespace, "action": action})
	if err != nil {
		return fmt.Errorf("encode effect intent: %w", err)
	}
	return s.cfg.appendState(s.cfg.statePath("effect-intents.jsonl"), b)
}

type vllmSetupFailureRecord struct {
	Kind        string `json:"kind"`
	Phase       string `json:"phase"`
	Time        string `json:"time"`
	Endpoint    string `json:"endpoint"`
	Actor       string `json:"actor"`
	Namespace   string `json:"namespace"`
	Action      string `json:"action"`
	TargetUID   string `json:"targetUid"`
	ServiceUID  string `json:"serviceUid,omitempty"`
	EventName   string `json:"eventName,omitempty"`
	Correlation string `json:"correlation,omitempty"`
	Mutated     bool   `json:"mutated"`
	Restoration string `json:"restoration"`
	Error       string `json:"error"`
}

func (s *Server) persistVLLMSetupFailure(actor, action, phase, targetUID, serviceUID string, candidate *attackStimulusEvidence, mutated bool, restoration string, cause error) error {
	if targetUID == "" || cause == nil {
		return fmt.Errorf("vLLM setup failure identity or cause is unavailable")
	}
	record := vllmSetupFailureRecord{Kind: "phorvex.console.vllm.setup", Phase: phase, Time: s.cfg.now().UTC().Format(time.RFC3339Nano), Endpoint: "/api/vllm/attack", Actor: actor, Namespace: vllmAttackNS, Action: action, TargetUID: targetUID, ServiceUID: serviceUID, Mutated: mutated, Restoration: restoration, Error: cause.Error()}
	if candidate != nil {
		record.EventName = candidate.EventName
		record.Correlation = candidate.Correlation
	}
	b, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode vLLM setup failure: %w", err)
	}
	return s.cfg.appendState(s.cfg.statePath("effect-intents.jsonl"), b)
}

// ValidateStateDir proves the configured sink supports create, write, fsync, readback,
// rename and directory fsync. The probe is removed only after all checks succeed.
func (c Config) ValidateStateDir() error {
	if c.StateDir == "" {
		return fmt.Errorf("console state directory is required (use an explicit ephemeral directory for nondurable operation)")
	}
	if err := os.MkdirAll(c.StateDir, 0o750); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	f, err := os.CreateTemp(c.StateDir, ".state-probe-*")
	if err != nil {
		return fmt.Errorf("create state probe: %w", err)
	}
	old, renamed := f.Name(), f.Name()+".ready"
	cleanup := func() { _ = f.Close(); _ = os.Remove(old); _ = os.Remove(renamed) }
	defer cleanup()
	want := []byte("phorvex-console-state-v1\n")
	if _, err = f.Write(want); err != nil {
		return fmt.Errorf("write state probe: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync state probe: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close state probe: %w", err)
	}
	if err = os.Rename(old, renamed); err != nil {
		return fmt.Errorf("rename state probe: %w", err)
	}
	got, err := os.ReadFile(renamed)
	if err != nil {
		return fmt.Errorf("read back state probe: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("read back state probe: content mismatch")
	}
	d, err := os.Open(c.StateDir)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

// appendState appends one complete JSONL record and does not report success until fsync.
// It retains one previous segment and never replaces the current file before the segment is durable.
func appendState(path string, record []byte) error {
	if path == "" {
		return fmt.Errorf("console state path is not configured")
	}
	if bytes.IndexByte(record, '\n') >= 0 {
		return fmt.Errorf("state record contains newline")
	}
	if len(record)+1 > consoleStateRecordLimit {
		return fmt.Errorf("state record is %d bytes; limit is %d", len(record), consoleStateRecordLimit-1)
	}
	consoleStateMu.Lock()
	defer consoleStateMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if st, err := os.Stat(path); err == nil && st.Size()+int64(len(record)+1) > consoleStateFileLimit {
		if err := rotateState(path); err != nil {
			return fmt.Errorf("rotate state: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	_, statErr := os.Stat(path)
	created := os.IsNotExist(statErr)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	start, seekErr := f.Seek(0, io.SeekEnd)
	if seekErr != nil {
		_ = f.Close()
		return seekErr
	}
	payload := append(append([]byte(nil), record...), '\n')
	written := 0
	for written < len(payload) && err == nil {
		var n int
		n, err = f.Write(payload[written:])
		written += n
		if n == 0 && err == nil {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		_ = f.Truncate(start)
		_ = f.Sync()
	} else if written != len(payload) {
		err = io.ErrShortWrite
		_ = f.Truncate(start)
		_ = f.Sync()
	} else {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil && created {
		err = syncStateDirectory(filepath.Dir(path))
	}
	return err
}

func syncStateDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func atomicWriteState(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("console state path is not configured")
	}
	consoleStateMu.Lock()
	defer consoleStateMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-replace-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncStateDirectory(filepath.Dir(path))
}

func readStateLedger(path string) ([]byte, error) {
	var backup, current []byte
	for _, candidate := range []string{path + ".1", path} {
		st, err := os.Stat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("retained state %s is not a regular file", candidate)
		}
		if st.Size() > consoleStateFileLimit {
			return nil, fmt.Errorf("retained state %s exceeds %d-byte reader limit", candidate, consoleStateFileLimit)
		}
		b, err := os.ReadFile(candidate)
		if err != nil {
			return nil, err
		}
		if candidate == path {
			current = b
		} else {
			backup = b
		}
	}
	if current != nil {
		return current, nil
	}
	return backup, nil
}

func readStateLedgerHistory(path string) ([]byte, error) {
	var all []byte
	for _, candidate := range []string{path + ".1", path} {
		st, err := os.Stat(candidate)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() || st.Size() > consoleStateFileLimit {
			return nil, fmt.Errorf("invalid retained state segment %s", candidate)
		}
		b, err := os.ReadFile(candidate)
		if err != nil {
			return nil, err
		}
		all = append(all, b...)
	}
	return all, nil
}

func rotateState(path string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return err
	}
	start := st.Size() - consoleStateFileLimit/2
	if start < 0 {
		start = 0
	}
	if _, err = src.Seek(start, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(src, consoleStateFileLimit/2+1))
	if err != nil {
		return err
	}
	if start > 0 {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-rotate-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(path, path+".1"); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		_ = os.Rename(path+".1", path)
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
