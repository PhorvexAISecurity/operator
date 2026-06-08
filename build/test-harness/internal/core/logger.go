package core

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// trialLogger is the per-trial Logger: it writes timestamped lines to a raw log
// file AND mirrors them to an optional run-wide sink (stdout). It records every
// provenance command so the metric schema's Commands field is exact.
type trialLogger struct {
	mu       sync.Mutex
	f        *os.File
	w        *bufio.Writer
	path     string
	commands []string
	mirror   func(string) // optional run-wide mirror (e.g. stdout)
}

// NewTrialLogger opens (truncating) the per-trial raw log file at path. The
// mirror func (may be nil) receives every formatted line too.
func NewTrialLogger(path string, mirror func(string)) (Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &trialLogger{f: f, w: bufio.NewWriter(f), path: path, mirror: mirror}, nil
}

func (l *trialLogger) line(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	full := ts + " " + s
	_, _ = l.w.WriteString(full + "\n")
	_ = l.w.Flush()
	if l.mirror != nil {
		l.mirror(full)
	}
}

func (l *trialLogger) Logf(format string, args ...any) {
	l.line(fmt.Sprintf(format, args...))
}

func (l *trialLogger) Command(cmd string) {
	l.mu.Lock()
	l.commands = append(l.commands, cmd)
	l.mu.Unlock()
	l.line("$ " + cmd)
}

func (l *trialLogger) Commands() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.commands))
	copy(out, l.commands)
	return out
}

func (l *trialLogger) RawLogPath() string { return l.path }

// Close flushes and closes the raw log file.
func (l *trialLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.w.Flush(); err != nil {
		return err
	}
	return l.f.Close()
}
