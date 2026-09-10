package audit

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/model"
	dto "github.com/prometheus/client_model/go"
)

type faultSink struct {
	bytes.Buffer
	short                       bool
	writeErr, flushErr, syncErr error
	calls                       string
}

func (f *faultSink) Write(b []byte) (int, error) {
	f.calls += "w"
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return 0, nil
	}
	return f.Buffer.Write(b)
}
func (f *faultSink) Flush() error { f.calls += "f"; return f.flushErr }
func (f *faultSink) Sync() error  { f.calls += "s"; return f.syncErr }
func TestM017PersistenceFaultsAndOrder(t *testing.T) {
	boom := errors.New("disk unavailable")
	for _, tc := range []struct {
		name  string
		sink  faultSink
		want  error
		calls string
	}{
		{"healthy", faultSink{}, nil, "wfs"},
		{"short", faultSink{short: true}, io.ErrShortWrite, "w"},
		{"write", faultSink{writeErr: boom}, boom, "w"},
		{"flush", faultSink{flushErr: boom}, boom, "wf"},
		{"sync", faultSink{syncErr: boom}, boom, "wfs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := errorCount()
			l := New(logr.Discard(), &tc.sink)
			err := l.Record(model.Decision{})
			if !errors.Is(err, tc.want) || tc.sink.calls != tc.calls {
				t.Fatalf("err=%v calls=%s", err, tc.sink.calls)
			}
			if tc.want != nil && errorCount() != before+1 {
				t.Fatal("failure not counted")
			}
		})
	}
	f := &faultSink{}
	l := New(logr.Discard(), f)
	if err := l.writeRecord("t", math.NaN()); err == nil || f.calls != "" {
		t.Fatal("serialization failure must not write")
	}
}
func TestM017ZeroBackupsPreservesEvidence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit")
	if err := os.WriteFile(p, []byte("evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, -1} {
		if _, err := NewRotatingWriter(p, 10, n); err == nil {
			t.Fatal("accepted unsafe backups")
		}
	}
	b, _ := os.ReadFile(p)
	if string(b) != "evidence" {
		t.Fatal("existing evidence changed")
	}
}
func TestM017RotationFailurePreservesLiveFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit")
	w, err := NewRotatingWriter(p, 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("old\n")); err != nil {
		t.Fatal(err)
	}
	// A directory at the destination forces rename failure on real filesystem.
	if err = os.Mkdir(p+".1", 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte("new\n")); err == nil {
		t.Fatal("rotation error hidden")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "old\n" {
		t.Fatal("lost original evidence")
	}
	if _, err = w.Write([]byte("again\n")); err == nil {
		t.Fatal("blind rotation retry")
	}
	if err = w.Close(); err == nil {
		t.Fatal("close must retain failure")
	}
}

func errorCount() float64 {
	var m dto.Metric
	_ = persistenceErrors.Write(&m)
	return m.GetCounter().GetValue()
}

func TestM017SinkRecoveryDoesNotClearOtherTenantFailure(t *testing.T) {
	a, b := &faultSink{syncErr: errors.New("sync failure")}, &faultSink{}
	l := New(logr.Discard(), nil)
	l.SetTenantSink(func(tenant string) io.Writer {
		if tenant == "a" {
			return a
		}
		return b
	})
	if err := l.Record(model.Decision{Tenant: "a"}); err == nil {
		t.Fatal("missing failure")
	}
	if err := l.Record(model.Decision{Tenant: "b"}); err != nil {
		t.Fatal(err)
	}
	if !l.degraded["a"] {
		t.Fatal("other tenant success cleared failed route")
	}
	a.syncErr = nil
	if err := l.Record(model.Decision{Tenant: "a"}); err != nil {
		t.Fatal(err)
	}
	if l.degraded["a"] {
		t.Fatal("recovery not observed")
	}
}
