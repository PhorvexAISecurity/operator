package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"strings"
	"testing"
)

func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if raw == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("line is not JSON: %q: %v", raw, err)
		}
		out = append(out, line)
	}
	return out
}

func TestJSONLinesCarryServiceAndVersion(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, Options{Service: "brain", Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	l.Info("decided", "tenant", "voice", "moves", 2)
	got := lines(t, &buf)
	if len(got) != 1 {
		t.Fatalf("lines = %d, want 1", len(got))
	}
	want := map[string]any{"level": "INFO", "msg": "decided", "service": "brain", "version": "1.2.3", "tenant": "voice", "moves": float64(2)}
	for key, value := range want {
		if got[0][key] != value {
			t.Errorf("%s = %v, want %v", key, got[0][key], value)
		}
	}
	if _, ok := got[0]["time"]; !ok {
		t.Error("missing time")
	}
}

func TestLevelFiltersAndDefaultsToInfo(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, Options{Service: "sensor"})
	if err != nil {
		t.Fatal(err)
	}
	l.Debug("hidden")
	l.Warn("shown")
	got := lines(t, &buf)
	if len(got) != 1 || got[0]["msg"] != "shown" || got[0]["version"] != "unknown" {
		t.Fatalf("got %v", got)
	}

	buf.Reset()
	l, err = New(&buf, Options{Service: "sensor", Level: "DEBUG"})
	if err != nil {
		t.Fatal(err)
	}
	l.Debug("visible")
	if got := lines(t, &buf); len(got) != 1 || got[0]["level"] != "DEBUG" {
		t.Fatalf("got %v", got)
	}
}

func TestTextFormatForLocalReading(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, Options{Service: "console", Format: FormatText})
	if err != nil {
		t.Fatal(err)
	}
	l.Info("listening", "addr", ":8090")
	if s := buf.String(); !strings.Contains(s, "service=console") || !strings.Contains(s, "addr=:8090") || strings.HasPrefix(s, "{") {
		t.Fatalf("text line = %q", s)
	}
}

func TestInvalidOptionsAreRejected(t *testing.T) {
	for name, o := range map[string]Options{
		"no service":     {Level: "info"},
		"unknown level":  {Service: "x", Level: "verbose"},
		"unknown format": {Service: "x", Format: "yaml"},
	} {
		if _, err := New(&bytes.Buffer{}, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLogrBridgeKeepsAttributesAndMapsVerbosity(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, Options{Service: "dispatcher", Version: "abc", Level: "debug"})
	if err != nil {
		t.Fatal(err)
	}
	lr := Logr(l).WithName("controller").WithValues("policy", "voice-defense")
	lr.Info("reconciled")
	lr.V(1).Info("detail")
	lr.Error(errors.New("boom"), "failed")
	got := lines(t, &buf)
	if len(got) != 3 {
		t.Fatalf("lines = %d, want 3: %v", len(got), got)
	}
	levels := []any{"INFO", "DEBUG", "ERROR"}
	for i, line := range got {
		if line["service"] != "dispatcher" || line["policy"] != "voice-defense" || line["logger"] != "controller" {
			t.Errorf("line %d lost attributes: %v", i, line)
		}
		if line["level"] != levels[i] {
			t.Errorf("line %d level = %v, want %v", i, line["level"], levels[i])
		}
	}
	if got[2]["err"] != "boom" {
		t.Errorf("error line = %v", got[2])
	}
}

func TestRegisterFlagsDefaults(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	var o Options
	RegisterFlags(fs, &o)
	if err := fs.Parse([]string{"--log-level=warn"}); err != nil {
		t.Fatal(err)
	}
	if o.Level != "warn" || o.Format != FormatJSON {
		t.Fatalf("options = %+v", o)
	}
}
