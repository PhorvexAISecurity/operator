// Package logging builds the structured logger every Phorvex service uses.
//
// Each line is one JSON object on the writer (stdout in a Pod) carrying the
// service name and version, so a log viewer such as Argo CD can tell services
// apart without parsing prose. controller-runtime and klog receive the same
// handler through Logr.
package logging

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/go-logr/logr"
)

// Formats accepted by Options.Format.
const (
	FormatJSON = "json"
	FormatText = "text"
)

// Options selects the logger's identity, verbosity and encoding.
type Options struct {
	// Service and Version are attached to every line.
	Service string
	Version string
	// Level is a slog level name: debug, info, warn or error (case-insensitive,
	// offsets such as "info+2" allowed). Empty means info.
	Level string
	// Format is "json" (the default) or "text" for local reading.
	Format string
}

// RegisterFlags binds --log-level and --log-format to o on fs.
func RegisterFlags(fs *flag.FlagSet, o *Options) {
	fs.StringVar(&o.Level, "log-level", "info", "Minimum log level: debug, info, warn or error.")
	fs.StringVar(&o.Format, "log-format", FormatJSON, "Log encoding: json or text.")
}

// New returns a logger writing to w, or an error for an unknown level or format.
func New(w io.Writer, o Options) (*slog.Logger, error) {
	if strings.TrimSpace(o.Service) == "" {
		return nil, fmt.Errorf("logging: service name is required")
	}
	var level slog.Level
	if o.Level != "" {
		if err := level.UnmarshalText([]byte(o.Level)); err != nil {
			return nil, fmt.Errorf("logging: invalid level %q: %w", o.Level, err)
		}
	}
	handlerOptions := &slog.HandlerOptions{Level: level, ReplaceAttr: debugLabel}
	var handler slog.Handler
	switch o.Format {
	case "", FormatJSON:
		handler = slog.NewJSONHandler(w, handlerOptions)
	case FormatText:
		handler = slog.NewTextHandler(w, handlerOptions)
	default:
		return nil, fmt.Errorf("logging: invalid format %q (want %s or %s)", o.Format, FormatJSON, FormatText)
	}
	version := o.Version
	if version == "" {
		version = "unknown"
	}
	return slog.New(handler.WithAttrs([]slog.Attr{
		slog.String("service", o.Service),
		slog.String("version", version),
	})), nil
}

// Logr adapts l for libraries that log through logr, such as controller-runtime
// and klog. logr verbosity V(n) maps to slog level -n: hidden at info, shown at
// debug, and labelled DEBUG.
func Logr(l *slog.Logger) logr.Logger {
	return logr.FromSlogHandler(l.Handler())
}

// debugLabel names every level below info DEBUG, so logr verbosities read as
// DEBUG instead of offsets such as DEBUG+3.
func debugLabel(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.LevelKey {
		if level, ok := a.Value.Any().(slog.Level); ok && level < slog.LevelInfo {
			a.Value = slog.StringValue("DEBUG")
		}
	}
	return a
}
