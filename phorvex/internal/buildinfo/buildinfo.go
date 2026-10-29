// Package buildinfo resolves the exact operator build identity used by the
// decision trace. The Docker build links the Git revision; local builds fall
// back to Go's VCS settings. Runtime environment supplies the configured image.
package buildinfo

import (
	"encoding/json"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

const NotAvailable = "notAvailable"

// linkedGitSHA and linkedVersion are set by every release Dockerfile. They stay
// honest on ad-hoc builds instead of inventing a release identity.
var (
	linkedGitSHA  = NotAvailable
	linkedVersion = "dev"
)

type Identity struct {
	BrainImage string
	GitSHA     string
	Version    string
}

// Embedded returns the build identity carried by the binary itself. Runtime
// environment cannot override this proof.
func Embedded() Identity {
	revision := strings.TrimSpace(linkedGitSHA)
	if revision == "" || revision == NotAvailable {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" && strings.TrimSpace(setting.Value) != "" {
					revision = strings.TrimSpace(setting.Value)
					break
				}
			}
		}
	}
	if revision == "" {
		revision = NotAvailable
	}
	version := strings.TrimSpace(linkedVersion)
	if version == "" {
		version = "dev"
	}
	return Identity{BrainImage: NotAvailable, GitSHA: revision, Version: version}
}

// Current preserves the runtime image/SHA overrides used by decision evidence.
func Current() Identity {
	identity := Embedded()
	identity.BrainImage = strings.TrimSpace(os.Getenv("PHORVEX_BRAIN_IMAGE"))
	if identity.BrainImage == "" {
		identity.BrainImage = NotAvailable
	}
	if revision := strings.TrimSpace(os.Getenv("PHORVEX_GIT_SHA")); revision != "" {
		identity.GitSHA = revision
	}
	return identity
}

// WriteVersion emits the stable, machine-readable identity exposed by each
// released service binary's -version flag.
func WriteVersion(w io.Writer, service string) error {
	identity := Embedded()
	return json.NewEncoder(w).Encode(struct {
		Service string `json:"service"`
		Version string `json:"version"`
		GitSHA  string `json:"gitSHA"`
	}{Service: service, Version: identity.Version, GitSHA: identity.GitSHA})
}
