// Package buildinfo resolves the exact operator build identity used by the
// decision trace. The Docker build links the Git revision; local builds fall
// back to Go's VCS settings. Runtime environment supplies the configured image.
package buildinfo

import (
	"os"
	"runtime/debug"
	"strings"
)

const NotAvailable = "notAvailable"

// linkedGitSHA is set by deploy/docker/operator.Dockerfile. It stays honest on
// ad-hoc builds instead of inventing a revision.
var linkedGitSHA = NotAvailable

type Identity struct {
	BrainImage string
	GitSHA     string
}

func Current() Identity {
	image := strings.TrimSpace(os.Getenv("PHORVEX_BRAIN_IMAGE"))
	if image == "" {
		image = NotAvailable
	}
	revision := strings.TrimSpace(os.Getenv("PHORVEX_GIT_SHA"))
	if revision == "" {
		revision = strings.TrimSpace(linkedGitSHA)
	}
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
	return Identity{BrainImage: image, GitSHA: revision}
}
