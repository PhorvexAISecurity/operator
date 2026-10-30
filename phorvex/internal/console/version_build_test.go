package console

import (
	"testing"

	"github.com/phorvex/phorvex/internal/buildinfo"
)

func TestBuildVersionFieldsPreserveReleaseVersionAndAddExactGitSHA(t *testing.T) {
	old := BuildStamp
	t.Cleanup(func() { BuildStamp = old })
	BuildStamp = "1.2.3"
	got := buildVersionFields()
	if got["console"] != "1.2.3" || got["consoleBuild"] != "1.2.3" {
		t.Fatalf("release-version fields changed: %#v", got)
	}
	if got["gitSHA"] != buildinfo.Embedded().GitSHA || got["gitSHA"] == "" {
		t.Fatalf("embedded Git SHA missing: %#v", got)
	}
}
