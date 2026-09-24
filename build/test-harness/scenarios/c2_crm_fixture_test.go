package scenarios

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func TestCRMFixtureExactSourceAndDependencyLock(t *testing.T) {
	app, probe, err := crmFixtureFiles()
	if err != nil || len(app) != 5438 || len(probe) == 0 {
		t.Fatalf("exact CRM fixture sources unavailable: app=%d probe=%d err=%v", len(app), len(probe), err)
	}
	lock, err := crmLoadDependencyLock()
	if err != nil || lock.Packages["pymongo"] != "4.17.0" || lock.Packages["fastapi"] != "0.115.14" {
		t.Fatalf("CRM installed dependency closure differs: %v", err)
	}
}

func TestCRMFixtureManifestRejectsTagsAndDependencyDrift(t *testing.T) {
	manifest := crmFixtureManifest{Schema: crmFixtureSchema,
		CRMImage:        "example.invalid/crm@sha256:" + strings.Repeat("a", 64),
		MongoImage:      "example.invalid/mongo@sha256:" + strings.Repeat("b", 64),
		BaseImageDigest: crmInstalledBaseImage, SourceSHA256: crmInstalledSourceSHA,
		DependencyLockSHA256: crmDependencyLockSHA, WheelhouseManifestSHA256: strings.Repeat("c", 64), Dependencies: crmExpectedDependencies}
	path := filepath.Join(t.TempDir(), "fixture.json")
	write := func() {
		t.Helper()
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, _, err := crmLoadManifest(path); err != nil {
		t.Fatalf("valid manifest refused: %v", err)
	}
	manifest.CRMImage = "example.invalid/crm:latest"
	write()
	if _, _, err := crmLoadManifest(path); err == nil {
		t.Fatal("mutable fixture image was accepted")
	}
	manifest.CRMImage = "example.invalid/crm@sha256:" + strings.Repeat("a", 64)
	manifest.DependencyLockSHA256 = strings.Repeat("0", 64)
	write()
	if _, _, err := crmLoadManifest(path); err == nil {
		t.Fatal("dependency lock drift was accepted")
	}
}

func TestCRMCapabilityControlsAbstainWithoutPreparedImage(t *testing.T) {
	t.Setenv(crmFixtureManifestEnv, "")
	for _, sc := range []core.Scenario{&c2CRMRefundCapability{}, &c2CRMResetCapability{}} {
		name := sc.Metadata().Name
		if err := sc.Setup(context.Background(), &core.Env{}); err != nil {
			t.Fatalf("%s unavailable setup failed: %v", name, err)
		}
		got, err := sc.Execute(context.Background(), &core.Env{})
		if err != nil || !got.Skipped || got.SkipReason == "" || !sc.Metadata().BenignControl || sc.Metadata().EffectiveRealism() != core.RealismExecutable {
			t.Fatalf("%s missing-image outcome invalid: result=%+v err=%v", name, got, err)
		}
		if err := sc.Teardown(context.Background(), &core.Env{}); err != nil {
			t.Fatalf("%s unavailable teardown failed: %v", name, err)
		}
	}
}
