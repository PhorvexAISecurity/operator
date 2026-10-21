package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/phorvex/phorvex/internal/epssmeta"
	"github.com/phorvex/phorvex/internal/metrics"
)

// epss_lookup_test.go — PHORVEXSEC-203 / M-141: exact digest -> latest scan of the same
// repository (flagged) -> miss. No fuzz, no age window, no network on the tick path.

const (
	repoA        = "ghcr.io/berriai/litellm"
	digestCached = repoA + "@sha256:afdc3cc37493d4f86d485ad7ac4445e7154c568a8d47c01bad15c9cf062c66b5"
	digestOlder  = repoA + "@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestRun    = repoA + "@sha256:af806882b7a6ced41658db5b6a7e98ed7b9b51d03b935e0417bf1c8552d688af"
	otherRepoRun = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
)

type seedEntry = struct {
	EPSS   float64
	CVSS   float64
	ScanTS string
}

func lookupCount(t *testing.T, result string) float64 {
	t.Helper()
	var m dto.Metric
	if err := metrics.EPSSLookupCounter(result).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// (a) exact hit: the running digest itself is scored.
func TestEPSSLookupExactHit(t *testing.T) {
	SeedEPSSEntries(map[string]seedEntry{digestRun: {EPSS: 0.5, CVSS: 5, ScanTS: "2026-09-01T03:17:00Z"}})
	defer SeedEPSS(nil)
	before := lookupCount(t, "hit")
	lk := lookupEPSS(digestRun)
	if lk.Basis != EPSSBasisExact || !lk.Present || lk.CachedDigest != digestRun || lk.RunningDigest != digestRun || lk.ScanTS != "2026-09-01T03:17:00Z" {
		t.Fatalf("exact lookup = %+v", lk)
	}
	if m, ok, _ := epssmeta.EPSSMultiplier(lk.EPSS, lk.CVSS, lk.Present); !ok || m != 1+0.5*(5.0/10) {
		t.Fatalf("multiplier = %v ok=%v, want the M-104 form 1 + e·c/10 = 1.25", m, ok)
	}
	if lookupCount(t, "hit") != before+1 {
		t.Fatal("hit was not counted")
	}
}

// (b) digest miss + an entry for the same repository -> repo-fallback, flagged, with both
// digests in the answer. Old code: silent miss (present=false, multiplier 1.0) — fails on old.
func TestEPSSLookupFallsBackToLatestScanOfSameRepository(t *testing.T) {
	SeedEPSSEntries(map[string]seedEntry{
		digestOlder:  {EPSS: 0.10, CVSS: 3.0, ScanTS: "2026-08-01T00:00:00Z"},
		digestCached: {EPSS: 0.99999, CVSS: 7.5, ScanTS: "2026-08-23T03:17:00Z"},
	})
	defer SeedEPSS(nil)
	before := lookupCount(t, "repo-fallback")
	lk := lookupEPSS(digestRun)
	if lk.Basis != EPSSBasisRepoFallback || !lk.Present {
		t.Fatalf("repo fallback did not happen (old behaviour: silent miss): %+v", lk)
	}
	if lk.CachedDigest != digestCached || lk.RunningDigest != digestRun || lk.ScanTS != "2026-08-23T03:17:00Z" {
		t.Fatalf("fallback must pick the LATEST scan of the repository and record both digests: %+v", lk)
	}
	if lk.EPSS != 0.99999 || lk.CVSS != 7.5 {
		t.Fatalf("fallback value = %v/%v", lk.EPSS, lk.CVSS)
	}
	if lookupCount(t, "repo-fallback") != before+1 {
		t.Fatal("repo-fallback was not counted")
	}
	// The exact digest, when present, still wins over the repository's latest scan.
	SeedEPSSEntries(map[string]seedEntry{
		digestRun:    {EPSS: 0.2, CVSS: 2, ScanTS: "2026-01-01T00:00:00Z"},
		digestCached: {EPSS: 0.99999, CVSS: 7.5, ScanTS: "2026-08-23T03:17:00Z"},
	})
	if lk := lookupEPSS(digestRun); lk.Basis != EPSSBasisExact || lk.EPSS != 0.2 {
		t.Fatalf("exact must precede repo-fallback: %+v", lk)
	}
}

// (c) neither the digest nor its repository is scored -> miss: neutral, present=false, counted.
func TestEPSSLookupMissIsNeutralAndCounted(t *testing.T) {
	SeedEPSSEntries(map[string]seedEntry{digestCached: {EPSS: 0.99999, CVSS: 7.5, ScanTS: "2026-08-23T03:17:00Z"}})
	defer SeedEPSS(nil)
	before := lookupCount(t, "miss")
	lk := lookupEPSS(otherRepoRun)
	if lk.Basis != EPSSBasisMiss || lk.Present || lk.EPSS != 0 || lk.CachedDigest != "" || lk.RunningDigest != otherRepoRun {
		t.Fatalf("miss = %+v (a miss must never carry a stale cached value)", lk)
	}
	if lookupCount(t, "miss") != before+1 {
		t.Fatal("miss was not counted")
	}
	if m := epssMultiplier(otherRepoRun); m != 1.0 {
		t.Fatalf("a miss must be neutral: multiplier %v", m)
	}
	if lk := lookupEPSS(""); lk.Basis != "" || lk.Present {
		t.Fatalf("no image identity must be neutral and unbased: %+v", lk)
	}
}

// (f) scanTS is recorded and is the ONLY ordering key; two undated entries of one repository
// are ambiguous and produce a miss (no guess), never the "newest-looking" digest.
func TestEPSSLookupScanTSOrdersFallbackAndAmbiguityIsAMiss(t *testing.T) {
	SeedEPSSEntries(map[string]seedEntry{
		digestOlder:  {EPSS: 0.10, CVSS: 3.0},
		digestCached: {EPSS: 0.99999, CVSS: 7.5},
	})
	defer SeedEPSS(nil)
	if lk := lookupEPSS(digestRun); lk.Basis != EPSSBasisMiss {
		t.Fatalf("two undated same-repo entries must not be guessed between: %+v", lk)
	}
	// A single undated entry for the repository is unambiguous and still serves as fallback.
	SeedEPSSEntries(map[string]seedEntry{digestCached: {EPSS: 0.99999, CVSS: 7.5}})
	if lk := lookupEPSS(digestRun); lk.Basis != EPSSBasisRepoFallback || lk.ScanTS != "" {
		t.Fatalf("single undated entry must fall back with scanTS recorded empty: %+v", lk)
	}
	// Dated beats undated regardless of digest order.
	SeedEPSSEntries(map[string]seedEntry{
		digestCached: {EPSS: 0.99999, CVSS: 7.5},
		digestOlder:  {EPSS: 0.10, CVSS: 3.0, ScanTS: "2026-08-01T00:00:00Z"},
	})
	if lk := lookupEPSS(digestRun); lk.Basis != EPSSBasisRepoFallback || lk.CachedDigest != digestOlder {
		t.Fatalf("a dated scan must outrank an undated one: %+v", lk)
	}
}

// The repository key: before "@sha256:" for digests, before the tag otherwise, no normalisation.
func TestEPSSRepoOfIsRepoLevelNeverFuzzy(t *testing.T) {
	for in, want := range map[string]string{
		digestRun:                          repoA,
		"docker.io/library/python:3.12":    "docker.io/library/python",
		"localhost:5000/team/app:v1":       "localhost:5000/team/app",
		"localhost:5000/team/app@sha256:x": "localhost:5000/team/app",
		"python":                           "python",
	} {
		if got := epssRepoOf(in); got != want {
			t.Fatalf("repoOf(%q) = %q, want %q", in, got, want)
		}
	}
	if epssRepoOf("docker.io/library/python@sha256:a") == epssRepoOf("python@sha256:a") {
		t.Fatal("repositories must not be normalised across registries (no fuzz)")
	}
}

// (e) static: the lookup path has no network. The cache is seeded from a file by the
// refresher; the decision path never resolves a registry.
func TestEPSSLookupPathHasNoNetworkImports(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	for _, name := range []string{"epss.go", "epss_refresh.go", "platform.go"} {
		src, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), name))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{`"net/http"`, `"net"`, `k8s.io/client-go/kubernetes`, "epssfeed"} {
			if strings.Contains(string(src), forbidden) {
				t.Fatalf("%s imports %s: the tick-path lookup must not reach a registry or the feed", name, forbidden)
			}
		}
	}
}
