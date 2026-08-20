/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package epssfeed

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/platform"
)

const report = `[
{"ArtifactName":"nginx:1.27",
 "Metadata":{"RepoDigests":["public.ecr.aws/nginx/nginx@sha256:aaaa"]},
 "Results":[
   {"Vulnerabilities":[
     {"VulnerabilityID":"CVE-2024-0001","CVSS":{"nvd":{"V3Score":9.8},"redhat":{"V3Score":7.5}}},
     {"VulnerabilityID":"CVE-2024-0002","CVSS":{"nvd":{"V3Score":5.3}}},
     {"VulnerabilityID":"GHSA-xxxx-yyyy","CVSS":{"nvd":{"V3Score":9.9}}}
   ]},
   {"Vulnerabilities":[
     {"VulnerabilityID":"CVE-2024-0001","CVSS":{"nvd":{"V3Score":4.0}}}
   ]}
 ]},
{"ArtifactName":"clean:1.0",
 "Metadata":{"RepoDigests":["example.com/clean@sha256:bbbb"]},
 "Results":[]},
{"ArtifactName":"notag",
 "Metadata":{"RepoDigests":[]},
 "Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","CVSS":{"nvd":{"V3Score":9.8}}}]}]}
]`

func parse(t *testing.T) []ScanResult {
	t.Helper()
	got, err := ParseTrivyReports(strings.NewReader(report))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestParseTrivyReportsAcceptsNewlineDelimitedObjects(t *testing.T) {
	ndjson := `{"ArtifactName":"a","Metadata":{"RepoDigests":["repo/a@sha256:aaaa"]},"Results":[]}
{"ArtifactName":"b","Metadata":{"RepoDigests":["repo/b@sha256:bbbb"]},"Results":[]}`
	got, err := ParseTrivyReports(strings.NewReader(ndjson))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Digest != "repo/a@sha256:aaaa" || got[1].Digest != "repo/b@sha256:bbbb" {
		t.Fatalf("NDJSON parsed as %+v, want two ordered reports", got)
	}
}

// An image with no digest cannot be keyed to a running pod's ImageID. Guessing from the tag
// would attach scores to the wrong image the moment a tag moved, so it is skipped.
func TestImagesWithoutADigestAreSkipped(t *testing.T) {
	got := parse(t)
	for _, s := range got {
		if !strings.Contains(s.Digest, "@sha256:") {
			t.Fatalf("kept a scan with no digest: %q", s.Digest)
		}
	}
	if len(got) != 2 {
		t.Fatalf("kept %d scans, want 2 (the third has no digest)", len(got))
	}
}

// Non-CVE advisory ids are not in the EPSS corpus, so carrying them would only add unscored
// noise the join has to drop anyway.
func TestNonCVEAdvisoriesAreDropped(t *testing.T) {
	for _, s := range parse(t) {
		for _, v := range s.Vulns {
			if !strings.HasPrefix(v.CVE, "CVE-") {
				t.Fatalf("kept non-CVE id %q", v.CVE)
			}
		}
	}
}

// The same CVE appears once per affected package layer. Counting it repeatedly would let a
// duplicate shift the percentile purely by being duplicated.
func TestDuplicateCVEsAreCollapsedToTheHighestSeverity(t *testing.T) {
	var nginx ScanResult
	for _, s := range parse(t) {
		if strings.Contains(s.Digest, "nginx") {
			nginx = s
		}
	}
	n := 0
	for _, v := range nginx.Vulns {
		if v.CVE == "CVE-2024-0001" {
			n++
			if v.CVSS != 9.8 {
				t.Errorf("CVSS = %v, want 9.8 (highest across sources and layers)", v.CVSS)
			}
		}
	}
	if n != 1 {
		t.Fatalf("CVE-2024-0001 appears %d times, want 1", n)
	}
}

// A CVE the corpus does not score must be DROPPED, not defaulted to zero. Treating unscored as
// probability zero would drag an image's percentile down in proportion to how many of its CVEs
// are new — penalising exactly the images with the freshest vulnerabilities.
func TestUnscoredCVEsAreDroppedNotZeroed(t *testing.T) {
	scans := []ScanResult{{Digest: "img@sha256:cccc", Vulns: []platform.Vuln{
		{CVE: "CVE-SCORED-1", CVSS: 7.0},
		{CVE: "CVE-UNSCORED-1", CVSS: 9.9},
		{CVE: "CVE-UNSCORED-2", CVSS: 9.9},
	}}}
	cache, _ := Build(scans, map[string]float64{"CVE-SCORED-1": 0.42})

	e, ok := cache["img@sha256:cccc"]
	if !ok {
		t.Fatal("image missing from cache")
	}
	if e.Considered != 1 {
		t.Fatalf("considered = %d, want 1 — unscored CVEs leaked into the distribution", e.Considered)
	}
	if e.EPSS != 0.42 || e.CVE != "CVE-SCORED-1" {
		t.Fatalf("selected (%v, %q), want (0.42, CVE-SCORED-1)", e.EPSS, e.CVE)
	}
}

// A clean image must be omitted, never written as zero. Zero scores 1.0 — numerically identical
// to honest-absent but a claim rather than an absence, and the two must stay distinguishable.
func TestCleanImageIsOmittedFromTheCache(t *testing.T) {
	scans, _ := ParseTrivyReports(strings.NewReader(report))
	cache, skipped := Build(scans, map[string]float64{"CVE-2024-0001": 0.9, "CVE-2024-0002": 0.1})

	if _, ok := cache["example.com/clean@sha256:bbbb"]; ok {
		t.Fatal("a clean image was written into the cache; it must be absent so lookups degrade to 1.0")
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	if _, ok := cache["public.ecr.aws/nginx/nginx@sha256:aaaa"]; !ok {
		t.Fatal("the scored image is missing")
	}
}

// The emitted file must be exactly what LoadEPSSFromFile parses, or the pipeline produces a
// file the operator silently ignores.
func TestMarshalRoundTripsThroughTheOperatorLoader(t *testing.T) {
	cache := map[string]Entry{
		"b@sha256:2": {EPSS: 0.5, CVSS: 7.5, CVE: "CVE-2", Considered: 9},
		"a@sha256:1": {EPSS: 0.25, CVSS: 9.1, CVE: "CVE-1", Considered: 3},
	}
	b, err := Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]struct {
		EPSS float64 `json:"epss"`
		CVSS float64 `json:"cvss"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("operator loader could not parse the emitted cache: %v\n%s", err, b)
	}
	if back["a@sha256:1"].EPSS != 0.25 || back["b@sha256:2"].CVSS != 7.5 {
		t.Fatalf("round-trip lost values: %+v", back)
	}
	if strings.Index(string(b), "a@sha256:1") > strings.Index(string(b), "b@sha256:2") {
		t.Error("output is not key-sorted; an unchanged fleet would rewrite the ConfigMap every run")
	}
}

// Byte-stability matters operationally: an unchanged fleet must produce an identical file so the
// ConfigMap is not rewritten, which would otherwise churn the mount and the refresher every run.
func TestMarshalIsByteStable(t *testing.T) {
	cache := map[string]Entry{"x@sha256:1": {EPSS: 0.1, CVSS: 2}, "y@sha256:2": {EPSS: 0.3, CVSS: 4}}
	first, _ := Marshal(cache)
	for i := 0; i < 20; i++ {
		got, _ := Marshal(cache)
		if string(got) != string(first) {
			t.Fatal("Marshal is not byte-stable across runs")
		}
	}
}

// The published corpus starts with a `#model_version:` line before the header.
func TestCorpusParsesThePublishedHeader(t *testing.T) {
	csv := "#model_version:v2026.06.15,score_date:2026-08-18T12:04:07Z\ncve,epss,percentile\nCVE-1999-0001,0.03351,0.87666\nCVE-1999-0002,0.5,0.9\n"
	got, err := ParseEPSSCorpus(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d rows, want 2: %v", len(got), got)
	}
	if got["CVE-1999-0001"] != 0.03351 {
		t.Fatalf("EPSS = %v, want 0.03351", got["CVE-1999-0001"])
	}
}

// An empty corpus must be an error, not an empty map: silently proceeding would rebuild the
// cache with every image unscored and wipe the whole feed on the next refresh.
func TestEmptyCorpusIsAnError(t *testing.T) {
	if _, err := ParseEPSSCorpus(strings.NewReader("#only a comment\n")); err == nil {
		t.Fatal("an empty corpus parsed successfully; that would silently empty the cache")
	}
}

// A single malformed row must not lose the corpus.
func TestOneBadRowDoesNotLoseTheCorpus(t *testing.T) {
	csv := "cve,epss,percentile\nCVE-1,not-a-number,0.5\nCVE-2,0.7,0.9\n"
	got, err := ParseEPSSCorpus(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if got["CVE-2"] != 0.7 || len(got) != 1 {
		t.Fatalf("got %v, want only CVE-2 at 0.7", got)
	}
}
