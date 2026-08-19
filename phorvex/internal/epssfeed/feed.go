/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package epssfeed turns a container-image vulnerability scan plus the public FIRST.org EPSS
// corpus into the image-digest -> {epss,cvss} cache the exploitability multiplier reads
// (PHVX-14b).
//
// It is deliberately I/O-free: every function takes a reader or a map and returns data. The
// scanning, the HTTP fetch and the ConfigMap write live in the caller, so the part that decides
// what an image's score IS can be tested offline against the real corpus.
//
// HONESTY RULES, both of which the multiplier depends on:
//
//	An image with no findings is OMITTED from the cache, never written as zero. A zero scores
//	1 + clamp01(0) = 1.0, numerically identical to honest-absent but semantically a claim —
//	"we looked and there is nothing exploitable" rather than "we have no data". Those must stay
//	distinguishable, because one is evidence and the other is its absence.
//
//	A CVE the EPSS corpus does not score is DROPPED from that image's list rather than defaulted
//	to zero. EPSS covers published CVEs; a missing entry means unscored, and treating unscored as
//	"probability zero" would silently drag every image's percentile down in proportion to how
//	many of its CVEs are new.
package epssfeed

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/phorvex/phorvex/internal/platform"
)

// Entry is one image's cache record, in the shape LoadEPSSFromFile parses.
type Entry struct {
	EPSS float64 `json:"epss"`
	CVSS float64 `json:"cvss"`
	// CVE records WHICH vulnerability produced the pair. Not read by the multiplier; present so
	// a surprising score can be traced to a real advisory instead of being taken on faith.
	CVE string `json:"cve,omitempty"`
	// Considered is how many scored CVEs the selection was made from, so a score derived from
	// three CVEs is not mistaken for one derived from three hundred.
	Considered int `json:"considered,omitempty"`
}

// trivyReport is the subset of Trivy's JSON output this needs. Declared narrowly on purpose: a
// wider struct would couple the feed to scanner-version churn it does not care about.
type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Metadata     struct {
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			CVSS            map[string]struct {
				V3Score float64 `json:"V3Score"`
				V2Score float64 `json:"V2Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ScanResult is one image's findings, keyed the way the Kubernetes API reports images so the
// cache lookup actually hits: an ImageID is "repo@sha256:...", not a tag.
type ScanResult struct {
	Digest string
	Vulns  []platform.Vuln
}

// ParseTrivyReports reads one or more Trivy JSON reports (a JSON array, or newline-delimited
// objects) and returns one ScanResult per image.
//
// CVSS is taken as the highest V3 base score any source assigned that CVE, falling back to V2
// when no V3 exists. Sources disagree, and the multiplier wants severity; taking the maximum is
// the conservative reading and it is applied per CVE, so the pair stays attached to one real
// vulnerability.
func ParseTrivyReports(r io.Reader) ([]ScanResult, error) {
	dec := json.NewDecoder(r)
	var out []ScanResult

	// Tolerate both a top-level array and a stream of objects: `trivy image -f json` emits one
	// object per invocation, and a scan loop naturally concatenates them.
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read trivy report: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		// Not an array: rewind is impossible, so decode this first value then continue streaming.
		return nil, fmt.Errorf("trivy report must be a JSON array of reports (got %v); pipe scans through `jq -s .`", tok)
	}
	for dec.More() {
		var rep trivyReport
		if err := dec.Decode(&rep); err != nil {
			return nil, fmt.Errorf("decode trivy report: %w", err)
		}
		digest := pickDigest(rep)
		if digest == "" {
			// No digest means nothing can key this scan to a running pod's ImageID. Skipping is
			// the honest outcome; guessing from the tag would attach scores to the wrong image
			// as soon as a tag moved.
			continue
		}
		out = append(out, ScanResult{Digest: digest, Vulns: vulnsOf(rep)})
	}
	return out, nil
}

func pickDigest(rep trivyReport) string {
	for _, d := range rep.Metadata.RepoDigests {
		if strings.Contains(d, "@sha256:") {
			return d
		}
	}
	if strings.Contains(rep.ArtifactName, "@sha256:") {
		return rep.ArtifactName
	}
	return ""
}

func vulnsOf(rep trivyReport) []platform.Vuln {
	// A CVE can appear in several Results (one per package layer). Keep the highest severity
	// seen; the aggregate selects one CVE, so a duplicate must not get extra weight by count.
	best := map[string]float64{}
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			if !strings.HasPrefix(v.VulnerabilityID, "CVE-") {
				continue // GHSA/OSV ids are not in the EPSS corpus
			}
			score := 0.0
			for _, s := range v.CVSS {
				if s.V3Score > score {
					score = s.V3Score
				}
			}
			if score == 0 {
				for _, s := range v.CVSS {
					if s.V2Score > score {
						score = s.V2Score
					}
				}
			}
			if cur, ok := best[v.VulnerabilityID]; !ok || score > cur {
				best[v.VulnerabilityID] = score
			}
		}
	}
	out := make([]platform.Vuln, 0, len(best))
	for cve, cvss := range best {
		out = append(out, platform.Vuln{CVE: cve, CVSS: cvss})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVE < out[j].CVE }) // deterministic
	return out
}

// ParseEPSSCorpus reads the FIRST.org daily CSV (cve,epss,percentile), tolerating the leading
// `#model_version:...` comment line the published file carries.
func ParseEPSSCorpus(r io.Reader) (map[string]float64, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.Comment = '#'

	rows, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read epss corpus: %w", err)
	}
	out := make(map[string]float64, len(rows))
	for i, rec := range rows {
		if len(rec) < 2 {
			continue
		}
		if i == 0 && strings.EqualFold(strings.TrimSpace(rec[0]), "cve") {
			continue // header
		}
		e, err := strconv.ParseFloat(strings.TrimSpace(rec[1]), 64)
		if err != nil {
			continue // a malformed row is skipped, not fatal: one bad line must not lose the corpus
		}
		out[strings.TrimSpace(rec[0])] = e
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("epss corpus contained no usable rows")
	}
	return out, nil
}

// Build joins scans against the EPSS corpus and produces the cache.
//
// Returns the cache plus the number of images skipped for having no scored CVE, which the
// caller should report: a feed that silently covers a fraction of the fleet is how EPSS came to
// read 1.0 on 97% of pods in the first place.
func Build(scans []ScanResult, epss map[string]float64) (map[string]Entry, int) {
	cache := make(map[string]Entry, len(scans))
	skipped := 0
	for _, s := range scans {
		scored := make([]platform.Vuln, 0, len(s.Vulns))
		for _, v := range s.Vulns {
			e, ok := epss[v.CVE]
			if !ok {
				continue // unscored != probability zero
			}
			v.EPSS = e
			scored = append(scored, v)
		}
		sel, ok := platform.AggregateVulns(scored)
		if !ok {
			skipped++ // clean, or nothing the corpus scores: omit, never write a zero
			continue
		}
		cache[s.Digest] = Entry{EPSS: sel.EPSS, CVSS: sel.CVSS, CVE: sel.CVE, Considered: len(scored)}
	}
	return cache, skipped
}

// Marshal renders the cache in the exact shape LoadEPSSFromFile expects, sorted so an unchanged
// fleet produces a byte-identical file and the ConfigMap is not rewritten for nothing.
func Marshal(cache map[string]Entry) ([]byte, error) {
	keys := make([]string, 0, len(cache))
	for k := range cache {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("{\n")
	for i, k := range keys {
		e := cache[k]
		row, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		b.WriteString("  ")
		b.Write(kb)
		b.WriteString(": ")
		b.Write(row)
		if i < len(keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return []byte(b.String()), nil
}
