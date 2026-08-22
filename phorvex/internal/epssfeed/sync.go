/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// sync.go runs the one-shot cluster inventory, Trivy scan, FIRST lookup, and ConfigMap update.
// It runs outside the decision path: inventory the running images, scan them with Trivy,
// resolve the reported CVEs against FIRST's public EPSS API, then atomically replace one
// ConfigMap key. A failed refresh leaves the last-known-good cache untouched.
package epssfeed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"github.com/phorvex/phorvex/internal/platform"
)

const (
	defaultFIRSTURL = "https://api.first.org/data/v1/epss"
	maxFIRSTBatch   = 100
)

// Score is the same on-disk contract produced by the offline builder.
type Score = Entry

// ScanFailure makes partial registry/authentication failures visible without dropping a
// still-running image's last-known-good score.
type ScanFailure struct {
	Image string `json:"image"`
	Error string `json:"error"`
}

// Result is emitted as the CronJob's machine-readable before/after evidence.
type Result struct {
	Mode                    string           `json:"mode"`
	ObservedPods            int              `json:"observedPods"`
	RunningContainers       int              `json:"runningContainers"`
	UniqueImages            int              `json:"uniqueImages"`
	ScannedImages           int              `json:"scannedImages"`
	FailedImages            int              `json:"failedImages"`
	EntriesBefore           int              `json:"entriesBefore"`
	EntriesAfter            int              `json:"entriesAfter"`
	CoveredPodsBefore       int              `json:"coveredPodsBefore"`
	CoveredPodsAfter        int              `json:"coveredPodsAfter"`
	CoveredContainersBefore int              `json:"coveredContainersBefore"`
	CoveredContainersAfter  int              `json:"coveredContainersAfter"`
	GeneratedAt             time.Time        `json:"generatedAt"`
	ScanFailures            []ScanFailure    `json:"scanFailures,omitempty"`
	Cache                   map[string]Score `json:"cache,omitempty"`
}

// Scanner returns CVE -> measured CVSS for one exact image reference.
type Scanner interface {
	Scan(context.Context, string) (map[string]float64, error)
}

// EPSSSource resolves CVEs to FIRST EPSS probabilities.
type EPSSSource interface {
	Lookup(context.Context, []string) (map[string]float64, error)
}

// Options are explicit so the feed is easy to exercise against a fake client and scanner.
type Options struct {
	Client        kubernetes.Interface
	Scanner       Scanner
	EPSS          EPSSSource
	Namespace     string
	ConfigMapName string
	ConfigMapKey  string
	Apply         bool
	AllowPartial  bool
	Now           func() time.Time
	Progress      func(image string, done, total int)
}

type imageTarget struct {
	key        string
	reference  string
	containers int
}

type inventory struct {
	targets           []imageTarget
	primaryImageKeys  []string
	observedPods      int
	runningContainers int
}

// Run executes one complete refresh. Scanner failures are handled per image; FIRST or
// Kubernetes failures abort the refresh so a partial external outage cannot erase the cache.
func Run(ctx context.Context, opts Options) (Result, error) {
	if opts.Client == nil || opts.Scanner == nil || opts.EPSS == nil {
		return Result{}, errors.New("epss feed requires Kubernetes, scanner, and FIRST clients")
	}
	if opts.Namespace == "" || opts.ConfigMapName == "" || opts.ConfigMapKey == "" {
		return Result{}, errors.New("epss feed requires namespace, ConfigMap name, and key")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	pods, err := opts.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("list running images: %w", err)
	}
	inv := buildInventory(pods)
	if len(inv.targets) == 0 {
		return Result{}, errors.New("no running container images found; retaining last-known-good EPSS cache")
	}

	cm, err := opts.Client.CoreV1().ConfigMaps(opts.Namespace).Get(ctx, opts.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("read EPSS ConfigMap: %w", err)
	}
	before, err := decodeCache(cm.Data[opts.ConfigMapKey])
	if err != nil {
		return Result{}, fmt.Errorf("existing EPSS cache is invalid: %w", err)
	}

	vulnsByImage := make(map[string]map[string]float64, len(inv.targets))
	failures := make([]ScanFailure, 0)
	for i, target := range inv.targets {
		if opts.Progress != nil {
			opts.Progress(target.reference, i, len(inv.targets))
		}
		vulns, scanErr := opts.Scanner.Scan(ctx, target.reference)
		if scanErr != nil {
			failures = append(failures, ScanFailure{Image: target.key, Error: scanErr.Error()})
			continue
		}
		vulnsByImage[target.key] = vulns
	}
	if opts.Progress != nil {
		opts.Progress("", len(inv.targets), len(inv.targets))
	}
	if len(vulnsByImage) == 0 {
		return Result{}, fmt.Errorf("all %d image scans failed; retaining last-known-good EPSS cache", len(inv.targets))
	}

	cves := uniqueCVEs(vulnsByImage)
	epssScores, err := opts.EPSS.Lookup(ctx, cves)
	if err != nil {
		return Result{}, fmt.Errorf("FIRST EPSS lookup: %w", err)
	}
	if len(cves) > 0 && len(epssScores) == 0 {
		return Result{}, fmt.Errorf("FIRST EPSS lookup returned no scores for %d CVEs; retaining last-known-good cache", len(cves))
	}

	// Build only from the current inventory, pruning digest churn. For a scan that failed,
	// retain that current image's old score; a transient registry outage must not turn a
	// known signal back into honest-absent.
	after := make(map[string]Score, len(inv.targets))
	for _, target := range inv.targets {
		vulns, scanned := vulnsByImage[target.key]
		if !scanned {
			if old, ok := before[target.key]; ok {
				after[target.key] = old
			}
			continue
		}
		if score, ok := bestImageScore(vulns, epssScores); ok {
			after[target.key] = score
		}
	}

	now := opts.Now().UTC()
	result := Result{
		Mode:                    "dry-run",
		ObservedPods:            inv.observedPods,
		RunningContainers:       inv.runningContainers,
		UniqueImages:            len(inv.targets),
		ScannedImages:           len(vulnsByImage),
		FailedImages:            len(failures),
		EntriesBefore:           len(before),
		EntriesAfter:            len(after),
		CoveredPodsBefore:       countMatches(inv.primaryImageKeys, before),
		CoveredPodsAfter:        countMatches(inv.primaryImageKeys, after),
		CoveredContainersBefore: countContainerMatches(inv.targets, before),
		CoveredContainersAfter:  countContainerMatches(inv.targets, after),
		GeneratedAt:             now,
		ScanFailures:            failures,
		Cache:                   after,
	}
	if !opts.Apply {
		return result, nil
	}
	if len(failures) > 0 && !opts.AllowPartial {
		result.Mode = "rejected-partial"
		return result, fmt.Errorf("%d of %d image scans failed; refusing a partial cache update", len(failures), len(inv.targets))
	}

	cacheJSON, err := Marshal(after)
	if err != nil {
		return Result{}, fmt.Errorf("encode EPSS cache: %w", err)
	}
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh, getErr := opts.Client.CoreV1().ConfigMaps(opts.Namespace).Get(ctx, opts.ConfigMapName, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if fresh.Data == nil {
			fresh.Data = map[string]string{}
		}
		fresh.Data[opts.ConfigMapKey] = string(cacheJSON)
		if fresh.Annotations == nil {
			fresh.Annotations = map[string]string{}
		}
		fresh.Annotations["phorvex.ai/epss-last-success"] = now.Format(time.RFC3339)
		fresh.Annotations["phorvex.ai/epss-entries"] = strconv.Itoa(len(after))
		fresh.Annotations["phorvex.ai/epss-images-scanned"] = strconv.Itoa(len(vulnsByImage))
		fresh.Annotations["phorvex.ai/epss-images-failed"] = strconv.Itoa(len(failures))
		_, updateErr := opts.Client.CoreV1().ConfigMaps(opts.Namespace).Update(ctx, fresh, metav1.UpdateOptions{})
		return updateErr
	})
	if err != nil {
		return Result{}, fmt.Errorf("update EPSS ConfigMap: %w", err)
	}
	result.Mode = "applied"
	return result, nil
}

func buildInventory(pods *corev1.PodList) inventory {
	byKey := map[string]*imageTarget{}
	primary := make([]string, 0, len(pods.Items))
	observedPods := 0
	runningContainers := 0
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		specImages := make(map[string]string, len(pod.Spec.Containers))
		for _, c := range pod.Spec.Containers {
			specImages[c.Name] = c.Image
		}
		podObserved := false
		primaryRecorded := false
		for _, status := range pod.Status.ContainerStatuses {
			if status.State.Running == nil {
				continue
			}
			key := status.ImageID
			if key == "" {
				key = status.Image
			}
			if key == "" {
				key = specImages[status.Name]
			}
			if key == "" {
				continue
			}
			ref := scanReference(status.ImageID, status.Image, specImages[status.Name])
			if ref == "" {
				continue
			}
			target := byKey[key]
			if target == nil {
				target = &imageTarget{key: key, reference: ref}
				byKey[key] = target
			}
			target.containers++
			runningContainers++
			podObserved = true
			if !primaryRecorded {
				primary = append(primary, key)
				primaryRecorded = true
			}
		}
		if podObserved {
			observedPods++
		}
	}
	targets := make([]imageTarget, 0, len(byKey))
	for _, target := range byKey {
		targets = append(targets, *target)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].key < targets[j].key })
	sort.Strings(primary)
	return inventory{
		targets:           targets,
		primaryImageKeys:  primary,
		observedPods:      observedPods,
		runningContainers: runningContainers,
	}
}

func scanReference(candidates ...string) string {
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		for _, prefix := range []string{"docker-pullable://", "docker://", "containerd://"} {
			candidate = strings.TrimPrefix(candidate, prefix)
		}
		if candidate != "" && !strings.HasPrefix(candidate, "sha256:") {
			return candidate
		}
	}
	return ""
}

func decodeCache(raw string) (map[string]Score, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]Score{}, nil
	}
	var cache map[string]Score
	if err := json.Unmarshal([]byte(raw), &cache); err != nil {
		return nil, err
	}
	for image, score := range cache {
		if strings.TrimSpace(image) == "" || score.EPSS < 0 || score.EPSS > 1 || score.CVSS < 0 || score.CVSS > 10 {
			return nil, fmt.Errorf("invalid score for %q", image)
		}
	}
	return cache, nil
}

func uniqueCVEs(byImage map[string]map[string]float64) []string {
	set := map[string]struct{}{}
	for _, vulns := range byImage {
		for cve := range vulns {
			if strings.HasPrefix(cve, "CVE-") {
				set[cve] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for cve := range set {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

func bestImageScore(vulns, epss map[string]float64) (Score, bool) {
	scored := make([]platform.Vuln, 0, len(vulns))
	for cve, cvss := range vulns {
		probability, ok := epss[cve]
		if !ok || probability < 0 || probability > 1 || cvss <= 0 || cvss > 10 {
			continue
		}
		scored = append(scored, platform.Vuln{CVE: cve, EPSS: probability, CVSS: cvss})
	}
	selected, ok := platform.AggregateVulns(scored)
	if !ok {
		return Score{}, false
	}
	return Score{EPSS: selected.EPSS, CVSS: selected.CVSS, CVE: selected.CVE, Considered: len(scored)}, true
}

func countMatches(keys []string, cache map[string]Score) int {
	n := 0
	for _, key := range keys {
		if _, ok := cache[key]; ok {
			n++
		}
	}
	return n
}

func countContainerMatches(targets []imageTarget, cache map[string]Score) int {
	n := 0
	for _, target := range targets {
		if _, ok := cache[target.key]; ok {
			n += target.containers
		}
	}
	return n
}

// TrivyScanner invokes the pinned Trivy binary bundled in the feed image.
type TrivyScanner struct {
	Path     string
	CacheDir string
	Timeout  time.Duration
}

func (s TrivyScanner) Scan(ctx context.Context, image string) (map[string]float64, error) {
	if s.Path == "" {
		s.Path = "/trivy"
	}
	if s.CacheDir == "" {
		s.CacheDir = "/tmp/trivy"
	}
	if s.Timeout <= 0 {
		s.Timeout = 10 * time.Minute
	}
	scanCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	args := []string{
		"image", "--quiet", "--skip-version-check", "--scanners", "vuln",
		"--format", "json", "--cache-dir", s.CacheDir, "--timeout", s.Timeout.String(), image,
	}
	cmd := exec.CommandContext(scanCtx, s.Path, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("trivy scan %q: %s", image, message)
	}
	return parseTrivyReport(out)
}

type trivyCLIReport struct {
	Results []struct {
		Vulnerabilities []struct {
			ID   string `json:"VulnerabilityID"`
			CVSS map[string]struct {
				V2 float64 `json:"V2Score"`
				V3 float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parseTrivyReport(raw []byte) (map[string]float64, error) {
	var report trivyCLIReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse Trivy JSON: %w", err)
	}
	out := map[string]float64{}
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if !strings.HasPrefix(vuln.ID, "CVE-") {
				continue
			}
			cvss := 0.0
			for _, source := range vuln.CVSS {
				cvss = max(cvss, source.V3, source.V2)
			}
			if cvss > out[vuln.ID] {
				out[vuln.ID] = cvss
			}
		}
	}
	return out, nil
}

// FIRSTClient talks only from the CronJob. No FIRST or scanner network request can occur
// in a Phorvex decision tick.
type FIRSTClient struct {
	BaseURL string
	Client  *http.Client
}

func (c FIRSTClient) Lookup(ctx context.Context, cves []string) (map[string]float64, error) {
	out := make(map[string]float64, len(cves))
	if len(cves) == 0 {
		return out, nil
	}
	base := c.BaseURL
	if base == "" {
		base = defaultFIRSTURL
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	for start := 0; start < len(cves); start += maxFIRSTBatch {
		end := min(start+maxFIRSTBatch, len(cves))
		u, err := url.Parse(base)
		if err != nil {
			return nil, fmt.Errorf("invalid FIRST URL: %w", err)
		}
		q := u.Query()
		q.Set("cve", strings.Join(cves[start:end], ","))
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "phorvex-epss-feed/1")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("FIRST returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var payload struct {
			Data []struct {
				CVE  string          `json:"cve"`
				EPSS json.RawMessage `json:"epss"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("parse FIRST response: %w", err)
		}
		for _, row := range payload.Data {
			probability, err := parseJSONFloat(row.EPSS)
			if err != nil || probability < 0 || probability > 1 || !strings.HasPrefix(row.CVE, "CVE-") {
				continue
			}
			out[row.CVE] = probability
		}
	}
	return out, nil
}

func parseJSONFloat(raw json.RawMessage) (float64, error) {
	var number float64
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, err
	}
	return strconv.ParseFloat(text, 64)
}
