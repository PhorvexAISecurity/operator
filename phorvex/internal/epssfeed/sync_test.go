package epssfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeScanner struct {
	results map[string]map[string]float64
	errors  map[string]error
}

func (s fakeScanner) Scan(_ context.Context, image string) (map[string]float64, error) {
	if err := s.errors[image]; err != nil {
		return nil, err
	}
	return s.results[image], nil
}

type fakeEPSS map[string]float64

func (s fakeEPSS) Lookup(_ context.Context, cves []string) (map[string]float64, error) {
	out := map[string]float64{}
	for _, cve := range cves {
		if score, ok := s[cve]; ok {
			out[cve] = score
		}
	}
	return out, nil
}

func TestRunAppliesRefreshRetainsFailedImageAndPrunesDigestChurn(t *testing.T) {
	const (
		ns   = "phorvex-system"
		cm   = "phorvex-epss"
		key  = "epss-cache.json"
		imgA = "registry.example/a@sha256:aaa"
		imgB = "registry.example/b@sha256:bbb"
		imgC = "registry.example/c@sha256:ccc"
	)
	before := map[string]Score{
		imgB:                            {EPSS: 0.4, CVSS: 8},
		"registry.example/old@sha256:d": {EPSS: 0.9, CVSS: 9},
	}
	raw, _ := json.Marshal(before)
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cm, Namespace: ns}, Data: map[string]string{key: string(raw)}},
		runningPod("a", imgA), runningPod("b", imgB), runningPod("c", imgC),
	)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	result, err := Run(context.Background(), Options{
		Client:        client,
		Scanner:       fakeScanner{results: map[string]map[string]float64{imgA: {"CVE-2026-0001": 9.8}, imgC: {}}, errors: map[string]error{imgB: fmt.Errorf("registry denied")}},
		EPSS:          fakeEPSS{"CVE-2026-0001": 0.97},
		Namespace:     ns,
		ConfigMapName: cm,
		ConfigMapKey:  key,
		Apply:         true,
		AllowPartial:  true,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "applied" || result.ScannedImages != 2 || result.FailedImages != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.CoveredPodsBefore != 1 || result.CoveredPodsAfter != 2 {
		t.Fatalf("coverage before/after = %d/%d, want 1/2", result.CoveredPodsBefore, result.CoveredPodsAfter)
	}
	// M-141: a freshly scanned digest is stamped with the run time (the lookup's repo-latest
	// ordering key); a retained last-known-good score keeps whatever scanTS it had.
	if got := result.Cache[imgA]; got != (Score{EPSS: 0.97, CVSS: 9.8, CVE: "CVE-2026-0001", Considered: 1, ScanTS: "2026-08-17T12:00:00Z"}) {
		t.Fatalf("new image score = %+v", got)
	}
	if got := result.Cache[imgB]; got != before[imgB] {
		t.Fatalf("failed image lost its last-known-good score: %+v", got)
	}
	if _, ok := result.Cache["registry.example/old@sha256:d"]; ok {
		t.Fatal("stale digest was not pruned")
	}

	gotCM, err := client.CoreV1().ConfigMaps(ns).Get(context.Background(), cm, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotCM.Annotations["phorvex.ai/epss-last-success"] != now.Format(time.RFC3339) {
		t.Fatalf("missing refresh annotation: %#v", gotCM.Annotations)
	}
	gotCache, err := decodeCache(gotCM.Data[key])
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCache) != 2 || gotCache[imgA] != result.Cache[imgA] || gotCache[imgB] != result.Cache[imgB] {
		t.Fatalf("ConfigMap cache = %#v, want %#v", gotCache, result.Cache)
	}
}

func TestRunDryRunDoesNotMutateConfigMap(t *testing.T) {
	const (
		ns  = "phorvex-system"
		cm  = "phorvex-epss"
		key = "epss-cache.json"
		img = "registry.example/a@sha256:aaa"
	)
	original := `{"registry.example/old@sha256:d":{"epss":0.1,"cvss":4}}`
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cm, Namespace: ns}, Data: map[string]string{key: original}},
		runningPod("a", img),
	)
	result, err := Run(context.Background(), Options{
		Client: client, Scanner: fakeScanner{results: map[string]map[string]float64{img: {"CVE-2026-0001": 8}}},
		EPSS: fakeEPSS{"CVE-2026-0001": 0.5}, Namespace: ns, ConfigMapName: cm, ConfigMapKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "dry-run" || result.EntriesAfter != 1 {
		t.Fatalf("unexpected dry-run result: %+v", result)
	}
	got, _ := client.CoreV1().ConfigMaps(ns).Get(context.Background(), cm, metav1.GetOptions{})
	if got.Data[key] != original || len(got.Annotations) != 0 {
		t.Fatalf("dry-run mutated ConfigMap: %#v", got)
	}
}

func TestRunAllScansFailedPreservesConfigMap(t *testing.T) {
	const image = "registry.example/a@sha256:aaa"
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cache", Namespace: "ns"}, Data: map[string]string{"cache.json": `{}`}},
		runningPod("a", image),
	)
	_, err := Run(context.Background(), Options{
		Client: client, Scanner: fakeScanner{errors: map[string]error{image: fmt.Errorf("unavailable")}}, EPSS: fakeEPSS{},
		Namespace: "ns", ConfigMapName: "cache", ConfigMapKey: "cache.json", Apply: true,
	})
	if err == nil || !strings.Contains(err.Error(), "all 1 image scans failed") {
		t.Fatalf("error = %v", err)
	}
	got, _ := client.CoreV1().ConfigMaps("ns").Get(context.Background(), "cache", metav1.GetOptions{})
	if got.Data["cache.json"] != `{}` {
		t.Fatal("failed refresh changed last-known-good cache")
	}
}

func TestRunRejectsPartialApplyByDefault(t *testing.T) {
	const (
		good = "registry.example/good@sha256:aaa"
		bad  = "registry.example/bad@sha256:bbb"
	)
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cache", Namespace: "ns"}, Data: map[string]string{"cache.json": `{}`}},
		runningPod("good", good), runningPod("bad", bad),
	)
	result, err := Run(context.Background(), Options{
		Client: client,
		Scanner: fakeScanner{
			results: map[string]map[string]float64{good: {"CVE-2026-0001": 9}},
			errors:  map[string]error{bad: fmt.Errorf("registry denied")},
		},
		EPSS: fakeEPSS{"CVE-2026-0001": 0.8}, Namespace: "ns", ConfigMapName: "cache", ConfigMapKey: "cache.json", Apply: true,
	})
	if err == nil || result.Mode != "rejected-partial" || !strings.Contains(err.Error(), "refusing a partial cache update") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	got, _ := client.CoreV1().ConfigMaps("ns").Get(context.Background(), "cache", metav1.GetOptions{})
	if got.Data["cache.json"] != `{}` || len(got.Annotations) != 0 {
		t.Fatal("partial refresh changed last-known-good cache")
	}
}

func TestRunRejectsEmptyFIRSTResponseAndPreservesConfigMap(t *testing.T) {
	const image = "registry.example/a@sha256:aaa"
	original := `{"registry.example/old@sha256:d":{"epss":0.4,"cvss":8}}`
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cache", Namespace: "ns"}, Data: map[string]string{"cache.json": original}},
		runningPod("a", image),
	)

	_, err := Run(context.Background(), Options{
		Client: client,
		Scanner: fakeScanner{results: map[string]map[string]float64{
			image: {"CVE-2026-0001": 9},
		}},
		EPSS: fakeEPSS{}, Namespace: "ns", ConfigMapName: "cache", ConfigMapKey: "cache.json", Apply: true,
	})
	if err == nil || !strings.Contains(err.Error(), "returned no scores for 1 CVEs") {
		t.Fatalf("error = %v", err)
	}
	got, _ := client.CoreV1().ConfigMaps("ns").Get(context.Background(), "cache", metav1.GetOptions{})
	if got.Data["cache.json"] != original || len(got.Annotations) != 0 {
		t.Fatal("empty FIRST response changed last-known-good cache")
	}
}

func TestInventoryCountsPodWhoseFirstContainerIsNotRunning(t *testing.T) {
	const image = "registry.example/a@sha256:aaa"
	pod := runningPod("a", image)
	pod.Spec.Containers = append([]corev1.Container{{Name: "stopped", Image: "registry.example/stopped:latest"}}, pod.Spec.Containers...)
	pod.Status.ContainerStatuses = append([]corev1.ContainerStatus{{
		Name: "stopped", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}},
	}}, pod.Status.ContainerStatuses...)

	inv := buildInventory(&corev1.PodList{Items: []corev1.Pod{*pod}})
	if inv.observedPods != 1 || inv.runningContainers != 1 || len(inv.primaryImageKeys) != 1 || inv.primaryImageKeys[0] != image {
		t.Fatalf("inventory = %+v", inv)
	}
	if got := countMatches(inv.primaryImageKeys, map[string]Score{image: {EPSS: 0.5, CVSS: 8}}); got != 1 {
		t.Fatalf("covered pods = %d, want 1", got)
	}
}

func TestParseTrivyReportUsesMeasuredMaximumCVSSAndOnlyCVEs(t *testing.T) {
	report := []byte(`{
	  "Results": [{"Vulnerabilities": [
	    {"VulnerabilityID":"CVE-2026-0001","CVSS":{"nvd":{"V2Score":7.2,"V3Score":9.1},"redhat":{"V3Score":8.4}}},
	    {"VulnerabilityID":"CVE-2026-0001","CVSS":{"vendor":{"V3Score":9.8}}},
	    {"VulnerabilityID":"GHSA-not-a-cve","CVSS":{"nvd":{"V3Score":10}}}
	  ]}]
	}`)
	got, err := parseTrivyReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["CVE-2026-0001"] != 9.8 {
		t.Fatalf("parsed vulnerabilities = %#v", got)
	}
}

func TestFIRSTClientBatchesAndAcceptsStringScores(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		cves := strings.Split(r.URL.Query().Get("cve"), ",")
		if len(cves) > maxFIRSTBatch {
			t.Errorf("batch contains %d CVEs", len(cves))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"cve": cves[0], "epss": "0.123"}}})
	}))
	defer server.Close()
	cves := make([]string, maxFIRSTBatch+1)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2026-%04d", i)
	}
	got, err := (FIRSTClient{BaseURL: server.URL, Client: server.Client()}).Lookup(context.Background(), cves)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(got) != 2 || got[cves[0]] != 0.123 || got[cves[maxFIRSTBatch]] != 0.123 {
		t.Fatalf("requests=%d scores=%#v", requests, got)
	}
}

func runningPod(name, image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "workloads"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: strings.Split(image, "@")[0]}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "app", Image: strings.Split(image, "@")[0], ImageID: image,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
}
