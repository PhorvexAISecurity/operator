package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/epssmeta"
)

func TestAuthoritativeRefreshRequiresExactMountedAPIBytesAndExpires(t *testing.T) {
	defer SeedEPSS(nil)
	now := time.Now().UTC().Truncate(time.Second)
	digest := "registry.example/a@sha256:" + strings.Repeat("a", 64)
	cache := []byte(`{"` + digest + `":{"epss":0.5,"cvss":8,"scanTS":"2026-09-21T00:00:00Z"}}`)
	scope, _ := (epssmeta.Scope{Namespaces: []string{"workloads"}, Digests: []string{digest}}).Digest()
	metaBytes, err := epssmeta.Marshal(epssmeta.Metadata{SchemaVersion: epssmeta.SchemaVersion, ScopeSHA256: scope, CacheSHA256: epssmeta.SHA256(cache), ProducerSource: strings.Repeat("d", 40), GeneratedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute), ObservedPods: 1, RunningContainers: 1, UniqueImages: 1, ScannedImages: 1, Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cachePath, metaPath := filepath.Join(dir, "cache"), filepath.Join(dir, "meta")
	if err := os.WriteFile(cachePath, cache, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, metaBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "epss", Namespace: "ns", UID: types.UID("uid-1"), ResourceVersion: "9"}, Data: map[string]string{"cache": string(cache), "meta": string(metaBytes)}}
	r := &AuthoritativeEPSSRefresher{CachePath: cachePath, MetadataPath: metaPath, Namespace: "ns", ConfigMapName: "epss", CacheKey: "cache", MetadataKey: "meta", Reader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build(), Timeout: time.Second, Now: func() time.Time { return now }}
	r.Scope = epssmeta.Scope{Namespaces: []string{"workloads"}, Digests: []string{digest}}
	r.refreshOnce(context.Background())
	lk := lookupEPSS("containerd://" + digest)
	if !lk.Present || lk.Source.Status != "available" || lk.Source.ConfigMapUID != "uid-1" || lk.Source.ConfigMapResourceVersion != "9" {
		t.Fatalf("lookup = %+v", lk)
	}
	legacy := lk
	if err := os.WriteFile(metaPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.refreshOnce(context.Background())
	if got := lookupEPSS(digest); !got.Present || got.EPSS != legacy.EPSS || got.CVSS != legacy.CVSS || got.Basis != legacy.Basis || got.Source.Status != "available" {
		t.Fatalf("failed refresh did not retain exact prior snapshot: %+v", got)
	}
	r.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, _, err := r.refresh(context.Background()); err == nil {
		t.Fatal("expired metadata refreshed")
	}
	// Lookup uses the immutable expiry and becomes neutral without filesystem/API work.
	current := epssState.Load()
	expiredSource := current.source
	expiredSource.ExpiresAt = time.Now().Add(-time.Second)
	replaceEPSSWithProvenance(current.cache, expiredSource)
	if got := lookupEPSS("containerd://" + digest); got.Present || got.Source.Status != "expired" {
		t.Fatalf("expired lookup = %+v", got)
	}
}

func TestLegacyBareCachePreservesExactAndRepositoryFallback(t *testing.T) {
	defer SeedEPSS(nil)
	digest := "registry.example/a@sha256:" + strings.Repeat("a", 64)
	running := "registry.example/a@sha256:" + strings.Repeat("b", 64)
	path := filepath.Join(t.TempDir(), "legacy-cache.json")
	bare := `{"` + digest + `":{"epss":0.5,"cvss":8,"scanTS":"2026-09-21T00:00:00Z"}}`
	if err := os.WriteFile(path, []byte(bare), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LoadEPSSFromFile(path); err != nil {
		t.Fatal(err)
	}
	if exact := lookupEPSS(digest); !exact.Present || exact.Basis != EPSSBasisExact || exact.EPSS != .5 || exact.CVSS != 8 || exact.Source.Mode != "legacy" || exact.Source.Status != "provenance-unavailable" {
		t.Fatalf("legacy exact lookup changed: %+v", exact)
	}
	if fallback := lookupEPSS(running); !fallback.Present || fallback.Basis != EPSSBasisRepoFallback || fallback.CachedDigest != digest || fallback.EPSS != .5 || fallback.CVSS != 8 {
		t.Fatalf("legacy repository fallback changed: %+v", fallback)
	}
}

func TestAuthoritativeSnapshotPreparationDoesNotBlockLookup(t *testing.T) {
	defer SeedEPSS(nil)
	digest := "registry.example/a@sha256:" + strings.Repeat("a", 64)
	oldSource := EPSSProvenance{Mode: "authoritative", Status: "available", ExpiresAt: time.Now().Add(time.Hour)}
	initial := map[string]epssEntry{digest: {EPSS: .4, CVSS: 8}}
	replaceEPSSWithProvenance(initial, oldSource)
	initial[digest] = epssEntry{EPSS: .9, CVSS: 9}
	if got := lookupEPSS(digest); got.EPSS != .4 {
		t.Fatalf("published snapshot retained caller-owned mutable map: %+v", got)
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan *epssSnapshot, 1)
	go func() {
		done <- prepareEPSSSnapshot(map[string]epssEntry{digest: {EPSS: .8, CVSS: 9}}, oldSource, func(cache map[string]epssEntry) map[string]string {
			close(started)
			<-release
			return buildRepoIndex(cache)
		})
	}()
	<-started
	start := time.Now()
	if got := lookupEPSS(digest); !got.Present || got.EPSS != .4 {
		t.Fatalf("lookup during blocked snapshot preparation = %+v", got)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("lookup blocked on off-path snapshot construction")
	}
	close(release)
	prepared := <-done
	if prepared.cache[digest].EPSS != .8 {
		t.Fatalf("prepared snapshot = %+v", prepared.cache[digest])
	}
}

func TestAuthoritativeBlockedRefreshDoesNotBlockLookup(t *testing.T) {
	defer SeedEPSS(nil)
	digest := "registry.example/a@sha256:" + strings.Repeat("a", 64)
	replaceEPSSWithProvenance(map[string]epssEntry{digest: {EPSS: .4, CVSS: 8}}, EPSSProvenance{Mode: "authoritative", Status: "available", ExpiresAt: time.Now().Add(time.Hour)})
	blocked, release := make(chan struct{}), make(chan struct{})
	r := &AuthoritativeEPSSRefresher{CachePath: "cache", MetadataPath: "meta", Namespace: "ns", ConfigMapName: "epss", CacheKey: "cache", MetadataKey: "meta", Reader: fake.NewClientBuilder().Build(), Interval: time.Minute, ReadFile: func(string) ([]byte, error) { close(blocked); <-release; return nil, os.ErrNotExist }}
	done := make(chan struct{})
	go func() { r.refreshOnce(context.Background()); close(done) }()
	<-blocked
	start := time.Now()
	if got := lookupEPSS(digest); !got.Present {
		t.Fatal("blocked refresh hid prior snapshot")
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("lookup blocked on refresh I/O")
	}
	close(release)
	<-done
}

func TestAuthoritativeRefreshBoundsInjectedFilesAndCacheEntries(t *testing.T) {
	r := &AuthoritativeEPSSRefresher{CachePath: "cache", MetadataPath: "meta", Namespace: "ns", ConfigMapName: "epss", CacheKey: "cache", MetadataKey: "meta", Reader: fake.NewClientBuilder().Build(), ReadFile: func(string) ([]byte, error) {
		return make([]byte, epssmeta.MaxCacheBytes+1), nil
	}}
	if _, _, err := r.RefreshNow(context.Background()); err == nil {
		t.Fatal("oversized injected cache accepted")
	}
	entries := make(map[string]struct {
		EPSS float64 `json:"epss"`
		CVSS float64 `json:"cvss"`
	}, epssmeta.MaxCacheEntries+1)
	for i := 0; i <= epssmeta.MaxCacheEntries; i++ {
		entries[fmt.Sprintf("i%04d", i)] = struct {
			EPSS float64 `json:"epss"`
			CVSS float64 `json:"cvss"`
		}{EPSS: .1, CVSS: 1}
	}
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseEPSSBytes(b); err == nil {
		t.Fatal("cache entry bound not enforced")
	}
}
