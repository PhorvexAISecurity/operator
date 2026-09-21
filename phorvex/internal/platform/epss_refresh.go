/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package platform

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/epssmeta"
)

// epss_refresh.go re-reads the exploitability cache while the operator runs.
//
// WHY THIS EXISTS. LoadEPSSFromFile is called once at startup, which is correct for a
// hand-curated file baked into a ConfigMap and never touched again. It stops being correct the
// moment a scanner pipeline owns that ConfigMap: kubelet updates the mounted file within a
// minute or so of the ConfigMap changing, but nothing re-reads it, so a freshly-scanned feed
// stays invisible until the pod happens to restart. A pipeline whose output is only observed by
// accident is not a wired feed — it is a file being written into a void (PHVX-14b).
//
// WHAT IT DELIBERATELY DOES NOT DO. It never clears a good cache. A refresh that reads a
// missing, unreadable or malformed file leaves the previous entries in place and reports the
// error, because the alternative — every pod silently dropping to EPSS 1.0 because a ConfigMap
// was mid-edit — is a fleet-wide loss of signal caused by the thing meant to supply it. Honest-
// absent is the right answer when there has never been data; it is the wrong answer when the
// data exists and one read failed.

// EPSSRefresher periodically re-seeds the exploitability cache from path. It satisfies
// controller-runtime's Runnable, so the manager owns its lifetime and shuts it down with
// everything else.
type EPSSRefresher struct {
	// Path is the mounted cache file. Empty disables the refresher entirely.
	Path string
	// Interval between reads. Non-positive disables the refresher.
	Interval time.Duration
	// OnReload, when set, is called after each successful read with the resulting entry count
	// and whether the count changed. Used for logging and metrics; never for control flow.
	OnReload func(entries int, changed bool)
	// OnError, when set, is called when a read fails. The previous cache stays in force.
	OnError func(err error)
}

// AuthoritativeEPSSRefresher verifies projected bytes against the current API
// object before atomically publishing them. Refresh work is serialized; lookup
// performs no I/O and remains bounded even if a filesystem or API call stalls.
type AuthoritativeEPSSRefresher struct {
	CachePath, MetadataPath                         string
	Namespace, ConfigMapName, CacheKey, MetadataKey string
	Scope                                           epssmeta.Scope
	Reader                                          client.Reader
	Interval, Timeout                               time.Duration
	Now                                             func() time.Time
	ReadFile                                        func(string) ([]byte, error)
	OnReload                                        func(entries int, changed bool)
	OnError                                         func(error)
	mu                                              sync.Mutex
}

func (r *AuthoritativeEPSSRefresher) NeedLeaderElection() bool { return false }

func (r *AuthoritativeEPSSRefresher) Start(ctx context.Context) error {
	if r.CachePath == "" || r.MetadataPath == "" || r.Reader == nil || r.Interval <= 0 {
		return nil
	}
	r.refreshOnce(ctx)
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.refreshOnce(ctx)
		}
	}
}

func (r *AuthoritativeEPSSRefresher) refreshOnce(ctx context.Context) {
	if !r.mu.TryLock() {
		r.report(errors.New("authoritative EPSS refresh already in progress"))
		return
	}
	defer r.mu.Unlock()
	entries, changed, err := r.refresh(ctx)
	if err != nil {
		r.ensureAuthoritativeUnavailable()
		r.report(err)
		return
	}
	if r.OnReload != nil {
		r.OnReload(entries, changed)
	}
}

// RefreshNow runs one serialized authoritative refresh and is used by the
// source-bound API fixture. Production uses Start on the same implementation.
func (r *AuthoritativeEPSSRefresher) RefreshNow(ctx context.Context) (int, bool, error) {
	if !r.mu.TryLock() {
		return 0, false, errors.New("authoritative EPSS refresh already in progress")
	}
	defer r.mu.Unlock()
	entries, changed, err := r.refresh(ctx)
	if err != nil {
		r.ensureAuthoritativeUnavailable()
		r.report(err)
		return entries, changed, err
	}
	if r.OnReload != nil {
		r.OnReload(entries, changed)
	}
	return entries, changed, nil
}

func (r *AuthoritativeEPSSRefresher) ensureAuthoritativeUnavailable() {
	mode := epssState.Load().source.Mode
	if mode != "authoritative" {
		replaceEPSSWithProvenance(map[string]epssEntry{}, EPSSProvenance{Mode: "authoritative", Status: "unavailable"})
	}
}

func (r *AuthoritativeEPSSRefresher) report(err error) {
	if r.OnError != nil {
		r.OnError(err)
	}
}

func (r *AuthoritativeEPSSRefresher) refresh(parent context.Context) (int, bool, error) {
	if r.Reader == nil || r.CachePath == "" || r.MetadataPath == "" || r.Namespace == "" || r.ConfigMapName == "" || r.CacheKey == "" || r.MetadataKey == "" {
		return 0, false, errors.New("incomplete authoritative EPSS configuration")
	}
	readFile := r.ReadFile
	var cacheBytes []byte
	var err error
	if readFile == nil {
		cacheBytes, err = readBoundedFile(r.CachePath, epssmeta.MaxCacheBytes)
	} else {
		cacheBytes, err = readFile(r.CachePath)
	}
	if err != nil {
		return 0, false, fmt.Errorf("read projected EPSS cache: %w", err)
	}
	if len(cacheBytes) > epssmeta.MaxCacheBytes {
		return 0, false, fmt.Errorf("projected EPSS cache exceeds %d bytes", epssmeta.MaxCacheBytes)
	}
	var metadataBytes []byte
	if readFile == nil {
		metadataBytes, err = readBoundedFile(r.MetadataPath, epssmeta.MaxMetadataBytes)
	} else {
		metadataBytes, err = readFile(r.MetadataPath)
	}
	if err != nil {
		return 0, false, fmt.Errorf("read projected EPSS metadata: %w", err)
	}
	if len(metadataBytes) > epssmeta.MaxMetadataBytes {
		return 0, false, fmt.Errorf("projected EPSS metadata exceeds %d bytes", epssmeta.MaxMetadataBytes)
	}
	meta, err := epssmeta.Parse(metadataBytes)
	if err != nil {
		return 0, false, err
	}
	if !meta.Complete {
		return 0, false, errors.New("authoritative EPSS metadata is incomplete")
	}
	canonicalScope, err := r.Scope.Canonical()
	if err != nil {
		return 0, false, fmt.Errorf("invalid authoritative EPSS scope: %w", err)
	}
	scopeSHA, _ := canonicalScope.Digest()
	if meta.ScopeSHA256 != scopeSHA {
		return 0, false, errors.New("authoritative EPSS scope does not match metadata")
	}
	if epssmeta.SHA256(cacheBytes) != meta.CacheSHA256 {
		return 0, false, errors.New("projected EPSS cache hash does not match metadata")
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	if now.Before(meta.GeneratedAt) || !now.Before(meta.ValidUntil) {
		return 0, false, errors.New("authoritative EPSS metadata is not currently valid")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cm := &corev1.ConfigMap{}
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: r.ConfigMapName}, cm); err != nil {
		return 0, false, fmt.Errorf("verify EPSS ConfigMap: %w", err)
	}
	if cm.UID == "" || cm.ResourceVersion == "" {
		return 0, false, errors.New("EPSS ConfigMap lacks API identity")
	}
	if cm.Data[r.CacheKey] != string(cacheBytes) || cm.Data[r.MetadataKey] != string(metadataBytes) {
		return 0, false, errors.New("projected EPSS bytes do not match current API object")
	}
	next, err := parseEPSSBytes(cacheBytes)
	if err != nil {
		return 0, false, err
	}
	// The current API object authenticates the complete legacy-compatible cache
	// bytes. This process publishes only exact digests in its configured authority;
	// preserved out-of-scope entries intentionally remain unavailable here.
	allowed := make(map[string]bool, len(canonicalScope.Digests))
	for _, digest := range canonicalScope.Digests {
		allowed[digest] = true
	}
	for digest := range next {
		if !allowed[digest] {
			delete(next, digest)
		}
	}
	source := EPSSProvenance{Mode: "authoritative", Status: "available", ScopeSHA256: meta.ScopeSHA256,
		CacheSHA256: meta.CacheSHA256, MetadataSHA256: epssmeta.SHA256(metadataBytes), ConfigMapUID: string(cm.UID),
		ConfigMapResourceVersion: cm.ResourceVersion, ProducerSource: meta.ProducerSource, ObservedAt: now, ExpiresAt: meta.ValidUntil}
	return len(next), replaceEPSSWithProvenance(next, source), nil
}

// NeedLeaderElection reports false: the cache is per-process package state, so every replica
// must refresh its own copy. Gating this on leadership would leave standby replicas serving
// stale exploitability scores and then promote one of them on failover.
func (r *EPSSRefresher) NeedLeaderElection() bool { return false }

// Start blocks until ctx is cancelled, re-reading the cache every Interval. It returns nil on
// cancellation so a disabled or stopped refresher never fails the manager.
func (r *EPSSRefresher) Start(ctx context.Context) error {
	if r.Path == "" || r.Interval <= 0 {
		return nil // not wired: startup seeding stands
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.refreshOnce()
		}
	}
}

// refreshOnce performs one read. Split out so the failure semantics are directly testable.
func (r *EPSSRefresher) refreshOnce() {
	entries, changed, err := RefreshEPSSFromFile(r.Path)
	if err != nil {
		// The cache is untouched: LoadEPSSFromFile only calls SeedEPSS after a successful parse.
		if r.OnError != nil {
			r.OnError(err)
		}
		return
	}
	if r.OnReload != nil {
		r.OnReload(entries, changed)
	}
}
