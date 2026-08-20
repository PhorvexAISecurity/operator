/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package platform

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const goodFeed = `{"sha256:aaa":{"epss":0.5,"cvss":7.5},"sha256:bbb":{"epss":0.1,"cvss":4.0}}`

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The refresher must actually pick up a changed file — this is the entire reason it exists.
// Without it a scanner pipeline writes into a void until the pod happens to restart.
func TestRefreshPicksUpAChangedFeed(t *testing.T) {
	defer SeedEPSS(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "epss.json")

	writeFile(t, path, `{"sha256:aaa":{"epss":0.5,"cvss":7.5}}`)
	if err := LoadEPSSFromFile(path); err != nil {
		t.Fatal(err)
	}
	if got := EPSSLoaded(); got != 1 {
		t.Fatalf("startup seed loaded %d entries, want 1", got)
	}

	writeFile(t, path, goodFeed)
	r := &EPSSRefresher{Path: path, Interval: time.Millisecond}
	r.refreshOnce()

	if got := EPSSLoaded(); got != 2 {
		t.Fatalf("after refresh %d entries, want 2 — the updated feed was not observed", got)
	}
	if m := epssMultiplier("sha256:bbb"); m == 1.0 {
		t.Error("a digest from the refreshed feed still scores honest-absent 1.0")
	}
}

// The property that matters most. A refresh that fails must leave the previous cache in force:
// the alternative is every pod in the fleet silently dropping to EPSS 1.0 because one read hit
// a bad moment — a fleet-wide loss of signal caused by the mechanism meant to supply it.
func TestFailedRefreshKeepsThePreviousCache(t *testing.T) {
	defer SeedEPSS(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "epss.json")

	writeFile(t, path, goodFeed)
	if err := LoadEPSSFromFile(path); err != nil {
		t.Fatal(err)
	}
	before := EPSSLoaded()
	beforeMult := epssMultiplier("sha256:aaa")

	writeFile(t, path, `{"sha256:aaa":{"epss":0.5,`) // truncated mid-write
	var gotErr error
	r := &EPSSRefresher{Path: path, Interval: time.Millisecond, OnError: func(e error) { gotErr = e }}
	r.refreshOnce()

	if gotErr == nil {
		t.Error("a malformed feed did not report an error")
	}
	if got := EPSSLoaded(); got != before {
		t.Fatalf("cache went from %d to %d entries on a failed read — the fleet just lost its exploitability signal", before, got)
	}
	if got := epssMultiplier("sha256:aaa"); got != beforeMult {
		t.Fatalf("multiplier changed from %v to %v on a failed read", beforeMult, got)
	}
}

// A deleted file is the same story: the ConfigMap being unmounted or replaced must not wipe
// scores that were valid a second ago.
func TestDeletedFeedKeepsThePreviousCache(t *testing.T) {
	defer SeedEPSS(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "epss.json")

	writeFile(t, path, goodFeed)
	if err := LoadEPSSFromFile(path); err != nil {
		t.Fatal(err)
	}
	before := EPSSLoaded()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var gotErr error
	reloads := 0
	(&EPSSRefresher{
		Path: path, Interval: time.Millisecond,
		OnError:  func(err error) { gotErr = err },
		OnReload: func(int, bool) { reloads++ },
	}).refreshOnce()

	if got := EPSSLoaded(); got != before {
		t.Fatalf("cache went from %d to %d entries after the file vanished", before, got)
	}
	if gotErr == nil || reloads != 0 {
		t.Fatalf("deleted configured feed: error=%v reloads=%d, want one error and no successful reload", gotErr, reloads)
	}
}

func TestReloadDetectsSameCountScoreChanges(t *testing.T) {
	defer SeedEPSS(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "epss.json")
	writeFile(t, path, `{"sha256:aaa":{"epss":0.1,"cvss":4.0}}`)

	var changes []bool
	r := &EPSSRefresher{Path: path, Interval: time.Millisecond,
		OnReload: func(_ int, changed bool) { changes = append(changes, changed) }}
	r.refreshOnce()
	before := epssMultiplier("sha256:aaa")

	writeFile(t, path, `{"sha256:aaa":{"epss":0.9,"cvss":9.0}}`)
	r.refreshOnce()
	after := epssMultiplier("sha256:aaa")

	if len(changes) != 2 || !changes[0] || !changes[1] {
		t.Fatalf("same-count score update flags = %v, want [true true]", changes)
	}
	if before == after {
		t.Fatalf("same-count score update left multiplier unchanged at %v", before)
	}
}

// changed must distinguish a real update from a no-op re-read, so the log records feed changes
// rather than emitting a line every interval forever.
func TestReloadReportsWhetherAnythingChanged(t *testing.T) {
	defer SeedEPSS(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "epss.json")
	writeFile(t, path, goodFeed)

	var changes []bool
	r := &EPSSRefresher{Path: path, Interval: time.Millisecond,
		OnReload: func(_ int, changed bool) { changes = append(changes, changed) }}

	r.refreshOnce() // 0 -> 2 entries: changed
	r.refreshOnce() // same file: unchanged
	if len(changes) != 2 || !changes[0] || changes[1] {
		t.Fatalf("changed flags = %v, want [true false]", changes)
	}
}

// Unconfigured must be a clean no-op, not an error that fails the manager at startup.
func TestUnwiredRefresherStopsImmediately(t *testing.T) {
	for _, r := range []*EPSSRefresher{
		{Path: "", Interval: time.Minute},
		{Path: "/tmp/whatever", Interval: 0},
	} {
		if err := r.Start(context.Background()); err != nil {
			t.Errorf("unwired refresher returned %v, want nil", err)
		}
	}
}

// Every replica keeps its own package-level cache, so refreshing must not be gated on
// leadership — a standby that never refreshes would serve stale scores and then be promoted.
func TestRefresherDoesNotRequireLeaderElection(t *testing.T) {
	if (&EPSSRefresher{}).NeedLeaderElection() {
		t.Fatal("refresher requires leader election; standby replicas would serve stale exploitability scores")
	}
}

// Start must return on context cancellation so the manager can shut down.
func TestStartReturnsOnCancel(t *testing.T) {
	defer SeedEPSS(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "epss.json")
	writeFile(t, path, goodFeed)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&EPSSRefresher{Path: path, Interval: time.Hour}).Start(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v on cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within 5s of cancellation")
	}
}
