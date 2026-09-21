/*
 * Phorvex Console (P-DASHBOARD) — config + paths.
 */

package console

import (
	"github.com/phorvex/phorvex/internal/audittransport"
	"k8s.io/client-go/rest"
	"path/filepath"
	"time"
)

// Config locates the Phorvex tree the console reads (read-only) and triggers.
type Config struct {
	Root        string                 // the Phorvex root (holds phorvex/ + build/test-harness/)
	PhorvexBin  string                 // phorvex.exe (for --scan/--ablation/--native-demo/--audit-json)
	HarnessBin  string                 // harness.exe (for -config <yaml>)
	HarnessDir  string                 // build/test-harness (cwd for harness runs)
	StateDir    string                 // writable console-owned state; never the manager decision audit
	AuditPath   string                 // optional explicit audit JSONL (owner-view source)
	AuditSource *audittransport.Client // remote mTLS source; nil keeps local-file mode
	// AuditSourceIdentity binds durable history to the configured endpoint. Production sets this
	// to the remote origin and TLS server identity; it contains no credential material.
	AuditSourceIdentity string
	Addr                string // http listen address
	Web                 string // static SPA dir (dashboard-web/out) served at / alongside /api
	// MetricsAllow is the SSRF allowlist for /api/metrics?url= (host or host:port). Loopback
	// is always allowed; metadata/link-local is always blocked; any other host must be listed.
	MetricsAllow []string
	// Exec, when set, replaces the kubectl/harness process launcher (test seam; nil = real exec).
	Exec func(timeout time.Duration, bin string, args ...string) (string, error)
	// StateAppend is a test seam for storage faults. Production always uses durable appendState.
	StateAppend func(path string, record []byte) error
	// Now and Sleep bound the long-running experiment orchestrator in permanent tests.
	// Production leaves both nil and uses the wall clock.
	Now   func() time.Time
	Sleep func(time.Duration)
	// ExperimentRESTConfig is an isolated local-API test seam. Production derives
	// the in-cluster/default kube config when this is nil.
	ExperimentRESTConfig *rest.Config
	AttackWatchDuration  time.Duration
	AttackWatchInterval  time.Duration
	BlindRotationDelay   time.Duration
	// MutationAuditPath is a compatibility override for the mutation journal. Empty uses StateDir.
	MutationAuditPath string
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) sleep(d time.Duration) {
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (c Config) appendState(path string, record []byte) error {
	if c.StateAppend != nil {
		return c.StateAppend(path, record)
	}
	return appendState(path, record)
}

func (c Config) runsDir() string { return c.statePath("runs") }
func (c Config) runOutputPath(out string) string {
	if base := c.runsDir(); base != "" {
		return filepath.Join(base, filepath.Base(out))
	}
	return ""
}

// DefaultConfig derives the standard in-repo layout from a root.
func DefaultConfig(root string) Config {
	hd := filepath.Join(root, "build", "test-harness")
	return Config{
		Root:       root,
		PhorvexBin: filepath.Join(root, "phorvex", "bin", "phorvex.exe"),
		HarnessBin: filepath.Join(hd, "bin", "harness.exe"),
		HarnessDir: hd,
		StateDir:   hd, // standalone compatibility; deployments must configure a dedicated mount
		Addr:       ":8090",
		Web:        filepath.Join(root, "dashboard-web", "out"),
	}
}
