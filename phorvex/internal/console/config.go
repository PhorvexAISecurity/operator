/*
 * Phorvex Console (P-DASHBOARD) — config + paths.
 */

package console

import (
	"fmt"
	"math"
	"path/filepath"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
	"k8s.io/client-go/rest"
)

// Config locates the Phorvex tree the console reads (read-only) and triggers.
type Config struct {
	Root       string // the Phorvex root (holds phorvex/ + build/test-harness/)
	PhorvexBin string // phorvex.exe (for --scan/--ablation/--native-demo/--audit-json)
	HarnessBin string // harness.exe (for -config <yaml>)
	HarnessDir string // build/test-harness (cwd for harness runs)
	StateDir   string // writable console-owned state; never the manager decision audit
	// HistoryArchiveMaxBytes and HistoryMinFreeBytes bound the append-only durable history
	// importer. Existing records remain readable when either limit pauses new imports.
	HistoryArchiveMaxBytes int64
	HistoryMinFreeBytes    int64
	HistoryRetentionDays   int // zero preserves append-only behavior; explicit configuration authorizes expiry
	// historyTransactionReserveBytes is a same-package test seam. Production uses the
	// conservative default that covers one bounded import and bbolt allocation overhead.
	historyTransactionReserveBytes int64
	AuditPath                      string                 // optional explicit audit JSONL (owner-view source)
	AuditSource                    *audittransport.Client // remote mTLS source; nil keeps local-file mode
	// AuditSourceIdentity binds durable history to the configured endpoint. Production sets this
	// to the remote origin and TLS server identity; it contains no credential material.
	AuditSourceIdentity string
	// MongoExposureEnabled is set only by the opt-in chart installation that
	// grants the fixed document-store fixture permissions.
	MongoExposureEnabled bool
	Addr                 string // http listen address
	Web                  string // static SPA dir (dashboard-web/out) served at / alongside /api
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
	// CatalogueV1 is the opt-in, server-owned runtime for the six limited-v1
	// checks. Catalogue rows remain visible when disabled; launch fails with the
	// recorded prerequisite rather than accepting caller-supplied destinations.
	CatalogueV1 CatalogueV1Config
}

type CatalogueV1Config struct {
	Enabled                     bool
	Executable                  string
	KubeconfigPath              string
	KubeContext                 string
	LoopbackURL                 string
	ScopedTokenFile             string
	AllowedTenant               string
	DeniedTenant                string
	DeniedTarget                string
	ExpectedSubject             string
	GrantFile                   string
	VoiceEnabled                bool
	VoiceNamespace              string
	VoiceDeployment             string
	VoiceService                string
	VoiceContainer              string
	VoiceServicePort            int32
	VoicePDB                    string
	TranscriptSelector          string
	TranscriptContainer         string
	GPUEnabled                  bool
	GPUFixtureNamespace         string
	GPUFixtureConfig            string
	GPUKubeconfigPath           string
	GPUKubeContext              string
	GuardrailCalibrationEnabled bool
	GuardrailNamespace          string
	GuardrailService            string
	GuardrailPort               int32
	GuardrailContainer          string
	GuardrailSourceConfigMap    string
	GuardrailSourceKey          string
	GuardrailSourceSHA256       string
	MCPEnabled                  bool
	MCPNamespace                string
	MCPDeployment               string
	MCPService                  string
	MCPContainer                string
	MCPPort                     int32
	MCPSourceConfigMap          string
	MCPSourceKey                string
	MCPImageID                  string
	MCPSourceSHA256             string
	ChromaEnabled               bool
	ChromaNamespace             string
	ChromaDeployment            string
	ChromaService               string
	ChromaContainer             string
	ChromaPort                  int32
	ChromaImageID               string
	ChromaVersionSourceSHA256   string
	ChromaServerSourceSHA256    string
	ChromaSchemaSourceSHA256    string
	LiteLLMEnabled              bool
	LiteLLMNamespace            string
	LiteLLMDeployment           string
	LiteLLMService              string
	LiteLLMContainer            string
	LiteLLMPort                 int32
	LiteLLMConfigMap            string
	LiteLLMConfigKey            string
	LiteLLMConfigSHA256         string
}

const (
	DefaultHistoryArchiveMaxBytes         int64 = 2 << 30
	DefaultHistoryMinFreeBytes            int64 = 512 << 20
	defaultHistoryTransactionReserveBytes int64 = 64 << 20
)

func (c Config) historyCapacityLimits() (archiveMax, minFree, transactionReserve int64, err error) {
	archiveMax, minFree = c.HistoryArchiveMaxBytes, c.HistoryMinFreeBytes
	if archiveMax == 0 {
		archiveMax = DefaultHistoryArchiveMaxBytes
	}
	if minFree == 0 {
		minFree = DefaultHistoryMinFreeBytes
	}
	transactionReserve = c.historyTransactionReserveBytes
	if transactionReserve == 0 {
		transactionReserve = defaultHistoryTransactionReserveBytes
	}
	if transactionReserve <= 0 || transactionReserve > math.MaxInt64/2 {
		return 0, 0, 0, fmt.Errorf("history transaction reserve %d is outside the supported range", transactionReserve)
	}
	if archiveMax < 2*transactionReserve {
		return 0, 0, 0, fmt.Errorf("history archive maximum %d must be at least twice transaction reserve %d", archiveMax, transactionReserve)
	}
	if minFree < transactionReserve {
		return 0, 0, 0, fmt.Errorf("history minimum free bytes %d must be at least transaction reserve %d", minFree, transactionReserve)
	}
	if minFree > math.MaxInt64-transactionReserve {
		return 0, 0, 0, fmt.Errorf("history minimum free bytes %d plus transaction reserve %d exceeds the supported range", minFree, transactionReserve)
	}
	return archiveMax, minFree, transactionReserve, nil
}

// ValidateHistoryCapacity rejects unsafe importer limits before the console starts.
func (c Config) ValidateHistoryCapacity() error {
	_, _, _, err := c.historyCapacityLimits()
	return err
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
		Root:                   root,
		PhorvexBin:             filepath.Join(root, "phorvex", "bin", "phorvex.exe"),
		HarnessBin:             filepath.Join(hd, "bin", "harness.exe"),
		HarnessDir:             hd,
		StateDir:               hd, // standalone compatibility; deployments must configure a dedicated mount
		HistoryArchiveMaxBytes: DefaultHistoryArchiveMaxBytes,
		HistoryMinFreeBytes:    DefaultHistoryMinFreeBytes,
		Addr:                   ":8090",
		Web:                    filepath.Join(root, "dashboard-web", "out"),
	}
}
