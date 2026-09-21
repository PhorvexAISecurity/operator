// Package config loads and validates the per-target harness configuration.
//
// NOTHING environment-specific is hardcoded: the same binary targets kind / EKS /
// CoreWeave / vcluster purely by swapping this config. The config REQUIRES an
// owned/authorized acknowledgement; the harness REFUSES to run any mutating
// behavior without it (see internal/safety).
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

// TargetConfig is the per-run target configuration. It is the ONLY place the
// environment is named — there is no hardcoded context/host/namespace anywhere.
type TargetConfig struct {
	// Kubeconfig is the path to the kubeconfig file. Empty falls back to the
	// standard KUBECONFIG / ~/.kube/config resolution (still validated against
	// the named Context).
	Kubeconfig string `json:"kubeconfig"`

	// Context is the kube-context this run is authorized to target. The safety
	// guard refuses any other live context AND verifies the apiserver host of
	// this named context matches the live connection before ANY mutating call.
	Context string `json:"context"`

	// Namespace is the sandbox namespace. ALL attack behavior and every created
	// object is confined here; the sandbox guard refuses objects elsewhere.
	Namespace string `json:"namespace"`

	// OwnedAck is the REQUIRED owned/authorized acknowledgement. The harness
	// refuses to run if this is not exactly true.
	OwnedAck bool `json:"ownedAck"`

	// TrialsPerArm is the trial count per (scenario, defender) arm. Smoke = 2;
	// the full benchmark sets >=20 with the SAME loop. Wired as a config knob.
	TrialsPerArm int `json:"trialsPerArm"`

	// MasterSeed is the fixed master seed; every per-trial RNG derives
	// deterministically from it, so the whole run is reproducible.
	MasterSeed int64 `json:"masterSeed"`

	// PhoenixSrcDir is the path to the phoenix-extended source tree used by the
	// FullPhoenix defender to build bin/manager.exe and install CRDs. Empty =
	// the FullPhoenix arm skips-with-note (portable default).
	PhoenixSrcDir string `json:"phoenixSrcDir"`

	// OutDir is where metrics.jsonl, raw logs, provenance.json and report.md are
	// written. Empty defaults to "./out".
	OutDir string `json:"outDir"`

	// DefenderFilter optionally restricts the run to a subset of defenders by
	// name; empty runs all registered defenders.
	DefenderFilter []string `json:"defenderFilter"`

	// ScenarioFilter optionally restricts the run to a subset of scenarios by
	// name; empty runs all registered scenarios.
	ScenarioFilter []string `json:"scenarioFilter"`

	// ---- PASS-B $ ROI KNOBS (swappable; clearly-labeled defaults applied in
	// applyDefaults() so Pass-A configs that omit them still parse) ----

	// RoiGpuCount is the GPU count the ROI math prices against. DEFAULT 8 (a single
	// DGX-class node). Swap for your fleet size.
	RoiGpuCount int `json:"roiGpuCount"`

	// RoiDollarsPerGpuHour is the $/GPU-hour rate. DEFAULT 2.50 — a cloud
	// H100-class list-ish PLACEHOLDER; SWAP for your contract/reserved rate.
	RoiDollarsPerGpuHour float64 `json:"roiDollarsPerGpuHour"`

	// RoiGpuOverheadPercent is the rotation/MTD compute overhead avoided vs a
	// static-but-unprotected baseline. DEFAULT 0.015 — the midpoint of R6's stated
	// "1-2% overhead". Swap for your measured overhead.
	RoiGpuOverheadPercent float64 `json:"roiGpuOverheadPercent"`

	// RoiAvoidedBreachValueDollars is the breach value an averted compromise saves.
	// DEFAULT 4_880_000 — an industry-average breach-cost PLACEHOLDER; SWAP.
	RoiAvoidedBreachValueDollars float64 `json:"roiAvoidedBreachValueDollars"`

	// RoiHorizonYears is the costing horizon. DEFAULT 1.0.
	RoiHorizonYears float64 `json:"roiHorizonYears"`

	// CredentialObservationWindowSeconds is the positive observation interval the
	// credential-replay scenario waits between the initial post-capture usability
	// replay and the final continued-capability replay of the SAME captured
	// credential. It is how long the attacker "holds" an exfiltrated token before
	// re-using it, so a defender that revokes/rotates within the window is
	// measured, not credited for the token's own natural expiry. DEFAULT 90s;
	// omitted (0) gets the default. Bounded to <= 30 minutes so a live matrix
	// stays finite. Tests inject a wait seam so they never actually sleep.
	CredentialObservationWindowSeconds int `json:"credentialObservationWindowSeconds"`

	// BenignSessionNodeSelector optionally pins both Pods used by the benign
	// ephemeral-session control to the same reviewed CPU node. It has no effect
	// on any other scenario. Empty retains ordinary Kubernetes scheduling.
	BenignSessionNodeSelector map[string]string `json:"benignSessionNodeSelector"`

	// BenignCheckpointStorageClass explicitly selects an existing reviewed
	// provisioner for the benign checkpoint-continuity control. Empty keeps that
	// control unavailable and causes no storage mutation.
	BenignCheckpointStorageClass string `json:"benignCheckpointStorageClass"`

	// BenignCheckpointNodeSelector pins only the benign checkpoint workload and
	// its producer to the reviewed node used by the local fixture. It is a
	// local-fixture-only field; the ordinary provisioned path rejects it.
	BenignCheckpointNodeSelector map[string]string `json:"benignCheckpointNodeSelector"`

	// BenignCheckpointLocalFixture opts the checkpoint-continuity control into
	// the separately owned local-volume fixture. The default false preserves the
	// existing provisioned-storage behavior. The identity fields below are valid
	// only when this flag is true and bind the runtime-created holder and node.
	BenignCheckpointLocalFixture   bool   `json:"benignCheckpointLocalFixture"`
	BenignCheckpointLocalHolderUID string `json:"benignCheckpointLocalHolderUID"`
	BenignCheckpointLocalNodeUID   string `json:"benignCheckpointLocalNodeUID"`
	BenignCheckpointLocalNonce     string `json:"benignCheckpointLocalNonce"`
}

// DefaultCredentialObservationWindowSeconds is the observation interval applied
// when the config omits it (0). It is a deliberate, documented positive default.
const DefaultCredentialObservationWindowSeconds = 90

// MaxCredentialObservationWindowSeconds bounds the observation interval so a
// live run cannot be made to wait indefinitely (30 minutes).
const MaxCredentialObservationWindowSeconds = 30 * 60

// MaxBenignSessionNodeSelectorEntries keeps this narrowly-scoped placement
// override reviewable and prevents an accidentally unbounded config object.
const MaxBenignSessionNodeSelectorEntries = 8

var kubernetesUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrAckMissing is returned when OwnedAck is not true.
var ErrAckMissing = errors.New("config: ownedAck is REQUIRED and must be true — this is an offensive harness; you must acknowledge you OWN/are AUTHORIZED on the target cluster")

// Load reads and validates a YAML/JSON config file.
func Load(path string) (TargetConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return TargetConfig{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(raw)
}

// Parse validates an in-memory config blob (YAML or JSON).
func Parse(raw []byte) (TargetConfig, error) {
	var cfg TargetConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return TargetConfig{}, fmt.Errorf("config: unmarshal: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return TargetConfig{}, err
	}
	return cfg, nil
}

func (c *TargetConfig) applyDefaults() {
	if c.TrialsPerArm == 0 {
		c.TrialsPerArm = 2 // smoke default; full benchmark overrides to >=20
	}
	if c.OutDir == "" {
		c.OutDir = "out"
	}
	// PASS-B $ ROI defaults — transparent, swappable placeholders. Applied only
	// when omitted so a Pass-A config (which never set them) still parses and the
	// ROI columns are computed with clearly-labeled defaults.
	if c.RoiGpuCount == 0 {
		c.RoiGpuCount = 8 // a single DGX-class node
	}
	if c.RoiDollarsPerGpuHour == 0 {
		c.RoiDollarsPerGpuHour = 2.50 // cloud H100-class list-ish placeholder; SWAP
	}
	if c.RoiGpuOverheadPercent == 0 {
		c.RoiGpuOverheadPercent = 0.015 // midpoint of R6's stated 1-2% overhead
	}
	if c.RoiAvoidedBreachValueDollars == 0 {
		c.RoiAvoidedBreachValueDollars = 4_880_000 // industry avg breach cost placeholder; SWAP
	}
	if c.RoiHorizonYears == 0 {
		c.RoiHorizonYears = 1.0
	}
	if c.CredentialObservationWindowSeconds == 0 {
		c.CredentialObservationWindowSeconds = DefaultCredentialObservationWindowSeconds
	}
}

// ROIInputs returns the swappable ROI knobs as a plain tuple (the core economics
// math consumes this so core stays decoupled from config).
func (c TargetConfig) ROIInputs() (gpuCount int, dollarsPerGpuHour, gpuOverheadPercent, avoidedBreachValue, horizonYears float64) {
	return c.RoiGpuCount, c.RoiDollarsPerGpuHour, c.RoiGpuOverheadPercent, c.RoiAvoidedBreachValueDollars, c.RoiHorizonYears
}

// WithDollarDefaults returns a copy of c with the ROI $ defaults applied (without
// running Validate). The Pass-A-with-dollars post-processor uses this when no
// config blob is at hand for a historical metrics file.
func WithDollarDefaults(c TargetConfig) TargetConfig {
	c.applyDefaults()
	return c
}

// Validate enforces the non-negotiable preconditions. It REFUSES (returns
// ErrAckMissing) when the owned/authorized acknowledgement is absent, and
// rejects an empty context/namespace so the safety guard always has a concrete
// target to assert against.
func (c TargetConfig) Validate() error {
	if !c.OwnedAck {
		return ErrAckMissing
	}
	if strings.TrimSpace(c.Context) == "" {
		return errors.New("config: context is required (the only kube-context this run is authorized to target)")
	}
	if strings.TrimSpace(c.Namespace) == "" {
		return errors.New("config: namespace is required (the sandbox namespace all attack behavior is confined to)")
	}
	if c.TrialsPerArm < 1 {
		return fmt.Errorf("config: trialsPerArm must be >= 1, got %d", c.TrialsPerArm)
	}
	if c.CredentialObservationWindowSeconds < 0 {
		return fmt.Errorf("config: credentialObservationWindowSeconds must be >= 0 (0 = default %ds), got %d",
			DefaultCredentialObservationWindowSeconds, c.CredentialObservationWindowSeconds)
	}
	if c.CredentialObservationWindowSeconds > MaxCredentialObservationWindowSeconds {
		return fmt.Errorf("config: credentialObservationWindowSeconds must be <= %d (30m), got %d",
			MaxCredentialObservationWindowSeconds, c.CredentialObservationWindowSeconds)
	}
	if len(c.BenignSessionNodeSelector) > MaxBenignSessionNodeSelectorEntries {
		return fmt.Errorf("config: benignSessionNodeSelector must contain at most %d entries, got %d",
			MaxBenignSessionNodeSelectorEntries, len(c.BenignSessionNodeSelector))
	}
	for key, value := range c.BenignSessionNodeSelector {
		if problems := validation.IsQualifiedName(key); len(problems) != 0 {
			return fmt.Errorf("config: benignSessionNodeSelector key %q is invalid: %s", key, strings.Join(problems, "; "))
		}
		if problems := validation.IsValidLabelValue(value); len(problems) != 0 {
			return fmt.Errorf("config: benignSessionNodeSelector value for %q is invalid: %s", key, strings.Join(problems, "; "))
		}
	}
	for key, value := range c.BenignCheckpointNodeSelector {
		if problems := validation.IsQualifiedName(key); len(problems) != 0 {
			return fmt.Errorf("config: benignCheckpointNodeSelector key %q is invalid: %s", key, strings.Join(problems, "; "))
		}
		if problems := validation.IsValidLabelValue(value); len(problems) != 0 {
			return fmt.Errorf("config: benignCheckpointNodeSelector value for %q is invalid: %s", key, strings.Join(problems, "; "))
		}
	}
	if value := strings.TrimSpace(c.BenignCheckpointStorageClass); value != "" {
		if problems := validation.IsDNS1123Subdomain(value); len(problems) != 0 {
			return fmt.Errorf("config: benignCheckpointStorageClass %q is invalid: %s", value, strings.Join(problems, "; "))
		}
	}
	localValues := []string{c.BenignCheckpointLocalHolderUID, c.BenignCheckpointLocalNodeUID, c.BenignCheckpointLocalNonce}
	if !c.BenignCheckpointLocalFixture {
		if len(c.BenignCheckpointNodeSelector) != 0 {
			return errors.New("config: benignCheckpointNodeSelector requires benignCheckpointLocalFixture=true")
		}
		for _, value := range localValues {
			if strings.TrimSpace(value) != "" {
				return errors.New("config: benign checkpoint local identity fields require benignCheckpointLocalFixture=true")
			}
		}
		return nil
	}
	if strings.TrimSpace(c.BenignCheckpointStorageClass) == "" {
		return errors.New("config: benignCheckpointStorageClass is required for benign checkpoint local fixture")
	}
	if c.TrialsPerArm != 3 {
		return fmt.Errorf("config: benign checkpoint local fixture requires exactly 3 trialsPerArm, got %d", c.TrialsPerArm)
	}
	if len(c.BenignCheckpointNodeSelector) != 1 || strings.TrimSpace(c.BenignCheckpointNodeSelector["kubernetes.io/hostname"]) == "" {
		return errors.New("config: benign checkpoint local fixture requires exactly one kubernetes.io/hostname node selector")
	}
	if !kubernetesUIDPattern.MatchString(c.BenignCheckpointLocalHolderUID) {
		return errors.New("config: benignCheckpointLocalHolderUID must be an exact lowercase Kubernetes UUID")
	}
	if !kubernetesUIDPattern.MatchString(c.BenignCheckpointLocalNodeUID) {
		return errors.New("config: benignCheckpointLocalNodeUID must be an exact lowercase Kubernetes UUID")
	}
	if value := c.BenignCheckpointLocalNonce; strings.TrimSpace(value) != value || value == "" || len(value) > 63 || len(validation.IsValidLabelValue(value)) != 0 {
		return errors.New("config: benignCheckpointLocalNonce must be a nonempty label-safe value of at most 63 bytes")
	}
	return nil
}
