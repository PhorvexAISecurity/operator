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
	"strings"

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
}

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
	return nil
}
