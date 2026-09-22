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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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

	// NATSJetStreamFixture is an optional, explicitly pinned three-volume
	// authority for the isolated c2-nats-jetstream-durability scenario. Nil
	// keeps the scenario unavailable and creates no NATS or storage objects.
	NATSJetStreamFixture *NATSJetStreamFixtureConfig `json:"natsJetStreamFixture,omitempty"`

	// InstalledManagerFixture attaches one catalogue arm to an already installed
	// manager and its existing authenticated audit API. It is a complete runtime
	// pin; nil keeps the arm unavailable and causes no manager/CRD mutation.
	InstalledManagerFixture *InstalledManagerFixtureConfig `json:"installedManagerFixture,omitempty"`

	// GPUFunctionalFixture binds one benign functional trial to an externally
	// provisioned, supervisor-owned ordinary-GPU vLLM fixture. The harness never
	// creates or deletes GPU capacity and never accepts an arbitrary serving URL.
	GPUFunctionalFixture *GPUFunctionalFixtureConfig `json:"gpuFunctionalFixture,omitempty"`
}

type GPUFunctionalFixtureConfig struct {
	Operation          string `json:"operation"`
	Mode               string `json:"mode"`
	NamespaceUID       string `json:"namespaceUID"`
	RunLabel           string `json:"runLabel"`
	NodeName           string `json:"nodeName"`
	NodeUID            string `json:"nodeUID"`
	PodName            string `json:"podName"`
	PodUID             string `json:"podUID"`
	OwnerKind          string `json:"ownerKind"`
	OwnerName          string `json:"ownerName"`
	OwnerUID           string `json:"ownerUID"`
	ServiceName        string `json:"serviceName"`
	ServiceUID         string `json:"serviceUID"`
	ContainerName      string `json:"containerName"`
	Image              string `json:"image"`
	ImageID            string `json:"imageID"`
	StartedAt          string `json:"startedAt"`
	RestartCount       int32  `json:"restartCount"`
	Port               int32  `json:"port"`
	Model              string `json:"model"`
	ModelDigest        string `json:"modelDigest"`
	EngineSourceSHA256 string `json:"engineSourceSHA256"`
	ProxySourceGitSHA  string `json:"proxySourceGitSHA"`
	BearerTokenFile    string `json:"bearerTokenFile"`
}

type NATSJetStreamLocalPV struct {
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Slot       int    `json:"slot"`
	PathSHA256 string `json:"pathSHA256"`
}

type NATSJetStreamFixtureConfig struct {
	Mode            string                 `json:"mode"`
	StorageClass    string                 `json:"storageClass"`
	StorageClassUID string                 `json:"storageClassUID"`
	NodeName        string                 `json:"nodeName"`
	NodeUID         string                 `json:"nodeUID"`
	HolderName      string                 `json:"holderName"`
	HolderUID       string                 `json:"holderUID"`
	Nonce           string                 `json:"nonce"`
	PVs             []NATSJetStreamLocalPV `json:"pvs"`
}

type InstalledManagerFixtureConfig struct {
	ManagerNamespace           string `json:"managerNamespace"`
	ManagerServiceAccount      string `json:"managerServiceAccount"`
	FixtureNonce               string `json:"fixtureNonce"`
	AuthorizationDenyNamespace string `json:"authorizationDenyNamespace"`
	DeploymentName             string `json:"deploymentName"`
	DeploymentUID              string `json:"deploymentUID"`
	ReplicaSetName             string `json:"replicaSetName"`
	ReplicaSetUID              string `json:"replicaSetUID"`
	PodName                    string `json:"podName"`
	PodUID                     string `json:"podUID"`
	ContainerName              string `json:"containerName"`
	Image                      string `json:"image"`
	ImageID                    string `json:"imageID"`
	StartedAt                  string `json:"startedAt"`
	RestartCount               int32  `json:"restartCount"`
	OCIRevision                string `json:"ociRevision"`
	ExpectedBrainImage         string `json:"expectedBrainImage"`
	TraceSchema                string `json:"traceSchema"`
	PolicyCRDUID               string `json:"policyCRDUID"`
	PolicyCRDResourceVersion   string `json:"policyCRDResourceVersion"`
	ObserverBinary             string `json:"observerBinary"`
	ObserverBinarySHA256       string `json:"observerBinarySHA256"`
	AuditURL                   string `json:"auditURL"`
	AuditServerName            string `json:"auditServerName"`
	AuditCAFile                string `json:"auditCAFile"`
	AuditClientCertFile        string `json:"auditClientCertFile"`
	AuditClientKeyFile         string `json:"auditClientKeyFile"`
	ParameterManifestID        string `json:"parameterManifestID"`
	ParameterManifestHash      string `json:"parameterManifestHash"`
	ObservationTimeoutSeconds  int    `json:"observationTimeoutSeconds"`
	ObservationMaxBytes        int64  `json:"observationMaxBytes"`
	ObservationMaxRows         int    `json:"observationMaxRows"`
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
		if err := validateNATSJetStreamFixture(c); err != nil {
			return err
		}
		if err := validateGPUFunctionalFixture(c); err != nil {
			return err
		}
		return validateInstalledManagerFixture(c)
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
	if err := validateNATSJetStreamFixture(c); err != nil {
		return err
	}
	if err := validateGPUFunctionalFixture(c); err != nil {
		return err
	}
	return validateInstalledManagerFixture(c)
}

func validateGPUFunctionalFixture(c TargetConfig) error {
	fixture := c.GPUFunctionalFixture
	if fixture == nil {
		return nil
	}
	wantScenario := map[string]string{
		"prefix-cache-reset": "c2-vllm-prefix-cache-reset",
		"request-drain":      "c2-vllm-request-drain",
	}[fixture.Operation]
	if wantScenario == "" {
		return errors.New("config: gpuFunctionalFixture operation must be prefix-cache-reset or request-drain")
	}
	if fixture.Mode != "no-action" && fixture.Mode != "direct" {
		return errors.New("config: gpuFunctionalFixture mode must be no-action or direct")
	}
	if c.TrialsPerArm != 1 || len(c.ScenarioFilter) != 1 || c.ScenarioFilter[0] != wantScenario || len(c.DefenderFilter) != 1 || c.DefenderFilter[0] != "d-nomtd" {
		return fmt.Errorf("config: gpuFunctionalFixture requires one %s trial with defenderFilter=[d-nomtd]", wantScenario)
	}
	for label, value := range map[string]string{
		"nodeName": fixture.NodeName, "podName": fixture.PodName, "ownerName": fixture.OwnerName,
		"serviceName": fixture.ServiceName, "containerName": fixture.ContainerName,
	} {
		if value == "" || len(validation.IsDNS1123Subdomain(value)) != 0 {
			return fmt.Errorf("config: gpuFunctionalFixture %s must be an exact DNS subdomain", label)
		}
	}
	for label, value := range map[string]string{
		"namespaceUID": fixture.NamespaceUID, "nodeUID": fixture.NodeUID, "podUID": fixture.PodUID,
		"ownerUID": fixture.OwnerUID, "serviceUID": fixture.ServiceUID,
	} {
		if !kubernetesUIDPattern.MatchString(value) {
			return fmt.Errorf("config: gpuFunctionalFixture %s must be an exact lowercase Kubernetes UUID", label)
		}
	}
	if fixture.OwnerKind != "Deployment" && fixture.OwnerKind != "ReplicaSet" && fixture.OwnerKind != "StatefulSet" {
		return errors.New("config: gpuFunctionalFixture ownerKind must be Deployment, ReplicaSet or StatefulSet")
	}
	if fixture.RunLabel == "" || len(fixture.RunLabel) > 63 || len(validation.IsValidLabelValue(fixture.RunLabel)) != 0 {
		return errors.New("config: gpuFunctionalFixture runLabel must be a nonempty label-safe value")
	}
	if fixture.Port != 8000 || fixture.Model != "facebook/opt-125m" {
		return errors.New("config: gpuFunctionalFixture requires port 8000 and model facebook/opt-125m")
	}
	if fixture.RestartCount < 0 {
		return errors.New("config: gpuFunctionalFixture restartCount must be nonnegative")
	}
	if _, err := time.Parse(time.RFC3339Nano, fixture.StartedAt); err != nil {
		return errors.New("config: gpuFunctionalFixture startedAt must be exact RFC3339Nano")
	}
	imageRef := regexp.MustCompile(`^[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}$`)
	imageID := regexp.MustCompile(`^((docker-pullable://)?[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}|containerd://sha256:[0-9a-f]{64})$`)
	if !imageRef.MatchString(fixture.Image) || !imageID.MatchString(fixture.ImageID) {
		return errors.New("config: gpuFunctionalFixture image and imageID must be digest-bound")
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex40 := regexp.MustCompile(`^[0-9a-f]{40}$`)
	canonicalDigest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	if !canonicalDigest.MatchString(fixture.ModelDigest) || !hex64.MatchString(fixture.EngineSourceSHA256) {
		return errors.New("config: gpuFunctionalFixture modelDigest must be a canonical sha256 digest and engineSourceSHA256 must be lowercase SHA-256")
	}
	if fixture.Operation == "request-drain" && !hex40.MatchString(fixture.ProxySourceGitSHA) {
		return errors.New("config: request-drain gpuFunctionalFixture proxySourceGitSHA must be a lowercase 40-character Git SHA")
	}
	if fixture.Operation == "prefix-cache-reset" && fixture.ProxySourceGitSHA != "" && !hex40.MatchString(fixture.ProxySourceGitSHA) {
		return errors.New("config: prefix-cache-reset gpuFunctionalFixture proxySourceGitSHA must be empty or a lowercase 40-character Git SHA")
	}
	if !filepath.IsAbs(fixture.BearerTokenFile) || filepath.Clean(fixture.BearerTokenFile) != fixture.BearerTokenFile {
		return errors.New("config: gpuFunctionalFixture bearerTokenFile must be a clean absolute path")
	}
	return nil
}

func validateNATSJetStreamFixture(c TargetConfig) error {
	fixture := c.NATSJetStreamFixture
	if fixture == nil {
		return nil
	}
	if c.TrialsPerArm != 1 || len(c.ScenarioFilter) != 1 || c.ScenarioFilter[0] != "c2-nats-jetstream-durability" || len(c.DefenderFilter) != 1 || c.DefenderFilter[0] != "d-nomtd" {
		return errors.New("config: natsJetStreamFixture requires one c2-nats-jetstream-durability trial with defenderFilter=[d-nomtd]")
	}
	if fixture.Mode != "no-action" && fixture.Mode != "member-restart" {
		return errors.New("config: natsJetStreamFixture mode must be no-action or member-restart; direct-native and installed-dispatch use separately reviewed entries")
	}
	for label, value := range map[string]string{"storageClass": fixture.StorageClass, "nodeName": fixture.NodeName, "holderName": fixture.HolderName} {
		if value == "" || len(validation.IsDNS1123Subdomain(value)) != 0 {
			return fmt.Errorf("config: natsJetStreamFixture %s must be an exact DNS subdomain", label)
		}
	}
	if !kubernetesUIDPattern.MatchString(fixture.StorageClassUID) || !kubernetesUIDPattern.MatchString(fixture.NodeUID) || !kubernetesUIDPattern.MatchString(fixture.HolderUID) {
		return errors.New("config: natsJetStreamFixture storageClassUID, nodeUID and holderUID must be exact lowercase Kubernetes UUIDs")
	}
	if fixture.Nonce == "" || len(fixture.Nonce) > 63 || len(validation.IsValidLabelValue(fixture.Nonce)) != 0 {
		return errors.New("config: natsJetStreamFixture nonce must be a nonempty label-safe value")
	}
	if len(fixture.PVs) != 3 {
		return fmt.Errorf("config: natsJetStreamFixture requires exactly three PV authorities, got %d", len(fixture.PVs))
	}
	names, uids, slots := map[string]bool{}, map[string]bool{}, map[int]bool{}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, pv := range fixture.PVs {
		if pv.Name == "" || len(validation.IsDNS1123Subdomain(pv.Name)) != 0 || !kubernetesUIDPattern.MatchString(pv.UID) || pv.Slot < 0 || pv.Slot > 255 || !hex64.MatchString(pv.PathSHA256) || names[pv.Name] || uids[pv.UID] || slots[pv.Slot] {
			return errors.New("config: natsJetStreamFixture PV name/UID/slot/path hash authority is invalid or duplicated")
		}
		names[pv.Name], uids[pv.UID], slots[pv.Slot] = true, true, true
	}
	return nil
}

func validateInstalledManagerFixture(c TargetConfig) error {
	fixture := c.InstalledManagerFixture
	if fixture == nil {
		return nil
	}
	if c.TrialsPerArm != 1 || len(c.ScenarioFilter) != 1 || c.ScenarioFilter[0] != "c2-installed-manager-session" || len(c.DefenderFilter) != 1 || c.DefenderFilter[0] != "d-phorvex-installed" {
		return errors.New("config: installedManagerFixture requires one c2-installed-manager-session trial with defenderFilter=[d-phorvex-installed]")
	}
	for label, value := range map[string]string{
		"managerNamespace": fixture.ManagerNamespace, "managerServiceAccount": fixture.ManagerServiceAccount, "deploymentName": fixture.DeploymentName,
		"replicaSetName": fixture.ReplicaSetName, "podName": fixture.PodName, "containerName": fixture.ContainerName,
		"auditServerName": fixture.AuditServerName,
	} {
		if value == "" || len(validation.IsDNS1123Subdomain(value)) != 0 {
			return fmt.Errorf("config: installedManagerFixture %s must be an exact DNS subdomain", label)
		}
	}
	if fixture.FixtureNonce == "" || len(validation.IsDNS1123Label(fixture.FixtureNonce)) != 0 {
		return errors.New("config: installedManagerFixture fixtureNonce must be an exact DNS label")
	}
	if fixture.AuthorizationDenyNamespace == "" || fixture.AuthorizationDenyNamespace == c.Namespace || len(validation.IsDNS1123Subdomain(fixture.AuthorizationDenyNamespace)) != 0 {
		return errors.New("config: installedManagerFixture authorizationDenyNamespace must be a distinct exact DNS namespace")
	}
	for label, value := range map[string]string{
		"deploymentUID": fixture.DeploymentUID, "replicaSetUID": fixture.ReplicaSetUID,
		"podUID": fixture.PodUID, "policyCRDUID": fixture.PolicyCRDUID,
	} {
		if !kubernetesUIDPattern.MatchString(value) {
			return fmt.Errorf("config: installedManagerFixture %s must be an exact lowercase Kubernetes UUID", label)
		}
	}
	if fixture.RestartCount < 0 {
		return errors.New("config: installedManagerFixture restartCount must be non-negative")
	}
	if _, err := time.Parse(time.RFC3339Nano, fixture.StartedAt); err != nil {
		return errors.New("config: installedManagerFixture startedAt must be RFC3339Nano")
	}
	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imageID := regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)
	if fixture.Image == "" || strings.TrimSpace(fixture.Image) != fixture.Image || !imageID.MatchString(fixture.ImageID) {
		return errors.New("config: installedManagerFixture image must be exact and imageID must carry an immutable SHA-256 digest")
	}
	if fixture.ExpectedBrainImage != fixture.Image {
		return errors.New("config: installedManagerFixture expectedBrainImage must equal the exact observed manager spec image")
	}
	if !regexp.MustCompile(`^[0-9a-f]{7,64}$`).MatchString(fixture.OCIRevision) {
		return errors.New("config: installedManagerFixture ociRevision must be a lowercase hexadecimal revision")
	}
	if fixture.TraceSchema != "phorvex.decision-trace.v6" {
		return errors.New("config: installedManagerFixture traceSchema must be phorvex.decision-trace.v6")
	}
	if fixture.PolicyCRDResourceVersion == "" || len(fixture.PolicyCRDResourceVersion) > 128 {
		return errors.New("config: installedManagerFixture policyCRDResourceVersion is required and bounded")
	}
	if fixture.ParameterManifestID == "" || len(fixture.ParameterManifestID) > 253 || !digest.MatchString(fixture.ParameterManifestHash) {
		return errors.New("config: installedManagerFixture parameter manifest identity/hash invalid")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fixture.ObserverBinarySHA256) {
		return errors.New("config: installedManagerFixture observerBinarySHA256 must be an exact lowercase SHA-256")
	}
	for label, value := range map[string]string{
		"observerBinary": fixture.ObserverBinary, "auditCAFile": fixture.AuditCAFile,
		"auditClientCertFile": fixture.AuditClientCertFile, "auditClientKeyFile": fixture.AuditClientKeyFile,
	} {
		if value == "" || !filepath.IsAbs(value) {
			return fmt.Errorf("config: installedManagerFixture %s must be an absolute private path", label)
		}
	}
	auditURL, err := url.Parse(fixture.AuditURL)
	if err != nil || auditURL.Scheme != "https" || auditURL.Host == "" || auditURL.User != nil || auditURL.Path != "" || auditURL.RawQuery != "" || auditURL.Fragment != "" {
		return errors.New("config: installedManagerFixture auditURL must be a bare HTTPS origin")
	}
	if fixture.ObservationTimeoutSeconds < 5 || fixture.ObservationTimeoutSeconds > 30 {
		return errors.New("config: installedManagerFixture observationTimeoutSeconds must be in [5,30]")
	}
	if fixture.ObservationMaxBytes < 8<<20 || fixture.ObservationMaxBytes > 64<<20 {
		return errors.New("config: installedManagerFixture observationMaxBytes must be explicitly set in [8MiB,64MiB]")
	}
	if fixture.ObservationMaxRows < 64 || fixture.ObservationMaxRows > 1024 {
		return errors.New("config: installedManagerFixture observationMaxRows must be explicitly set in [64,1024]")
	}
	return nil
}
