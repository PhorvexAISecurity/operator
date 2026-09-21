/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 *
 * The brain on top of UNMODIFIED extended Phoenix: ingest -> graph -> physics/
 * context/belief/cost/feasibility -> decision -> audit/metrics, actuating (active
 * mode only) by emitting SecurityEvent + AMTD CRs that Phoenix executes (Seam 1).
 */

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmanager "sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/calib"
	"github.com/phorvex/phorvex/internal/codeexec"
	"github.com/phorvex/phorvex/internal/controller"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/epssfeed"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/losshistory"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/physics"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/runner"
	"github.com/phorvex/phorvex/internal/startupauthz"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const (
	defaultAuditMaxBytes   int64 = 512 << 20
	defaultAuditMaxBackups       = 4
)

var (
	// pcieClasses is the M-114 PCIe capacity class fallback (--pcie-class-table), shared by
	// the live tick, the one-shot scan and the ablation snapshot.
	pcieClasses ingest.PCIeClassTable
	scheme      = runtime.NewScheme()
	setupLog    = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(apiextv1.AddToScheme(scheme))
	// Register the Phoenix types so Phorvex can construct/emit SecurityEvent + AMTD
	// CRs over Seam 1 (the ONLY reason Phorvex depends on the Phoenix module).
	utilruntime.Must(amtdv1beta1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr              string
		probeAddr                string
		enableLeader             bool
		baseInterval             time.Duration
		promURL                  string
		epssCachePath            string
		epssCacheRefresh         time.Duration
		epssFeed                 bool
		epssFeedApply            bool
		epssFeedPartial          bool
		epssFeedNS               string
		epssFeedCM               string
		epssFeedKey              string
		epssFeedFIRSTURL         string
		epssFeedTrivy            string
		epssFeedTimeout          time.Duration
		killSwitch               bool
		auditJSON                string
		operatorNS               string
		integrationEmit          bool
		emitNamespace            string
		emitPod                  string
		emitAction               string
		emitTenant               string
		emitMatchLabels          string
		engineName               string
		ablation                 bool
		ablationNS               string
		ablationSelector         string
		ablationBudget           int
		ablationSeeds            int
		scan                     bool
		scanNS                   string
		kubeContext              string
		nativeDemo               bool
		nativeDemoNS             string
		auditMaxBytes            int64
		auditMaxBackups          int
		gpuEnvelopeMax           float64
		supportDebounce          int
		calibrationShadow        bool
		calibrationRefresh       time.Duration
		calibrationSample        time.Duration
		calibrationLookback      time.Duration
		calibrationExportDir     string
		admissionWebhook         bool
		webhookPort              int
		webhookCertDir           string
		pcieClassTableRaw        string
		flowClasses              string
		trustedDetectors         string
		trustedLossObservers     string
		lossHistoryDir           string
		auditSourceAddr          string
		auditSourceCert          string
		auditSourceKey           string
		auditSourceCA            string
		auditSourceClientDNS     string
		auditSourceVClusterPath  string
		loraCleanSourcesFile     string
		migProfilesFile          string
		servingSecurityFile      string
		servingSecurityMode      string
		migNodeExec              bool
		migAgentNamespace        string
		migAgentServiceAccounts  string
		migAgentDaemonSet        string
		migAgentGPUContainer     string
		migAgentHelperContainer  string
		migAllocationHelper      string
		migAllocationSocket      string
		migExecTimeout           time.Duration
		migAllocationReadTimeout time.Duration
		migReleaseTimeout        time.Duration
		migExclusiveMaintenance  bool
		maxRetainedQuarantines   int
	)
	flag.BoolVar(&nativeDemo, "native-demo", false, "One-shot (P-ACTUATOR): drive the native actuator's full action set live against a demo namespace, verify cluster state + safety, print a table, then exit.")
	flag.StringVar(&nativeDemoNS, "native-demo-namespace", "phorvex-actuator-demo", "[native-demo] namespace for the live actuation proof.")
	flag.BoolVar(&scan, "scan", false, "One-shot (P-PHYSICS): scan the live cluster, print the DISCOVERED both-products PhysicsWitness per pod + the scarcity ablation, then exit.")
	flag.StringVar(&scanNS, "scan-namespace", "", "[scan] restrict the scan/ablation to this namespace.")
	flag.StringVar(&kubeContext, "context", "", "[scan] kubeconfig context to scan (empty = current-context; the console derives this from your kubeconfig, never hardcoded).")
	flag.StringVar(&engineName, "engine", "p1", "Decision brain. Only p1 (submodular recon-coverage) exists; the deprecated p0 greedy baseline was removed (M-107) and is rejected with an error rather than silently ignored.")
	flag.BoolVar(&ablation, "ablation", false, "One-shot: run the STEP-3 IP ablation (P1 vs random per-dollar) live, print, exit.")
	flag.StringVar(&ablationNS, "ablation-namespace", "", "[ablation] namespace to evaluate.")
	flag.StringVar(&ablationSelector, "ablation-selector", "", "[ablation] label selector, e.g. app=demo.")
	flag.IntVar(&ablationBudget, "ablation-budget", 2, "[ablation] move budget B per arm.")
	flag.IntVar(&ablationSeeds, "ablation-seeds", 40, "[ablation] number of random-arm seeds.")
	flag.StringVar(&pcieClassTableRaw, "pcie-class-table", os.Getenv("PHORVEX_PCIE_CLASS_TABLE"), "JSON map of DCGM modelName -> {gen,width} used as the PCIe capacity fallback when the exporter publishes no link gen/width (M-114). Merged over the shipped default {\"Tesla T4\":{\"gen\":3,\"width\":16}}.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address the health probe binds to.")
	flag.BoolVar(&enableLeader, "leader-elect", true, "Enable leader election (single active controller). Set --leader-elect=false only for an explicitly isolated single-instance run.")
	flag.BoolVar(&admissionWebhook, "admission-webhook", false, "Serve the PhorvexPolicy validating admission webhook.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "TLS port for the validating admission webhook.")
	flag.StringVar(&webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs", "Directory containing tls.crt and tls.key for the validating admission webhook.")
	flag.StringVar(&flowClasses, "flow-residual-classes", os.Getenv("PHORVEX_FLOW_RESIDUAL_CLASSES"), "Comma-separated workload classes (namespaces) whose Little's-law flow residual is ACTIVATED (M-115). Availability of the inputs is not activation: the per-class verdict belongs to the math ruling. Empty (default) = no class active; the component is absent with reason class-not-activated and enters no aggregate and no fact.")
	flag.StringVar(&trustedDetectors, "trusted-detectors", os.Getenv("PHORVEX_TRUSTED_DETECTORS"), "Comma-separated allowlist of detector identities whose SecurityEvents may become belief evidence (M-94), e.g. \"vllm/detector-kv-canary,vllm/detector-adapter-inv\". Matched against the admission-stamped authenticated creator, never against the self-declared spec.rule.source. Empty = no external detector is trusted (fail-closed).")
	flag.StringVar(&trustedLossObservers, "trusted-loss-observers", os.Getenv("PHORVEX_TRUSTED_LOSS_OBSERVERS"), "Comma-separated dedicated ServiceAccount identities allowed to create synthetic completed-disclosure evidence. General detector trust does not grant this authority.")
	flag.StringVar(&lossHistoryDir, "loss-history-dir", os.Getenv("PHORVEX_LOSS_HISTORY_DIR"), "Private durable directory for immutable completed-disclosure history. Empty keeps M100 history unavailable.")
	flag.StringVar(&loraCleanSourcesFile, "lora-clean-sources-file", "", "Operator-owned JSON mapping exact namespace and adapter identities to serving-local reload paths. Empty disables reload.")
	flag.StringVar(&migProfilesFile, "mig-profiles-file", "", "Operator-owned JSON mapping exact namespace and MIG resource classes to approved profiles. Empty disables mig-rebind.")
	flag.StringVar(&servingSecurityFile, "serving-security-file", "", "Operator-owned versioned exact policy/workload binding configuration for serving TLS credentials.")
	flag.StringVar(&servingSecurityMode, "serving-security-mode", string(actuator.ServingSecuritySecureRequired), "Serving control mode: secure-required (default) or explicit legacy-plaintext migration compatibility.")
	flag.BoolVar(&migNodeExec, "mig-node-exec", false, "Enable the explicitly configured trusted MIG node-agent transport.")
	flag.StringVar(&migAgentNamespace, "mig-agent-namespace", "", "Exact namespace of the trusted MIG node-agent DaemonSet.")
	flag.StringVar(&migAgentServiceAccounts, "mig-agent-service-accounts", "", "Comma-separated exact ServiceAccount allowlist for the trusted MIG node agent.")
	flag.StringVar(&migAgentDaemonSet, "mig-agent-daemonset", "", "Exact trusted MIG node-agent DaemonSet name.")
	flag.StringVar(&migAgentGPUContainer, "mig-agent-gpu-container", "", "Exact GPU tooling container name in the trusted agent.")
	flag.StringVar(&migAgentHelperContainer, "mig-agent-helper-container", "", "Exact PodResources helper container name in the trusted agent.")
	flag.StringVar(&migAllocationHelper, "mig-allocation-helper", "/phorvex-mig-allocation-helper", "Fixed absolute helper path inside the trusted helper container.")
	flag.StringVar(&migAllocationSocket, "mig-allocation-socket", "/var/lib/kubelet/pod-resources/kubelet.sock", "Fixed kubelet PodResources Unix socket path inside the trusted helper container.")
	flag.DurationVar(&migExecTimeout, "mig-agent-exec-timeout", 5*time.Second, "Deadline for each trusted-agent read or GPU command.")
	flag.DurationVar(&migAllocationReadTimeout, "mig-allocation-read-timeout", 3*time.Second, "Deadline for each kubelet PodResources helper request (maximum 30s).")
	flag.DurationVar(&migReleaseTimeout, "mig-allocation-release-timeout", 45*time.Second, "Deadline to observe target PodResources allocation release after UID-bound deletion.")
	flag.BoolVar(&migExclusiveMaintenance, "mig-exclusive-maintenance", false, "Declare that MIG repartition runs only under an externally controlled exclusive-maintenance scheduling contract.")
	flag.DurationVar(&baseInterval, "base-interval", 10*time.Second, "Base tick interval for the decision loop.")
	flag.IntVar(&supportDebounce, "actions-supported-debounce", runner.DefaultActionsSupportedDebounceTicks, "Consecutive unsupported capability ticks before ActionsSupported becomes False.")
	flag.BoolVar(&calibrationShadow, "calibration-shadow", true, "Run cluster scale calibration in shadow; learned values are never applied to production scoring.")
	flag.DurationVar(&calibrationRefresh, "calibration-refresh", calib.DefaultRefreshInterval, "Shadow scale refresh interval.")
	flag.DurationVar(&calibrationSample, "calibration-sample", calib.DefaultSampleInterval, "Snapshot sampling interval used by walk-forward cadence evaluation.")
	flag.DurationVar(&calibrationLookback, "calibration-lookback", calib.DefaultLookback, "Maximum age of calibration samples and ready-delay outcomes.")
	flag.StringVar(&calibrationExportDir, "calibration-export-dir", "", "Directory for raw calibration CSV/JSON evidence (empty disables file export; metrics remain enabled).")
	flag.StringVar(&promURL, "prometheus-url", "", "Prometheus base URL for telemetry ingest (empty = no telemetry, K8s-only signals).")
	flag.Float64Var(&gpuEnvelopeMax, "gpu-envelope-max", cost.DefaultGPUEnvelopeMax, "Normalized [0,1] GPU reload/warm-up envelope measured on the deployed hardware (default 1.0 is conservative/unconfigured).")
	flag.StringVar(&epssCachePath, "epss-cache", os.Getenv("PHORVEX_EPSS_CACHE"), "Path to a JSON image-digest->{epss,cvss} exploitability cache (scanner/NVD-FIRST export). Empty/missing = EPSS honest-absent (1.0).")
	flag.DurationVar(&epssCacheRefresh, "epss-cache-refresh", 0, "Re-read --epss-cache at this interval so a scanner pipeline that owns the ConfigMap is actually observed (0 = read once at startup, the previous behaviour). A failed read keeps the existing cache.")
	flag.BoolVar(&epssFeed, "epss-feed", false, "One-shot: scan running images with Trivy, resolve CVEs through FIRST EPSS, and refresh the EPSS ConfigMap.")
	flag.BoolVar(&epssFeedApply, "epss-feed-apply", false, "[epss-feed] apply the generated cache; false is a non-mutating dry-run.")
	flag.BoolVar(&epssFeedPartial, "epss-feed-allow-partial", false, "[epss-feed] permit apply when an image scan fails; the default rejects partial refreshes.")
	flag.StringVar(&epssFeedNS, "epss-feed-namespace", os.Getenv("POD_NAMESPACE"), "[epss-feed] namespace containing the EPSS ConfigMap.")
	flag.StringVar(&epssFeedCM, "epss-feed-configmap", "phorvex-epss", "[epss-feed] ConfigMap to read/update.")
	flag.StringVar(&epssFeedKey, "epss-feed-key", "epss-cache.json", "[epss-feed] ConfigMap data key to read/update.")
	flag.StringVar(&epssFeedFIRSTURL, "epss-feed-first-url", "https://api.first.org/data/v1/epss", "[epss-feed] FIRST EPSS API endpoint.")
	flag.StringVar(&epssFeedTrivy, "epss-feed-trivy", "/trivy", "[epss-feed] path to the Trivy executable.")
	flag.DurationVar(&epssFeedTimeout, "epss-feed-scan-timeout", 10*time.Minute, "[epss-feed] maximum duration for each image scan.")
	flag.BoolVar(&killSwitch, "global-kill-switch", false, "Engage the global actuation kill-switch at startup.")
	flag.StringVar(&auditJSON, "audit-json", "", "Optional path to append the JSON-Lines decision audit trail.")
	flag.StringVar(&auditSourceAddr, "audit-source-addr", "", "Optional mTLS read-only audit listener; disabled when empty.")
	flag.StringVar(&auditSourceCert, "audit-source-cert", "", "[audit-source-addr] server leaf certificate file.")
	flag.StringVar(&auditSourceKey, "audit-source-key", "", "[audit-source-addr] server private key file.")
	flag.StringVar(&auditSourceCA, "audit-source-ca", "", "[audit-source-addr] trusted audit-client CA file.")
	flag.StringVar(&auditSourceClientDNS, "audit-source-client-dns", "", "[audit-source-addr] required audit client certificate DNS SAN.")
	flag.StringVar(&auditSourceVClusterPath, "audit-source-vcluster-path", "", "[audit-source-addr] optional fixed vCluster audit JSONL path.")
	flag.Int64Var(&auditMaxBytes, "audit-max-bytes", defaultAuditMaxBytes, "[audit-json] target live-segment size in bytes (0 = unbounded). Whole records are preserved, so a segment may exceed this nominal cap. Default 512 MiB.")
	flag.IntVar(&auditMaxBackups, "audit-max-backups", defaultAuditMaxBackups, "[audit-json] number of rotated segments to keep. Nominal budget is max-bytes*(backups+1); oversized records and pre-existing files can exceed it.")
	flag.StringVar(&operatorNS, "operator-namespace", os.Getenv("POD_NAMESPACE"), "Namespace holding the kill-switch ConfigMap.")
	flag.IntVar(&maxRetainedQuarantines, "max-retained-quarantines-per-namespace", 1, fmt.Sprintf("Hard namespace-wide bound on retained or pending Phorvex quarantines (0 disables new quarantine, maximum %d).", actuator.MaxRetainedQuarantinesUpperBound))
	// One-shot Seam-1 integration proof (emit a single SecurityEvent + ensure AMTD, then exit).
	flag.BoolVar(&integrationEmit, "integration-emit", false, "One-shot: emit one Phorvex SecurityEvent + ensure the AMTD, then exit (Seam-1 proof).")
	flag.StringVar(&emitNamespace, "emit-namespace", "", "[integration-emit] target pod namespace.")
	flag.StringVar(&emitPod, "emit-pod", "", "[integration-emit] target pod name.")
	flag.StringVar(&emitAction, "emit-action", "rotate", "[integration-emit] rotate|quarantine.")
	flag.StringVar(&emitTenant, "emit-tenant", "", "[integration-emit] tenant id (defaults to emit-namespace).")
	flag.StringVar(&emitMatchLabels, "emit-matchlabels", "", "[integration-emit] AMTD guest-list matchLabels, e.g. app=demo,tier=web.")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	if parsed, err := ingest.ParsePCIeClassTable(pcieClassTableRaw); err != nil {
		setupLog.Error(err, "invalid --pcie-class-table; refusing to start with an unparseable PCIe capacity table")
		os.Exit(1)
	} else {
		pcieClasses = parsed
	}
	physics.ConfigureFlowActivation(strings.Split(flowClasses, ","))
	detectors := ingest.NewTrustedDetectors(strings.Split(trustedDetectors, ","))
	ingest.ConfigureEventTrust(detectors)
	lossObservers := ingest.NewTrustedDetectors(strings.Split(trustedLossObservers, ","))
	ingest.ConfigureCompletedDisclosureTrust(lossObservers)
	actuator.ConfigureAdapterDetectorIdentities(detectors.List())
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	if detectors.Empty() {
		setupLog.Info("WARNING: no trusted detector identities configured — every external SecurityEvent is ingested as untrusted and supplies NO belief evidence (M-94 fail-closed). Set --trusted-detectors / phorvex.trustedDetectors.")
	} else {
		// The allowlist is configuration, not enforcement: a stamped identity is only a FACT
		// when the cluster also runs the creator-identity ValidatingAdmissionPolicy + Deny
		// binding the chart ships. This process cannot observe that from its own flags.
		setupLog.Info("SecurityEvent detector allowlist configured (M-94); trusting a stamp additionally requires the creator-identity ValidatingAdmissionPolicy + binding to be installed in the cluster",
			"trustedDetectors", detectors.List())
	}
	if (lossHistoryDir == "") != lossObservers.Empty() {
		setupLog.Error(fmt.Errorf("loss-history-dir and trusted-loss-observers must be configured together"), "invalid completed-disclosure configuration")
		os.Exit(2)
	}
	if err := cost.ConfigureGPUEnvelopeMax(gpuEnvelopeMax); err != nil {
		setupLog.Error(err, "invalid GPU warm-up calibration")
		os.Exit(2)
	}
	if supportDebounce < 1 {
		setupLog.Error(fmt.Errorf("must be at least 1"), "invalid actions-supported-debounce", "value", supportDebounce)
		os.Exit(2)
	}
	if maxRetainedQuarantines < 0 || maxRetainedQuarantines > actuator.MaxRetainedQuarantinesUpperBound {
		setupLog.Error(fmt.Errorf("must be in [0,%d]", actuator.MaxRetainedQuarantinesUpperBound), "invalid max-retained-quarantines-per-namespace", "value", maxRetainedQuarantines)
		os.Exit(2)
	}
	if calibrationShadow && (calibrationRefresh <= 0 || calibrationSample <= 0 || calibrationLookback <= 0 || calibrationSample > calibrationRefresh) {
		setupLog.Error(fmt.Errorf("durations must be positive and sample must not exceed refresh"), "invalid calibration cadence",
			"sample", calibrationSample, "refresh", calibrationRefresh, "lookback", calibrationLookback)
		os.Exit(2)
	}
	// [M-21 R1-1] Resolve PHORVEX_ACTUATOR HERE: after flag parsing, before ANY entrypoint
	// below can dispatch. Every branch that follows — epss-feed, integration-emit, ablation,
	// native-demo, scan and the controller — is an action entrypoint, and several of them
	// construct an actuator directly or reach the cluster without going through the runner's
	// checked constructor. Validating only inside that constructor left those paths able to
	// run, and mutate, on a selector that names no backend. One resolution, at the top,
	// closes all of them at once and is the only read of the variable in this process.
	backend, backendErr := actuator.ResolveBackendFromEnv()
	if backendErr != nil {
		setupLog.Error(backendErr, "invalid actuator configuration; refusing to run")
		os.Exit(2)
	}
	// Logged HERE, not only where an actuator is constructed: --integration-emit and
	// --native-demo drive a fixed backend and build no runner, so this is the only point
	// at which every entrypoint reports what was configured and where it came from.
	setupLog.Info("actuator configuration resolved",
		"actuator", string(backend.Backend), "source", backend.Origin())
	adapterSources, sourceErr := actuator.LoadAdapterSourcesFile(loraCleanSourcesFile)
	if sourceErr != nil {
		setupLog.Error(sourceErr, "invalid adapter reload source configuration; refusing to start")
		os.Exit(2)
	}
	migProfiles, migProfilesErr := actuator.LoadMIGProfilesFile(migProfilesFile)
	if migProfilesErr != nil {
		setupLog.Error(migProfilesErr, "invalid MIG profile authority configuration; refusing to start")
		os.Exit(2)
	}
	securityMode, securityModeErr := actuator.ParseServingSecurityMode(servingSecurityMode)
	if securityModeErr != nil {
		setupLog.Error(securityModeErr, "invalid serving security mode; refusing to start")
		os.Exit(2)
	}
	servingSecurity, servingSecurityErr := actuator.LoadServingSecurityFile(servingSecurityFile, securityMode, operatorNS)
	if servingSecurityErr != nil {
		setupLog.Error(servingSecurityErr, "invalid serving security configuration; refusing to start")
		os.Exit(2)
	}
	setupLog.Info("serving control security configured", "mode", securityMode, "bindings", len(servingSecurity.Bindings))

	if epssFeed {
		if err := runEPSSFeed(epssFeedApply, epssFeedPartial, epssFeedNS, epssFeedCM, epssFeedKey, epssFeedFIRSTURL, epssFeedTrivy, epssFeedTimeout); err != nil {
			setupLog.Error(err, "epss-feed failed; last-known-good cache was not changed")
			os.Exit(1)
		}
		return
	}

	// Seed the exploitability (EPSS/CVSS) cache from the scanner export, if wired. This makes the
	// EPSS physics leg data-driven for BOTH the --scan path and the live operator loop; a missing/empty
	// path leaves EPSS honest-absent (1.0). One package-level cache, seeded once at startup.
	if err := platform.LoadEPSSFromFile(epssCachePath); err != nil {
		setupLog.Error(err, "epss-cache load failed (continuing with EPSS honest-absent)", "path", epssCachePath)
	} else if n := platform.EPSSLoaded(); n > 0 {
		setupLog.Info("epss: exploitability cache seeded", "images", n, "path", epssCachePath)
	}

	if integrationEmit {
		if err := runIntegrationEmit(emitTenant, emitNamespace, emitPod, emitAction, emitMatchLabels); err != nil {
			setupLog.Error(err, "integration-emit failed")
			os.Exit(1)
		}
		return
	}

	if ablation {
		if err := runAblation(ablationNS, ablationSelector, ablationBudget, ablationSeeds, backend); err != nil {
			setupLog.Error(err, "ablation failed")
			os.Exit(1)
		}
		return
	}

	if nativeDemo {
		if err := runNativeActuatorDemo(nativeDemoNS, operatorNS); err != nil {
			setupLog.Error(err, "native-demo failed")
			os.Exit(1)
		}
		return
	}

	if scan {
		if err := runScan(scanNS, promURL, kubeContext, backend); err != nil {
			setupLog.Error(err, "scan failed")
			os.Exit(1)
		}
		return
	}

	managerOptions := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeader,
		LeaderElectionID:       "phorvex.phorvex.ai",
	}
	if admissionWebhook {
		managerOptions.WebhookServer = webhook.NewServer(webhook.Options{Port: webhookPort, CertDir: webhookCertDir})
	}
	restConfig := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(restConfig, managerOptions)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	cs, csErr := kubernetes.NewForConfig(restConfig)
	var bootReviews startupauthz.SSARClient
	if csErr == nil {
		bootReviews = cs.AuthorizationV1().SelfSubjectAccessReviews()
	}
	bootConfig := startupauthz.Config{
		Backend: backend.Backend, OperatorNamespace: operatorNS,
		ServingSecurity: servingSecurity,
	}
	if migNodeExec {
		bootConfig.MIGAgent = &startupauthz.MIGAgentAccess{Namespace: migAgentNamespace, DaemonSet: migAgentDaemonSet}
	}
	bootReport, bootErr := startupauthz.Check(context.Background(), mgr.GetAPIReader(), bootReviews, bootConfig)
	if bootErr != nil {
		setupLog.Error(bootErr, "startup authorization preflight failed; refusing to start")
		os.Exit(1)
	}
	setupLog.Info("startup authorization preflight passed",
		"policies", bootReport.Policies, "activePolicies", bootReport.ActivePolicies,
		"dryRunPolicies", bootReport.DryRunPolicies, "namespaces", bootReport.Namespaces,
		"requirements", bootReport.Requirements, "noPolicies", bootReport.NoPolicies)

	// [M-21] Resolve the actuator BEFORE anything is registered or started. An explicit
	// PHORVEX_ACTUATOR that names no backend is fatal here, so the operator never begins
	// reconciling — let alone mutating — on a backend it silently substituted.
	rmgr, err := runner.NewManagerWithBackend(mgr.GetClient(), ctrl.Log, backend)
	if err != nil {
		setupLog.Error(err, "cannot construct the resolved actuator; refusing to start")
		os.Exit(1)
	}
	quarantineCapacity, capacityErr := actuator.NewQuarantineCapacity(mgr.GetClient(), mgr.GetAPIReader(), operatorNS, maxRetainedQuarantines)
	if capacityErr != nil {
		setupLog.Error(capacityErr, "quarantine capacity guard unavailable; refusing to start")
		os.Exit(1)
	}
	rmgr.QuarantineCapacity = quarantineCapacity
	rmgr.OwnershipReader = mgr.GetAPIReader()
	rmgr.VocabularyReader = mgr.GetAPIReader()
	if native, ok := rmgr.Actuator.(*actuator.NativeActuator); ok {
		native.SetBoundaryReader(mgr.GetAPIReader())
		native.JournalNamespace = operatorNS
		native.SetAdapterSources(adapterSources)
		native.SetMIGProfiles(migProfiles)
		native.SetServingSecurity(servingSecurity)
	}
	if hybrid, ok := rmgr.Actuator.(*actuator.HybridActuator); ok {
		hybrid.ConfigureNativeJournal(mgr.GetAPIReader(), operatorNS)
		hybrid.SetAdapterSources(adapterSources)
		hybrid.SetMIGProfiles(migProfiles)
		hybrid.SetServingSecurity(servingSecurity)
	}
	rmgr.BoundaryReader = mgr.GetAPIReader()
	rmgr.LossHistoryReader = mgr.GetAPIReader()
	if lossHistoryDir != "" {
		lossStore, storeErr := losshistory.New(lossHistoryDir)
		if storeErr != nil {
			// M100 history is optional reporting evidence. Its failure is explicit,
			// but cannot disable otherwise authorized defensive actuation.
			setupLog.Error(storeErr, "loss history store unavailable; retained disclosure history disabled")
		} else {
			rmgr.LossHistory = lossStore
			setupLog.Info("synthetic completed-disclosure history enabled", "history", lossStore.String(), "trustedLossObservers", lossObservers.List())
		}
	}
	rmgr.BaseInterval = baseInterval
	rmgr.ActionsSupportedDebounce = supportDebounce
	rmgr.Recorder = mgr.GetEventRecorderFor("phorvex-actions-supported")
	rmgr.ActuationRecorder = mgr.GetEventRecorderFor("phorvex-actuation")
	// T1-E: wire the SSAR capability checker so the gate's no-rbac leg is live. A
	// failure here leaves rmgr.Authz nil — the gate then still enforces installability,
	// cover and runtime capability, just not RBAC (never a silent actuation of an
	// unpermitted action: the actuation itself still fails closed on real RBAC).
	if csErr == nil {
		rmgr.Authz = authz.NewChecker(cs, authz.DefaultTTL)
	} else {
		setupLog.Error(csErr, "SSAR checker unavailable; capability-gate RBAC leg disabled")
	}
	if migNodeExec {
		if csErr != nil {
			setupLog.Error(csErr, "MIG node-exec enabled but clientset is unavailable; refusing to start")
			os.Exit(2)
		}
		serviceAccounts := strings.Split(migAgentServiceAccounts, ",")
		if err := actuator.WireRemoteNodeExec(actuator.RemoteExecConfig{Config: restConfig, Clientset: cs, Agent: actuator.MIGAgentPolicy{
			Namespace: migAgentNamespace, ServiceAccounts: serviceAccounts, DaemonSet: migAgentDaemonSet,
			Container: migAgentGPUContainer, AllocationContainer: migAgentHelperContainer,
			AllocationHelper: migAllocationHelper, AllocationSocket: migAllocationSocket,
			ExecTimeout: migExecTimeout, AllocationReadTimeout: migAllocationReadTimeout, AllocationReleaseTimeout: migReleaseTimeout, ExclusiveMaintenance: migExclusiveMaintenance,
		}}); err != nil {
			setupLog.Error(err, "invalid MIG node-exec configuration; refusing to start")
			os.Exit(2)
		}
		setupLog.Info("trusted MIG node-exec transport wired", "namespace", migAgentNamespace, "daemonSet", migAgentDaemonSet)
	}
	// M-6: the code-exec admission-capability verifier. It is ALWAYS wired (never nil at
	// runtime), starts UNAVAILABLE (fail-closed until the first successful verification), and
	// re-verifies every poll interval via GET-by-resourceName + SSAR (no watch). Registered as
	// a manager Runnable so its lifecycle tracks the operator process. If the clientset could
	// not be built, the verifier reads through an always-fail reader and stays unavailable, so
	// debugger/custom-inject are fail-closed out of BOTH the offer set and the dispatch path.
	var ceReader codeexec.PolicyReader
	if csErr == nil {
		ceReader = codeexec.NewK8sReader(cs)
	} else {
		ceReader = codeexec.NewUnavailableReader("cluster clientset unavailable at boot")
	}
	codeExecVerifier := codeexec.New(ceReader, codeexec.Config{})
	rmgr.CodeExec = codeExecVerifier
	if addErr := mgr.Add(ctrlmanager.RunnableFunc(func(ctx context.Context) error {
		codeExecVerifier.Run(ctx)
		return nil
	})); addErr != nil {
		setupLog.Error(addErr, "cannot register M-6 code-exec admission verifier loop; verifier stays unavailable (fail-closed)")
	}
	setupLog.Info("M-6 code-exec admission verifier wired (fail-closed until first successful verification)",
		"policy", codeexec.PolicyName, "version", codeexec.PolicyVersion,
		"deadline", codeexec.DefaultDeadline, "ttl", codeexec.DefaultTTL, "poll", codeexec.DefaultPoll)
	if calibrationShadow {
		rmgr.Calibration = calib.NewRuntime(calib.RuntimeConfig{
			RefreshInterval: calibrationRefresh, SampleInterval: calibrationSample,
			Lookback: calibrationLookback, ExportDir: calibrationExportDir,
		}, ctrl.Log)
		setupLog.Info("scale calibration shadow enabled", "sample", calibrationSample,
			"refresh", calibrationRefresh, "lookback", calibrationLookback, "exportDir", calibrationExportDir)
	} else {
		rmgr.Calibration = nil
		setupLog.Info("scale calibration shadow disabled")
	}
	optimizer, engErr := decision.SelectOptimizer(engineName)
	if engErr != nil {
		setupLog.Error(engErr, "refusing to start with an unsupported decision brain")
		os.Exit(1)
	}
	rmgr.Optimizer = optimizer
	setupLog.Info("decision brain", "engine", rmgr.Optimizer.Name())
	// Kill-switch dispatch admission must bypass the informer cache: every route,
	// selected dispatch, fallback and maintenance boundary reads current sentinel state.
	rmgr.KillSwitch = &runner.KillSwitch{Static: killSwitch, Client: mgr.GetAPIReader(), Namespace: operatorNS}

	// Telemetry source: real Prometheus client if a URL is set, else honest nil source.
	rmgr.PromURL = promURL         // also feeds the live-tick GPU-half physics witness (DCGM via Prometheus)
	rmgr.PCIeClasses = pcieClasses // M-114: PCIe capacity class fallback (chart value)
	if promURL != "" {
		rmgr.MetricsSource = ingest.NewPromHTTP(promURL, nil)
		setupLog.Info("telemetry: prometheus", "url", promURL)
	} else {
		setupLog.Info("telemetry: none (K8s-only signals; metrics not fabricated)")
	}

	// Optional JSON audit sink.
	if auditJSON != "" {
		// [P4b fix] size-capped rotation bounds the audit JSONL (was unbounded append).
		// 256 MiB x (4+1) backups = ~1.25 GiB max on disk; tune via the flags.
		f, ferr := audit.NewRotatingWriter(auditJSON, auditMaxBytes, auditMaxBackups)
		if ferr != nil {
			setupLog.Error(ferr, "cannot open audit-json; continuing with logger-only audit")
		} else {
			defer func() {
				if err := f.Close(); err != nil {
					setupLog.Error(err, "audit close failed")
				}
			}()
			logger := audit.New(ctrl.Log, f)
			parameterStore, parameterErr := audit.NewParameterMaterialStore(auditJSON)
			if parameterErr != nil {
				setupLog.Error(parameterErr, "parameter material store unavailable; decision rows will mark provenance retention unavailable")
			} else {
				logger.SetParameterMaterialStore(parameterStore)
			}
			rmgr.Audit = logger
			setupLog.Info("audit JSON sink", "path", auditJSON, "capBytes", auditMaxBytes, "backups", auditMaxBackups)
		}
	}
	if auditSourceAddr != "" {
		server, sourceErr := (audittransport.ServerConfig{Addr: auditSourceAddr, AuditPath: auditJSON, VClusterAuditPath: auditSourceVClusterPath,
			CertFile: auditSourceCert, KeyFile: auditSourceKey, CAFile: auditSourceCA,
			ClientDNSName: auditSourceClientDNS, MaxBackups: auditMaxBackups}).Start()
		if sourceErr != nil {
			setupLog.Error(sourceErr, "audit source unavailable; manager reconciliation continues and remote console audit reads fail closed")
		} else {
			defer server.Close()
		}
	}

	if err = (&controller.PhorvexPolicyReconciler{Client: mgr.GetClient(), Manager: rmgr}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PhorvexPolicy")
		os.Exit(1)
	}
	if admissionWebhook {
		if err = controller.SetupPhorvexPolicyWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create validating webhook", "webhook", "PhorvexPolicy")
			os.Exit(1)
		}
		if err = controller.SetupSecurityEventWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create mutating webhook", "webhook", "SecurityEvent")
			os.Exit(1)
		}
		setupLog.Info("PhorvexPolicy validating admission webhook enabled", "port", webhookPort, "certDir", webhookCertDir)
		setupLog.Info("SecurityEvent creator-identity stamp enabled (M-94); the stamp is written here, but only the cluster's creator-identity admission policy makes a stamp unforgeable while this endpoint is down",
			"path", "/stamp-amtd-r6security-com-v1beta1-securityevent")
	}
	if err = mgr.Add(rmgr); err != nil {
		setupLog.Error(err, "unable to add the phorvex tick loop")
		os.Exit(1)
	}

	// Re-read the exploitability cache while running. Off by default: with a hand-curated
	// ConfigMap there is nothing to observe, and a startup-only read is the honest description
	// of that. It is turned on where a scanner pipeline owns the file (PHVX-14b).
	if epssCachePath != "" && epssCacheRefresh > 0 {
		refresher := &platform.EPSSRefresher{
			Path:     epssCachePath,
			Interval: epssCacheRefresh,
			OnReload: func(entries int, changed bool) {
				if changed {
					setupLog.Info("epss: exploitability cache reloaded", "images", entries, "path", epssCachePath)
				}
			},
			OnError: func(err error) {
				setupLog.Error(err, "epss-cache refresh failed (previous cache kept in force)", "path", epssCachePath)
			},
		}
		if err = mgr.Add(refresher); err != nil {
			setupLog.Error(err, "unable to add the epss cache refresher")
			os.Exit(1)
		}
		setupLog.Info("epss: cache refresh enabled", "interval", epssCacheRefresh, "path", epssCachePath)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}
	if admissionWebhook {
		if err := mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
			setupLog.Error(err, "unable to set up webhook ready check")
			os.Exit(1)
		}
	}

	setupLog.Info("starting phorvex", "baseInterval", baseInterval.String())
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func runEPSSFeed(apply, allowPartial bool, namespace, configMapName, configMapKey, firstURL, trivyPath string, scanTimeout time.Duration) error {
	if namespace == "" {
		return fmt.Errorf("epss-feed-namespace is required (set POD_NAMESPACE in-cluster)")
	}
	clientset, err := kubernetes.NewForConfig(ctrl.GetConfigOrDie())
	if err != nil {
		return err
	}
	result, err := epssfeed.Run(ctrl.SetupSignalHandler(), epssfeed.Options{
		Client: clientset,
		Scanner: epssfeed.TrivyScanner{
			Path: trivyPath, CacheDir: "/tmp/trivy", Timeout: scanTimeout,
		},
		EPSS:      epssfeed.FIRSTClient{BaseURL: firstURL},
		Namespace: namespace, ConfigMapName: configMapName, ConfigMapKey: configMapKey,
		Apply: apply, AllowPartial: allowPartial,
		Progress: func(image string, done, total int) {
			if image == "" {
				setupLog.Info("epss-feed: image scans complete", "completed", done, "total", total)
				return
			}
			setupLog.Info("epss-feed: scanning image", "image", image, "completed", done, "total", total)
		},
	})
	if result.Mode != "" {
		if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
			return encodeErr
		}
	}
	return err
}

// runIntegrationEmit proves Seam 1 without the full operator: it ensures the tenant
// AMTD and emits one controlled SecurityEvent for the target pod, then prints what
// it created so an operator can confirm Phoenix consumes it.
func runIntegrationEmit(tenant, namespace, pod, action, matchLabels string) error {
	if namespace == "" || pod == "" {
		return fmt.Errorf("emit-namespace and emit-pod are required")
	}
	if tenant == "" {
		tenant = namespace
	}
	act := model.Action(action)
	if act != model.ActionRotate && act != model.ActionQuarantine {
		return fmt.Errorf("emit-action must be rotate or quarantine, got %q", action)
	}
	ml := parseMatchLabels(matchLabels)
	if len(ml) == 0 {
		return fmt.Errorf("emit-matchlabels is required (the AMTD guest list), e.g. app=demo")
	}

	c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	ph := actuator.NewPhoenixActuator(c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if observation := actuationbrake.ObserveNamespace(ctx, c, actuationbrake.DefaultReadTimeout, namespace); observation.Engaged {
		return fmt.Errorf("namespace actuation brake: %s", observation.Cause)
	}
	podObservation, targetUID := actuationbrake.ObservePodIdentity(ctx, c, actuationbrake.DefaultReadTimeout, namespace, pod, "")
	if podObservation.Engaged {
		return fmt.Errorf("Pod actuation brake: %s", podObservation.Cause)
	}

	if err := ph.EnsurePolicy(ctx, actuator.TenantTarget{
		Tenant:      tenant,
		Namespace:   namespace,
		MatchLabels: ml,
		EnabledActions: map[model.Action]bool{
			model.ActionRotate:     true,
			model.ActionQuarantine: true,
		},
	}); err != nil {
		return fmt.Errorf("ensure AMTD: %w", err)
	}
	if observation := actuationbrake.ObserveNamespace(ctx, c, actuationbrake.DefaultReadTimeout, namespace); observation.Engaged {
		return fmt.Errorf("namespace actuation brake before dispatch: %s", observation.Cause)
	}
	if observation := actuationbrake.ObservePod(ctx, c, actuationbrake.DefaultReadTimeout, namespace, pod, targetUID); observation.Engaged {
		return fmt.Errorf("Pod actuation brake before dispatch: %s", observation.Cause)
	}
	res, err := ph.Actuate(ctx, actuator.Request{
		Tenant:    tenant,
		Namespace: namespace,
		Pod:       pod,
		TargetUID: targetUID,
		Action:    act,
		Reason:    "phorvex P0 Seam-1 integration proof",
		Score:     0.99,
	})
	if err != nil {
		return fmt.Errorf("emit SecurityEvent: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	setupLog.Info("Seam-1 emit complete", "amtd", res.AMTDName, "securityEvent", res.EventName, "rule", res.RuleType+"/"+res.RuleThreatLevel+"/"+res.RuleSource)
	return nil
}

// runScan is the P-PHYSICS proof: scan the live cluster, derive the both-products
// PhysicsWitness per pod (K8s values live; AI/GPU hardware validation is tracked by
// PHORVEXSEC-87 until a DCGM
// adapter answers), and run the separately-ablated scarcity A/B. Read-only.
func runScan(namespace, promURL, kubeContext string, backend actuator.BackendResolution) error {
	// Honor an explicit kubeconfig context (DERIVED by the console from the operator's
	// kubeconfig — never hardcoded); empty => current-context. EKS auth is the exec-credential
	// kubeconfig (zero AWS SDK linked).
	restCfg, err := ctrlconfig.GetConfigWithContext(kubeContext)
	if err != nil {
		return err
	}
	c, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	snap, err := ingest.CollectSnapshot(ctx, c, time.Now(), nil)
	if err != nil {
		return err
	}
	// Live GPU half: when a Prometheus/dcgm-exporter feed is configured, stamp the per-pod
	// VRAM/SM/PCIe witness so the GPU adapter can consume measured values.
	gpuIngestErr := ingest.PopulateGPUWitness(ctx, snap, promURL, pcieClasses)
	platformName, phys := platform.Derive(snap)
	fmt.Printf("=== P-PHYSICS live scan ===\nplatform-adapter: %s\nnodes: %d   pods: %d   PDBs: %d\n",
		platformName, len(snap.Nodes), len(snap.Pods), len(snap.PDBs))
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		fmt.Printf("  node %-28s allocCPU=%dm allocMem=%dMi allocGPU=%d migKinds=%d\n",
			n.Name, n.AllocatableCPUMilli, n.AllocatableMemBytes/(1024*1024), n.AllocatableGPU, len(n.MIGResources))
	}
	gpuPresent := false
	shown := 0
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if namespace != "" && p.Namespace != namespace {
			continue
		}
		w := phys[p.Namespace+"/"+p.Name]
		ai := "AI:unmeasured (no GPU/DCGM scan; PHORVEXSEC-87)"
		if w.GPUPresent {
			gpuPresent = true
			ai = fmt.Sprintf("AI: VRAMfrac=%.2f SM=%.2f link=%.2f modelRarity=%.2f SMsource=%s linkSource=%s", w.VRAMFraction, w.SMOccupancy, w.LinkBandwidth, w.ModelRarity, w.SMSource, w.LinkSource)
		}
		fmt.Printf("  %-34s K8s: imgRarity=%.2f coRes=%.2f slack=%.2f pdbMinAvail=%d migValid=%v epss=%.2f stateful=%v | %s\n",
			p.Namespace+"/"+p.Name, w.ImageRarity, w.CoResidency, w.SchedulerSlack, w.PDBMinAvailable, w.MIGGeometryValid, w.EPSSMultiplier, p.Stateful, ai)
		shown++
	}
	gpuNote := "unmeasured (no GPU/DCGM feed; PHORVEXSEC-87)"
	if gpuPresent {
		gpuNote = "live GPU/AI physics from DCGM"
	}
	fmt.Printf("(%d pods shown; GPU/AI values measured: %v — %s)\n", shown, gpuPresent, gpuNote)
	if gpuIngestErr != nil {
		fmt.Printf("GPU/DCGM ingest warning (partial data kept, unavailable signals remain honest-absent): %v\n", gpuIngestErr)
	}

	// P-GRAPH: emit the live reachability graph (nodes + directed edges) the console renders in
	// the Discovered blast-radius map. The edges are the three real lateral paths (NetworkPolicy
	// + RBAC + co-location); blast = the normalized blast-radius score. This is the wiring the
	// dashboard's [PENDING-wire] note referred to — now live from the same snapshot graph.
	if snap.Graph != nil {
		fmt.Printf("\n=== P-GRAPH reachability (nodes + edges: network + RBAC + co-location) ===\n")
		for i := range snap.Pods {
			p := &snap.Pods[i]
			if namespace != "" && p.Namespace != namespace {
				continue
			}
			key := p.Namespace + "/" + p.Name
			ai := 0
			if phys[key].GPUPresent {
				ai = 1
			}
			fmt.Printf("  NODE %s blast=%.3f ai=%d\n", key, snap.Graph.BlastRadius(p.Namespace, p.Name), ai)
			for _, nb := range snap.Graph.Neighbors(p.Namespace, p.Name) {
				fmt.Printf("  EDGE %s -> %s\n", key, nb)
			}
		}
	}

	if namespace != "" {
		// [M-21] Same fail-fast on the one-shot path: a scan reports what the CONFIGURED
		// backend would do, so an unresolvable selector must stop it rather than have it
		// silently report the default backend's answers.
		rmgr, mErr := runner.NewManagerWithBackend(c, ctrl.Log, backend)
		if mErr != nil {
			return mErr
		}
		if n, ok := rmgr.Actuator.(*actuator.NativeActuator); ok {
			n.SetBoundaryReader(c)
		}
		rmgr.PromURL = promURL // the fresh context/ablation snapshots must receive the same DCGM witness
		rmgr.PCIeClasses = pcieClasses

		// P4a: wire live telemetry (no longer telemetry-blind). The operator-supplied
		// --prometheus-url feeds cost/continuity/feasibility/context (the platform K8s-half
		// PhysicsWitness is telemetry-INDEPENDENT by design). Empty => honest nil source.
		if promURL != "" {
			rmgr.MetricsSource = ingest.NewPromHTTP(promURL, nil)
			names := make([]string, 0, len(snap.Pods))
			for i := range snap.Pods {
				if snap.Pods[i].Namespace == namespace {
					names = append(names, snap.Pods[i].Name)
				}
			}
			if tel, terr := rmgr.MetricsSource.PodMetrics(ctx, namespace, names); terr == nil {
				fmt.Printf("\n=== live telemetry (Prometheus: %s) — feeds cost/continuity/feasibility/context ===\n", promURL)
				any := false
				for _, n := range names {
					t, ok := tel[n]
					if !ok {
						continue
					}
					any = true
					fmt.Printf("  %-34s reqRate=%.2f p99Ms=%.1f gpuUtil=%.2f tokensPerSec=%.1f connCount=%.0f\n",
						namespace+"/"+n, t.ReqRate.Value, t.P99Ms.Value, t.GPUUtil.Value, t.TokensPerSec.Value, t.ConnCount.Value)
				}
				if !any {
					fmt.Printf("  (no pod reported telemetry — honest-absent; per-signal State=Absent, never fabricated)\n")
				}
			}
		}

		// P-CONTEXT: live kill-chain context (AI-stage classification + predictive horizon).
		rows, cerr := rmgr.ContextScan(ctx, namespace, labels.Everything())
		if cerr != nil {
			return cerr
		}
		fmt.Printf("\n=== P-CONTEXT live kill-chain (stage + moved-before-next-stage horizon) ===\n")
		for _, r := range rows {
			tag := "generic"
			if r.AIClassified {
				tag = "**AI**"
			}
			fmt.Printf("  %-34s stage=%-20s [%s] PHold=%.2f PreemptMargin=%.2f ProjNextStage=%.0fs infectionFrontier=%.1f\n",
				r.Pod, r.Stage, tag, r.PHold, r.PreemptMargin, r.ProjectedNextStageSec, r.InfectionFrontier)
		}

		seeds := make([]int64, 40)
		for i := range seeds {
			seeds[i] = int64(i + 1)
		}
		ab, pname, aerr := rmgr.AblateScarcity(ctx, namespace, labels.Everything(), seeds, 2)
		if aerr != nil {
			return aerr
		}
		fmt.Printf("\n=== Layer-C EMR scarcity ablation (separately ablated; platform=%s) ===\n", pname)
		fmt.Printf("baseline (standard-recon)  per-dollar ratio = %.3f\n", ab.Baseline.Ratio)
		fmt.Printf("scarcity (ucw-recon)       per-dollar ratio = %.3f\n", ab.Scarcity.Ratio)
		fmt.Printf("scarcity lift              = %.3fx  %s\n", ab.ScarcityLift, scarcityVerdict(ab.ScarcityLift))
	}
	return nil
}

func scarcityVerdict(lift float64) string {
	switch {
	case lift > 1.0001:
		return "(BEAT: heavy-tailed measured dispersion the greedy exploits)"
	case lift > 0.9999:
		return "(TIE: uniform fleet -> exact baseline, never regressed)"
	default:
		return "(below baseline: fleet dispersion not heavy-tailed enough to help; needs a crown-jewel tail / real GPU-multi-tenant data)"
	}
}

// runAblation runs the STEP-3 IP ablation live and prints the per-dollar comparison.
func runAblation(namespace, selector string, budget, nseeds int, backend actuator.BackendResolution) error {
	if namespace == "" {
		return fmt.Errorf("ablation-namespace is required")
	}
	sel := labels.Everything()
	if selector != "" {
		s, err := labels.Parse(selector)
		if err != nil {
			return fmt.Errorf("invalid ablation-selector: %w", err)
		}
		sel = s
	}
	c, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	rmgr, err := runner.NewManagerWithBackend(c, ctrl.Log, backend)
	if err != nil {
		return err
	}
	if n, ok := rmgr.Actuator.(*actuator.NativeActuator); ok {
		n.SetBoundaryReader(c)
	}
	if nseeds <= 0 {
		nseeds = 40
	}
	seeds := make([]int64, nseeds)
	for i := range seeds {
		seeds[i] = int64(i + 1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := rmgr.Ablate(ctx, namespace, sel, seeds, budget)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	verdict := "FAIL (P1 did NOT beat random per-dollar)"
	if res.Ratio > 1.0 {
		verdict = "PASS (P1 invalidates more recon per dollar than random)"
	}
	setupLog.Info("ablation verdict", "ratio", res.Ratio, "verdict", verdict)
	return nil
}

func parseMatchLabels(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return out
}
