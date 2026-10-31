/*
 * Phorvex Console (P-DASHBOARD) — the data-layer backend, and the attacks service.
 *
 * Run serves the console binary (cmd/console) and the attacks binary (cmd/attacks), which
 * share one configuration (ADR-0001, phase 6). With --attacks-url the console forwards attack
 * firing, the harness runs and their evidence to the attacks service; without it, it serves
 * them itself, as before.
 *
 * An HTTP API over the Phorvex reports/metrics/audit plus the operator controls, and the built
 * dashboard served from the same port. Every API route sits behind a verified identity.
 *
 * [M-136] There is no demo-trust mode. The console REFUSES TO START without at least one
 * configured credential path, and a broken auth configuration is a startup error rather than a
 * warning. The previous build did the opposite: an unset PHORVEX_OIDC_ISSUER, or an IdP that
 * failed to load, logged "staying demo-trust" and served an internet-facing control plane whose
 * identity was whatever the request asserted.
 *
 * Configuration (see docs/CONSOLE-AUTH.md):
 *
 *   ALB Cognito browser path (what console.phorvex.ai actually uses)
 *     PHORVEX_CONSOLE_ALB_SIGNER_ARN   the exact load-balancer ARN whose signature is trusted
 *     PHORVEX_CONSOLE_ALB_ISSUER       the Cognito user-pool issuer URL
 *     PHORVEX_CONSOLE_ALB_CLIENT_ID    the user-pool app-client id
 *     PHORVEX_CONSOLE_ALB_REGION       optional; defaults to the region inside the signer ARN
 *
 *   Bearer OIDC path (CLI / automation)
 *     PHORVEX_CONSOLE_OIDC_ISSUER      exact token issuer
 *     PHORVEX_CONSOLE_OIDC_AUDIENCE    exact required audience
 *     PHORVEX_CONSOLE_OIDC_JWKS_URL    https JWKS URL
 *     PHORVEX_CONSOLE_OIDC_ALGS        optional comma list; default RS256
 *
 *   Authorization and browser boundary
 *     PHORVEX_CONSOLE_GRANTS           path to the subject grant table (JSON)
 *     PHORVEX_CONSOLE_TRUSTED_ORIGINS  comma list of exact browser origins
 */

// Package consoleserver runs the console and attacks services.
package consoleserver

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/cataloguev1"
	"github.com/phorvex/phorvex/internal/console"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/identityfixture"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"phorvex.ai/libs/logging"
)

const (
	historyMaxBytesEnv = "PHORVEX_CONSOLE_HISTORY_MAX_BYTES"
	historyMinFreeEnv  = "PHORVEX_CONSOLE_HISTORY_MIN_FREE_BYTES"
)

func historyCapacityDefaults(lookup func(string) (string, bool)) (int64, int64, error) {
	read := func(name string, fallback int64) (int64, error) {
		raw, ok := lookup(name)
		if !ok {
			return fallback, nil
		}
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value <= 0 || raw != strconv.FormatInt(value, 10) {
			return 0, fmt.Errorf("%s must be a positive canonical decimal integer", name)
		}
		return value, nil
	}
	maximum, err := read(historyMaxBytesEnv, console.DefaultHistoryArchiveMaxBytes)
	if err != nil {
		return 0, 0, err
	}
	minimumFree, err := read(historyMinFreeEnv, console.DefaultHistoryMinFreeBytes)
	if err != nil {
		return 0, 0, err
	}
	return maximum, minimumFree, nil
}

// Run serves binary, console.ServiceConsole or console.ServiceAttacks, until a
// signal, and returns the exit code.
func Run(binary console.Service) int {
	// Install defaults first so configuration refusals before flag parsing are
	// structured too; the flags below may then change level and format.
	logOptions := logging.Options{Service: "phorvex-" + string(binary), Version: console.BuildStamp}
	if err := setLogger(logOptions); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	historyMaxDefault, historyMinFreeDefault, err := historyCapacityDefaults(os.LookupEnv)
	if err != nil {
		slog.Error("console history capacity configuration invalid", "err", err)
		return 2
	}
	var (
		root                 string
		addr                 string
		auditPath            string
		stateDir             string
		web                  string
		metricsAllow         string
		grantsPath           string
		origins              string
		auditSourceURL       string
		auditServerDNS       string
		auditClientCert      string
		auditClientKey       string
		auditSourceCA        string
		historyMaxBytes      int64
		historyMinFree       int64
		catalogueV1Job       string
		catalogueV1Reconcile string
		catalogueV1Runtime   string
		injectorIdentity     string
		attacksURL           string
		printVersion         bool
	)
	flag.BoolVar(&printVersion, "version", false, "Print the release version and exact Git SHA, then exit.")
	flag.StringVar(&root, "root", "", "Phorvex root dir (holds phorvex/ + build/test-harness/). Default: walk up from CWD.")
	flag.StringVar(&addr, "addr", ":8090", "HTTP listen address.")
	flag.StringVar(&auditPath, "audit-json", "", "Optional explicit decision-audit JSONL for the owner view.")
	flag.StringVar(&stateDir, "state-dir", "", "Writable console-owned durable state directory (independent of the decision audit).")
	flag.Int64Var(&historyMaxBytes, "history-max-bytes", historyMaxDefault, "Maximum durable audit-history database size before imports pause.")
	flag.Int64Var(&historyMinFree, "history-min-free-bytes", historyMinFreeDefault, "Minimum free bytes retained on the console state filesystem before imports pause.")
	flag.StringVar(&auditSourceURL, "audit-source-url", "", "Optional mTLS manager audit source HTTPS origin.")
	flag.StringVar(&auditServerDNS, "audit-source-server-dns", "", "[audit-source-url] exact server certificate DNS SAN.")
	flag.StringVar(&auditClientCert, "audit-source-client-cert", "", "[audit-source-url] client leaf certificate file.")
	flag.StringVar(&auditClientKey, "audit-source-client-key", "", "[audit-source-url] client private key file.")
	flag.StringVar(&auditSourceCA, "audit-source-ca", "", "[audit-source-url] trusted server CA file.")
	flag.StringVar(&web, "web", "", "Static SPA dir (default <root>/dashboard-web/out).")
	flag.StringVar(&metricsAllow, "metrics-allow", "", "Comma-separated host[:port] allowlist for /api/metrics?url= SSRF guard (loopback always allowed; metadata/link-local always blocked).")
	flag.StringVar(&grantsPath, "auth-grants", "", "Path to the subject grant table (JSON). Overrides PHORVEX_CONSOLE_GRANTS.")
	flag.StringVar(&origins, "trusted-origins", "", "Comma-separated exact browser origins allowed to drive the console. Overrides PHORVEX_CONSOLE_TRUSTED_ORIGINS.")
	flag.StringVar(&catalogueV1Job, "catalogue-v1-job", "", "Internal: execute one private fixed-suite job.")
	flag.StringVar(&catalogueV1Reconcile, "catalogue-v1-reconcile", "", "Internal: reconcile one interrupted fixed-suite job without replay.")
	flag.StringVar(&catalogueV1Runtime, "catalogue-v1-runtime", "", "Internal: private server-generated fixed-suite runtime file.")
	// The workload live arms create their SecurityEvents as this console; the sensor
	// and the actuator admit only this identity's (eventtrust.ConfigureInjector). The
	// fixed-suite workers inherit it through the environment.
	flag.StringVar(&injectorIdentity, "injector-identity", os.Getenv("PHORVEX_INJECTOR_IDENTITY"), "This console's ServiceAccount (namespace/name). Empty = "+eventtrust.DefaultInjector+".")
	if binary == console.ServiceConsole {
		flag.StringVar(&attacksURL, "attacks-url", os.Getenv("PHORVEX_CONSOLE_ATTACKS_URL"), "Origin of the attacks service the attack routes are forwarded to. Empty = serve them here.")
	}
	logging.RegisterFlags(flag.CommandLine, &logOptions)
	flag.Parse()
	if printVersion {
		if err := buildinfo.WriteVersion(os.Stdout, string(binary)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if err := setLogger(logOptions); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := eventtrust.ConfigureInjector(injectorIdentity); err != nil {
		slog.Error("injector identity invalid", "err", err)
		return 2
	}
	if catalogueV1Job != "" || catalogueV1Reconcile != "" {
		return runCatalogueV1Worker(catalogueV1Job, catalogueV1Reconcile, catalogueV1Runtime)
	}
	if historyMaxBytes <= 0 || historyMinFree <= 0 {
		fatal("console history capacity configuration invalid", "err", "history limits must be positive")
	}

	if root == "" {
		if wd, err := os.Getwd(); err == nil {
			root = guessRoot(wd)
		}
	}
	cfg := console.DefaultConfig(root)
	if stateDir != "" {
		cfg.StateDir = stateDir
	}
	if err := applyCatalogueV1Environment(&cfg, os.LookupEnv); err != nil {
		slog.Error("catalogue v1 configuration invalid", "err", err)
		return 2
	}
	cfg.HistoryArchiveMaxBytes = historyMaxBytes
	cfg.HistoryMinFreeBytes = historyMinFree
	if raw, present := os.LookupEnv("PHORVEX_CONSOLE_HISTORY_RETENTION_DAYS"); present {
		days, err := strconv.Atoi(raw)
		if err != nil || days < 0 || days > 3650 || raw != strconv.Itoa(days) {
			fatal("history retention days must be a canonical integer in 0..3650", "value", raw)
		}
		cfg.HistoryRetentionDays = days
	}
	cfg.Addr = addr
	cfg.Service, cfg.AttacksURL = serviceFor(binary, attacksURL), attacksURL
	// An environment beside another on one cluster reaps only its own SecurityEvents.
	cfg.SweepNamespaces = splitList(os.Getenv("PHORVEX_CONSOLE_SWEEP_NAMESPACES"))
	if err := cfg.ValidateService(); err != nil {
		fatal("service configuration invalid", "err", err)
	}
	if auditPath != "" {
		cfg.AuditPath = auditPath
	}
	if auditSourceURL != "" {
		client, err := audittransport.NewClient(audittransport.ClientConfig{URL: auditSourceURL, ServerDNSName: auditServerDNS, CertFile: auditClientCert, KeyFile: auditClientKey, CAFile: auditSourceCA})
		if err != nil {
			fatal("audit source configuration invalid", "err", err)
		}
		cfg.AuditSource = client
		cfg.AuditSourceIdentity = auditSourceURL + "|" + auditServerDNS
	}
	if web != "" {
		cfg.Web = web
	}
	if err := cfg.ValidateStateDir(); err != nil {
		fatal("console state storage unavailable", "err", err)
	}
	if err := cfg.ValidateHistoryCapacity(); err != nil {
		fatal("console history capacity configuration invalid", "err", err)
	}
	for _, h := range strings.Split(metricsAllow, ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.MetricsAllow = append(cfg.MetricsAllow, h)
		}
	}

	authCfg := console.AuthConfig{
		GrantsPath:     firstNonEmpty(grantsPath, os.Getenv("PHORVEX_CONSOLE_GRANTS")),
		TrustedOrigins: splitList(firstNonEmpty(origins, os.Getenv("PHORVEX_CONSOLE_TRUSTED_ORIGINS"))),
	}
	if arn := strings.TrimSpace(os.Getenv("PHORVEX_CONSOLE_ALB_SIGNER_ARN")); arn != "" {
		authCfg.ALB = &console.ALBConfig{
			SignerARN:            arn,
			AdditionalSignerARNs: splitList(os.Getenv("PHORVEX_CONSOLE_ALB_ADDITIONAL_SIGNER_ARNS")),
			Issuer:               os.Getenv("PHORVEX_CONSOLE_ALB_ISSUER"),
			ClientID:             os.Getenv("PHORVEX_CONSOLE_ALB_CLIENT_ID"),
			Region:               os.Getenv("PHORVEX_CONSOLE_ALB_REGION"),
		}
	}
	if iss := strings.TrimSpace(os.Getenv("PHORVEX_CONSOLE_OIDC_ISSUER")); iss != "" {
		authCfg.Bearer = &console.BearerConfig{
			Issuer:     iss,
			Audience:   os.Getenv("PHORVEX_CONSOLE_OIDC_AUDIENCE"),
			JWKSURL:    os.Getenv("PHORVEX_CONSOLE_OIDC_JWKS_URL"),
			Algorithms: splitList(os.Getenv("PHORVEX_CONSOLE_OIDC_ALGS")),
		}
	}
	// FAIL CLOSED. A missing or malformed identity configuration stops the process; it never
	// degrades into a console that serves cluster controls to whoever asks.
	auth, err := console.NewAuthenticator(authCfg)
	if err != nil {
		fatal("refusing to start without a valid identity configuration", "err", err,
			"hint", "configure the ALB signed identity (PHORVEX_CONSOLE_ALB_SIGNER_ARN / _ISSUER / _CLIENT_ID) "+
				"and/or a bearer IdP (PHORVEX_CONSOLE_OIDC_ISSUER / _AUDIENCE / _JWKS_URL); see docs/CONSOLE-AUTH.md")
	}

	url := "http://localhost" + addr
	_, statErr := os.Stat(filepath.Join(cfg.Web, "index.html"))
	hasWeb := statErr == nil
	if !hasWeb && cfg.Service != console.ServiceAttacks {
		slog.Warn("dashboard not built; serving the API only", "web", cfg.Web, "hint", "cd dashboard-web && npm run build")
	}
	grants := auth.GrantCount()
	if grants == 0 {
		// Visibly fail closed: the service runs, authenticates callers, and authorizes nobody
		// until DevOps supplies the bindings. Crash-looping the sidecar would take the operator
		// pod with it and hide the reason.
		slog.Warn("no subject grants configured; every authenticated caller is denied",
			"hint", "supply the subject grant table (-auth-grants / PHORVEX_CONSOLE_GRANTS) before rollout")
	}

	srv := console.NewServer(cfg)
	defer func() {
		if err := srv.Close(); err != nil {
			slog.Error("audit history close failed", "err", err)
		}
	}()
	srv.EnableAuth(auth)
	// The applier is nil => record-only until a deployment injects the per-namespace-SA CRD
	// patch (the UI labels this honestly).
	srv.EnableVCluster(console.NewTenantQuota(console.DefaultQuota()), console.NewApplyFixManager(nil, nil, nil))
	// P-UPTIME: background sampler records MEASURED service availability (K8s API) so /api/uptime can
	// show the real actuator impact on uptime. Read-only; no-ops if no cluster is reachable.
	if cfg.Service != console.ServiceAttacks {
		srv.StartUptimeSampler(context.Background())
	}
	// Reap fired red-team SecurityEvents after a TTL so an un-cleared attack cannot pin an app
	// to "under attack" forever (the state the dashboard was stuck in after heavy Fire-live use).
	// The process that fires them reaps them.
	if cfg.Service != console.ServiceConsole {
		srv.StartRedTeamSweeper(context.Background())
	}
	slog.Info(string(binary)+" started", "service", string(cfg.Service), "attacksURL", attacksURL,
		"addr", addr, "url", url, "root", root, "state", cfg.StateDir, "dashboard", hasWeb,
		"auth", strings.Join(auth.Modes(), "+"), "origins", originSummary(auth.TrustedOrigins()), "grants", grants,
		"applyFix", "record-only", "redTeamEventTTL", "5m")

	// Explicit server budgets. ReadHeaderTimeout bounds slow-header clients; WriteTimeout stays
	// zero because /api/live and /api/runs/stream are long-lived SSE streams that a write
	// deadline would sever mid-stream.
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.AuditGate(srv.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	stop, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.ListenAndServe() }()
	select {
	case <-stop.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("console shutdown failed", "err", err)
		}
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("console server stopped", "err", err)
			return 1
		}
	}
	return 0
}

func applyCatalogueV1Environment(cfg *console.Config, lookup func(string) (string, bool)) error {
	readBool := func(name string) (bool, error) {
		raw, ok := lookup(name)
		if !ok || raw == "" {
			return false, nil
		}
		if raw == "true" {
			return true, nil
		}
		if raw == "false" {
			return false, nil
		}
		return false, fmt.Errorf("%s must be true or false", name)
	}
	read := func(name string) string { value, _ := lookup(name); return strings.TrimSpace(value) }
	attackCatalogEnabled, err := readBool("PHORVEX_CONSOLE_ATTACK_CATALOG_ENABLED")
	if err != nil {
		return err
	}
	attackCatalogProfile := read("PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_PROFILE")
	attackCatalogTenant := read("PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_TENANT")
	attackCatalogAuthorizationTenant := read("PHORVEX_CONSOLE_ATTACK_CATALOG_AUTHORIZATION_TENANT")
	agentActionEnabled, err := readBool("PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTION_ENABLED")
	if err != nil {
		return err
	}
	agentActionImage := read("PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTION_IMAGE")
	agentManagerPrincipal := read("PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_MANAGER_PRINCIPAL")
	agentSensorPrincipal := read("PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_SENSOR_PRINCIPAL")
	agentActuatorPrincipal := read("PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTUATOR_PRINCIPAL")
	// Reactive k8s_cluster/infra remediation identities: the defender actuator the brain is
	// steered to (proven to hold the actuation verbs), and the dedicated delete-only cleanup
	// identity impersonated to undo actuator artifacts. Required when the launch adapter runs.
	catalogActuatorPrincipal := read("PHORVEX_CONSOLE_ATTACK_CATALOG_ACTUATOR_PRINCIPAL")
	catalogCleanupPrincipal := read("PHORVEX_CONSOLE_ATTACK_CATALOG_CLEANUP_PRINCIPAL")
	if attackCatalogTenant != "" && (!strings.HasPrefix(attackCatalogTenant, identityfixture.NamespacePrefix) || len(validation.IsDNS1123Label(attackCatalogTenant)) != 0) {
		return errors.New("PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_TENANT must name the fixed owned identity-fixture tenant")
	}
	if attackCatalogAuthorizationTenant != "" && len(validation.IsDNS1123Label(attackCatalogAuthorizationTenant)) != 0 {
		return errors.New("PHORVEX_CONSOLE_ATTACK_CATALOG_AUTHORIZATION_TENANT must name one exact environment tenant")
	}
	if attackCatalogEnabled && attackCatalogProfile != "/etc/phorvex-attack-catalog/identity-profile.json" {
		return errors.New("PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_PROFILE must be the fixed deployment path when enabled")
	}
	if attackCatalogEnabled && attackCatalogTenant == "" {
		return errors.New("PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_TENANT is required when the launch adapter is enabled")
	}
	if attackCatalogEnabled && attackCatalogAuthorizationTenant == "" {
		return errors.New("PHORVEX_CONSOLE_ATTACK_CATALOG_AUTHORIZATION_TENANT is required when the launch adapter is enabled")
	}
	if agentActionEnabled && !attackCatalogEnabled {
		return errors.New("PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTION_ENABLED requires the attack catalogue launch adapter")
	}
	if agentActionEnabled && !console.ValidAttackCatalogAgentActionImage(agentActionImage) {
		return errors.New("PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTION_IMAGE must be one repository@sha256 reference")
	}
	for name, principal := range map[string]string{
		"PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_MANAGER_PRINCIPAL":  agentManagerPrincipal,
		"PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_SENSOR_PRINCIPAL":   agentSensorPrincipal,
		"PHORVEX_CONSOLE_ATTACK_CATALOG_AGENT_ACTUATOR_PRINCIPAL": agentActuatorPrincipal,
	} {
		parts := strings.Split(principal, ":")
		if agentActionEnabled && (len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" ||
			len(validation.IsDNS1123Label(parts[2])) != 0 || len(validation.IsDNS1123Subdomain(parts[3])) != 0) {
			return fmt.Errorf("%s must be one exact in-cluster ServiceAccount principal", name)
		}
	}
	// The reactive k8s_cluster/infra remediation preflight proves actuation verbs against the
	// actuator identity and impersonates the cleanup identity; both are required wherever the
	// launch adapter actually runs (the attacks service), and must be exact SA principals.
	for name, principal := range map[string]string{
		"PHORVEX_CONSOLE_ATTACK_CATALOG_ACTUATOR_PRINCIPAL": catalogActuatorPrincipal,
		"PHORVEX_CONSOLE_ATTACK_CATALOG_CLEANUP_PRINCIPAL":  catalogCleanupPrincipal,
	} {
		if attackCatalogEnabled && principal == "" {
			return fmt.Errorf("%s is required when the attack catalogue launch adapter is enabled", name)
		}
		parts := strings.Split(principal, ":")
		if principal != "" && (len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" ||
			len(validation.IsDNS1123Label(parts[2])) != 0 || len(validation.IsDNS1123Subdomain(parts[3])) != 0) {
			return fmt.Errorf("%s must be one exact in-cluster ServiceAccount principal", name)
		}
	}
	if attackCatalogEnabled && catalogActuatorPrincipal == catalogCleanupPrincipal {
		return errors.New("PHORVEX_CONSOLE_ATTACK_CATALOG_CLEANUP_PRINCIPAL must be a dedicated delete-only identity, not the actuator")
	}
	cfg.AttackCatalogEnabled = attackCatalogEnabled
	cfg.AttackCatalogAuthorizationTenant = attackCatalogAuthorizationTenant
	cfg.AttackCatalogIdentityTenant = attackCatalogTenant
	cfg.AttackCatalogIdentityProfilePath = attackCatalogProfile
	cfg.AttackCatalogAgentActionEnabled = agentActionEnabled
	cfg.AttackCatalogAgentActionImage = agentActionImage
	cfg.AttackCatalogAgentManagerPrincipal = agentManagerPrincipal
	cfg.AttackCatalogAgentSensorPrincipal = agentSensorPrincipal
	cfg.AttackCatalogAgentActuatorPrincipal = agentActuatorPrincipal
	cfg.AttackCatalogActuatorPrincipal = catalogActuatorPrincipal
	cfg.AttackCatalogCleanupPrincipal = catalogCleanupPrincipal
	runPrometheusEvidenceEnabled, err := readBool("PHORVEX_CONSOLE_RUN_PROMETHEUS_EVIDENCE_ENABLED")
	if err != nil {
		return err
	}
	runPrometheusURL := read("PHORVEX_PROM_URL")
	runPrometheusEnvironment := read("PHORVEX_CONSOLE_RUN_PROMETHEUS_ENVIRONMENT")
	if runPrometheusEvidenceEnabled && !attackCatalogEnabled {
		return errors.New("PHORVEX_CONSOLE_RUN_PROMETHEUS_EVIDENCE_ENABLED requires the attack catalogue launch adapter")
	}
	if runPrometheusEvidenceEnabled && (runPrometheusURL == "" || runPrometheusEnvironment == "") {
		return errors.New("run Prometheus evidence requires PHORVEX_PROM_URL and PHORVEX_CONSOLE_RUN_PROMETHEUS_ENVIRONMENT")
	}
	cfg.RunPrometheusEvidence = console.PrometheusRunEvidenceConfig{
		Enabled: runPrometheusEvidenceEnabled, URL: runPrometheusURL, Environment: runPrometheusEnvironment,
	}
	if err := cfg.RunPrometheusEvidence.Validate(); err != nil {
		return err
	}
	enabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_V1_ENABLED")
	if err != nil {
		return err
	}
	voiceEnabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_ENABLED")
	if err != nil {
		return err
	}
	gpuEnabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_V1_GPU_ENABLED")
	if err != nil {
		return err
	}
	guardrailCalibrationEnabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_CALIBRATION_ENABLED")
	if err != nil {
		return err
	}
	mcpVoiceModelEnabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_MCP_VOICE_MODEL_ENABLED")
	if err != nil {
		return err
	}
	mcpEnabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_MCP_ENABLED")
	if err != nil {
		return err
	}
	mongoExposureEnabled, err := readBool("PHORVEX_CONSOLE_MONGO_EXPOSURE_ENABLED")
	if err != nil {
		return err
	}
	cfg.MongoExposureEnabled = mongoExposureEnabled
	mongoExposureProfileSHA256, _ := lookup("PHORVEX_CONSOLE_MONGO_EXPOSURE_PROFILE_SHA256")
	if mongoExposureEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(mongoExposureProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_MONGO_EXPOSURE_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.MongoExposureProfileSHA256 = mongoExposureProfileSHA256
	natsExposureEnabled, err := readBool("PHORVEX_CONSOLE_NATS_EXPOSURE_ENABLED")
	if err != nil {
		return err
	}
	cfg.NATSExposureEnabled = natsExposureEnabled
	natsExposureProfileSHA256, _ := lookup("PHORVEX_CONSOLE_NATS_EXPOSURE_PROFILE_SHA256")
	if natsExposureEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(natsExposureProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_NATS_EXPOSURE_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.NATSExposureProfileSHA256 = natsExposureProfileSHA256
	natsResponseEnabled, err := readBool("PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_ENABLED")
	if err != nil {
		return err
	}
	if natsResponseEnabled && !natsExposureEnabled {
		return errors.New("PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_ENABLED requires NATS exposure baseline")
	}
	cfg.NATSClientResponseEnabled = natsResponseEnabled
	natsResponseProfileSHA256, _ := lookup("PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_PROFILE_SHA256")
	if natsResponseEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(natsResponseProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.NATSClientResponseProfileSHA256 = natsResponseProfileSHA256
	guardrailStaticEnabled, err := readBool("PHORVEX_CONSOLE_GUARDRAIL_STATIC_ENABLED")
	if err != nil {
		return err
	}
	cfg.GuardrailStaticEnabled = guardrailStaticEnabled
	guardrailStaticProfileSHA256, _ := lookup("PHORVEX_CONSOLE_GUARDRAIL_STATIC_PROFILE_SHA256")
	if guardrailStaticEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(guardrailStaticProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_GUARDRAIL_STATIC_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.GuardrailStaticProfileSHA256 = guardrailStaticProfileSHA256
	guardrailAvailabilityEnabled, err := readBool("PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_ENABLED")
	if err != nil {
		return err
	}
	cfg.GuardrailAvailabilityEnabled = guardrailAvailabilityEnabled
	guardrailAvailabilityProfileSHA256, _ := lookup("PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_PROFILE_SHA256")
	if guardrailAvailabilityEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(guardrailAvailabilityProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.GuardrailAvailabilityProfileSHA256 = guardrailAvailabilityProfileSHA256
	guardrailEffectEnabled, err := readBool("PHORVEX_CONSOLE_GUARDRAIL_EFFECT_ENABLED")
	if err != nil {
		return err
	}
	cfg.GuardrailEffectEnabled = guardrailEffectEnabled
	guardrailEffectProfileSHA256, _ := lookup("PHORVEX_CONSOLE_GUARDRAIL_EFFECT_PROFILE_SHA256")
	if guardrailEffectEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(guardrailEffectProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_GUARDRAIL_EFFECT_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.GuardrailEffectProfileSHA256 = guardrailEffectProfileSHA256
	cfg.GuardrailEffectProfilePath = "/etc/phorvex-guardrail-effect/config.guardrail-effect.yaml"
	drainLiveEnabled, err := readBool("PHORVEX_CONSOLE_DRAIN_LIVE_ENABLED")
	if err != nil {
		return err
	}
	cfg.DrainLiveEnabled = drainLiveEnabled
	drainLiveSHA, _ := lookup("PHORVEX_CONSOLE_DRAIN_LIVE_PROFILE_SHA256")
	if drainLiveEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(drainLiveSHA) {
		return errors.New("PHORVEX_CONSOLE_DRAIN_LIVE_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.DrainLiveProfileSHA256 = drainLiveSHA
	cfg.DrainLiveProfilePath = "/etc/phorvex-drain-live/profile.json"
	cfg.DrainReleaseAuthority = console.DrainReleaseAuthority{}
	for name, target := range map[string]*string{
		"PHORVEX_CONSOLE_DRAIN_MANAGER_TEMPLATE_IMAGE": &cfg.DrainReleaseAuthority.Manager.TemplateImage,
		"PHORVEX_CONSOLE_DRAIN_MANAGER_IMAGE":          &cfg.DrainReleaseAuthority.Manager.Image,
		"PHORVEX_CONSOLE_DRAIN_MANAGER_SOURCE_SHA":     &cfg.DrainReleaseAuthority.Manager.SourceSHA,
		"PHORVEX_CONSOLE_DRAIN_CONSOLE_TEMPLATE_IMAGE": &cfg.DrainReleaseAuthority.Console.TemplateImage,
		"PHORVEX_CONSOLE_DRAIN_CONSOLE_IMAGE":          &cfg.DrainReleaseAuthority.Console.Image,
		"PHORVEX_CONSOLE_DRAIN_CONSOLE_SOURCE_SHA":     &cfg.DrainReleaseAuthority.Console.SourceSHA,
	} {
		*target, _ = lookup(name)
	}
	endpointLeaseEnabled, err := readBool("PHORVEX_CONSOLE_ENDPOINT_LEASE_ENABLED")
	if err != nil {
		return err
	}
	cfg.EndpointLeaseEnabled = endpointLeaseEnabled
	endpointLeaseSHA, _ := lookup("PHORVEX_CONSOLE_ENDPOINT_LEASE_PROFILE_SHA256")
	if endpointLeaseEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(endpointLeaseSHA) {
		return errors.New("PHORVEX_CONSOLE_ENDPOINT_LEASE_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.EndpointLeaseProfileSHA256 = endpointLeaseSHA
	cfg.EndpointLeaseProfilePath = "/etc/phorvex-endpoint-lease/profile.json"
	guardrailOutputEnabled, err := readBool("PHORVEX_CONSOLE_GUARDRAIL_OUTPUT_ENABLED")
	if err != nil {
		return err
	}
	cfg.GuardrailOutputEnabled = guardrailOutputEnabled
	guardrailOutputProfileSHA256, _ := lookup("PHORVEX_CONSOLE_GUARDRAIL_OUTPUT_PROFILE_SHA256")
	if guardrailOutputEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(guardrailOutputProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_GUARDRAIL_OUTPUT_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.GuardrailOutputProfileSHA256 = guardrailOutputProfileSHA256
	cfg.GuardrailOutputProfilePath = "/etc/phorvex-guardrail-output/config.guardrail-output-response.yaml"
	liteLLMLiveEnabled, err := readBool("PHORVEX_CONSOLE_LITELLM_LIVE_ENABLED")
	if err != nil {
		return err
	}
	cfg.LiteLLMLiveEnabled = liteLLMLiveEnabled
	if raw := strings.TrimSpace(os.Getenv("PHORVEX_CONSOLE_LIVE_ATTACK_DISABLED")); raw != "" {
		cfg.LiveAttackDisabled = map[string]bool{}
		for _, entry := range splitList(raw) {
			cfg.LiveAttackDisabled[entry] = true
		}
	}
	liteLLMLiveProfileSHA256, _ := lookup("PHORVEX_CONSOLE_LITELLM_LIVE_PROFILE_SHA256")
	if liteLLMLiveEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(liteLLMLiveProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_LITELLM_LIVE_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.LiteLLMLiveProfileSHA256 = liteLLMLiveProfileSHA256
	cfg.LiteLLMLiveProfilePath = "/etc/phorvex-litellm-live/profile.json"
	voiceAgencyLiveEnabled, err := readBool("PHORVEX_CONSOLE_VOICE_AGENCY_LIVE_ENABLED")
	if err != nil {
		return err
	}
	cfg.VoiceAgencyLiveEnabled = voiceAgencyLiveEnabled
	voiceAgencyProfileSHA256, _ := lookup("PHORVEX_CONSOLE_VOICE_AGENCY_LIVE_PROFILE_SHA256")
	if voiceAgencyLiveEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(voiceAgencyProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_VOICE_AGENCY_LIVE_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.VoiceAgencyLiveProfileSHA256 = voiceAgencyProfileSHA256
	cfg.VoiceAgencyLiveProfilePath = "/etc/phorvex-voice-agency/profile.json"
	liteLLMOutputEnabled, err := readBool("PHORVEX_CONSOLE_LITELLM_OUTPUT_ENABLED")
	if err != nil {
		return err
	}
	cfg.LiteLLMOutputEnabled = liteLLMOutputEnabled
	liteLLMOutputProfileSHA256, _ := lookup("PHORVEX_CONSOLE_LITELLM_OUTPUT_PROFILE_SHA256")
	if liteLLMOutputEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(liteLLMOutputProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_LITELLM_OUTPUT_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.LiteLLMOutputProfileSHA256 = liteLLMOutputProfileSHA256
	cfg.LiteLLMOutputProfilePath = "/etc/phorvex-litellm-output/profile.json"
	voiceOutputLiveEnabled, err := readBool("PHORVEX_CONSOLE_VOICE_OUTPUT_LIVE_ENABLED")
	if err != nil {
		return err
	}
	cfg.VoiceOutputLiveEnabled = voiceOutputLiveEnabled
	voiceOutputProfileSHA256, _ := lookup("PHORVEX_CONSOLE_VOICE_OUTPUT_LIVE_PROFILE_SHA256")
	if voiceOutputLiveEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(voiceOutputProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_VOICE_OUTPUT_LIVE_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.VoiceOutputLiveProfileSHA256 = voiceOutputProfileSHA256
	cfg.VoiceOutputLiveProfilePath = "/etc/phorvex-voice-output/profile.json"
	voiceAdmissionLiveEnabled, err := readBool("PHORVEX_CONSOLE_VOICE_ADMISSION_LIVE_ENABLED")
	if err != nil {
		return err
	}
	cfg.VoiceAdmissionLiveEnabled = voiceAdmissionLiveEnabled
	voiceAdmissionProfileSHA256, _ := lookup("PHORVEX_CONSOLE_VOICE_ADMISSION_LIVE_PROFILE_SHA256")
	if voiceAdmissionLiveEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(voiceAdmissionProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_VOICE_ADMISSION_LIVE_PROFILE_SHA256 must be lowercase SHA-256 when enabled")
	}
	cfg.VoiceAdmissionLiveProfileSHA256 = voiceAdmissionProfileSHA256
	cfg.VoiceAdmissionLiveProfilePath = "/etc/phorvex-voice-admission/profile.json"

	voiceMCPLiveEnabled, err := readBool("PHORVEX_CONSOLE_VOICE_MCP_LIVE_ENABLED")
	if err != nil {
		return err
	}
	cfg.VoiceMCPLiveEnabled = voiceMCPLiveEnabled
	voiceMCPProfileSHA256, _ := lookup("PHORVEX_CONSOLE_VOICE_MCP_LIVE_PROFILE_SHA256")
	if voiceMCPLiveEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(voiceMCPProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_VOICE_MCP_LIVE_PROFILE_SHA256 must be lowercase SHA-256 when enabled")
	}
	cfg.VoiceMCPLiveProfileSHA256 = voiceMCPProfileSHA256
	cfg.VoiceMCPLiveProfilePath = "/etc/phorvex-voice-mcp/profile.json"
	crmRefundLiveEnabled, err := readBool("PHORVEX_CONSOLE_CRM_LIVE_ENABLED")
	if err != nil {
		return err
	}
	cfg.CRMRefundLiveEnabled = crmRefundLiveEnabled
	podBoundTokenEnabled, err := readBool("PHORVEX_CONSOLE_POD_BOUND_TOKEN_ENABLED")
	if err != nil {
		return err
	}
	cfg.PodBoundTokenEnabled = podBoundTokenEnabled
	podBoundTokenProfileSHA256, _ := lookup("PHORVEX_CONSOLE_POD_BOUND_TOKEN_PROFILE_SHA256")
	if podBoundTokenEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(podBoundTokenProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_POD_BOUND_TOKEN_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.PodBoundTokenProfileSHA256 = podBoundTokenProfileSHA256
	podBoundTokenCPUEnabled, err := readBool("PHORVEX_CONSOLE_POD_BOUND_TOKEN_CPU_ENABLED")
	if err != nil {
		return err
	}
	cfg.PodBoundTokenCPUEnabled = podBoundTokenCPUEnabled
	podBoundTokenCPUProfileSHA256, _ := lookup("PHORVEX_CONSOLE_POD_BOUND_TOKEN_CPU_PROFILE_SHA256")
	if podBoundTokenCPUEnabled && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(podBoundTokenCPUProfileSHA256) {
		return errors.New("PHORVEX_CONSOLE_POD_BOUND_TOKEN_CPU_PROFILE_SHA256 must be a lowercase SHA-256 when enabled")
	}
	cfg.PodBoundTokenCPUProfileSHA256 = podBoundTokenCPUProfileSHA256
	chromaEnabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_CHROMA_ENABLED")
	if err != nil {
		return err
	}
	liteLLMEnabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_LITELLM_ENABLED")
	if err != nil {
		return err
	}
	liteLLMInferenceEnabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_LITELLM_INFERENCE_ENABLED")
	if err != nil {
		return err
	}
	liteLLMModelAlias := read("PHORVEX_CONSOLE_CATALOGUE_LITELLM_MODEL_ALIAS")
	if liteLLMInferenceEnabled && (!liteLLMEnabled || liteLLMModelAlias == "") {
		return errors.New("LiteLLM inference requires the installed LiteLLM profile and a reviewed model alias")
	}
	crmEnabled, err := readBool("PHORVEX_CONSOLE_CATALOGUE_CRM_ENABLED")
	if err != nil {
		return err
	}
	port := int64(0)
	if raw := read("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_PORT"); raw != "" {
		port, err = strconv.ParseInt(raw, 10, 32)
		if err != nil || port < 1 || port > 65535 || raw != strconv.FormatInt(port, 10) {
			return errors.New("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_PORT must be a canonical port")
		}
	}
	guardrailPort := int64(0)
	if raw := read("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_PORT"); raw != "" {
		guardrailPort, err = strconv.ParseInt(raw, 10, 32)
		if err != nil || guardrailPort < 1 || guardrailPort > 65535 || raw != strconv.FormatInt(guardrailPort, 10) {
			return errors.New("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_PORT must be a canonical port")
		}
	}
	mcpPort := int64(0)
	if raw := read("PHORVEX_CONSOLE_CATALOGUE_MCP_PORT"); raw != "" {
		mcpPort, err = strconv.ParseInt(raw, 10, 32)
		if err != nil || mcpPort < 1 || mcpPort > 65535 || raw != strconv.FormatInt(mcpPort, 10) {
			return errors.New("PHORVEX_CONSOLE_CATALOGUE_MCP_PORT must be a canonical port")
		}
	}
	chromaPort := int64(0)
	if raw := read("PHORVEX_CONSOLE_CATALOGUE_CHROMA_PORT"); raw != "" {
		chromaPort, err = strconv.ParseInt(raw, 10, 32)
		if err != nil || chromaPort < 1 || chromaPort > 65535 || raw != strconv.FormatInt(chromaPort, 10) {
			return errors.New("PHORVEX_CONSOLE_CATALOGUE_CHROMA_PORT must be a canonical port")
		}
	}
	liteLLMPort := int64(0)
	if raw := read("PHORVEX_CONSOLE_CATALOGUE_LITELLM_PORT"); raw != "" {
		liteLLMPort, err = strconv.ParseInt(raw, 10, 32)
		if err != nil || liteLLMPort < 1 || liteLLMPort > 65535 || raw != strconv.FormatInt(liteLLMPort, 10) {
			return errors.New("PHORVEX_CONSOLE_CATALOGUE_LITELLM_PORT must be a canonical port")
		}
	}
	executable, _ := os.Executable()
	kubeconfigPath := read("KUBECONFIG")
	gpuKubeconfigPath := read("PHORVEX_CONSOLE_CATALOGUE_V1_GPU_KUBECONFIG")
	if gpuKubeconfigPath == "" {
		gpuKubeconfigPath = kubeconfigPath
	}
	gpuKubeContext := read("PHORVEX_CONSOLE_CATALOGUE_V1_GPU_KUBE_CONTEXT")
	cfg.CatalogueV1 = console.CatalogueV1Config{Enabled: enabled, Executable: executable,
		KubeconfigPath: kubeconfigPath,
		LoopbackURL:    read("PHORVEX_CONSOLE_CATALOGUE_V1_LOOPBACK_URL"), ScopedTokenFile: read("PHORVEX_CONSOLE_CATALOGUE_V1_TOKEN_FILE"),
		AllowedTenant: read("PHORVEX_CONSOLE_CATALOGUE_V1_ALLOWED_TENANT"), DeniedTenant: read("PHORVEX_CONSOLE_CATALOGUE_V1_DENIED_TENANT"),
		DeniedTarget: read("PHORVEX_CONSOLE_CATALOGUE_V1_DENIED_TARGET"), ExpectedSubject: read("PHORVEX_CONSOLE_CATALOGUE_V1_EXPECTED_SUBJECT"),
		GrantFile: read("PHORVEX_CONSOLE_CATALOGUE_V1_GRANT_FILE"), VoiceEnabled: voiceEnabled,
		VoiceNamespace: read("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_NAMESPACE"), VoiceDeployment: read("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_DEPLOYMENT"),
		VoiceService: read("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_SERVICE"), VoiceContainer: read("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_CONTAINER"),
		VoiceServicePort: int32(port), VoicePDB: read("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_PDB"),
		TranscriptSelector: read("PHORVEX_CONSOLE_CATALOGUE_V1_TRANSCRIPT_SELECTOR"), TranscriptContainer: read("PHORVEX_CONSOLE_CATALOGUE_V1_TRANSCRIPT_CONTAINER"),
		GPUEnabled: gpuEnabled, GPUFixtureNamespace: read("PHORVEX_CONSOLE_CATALOGUE_V1_GPU_NAMESPACE"),
		GPUFixtureConfig: read("PHORVEX_CONSOLE_CATALOGUE_V1_GPU_CONFIG"), GPUKubeconfigPath: gpuKubeconfigPath, GPUKubeContext: gpuKubeContext,
		GuardrailCalibrationEnabled: guardrailCalibrationEnabled,
		GuardrailNamespace:          read("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_NAMESPACE"),
		GuardrailService:            read("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SERVICE"),
		GuardrailPort:               int32(guardrailPort),
		GuardrailContainer:          read("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_CONTAINER"),
		GuardrailSourceConfigMap:    read("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SOURCE_CONFIGMAP"),
		GuardrailSourceKey:          read("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SOURCE_KEY"),
		GuardrailSourceSHA256:       read("PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SOURCE_SHA256")}
	cfg.CatalogueV1.MCPVoiceModelEnabled = mcpVoiceModelEnabled
	cfg.CatalogueV1.MCPVoiceSourceSHA256 = read("PHORVEX_CONSOLE_CATALOGUE_MCP_VOICE_MODEL_VOICE_SOURCE_SHA256")
	cfg.CatalogueV1.MCPEnabled = mcpEnabled
	cfg.CatalogueV1.MCPNamespace = read("PHORVEX_CONSOLE_CATALOGUE_MCP_NAMESPACE")
	cfg.CatalogueV1.MCPDeployment = read("PHORVEX_CONSOLE_CATALOGUE_MCP_DEPLOYMENT")
	cfg.CatalogueV1.MCPService = read("PHORVEX_CONSOLE_CATALOGUE_MCP_SERVICE")
	cfg.CatalogueV1.MCPContainer = read("PHORVEX_CONSOLE_CATALOGUE_MCP_CONTAINER")
	cfg.CatalogueV1.MCPPort = int32(mcpPort)
	cfg.CatalogueV1.MCPSourceConfigMap = read("PHORVEX_CONSOLE_CATALOGUE_MCP_SOURCE_CONFIGMAP")
	cfg.CatalogueV1.MCPSourceKey = read("PHORVEX_CONSOLE_CATALOGUE_MCP_SOURCE_KEY")
	cfg.CatalogueV1.MCPImageID = read("PHORVEX_CONSOLE_CATALOGUE_MCP_IMAGE_ID")
	cfg.CatalogueV1.MCPSourceSHA256 = read("PHORVEX_CONSOLE_CATALOGUE_MCP_SOURCE_SHA256")
	cfg.CatalogueV1.ChromaEnabled = chromaEnabled
	cfg.CatalogueV1.ChromaNamespace = read("PHORVEX_CONSOLE_CATALOGUE_CHROMA_NAMESPACE")
	cfg.CatalogueV1.ChromaDeployment = read("PHORVEX_CONSOLE_CATALOGUE_CHROMA_DEPLOYMENT")
	cfg.CatalogueV1.ChromaService = read("PHORVEX_CONSOLE_CATALOGUE_CHROMA_SERVICE")
	cfg.CatalogueV1.ChromaContainer = read("PHORVEX_CONSOLE_CATALOGUE_CHROMA_CONTAINER")
	cfg.CatalogueV1.ChromaPort = int32(chromaPort)
	cfg.CatalogueV1.ChromaImageID = read("PHORVEX_CONSOLE_CATALOGUE_CHROMA_IMAGE_ID")
	cfg.CatalogueV1.ChromaVersionSourceSHA256 = read("PHORVEX_CONSOLE_CATALOGUE_CHROMA_VERSION_SOURCE_SHA256")
	cfg.CatalogueV1.ChromaServerSourceSHA256 = read("PHORVEX_CONSOLE_CATALOGUE_CHROMA_SERVER_SOURCE_SHA256")
	cfg.CatalogueV1.ChromaSchemaSourceSHA256 = read("PHORVEX_CONSOLE_CATALOGUE_CHROMA_SCHEMA_SOURCE_SHA256")
	cfg.CatalogueV1.LiteLLMEnabled = liteLLMEnabled
	cfg.CatalogueV1.LiteLLMInferenceEnabled = liteLLMInferenceEnabled
	cfg.CatalogueV1.LiteLLMModelAlias = liteLLMModelAlias
	cfg.CatalogueV1.LiteLLMNamespace = read("PHORVEX_CONSOLE_CATALOGUE_LITELLM_NAMESPACE")
	cfg.CatalogueV1.LiteLLMDeployment = read("PHORVEX_CONSOLE_CATALOGUE_LITELLM_DEPLOYMENT")
	cfg.CatalogueV1.LiteLLMService = read("PHORVEX_CONSOLE_CATALOGUE_LITELLM_SERVICE")
	cfg.CatalogueV1.LiteLLMContainer = read("PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONTAINER")
	cfg.CatalogueV1.LiteLLMPort = int32(liteLLMPort)
	cfg.CatalogueV1.LiteLLMConfigMap = read("PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIGMAP")
	cfg.CatalogueV1.LiteLLMConfigKey = read("PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_KEY")
	cfg.CatalogueV1.LiteLLMConfigSHA256 = read("PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_SHA256")
	cfg.CatalogueV1.CRMEnabled = crmEnabled
	cfg.CatalogueV1.CRMNamespace = read("PHORVEX_CONSOLE_CATALOGUE_CRM_NAMESPACE")
	cfg.CatalogueV1.CRMServiceAccountName = read("PHORVEX_CONSOLE_CATALOGUE_CRM_SERVICE_ACCOUNT")
	cfg.CatalogueV1.CRMNamespaceUID = read("PHORVEX_CONSOLE_CATALOGUE_CRM_NAMESPACE_UID")
	cfg.CatalogueV1.CRMManifestFile = read("PHORVEX_CONSOLE_CATALOGUE_CRM_MANIFEST_FILE")
	cfg.CatalogueV1.CRMManifestSHA256 = read("PHORVEX_CONSOLE_CATALOGUE_CRM_MANIFEST_SHA256")
	cfg.CatalogueV1.CRMHarnessSHA256 = read("PHORVEX_CONSOLE_CATALOGUE_CRM_HARNESS_SHA256")
	cfg.CatalogueV1.CRMKubeconfigPath = read("PHORVEX_CONSOLE_CATALOGUE_CRM_KUBECONFIG")
	cfg.CatalogueV1.CRMKubeconfigSHA256 = read("PHORVEX_CONSOLE_CATALOGUE_CRM_KUBECONFIG_SHA256")
	cfg.CatalogueV1.CRMKubeContext = read("PHORVEX_CONSOLE_CATALOGUE_CRM_KUBE_CONTEXT")
	if cfg.CatalogueV1.KubeconfigPath != "" && cfg.CatalogueV1.KubeContext == "" {
		loading := &clientcmd.ClientConfigLoadingRules{ExplicitPath: cfg.CatalogueV1.KubeconfigPath}
		raw, loadErr := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{}).RawConfig()
		if loadErr != nil || strings.TrimSpace(raw.CurrentContext) == "" {
			return errors.New("catalogue v1 KUBECONFIG has no resolvable current context")
		}
		cfg.CatalogueV1.KubeContext = raw.CurrentContext
	}
	if cfg.CatalogueV1.GPUKubeconfigPath != "" && cfg.CatalogueV1.GPUKubeContext == "" {
		loading := &clientcmd.ClientConfigLoadingRules{ExplicitPath: cfg.CatalogueV1.GPUKubeconfigPath}
		raw, loadErr := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{}).RawConfig()
		if loadErr != nil || strings.TrimSpace(raw.CurrentContext) == "" {
			return errors.New("catalogue v1 GPU kubeconfig has no resolvable current context")
		}
		cfg.CatalogueV1.GPUKubeContext = raw.CurrentContext
	}
	return nil
}

// setLogger installs the console's structured logger as the slog default. Output
// from the standard log package follows it.
func setLogger(o logging.Options) error {
	l, err := logging.New(os.Stderr, o)
	if err != nil {
		return err
	}
	slog.SetDefault(l)
	return nil
}

// fatal logs an error and exits 1 without running deferred calls, as log.Fatal did.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

func runCatalogueV1Worker(executePath, reconcilePath, runtimePath string) int {
	if (executePath == "") == (reconcilePath == "") || runtimePath == "" {
		slog.Error("catalogue v1 worker requires exactly one job mode and one runtime file")
		return 2
	}
	runtimeConfig, err := cataloguev1.LoadRuntimeConfig(runtimePath)
	if err != nil {
		slog.Error("catalogue v1 runtime invalid", "err", err)
		return 2
	}
	jobPath := executePath
	if jobPath == "" {
		jobPath = reconcilePath
	}
	job, err := cataloguev1.LoadJob(jobPath, runtimeConfig.StateDir)
	if err != nil {
		slog.Error("catalogue v1 job invalid", "err", err)
		return 2
	}
	restConfig, kube, err := workerKubernetesRuntime(job.Profile, runtimeConfig)
	if err != nil {
		slog.Error("catalogue v1 Kubernetes runtime unavailable", "err", err)
		return 2
	}
	runtime, err := runtimeConfig.Runtime(restConfig, kube, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		slog.Error("catalogue v1 runtime authority unavailable", "err", err)
		return 2
	}
	runner, err := cataloguev1.New(runtime,
		cataloguev1.NewVoiceMediaHandler(), cataloguev1.NewVoiceRecoveryHandler(),
		cataloguev1.NewGPUDrainHandler(),
		cataloguev1.NewAuthUnauthHandler(), cataloguev1.NewAuthScopeHandler(),
		cataloguev1.NewGuardrailCalibrationHandler(), cataloguev1.NewMCPSessionHandler(),
		cataloguev1.NewChromaHandler(), cataloguev1.NewLiteLLMHealthHandler(), cataloguev1.NewLiteLLMCredentialHandler(), cataloguev1.NewLiteLLMRoutingHandler(), cataloguev1.NewMCPVoiceModelHandler(),
		cataloguev1.NewCRMCapabilityHandler(cataloguev1.CRMRefund), cataloguev1.NewCRMCapabilityHandler(cataloguev1.CRMReset))
	if err != nil {
		slog.Error("catalogue v1 registry invalid", "err", err)
		return 2
	}
	release, err := cataloguev1.AcquireExecutionLock(job.OutputDir)
	if err != nil {
		slog.Error("catalogue v1 execution authority unavailable", "err", err)
		return 2
	}
	defer release()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var result cataloguev1.Result
	if executePath != "" {
		result = runner.Execute(ctx, job)
	} else {
		result = runner.Reconcile(ctx, job)
	}
	if err := cataloguev1.ValidateResult(job, result); err != nil {
		slog.Error("catalogue v1 terminal result invalid", "err", err)
		return 1
	}
	if result.Outcome == cataloguev1.OutcomeTestFailed {
		return 1
	}
	return 0
}

func workerKubernetesRuntime(profile cataloguev1.ProfileID, runtimeConfig cataloguev1.RuntimeConfig) (*rest.Config, kubernetes.Interface, error) {
	if profile != cataloguev1.VoiceMedia && profile != cataloguev1.VoiceRecovery &&
		profile != cataloguev1.GuardrailCalibration && profile != cataloguev1.MCPSessionBaseline &&
		profile != cataloguev1.ChromaOwnedVector && profile != cataloguev1.LiteLLMHealth && profile != cataloguev1.LiteLLMCredential && profile != cataloguev1.LiteLLMRouting && profile != cataloguev1.MCPVoiceModel {
		return nil, nil, nil
	}
	var restConfig *rest.Config
	var err error
	if runtimeConfig.KubeconfigPath != "" {
		loading := &clientcmd.ClientConfigLoadingRules{ExplicitPath: runtimeConfig.KubeconfigPath}
		overrides := &clientcmd.ConfigOverrides{CurrentContext: runtimeConfig.KubeContext}
		restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, overrides).ClientConfig()
	} else {
		restConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, nil, err
	}
	kube, err := kubernetes.NewForConfig(restConfig)
	return restConfig, kube, err
}

func boundedAuditGate(next http.Handler, probe func(context.Context) error, probeTimeout, requestTimeout time.Duration) http.Handler {
	return console.BoundedAuditGate(next, probe, probeTimeout, requestTimeout, nil)
}

// serviceFor is the part of the API binary serves: the console serves all of it
// until it is given the attacks service to forward to.
func serviceFor(binary console.Service, attacksURL string) console.Service {
	if binary == console.ServiceConsole && attacksURL == "" {
		return console.ServiceAll
	}
	return binary
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func splitList(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func originSummary(origins []string) string {
	if len(origins) == 0 {
		return "NONE CONFIGURED — browser state-changing requests are refused (bearer clients unaffected)"
	}
	return strings.Join(origins, ", ")
}

// guessRoot walks up from wd looking for the dir that contains both phorvex/ and
// build/test-harness/.
func guessRoot(wd string) string {
	d := wd
	for i := 0; i < 6; i++ {
		if dirExists(filepath.Join(d, "phorvex")) && dirExists(filepath.Join(d, "build", "test-harness")) {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return wd
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
