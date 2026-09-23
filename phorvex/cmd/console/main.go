/*
 * Phorvex Console (P-DASHBOARD) — the data-layer backend binary.
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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/cataloguev1"
	"github.com/phorvex/phorvex/internal/console"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	os.Exit(run())
}

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

func run() int {
	historyMaxDefault, historyMinFreeDefault, err := historyCapacityDefaults(os.LookupEnv)
	if err != nil {
		log.Printf("console history capacity configuration: %v", err)
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
	)
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
	flag.Parse()
	if catalogueV1Job != "" || catalogueV1Reconcile != "" {
		return runCatalogueV1Worker(catalogueV1Job, catalogueV1Reconcile, catalogueV1Runtime)
	}
	if historyMaxBytes <= 0 || historyMinFree <= 0 {
		log.Fatalf("console history capacity configuration: history limits must be positive")
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
		log.Printf("catalogue v1 configuration: %v", err)
		return 2
	}
	cfg.HistoryArchiveMaxBytes = historyMaxBytes
	cfg.HistoryMinFreeBytes = historyMinFree
	if raw, present := os.LookupEnv("PHORVEX_CONSOLE_HISTORY_RETENTION_DAYS"); present {
		days, err := strconv.Atoi(raw)
		if err != nil || days < 0 || days > 3650 || raw != strconv.Itoa(days) {
			log.Fatal("history retention days must be a canonical integer in 0..3650")
		}
		cfg.HistoryRetentionDays = days
	}
	cfg.Addr = addr
	if auditPath != "" {
		cfg.AuditPath = auditPath
	}
	var source *audittransport.Client
	if auditSourceURL != "" {
		client, err := audittransport.NewClient(audittransport.ClientConfig{URL: auditSourceURL, ServerDNSName: auditServerDNS, CertFile: auditClientCert, KeyFile: auditClientKey, CAFile: auditSourceCA})
		if err != nil {
			log.Fatalf("audit source configuration: %v", err)
		}
		source = client
		cfg.AuditSource = client
		cfg.AuditSourceIdentity = auditSourceURL + "|" + auditServerDNS
	}
	if web != "" {
		cfg.Web = web
	}
	if err := cfg.ValidateStateDir(); err != nil {
		log.Fatalf("console state storage unavailable: %v", err)
	}
	if err := cfg.ValidateHistoryCapacity(); err != nil {
		log.Fatalf("console history capacity configuration: %v", err)
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
		log.Fatalf("Phorvex Console: refusing to start — %v\n"+
			"Configure the ALB signed identity (PHORVEX_CONSOLE_ALB_SIGNER_ARN / _ISSUER / _CLIENT_ID) "+
			"and/or a bearer IdP (PHORVEX_CONSOLE_OIDC_ISSUER / _AUDIENCE / _JWKS_URL). See docs/CONSOLE-AUTH.md.", err)
	}

	url := "http://localhost" + addr
	_, statErr := os.Stat(filepath.Join(cfg.Web, "index.html"))
	hasWeb := statErr == nil
	log.Printf("Phorvex Console")
	log.Printf("  root      : %s", root)
	log.Printf("  state     : %s (write/read/sync verified)", cfg.StateDir)
	log.Printf("  dashboard : %s  ->  open %s", map[bool]string{true: "built (serving the SPA)", false: "NOT BUILT (run: cd dashboard-web && npm run build)"}[hasWeb], url)
	log.Printf("  api       : %s/api/* (authenticated; only /api/health and the static SPA are public)", url)
	log.Printf("  auth      : %s", strings.Join(auth.Modes(), "+"))
	log.Printf("  origins   : %s", originSummary(auth.TrustedOrigins()))
	if n := auth.GrantCount(); n == 0 {
		// Visibly fail closed: the service runs, authenticates callers, and authorizes nobody
		// until DevOps supplies the bindings. Crash-looping the sidecar would take the operator
		// pod with it and hide the reason.
		log.Printf("  grants    : NONE CONFIGURED — every authenticated caller is denied. " +
			"Supply the subject grant table (-auth-grants / PHORVEX_CONSOLE_GRANTS) before rollout; " +
			"no user is an operator until it is bound explicitly.")
	} else {
		log.Printf("  grants    : %d subject binding(s) loaded", n)
	}

	srv := console.NewServer(cfg)
	defer func() {
		if err := srv.Close(); err != nil {
			log.Printf("audit history close: %v", err)
		}
	}()
	srv.EnableAuth(auth)
	// The applier is nil => record-only until a deployment injects the per-namespace-SA CRD
	// patch (the UI labels this honestly).
	srv.EnableVCluster(console.NewTenantQuota(console.DefaultQuota()), console.NewApplyFixManager(nil, nil, nil))
	log.Printf("  apply-fix : %s/api/apply-fix/* (allowlist + gate-check + two-key on verified subjects; record-only applier [PENDING-CLUSTER-VALIDATION])", url)
	// P-UPTIME: background sampler records MEASURED service availability (K8s API) so /api/uptime can
	// show the real actuator impact on uptime. Read-only; no-ops if no cluster is reachable.
	srv.StartUptimeSampler(context.Background())
	log.Printf("  uptime    : %s/api/uptime (measured availability vs actuation markers)", url)
	// Reap fired red-team SecurityEvents after a TTL so an un-cleared attack cannot pin an app
	// to "under attack" forever (the state the dashboard was stuck in after heavy Fire-live use).
	srv.StartRedTeamSweeper(context.Background())
	log.Printf("  redteam   : auto-expiring fired attack events after %s", "5m")

	// Explicit server budgets. ReadHeaderTimeout bounds slow-header clients; WriteTimeout stays
	// zero because /api/live and /api/runs/stream are long-lived SSE streams that a write
	// deadline would sever mid-stream.
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           auditGate(srv.Handler(), source),
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
			log.Printf("console shutdown: %v", err)
		}
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("console server: %v", err)
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
	port := int64(0)
	if raw := read("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_PORT"); raw != "" {
		port, err = strconv.ParseInt(raw, 10, 32)
		if err != nil || port < 1 || port > 65535 || raw != strconv.FormatInt(port, 10) {
			return errors.New("PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_PORT must be a canonical port")
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
		GPUFixtureConfig: read("PHORVEX_CONSOLE_CATALOGUE_V1_GPU_CONFIG"), GPUKubeconfigPath: gpuKubeconfigPath, GPUKubeContext: gpuKubeContext}
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

func runCatalogueV1Worker(executePath, reconcilePath, runtimePath string) int {
	if (executePath == "") == (reconcilePath == "") || runtimePath == "" {
		log.Printf("catalogue v1 worker requires exactly one job mode and one runtime file")
		return 2
	}
	runtimeConfig, err := cataloguev1.LoadRuntimeConfig(runtimePath)
	if err != nil {
		log.Printf("catalogue v1 runtime: %v", err)
		return 2
	}
	jobPath := executePath
	if jobPath == "" {
		jobPath = reconcilePath
	}
	job, err := cataloguev1.LoadJob(jobPath, runtimeConfig.StateDir)
	if err != nil {
		log.Printf("catalogue v1 job: %v", err)
		return 2
	}
	var restConfig *rest.Config
	var kube kubernetes.Interface
	if job.Profile == cataloguev1.VoiceMedia || job.Profile == cataloguev1.VoiceRecovery {
		if runtimeConfig.KubeconfigPath != "" {
			loading := &clientcmd.ClientConfigLoadingRules{ExplicitPath: runtimeConfig.KubeconfigPath}
			overrides := &clientcmd.ConfigOverrides{CurrentContext: runtimeConfig.KubeContext}
			restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, overrides).ClientConfig()
		} else {
			restConfig, err = rest.InClusterConfig()
		}
		if err == nil {
			kube, err = kubernetes.NewForConfig(restConfig)
		}
		if err != nil {
			log.Printf("catalogue v1 Kubernetes runtime: %v", err)
			return 2
		}
	}
	runtime, err := runtimeConfig.Runtime(restConfig, kube, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		log.Printf("catalogue v1 runtime authority: %v", err)
		return 2
	}
	runner, err := cataloguev1.New(runtime,
		cataloguev1.NewVoiceMediaHandler(), cataloguev1.NewVoiceRecoveryHandler(),
		cataloguev1.NewGPUDrainHandler(),
		cataloguev1.NewAuthUnauthHandler(), cataloguev1.NewAuthScopeHandler())
	if err != nil {
		log.Printf("catalogue v1 registry: %v", err)
		return 2
	}
	release, err := cataloguev1.AcquireExecutionLock(job.OutputDir)
	if err != nil {
		log.Printf("catalogue v1 execution authority: %v", err)
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
		log.Printf("catalogue v1 terminal result: %v", err)
		return 1
	}
	if result.Outcome == cataloguev1.OutcomeTestFailed {
		return 1
	}
	return 0
}

func auditGate(next http.Handler, source *audittransport.Client) http.Handler {
	if source == nil {
		return next
	}
	return boundedAuditGate(next, source.ProbeContext, 5*time.Second, 30*time.Second)
}

// Admission happens before source probes, 16 MiB allocations, and segment scans.
// Long live SSE subscriptions have their own slots; they cannot occupy all
// short-read capacity needed by paged history and derived readers.
func boundedAuditGate(next http.Handler, probe func(context.Context) error, probeTimeout, requestTimeout time.Duration) http.Handler {
	shortReads := make(chan struct{}, 4)
	streams := make(chan struct{}, 2)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auditDependentRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		limit := shortReads
		stream := r.URL.Path == "/api/live"
		if stream {
			limit = streams
		}
		select {
		case limit <- struct{}{}:
			defer func() { <-limit }()
		case <-r.Context().Done():
			return
		default:
			http.Error(w, "remote audit reader limit reached", http.StatusServiceUnavailable)
			return
		}
		ctx := r.Context()
		cancelRequest := func() {}
		if !stream {
			ctx, cancelRequest = context.WithTimeout(ctx, requestTimeout)
			defer cancelRequest()
		}
		probeCtx, cancelProbe := context.WithTimeout(ctx, probeTimeout)
		err := probe(probeCtx)
		cancelProbe()
		if err != nil {
			http.Error(w, "live audit source unavailable", http.StatusServiceUnavailable)
			return
		}
		if ctx.Err() != nil {
			http.Error(w, "remote audit request timed out", http.StatusServiceUnavailable)
			return
		}
		if stream {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func auditDependentRoute(path string) bool {
	switch path {
	case "/api/live", "/api/live/history", "/api/owner/events", "/api/owner/tenants", "/api/cost-timeseries", "/api/cost", "/api/uptime", "/api/effectiveness", "/api/posture":
		return true
	default:
		return false
	}
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
