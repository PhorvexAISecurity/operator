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
	"regexp"
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
	restConfig, kube, err := workerKubernetesRuntime(job.Profile, runtimeConfig)
	if err != nil {
		log.Printf("catalogue v1 Kubernetes runtime: %v", err)
		return 2
	}
	runtime, err := runtimeConfig.Runtime(restConfig, kube, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		log.Printf("catalogue v1 runtime authority: %v", err)
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
