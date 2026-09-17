/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P4 — AI actuator stack)
 *
 * gpu_stack.go — the SERVING-STACK + GPU control-plane abstraction the AI handlers drive.
 *
 * DESIGN (persona panel: AI-Engineer / GPU-expert / MLSecOps / Cloud-engineer):
 *   - The serving control plane is HTTP (`vLLMClient`) — the production control plane vLLM/Triton/TGI
 *     already expose — NOT in-pod exec. Default impl talks vLLM's HTTP API; a Triton(gRPC)/TGI impl
 *     swaps in by implementing the SAME interface (the stack-specific calls are isolated here).
 *   - MIG reconfiguration is NVML/nvidia-smi behind a `nodeRunner` (the node-exec mechanism is
 *     infra-dependent — a privileged node agent / GPU-Operator mig-manager — so it is the part that is
 *     [PENDING-GPU-VALIDATION]; the COMMAND logic + ordering is real and unit-tested via a mock).
 *
 * HONEST tri-state every AI handler uses:
 *   (a) real call SUCCEEDS                      -> full effect.
 *   (b) endpoint UNREACHABLE (no serving stack, e.g. kind / no GPU node agent) -> the K8s mechanic is
 *       still enacted for real, the GPU/stack effect is recorded [PENDING-GPU-VALIDATION] (NEVER faked).
 *   (c) endpoint REACHABLE but the call FAILS   -> FAIL-CLOSED (return the error; never claim success).
 *
 * NONE of this is production-ready until calibrated on real GPU hardware — see [PENDING-GPU-VALIDATION].
 */

package actuator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// ---- serving-stack control plane (vLLM default; Triton/TGI swappable) ----

// servingEndpoint identifies a model-serving pod's reachable HTTP control plane.
type servingEndpoint struct {
	podIP      string
	port       int
	scheme     string
	client     *http.Client
	resetPath  string // the prefix/KV-cache reset path (vLLM default; configurable per pod)
	healthPath string // liveness probe path (vLLM default /health; configurable per pod)
	modelsPath string // loaded-models list path (vLLM default /v1/models; configurable per pod)
	token      string // optional bearer for the admin op
	// P-ACTUATOR-SET-COMPLETE routes (vLLM-shaped defaults; per-pod annotation overrides).
	unloadPath string // LoRA unload (adapter-rotate)
	loadPath   string // LoRA load (adapter-rotate)
	drainPath  string // request drain/abort (request-drain, warm-swap drain)
	guardPath  string // guardrail reload (guardrail-rotate)
	kvInvPath  string // disaggregated KV invalidate (kv-migrate-invalidate)
	configErr  error  // malformed explicit Pod configuration; never treated as unreachable
}

func (e servingEndpoint) reachable() bool { return e.podIP != "" && e.port > 0 }
func (e servingEndpoint) base() string {
	scheme := e.scheme
	if scheme == "" {
		scheme = "http"
	}
	return (&url.URL{Scheme: scheme, Host: net.JoinHostPort(e.podIP, strconv.Itoa(e.port))}).String()
}
func (e servingEndpoint) routeURL(route string) string {
	scheme := e.scheme
	if scheme == "" {
		scheme = "http"
	}
	return (&url.URL{Scheme: scheme, Host: net.JoinHostPort(e.podIP, strconv.Itoa(e.port)), Path: route}).String()
}

const (
	// Pod annotations let an operator declare the serving stack per workload without code change.
	annoServingPort  = "phorvex.ai/serving-port"  // default 8000 (vLLM OpenAI server)
	annoResetPath    = "phorvex.ai/kv-reset-path" // default vLLM prefix-cache reset
	annoHealthPath   = "phorvex.ai/health-path"   // default /health (liveness probe)
	annoModelsPath   = "phorvex.ai/models-path"   // default /v1/models (loaded-model list)
	annoServingTok   = "phorvex.ai/serving-token" // legacy-plaintext compatibility only; secure mode ignores it
	defaultServePort = 8000
	// [PENDING-GPU-VALIDATION] confirm EVERY route against the deployed vLLM version: recent vLLM exposes
	// the prefix-cache reset on the engine; the exact routes differ by version/flag. All configurable via
	// the phorvex.ai/* annotations above (no hardcoded literal reaches the wire).
	defaultResetPath  = "/reset_prefix_cache"
	defaultHealthPath = "/health"
	defaultModelsPath = "/v1/models"
)

var errServingConfiguration = errors.New("invalid serving endpoint configuration")

func invalidServingConfiguration(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errServingConfiguration, fmt.Sprintf(format, args...))
}

func servingRoute(raw, annotation, fallback string, explicitlyConfigured bool) (string, error) {
	if !explicitlyConfigured {
		return fallback, nil
	}
	if raw == "" || raw != strings.TrimSpace(raw) {
		return "", invalidServingConfiguration("%s must be a nonempty root-relative path without surrounding whitespace", annotation)
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return "", invalidServingConfiguration("%s contains a control character", annotation)
		}
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\?#%@") {
		return "", invalidServingConfiguration("%s must be an unambiguous root-relative path", annotation)
	}
	if path.Clean(raw) != raw {
		return "", invalidServingConfiguration("%s contains traversal or ambiguous path separators", annotation)
	}
	for _, segment := range strings.Split(raw, "/") {
		if segment == "." || segment == ".." {
			return "", invalidServingConfiguration("%s contains a traversal segment", annotation)
		}
	}
	return raw, nil
}

// validated checks the complete eight-route endpoint before any one route is used.
// Empty route fields exist only in small direct unit fixtures and receive the same
// documented defaults as absent Pod annotations.
func (e servingEndpoint) validated() (servingEndpoint, error) {
	if e.configErr != nil {
		return servingEndpoint{}, e.configErr
	}
	if e.podIP != "" {
		parsed := net.ParseIP(e.podIP)
		if parsed == nil || parsed.IsUnspecified() || e.podIP != strings.TrimSpace(e.podIP) {
			return servingEndpoint{}, invalidServingConfiguration("Pod IP %q is not a literal IP address", e.podIP)
		}
		e.podIP = parsed.String()
	}
	if e.port < 1 || e.port > 65535 {
		return servingEndpoint{}, invalidServingConfiguration("serving port must be in 1..65535")
	}
	routes := []struct {
		value      *string
		annotation string
		fallback   string
	}{
		{&e.resetPath, annoResetPath, defaultResetPath},
		{&e.healthPath, annoHealthPath, defaultHealthPath},
		{&e.modelsPath, annoModelsPath, defaultModelsPath},
		{&e.unloadPath, annoUnloadPath, defaultUnloadPath},
		{&e.loadPath, annoLoadPath, defaultLoadPath},
		{&e.drainPath, annoDrainPath, defaultDrainPath},
		{&e.guardPath, annoGuardrailPath, defaultGuardPath},
		{&e.kvInvPath, annoKVInvalidate, defaultKVInvPath},
	}
	for _, route := range routes {
		configured := *route.value != ""
		value, err := servingRoute(*route.value, route.annotation, route.fallback, configured)
		if err != nil {
			return servingEndpoint{}, err
		}
		*route.value = value
	}
	return e, nil
}

// endpointForPod derives the serving endpoint from a running pod (IP + declared port/path).
func endpointForPod(pod *corev1.Pod) servingEndpoint {
	ep := servingEndpoint{podIP: pod.Status.PodIP, port: defaultServePort}
	if raw, present := pod.Annotations[annoServingPort]; present {
		trimmed := strings.TrimSpace(raw)
		n, err := strconv.Atoi(trimmed)
		if trimmed == "" || err != nil || n < 1 || n > 65535 {
			ep.configErr = invalidServingConfiguration("%s must be an integer in 1..65535", annoServingPort)
		} else {
			ep.port = n
		}
	}
	routeAnnotations := []struct {
		key      string
		fallback string
		target   *string
	}{
		{annoResetPath, defaultResetPath, &ep.resetPath},
		{annoHealthPath, defaultHealthPath, &ep.healthPath},
		{annoModelsPath, defaultModelsPath, &ep.modelsPath},
		{annoUnloadPath, defaultUnloadPath, &ep.unloadPath},
		{annoLoadPath, defaultLoadPath, &ep.loadPath},
		{annoDrainPath, defaultDrainPath, &ep.drainPath},
		{annoGuardrailPath, defaultGuardPath, &ep.guardPath},
		{annoKVInvalidate, defaultKVInvPath, &ep.kvInvPath},
	}
	for _, route := range routeAnnotations {
		raw, present := pod.Annotations[route.key]
		value, err := servingRoute(raw, route.key, route.fallback, present)
		if err != nil && ep.configErr == nil {
			ep.configErr = err
		}
		*route.target = value
	}
	ep.token = pod.Annotations[annoServingTok]
	return ep
}

func validatedEndpointForPod(pod *corev1.Pod) (servingEndpoint, error) {
	return endpointForPod(pod).validated()
}

// errStackUnreachable signals case (b): the request could not have reached a
// serving backend. Timeouts, cancellation, EOF/reset, TLS failure and opaque
// transports do not prove this and must retain an unknown outcome instead.
var errStackUnreachable = errors.New("serving endpoint unreachable [PENDING-GPU-VALIDATION]")

// errServingOutcomeUnknown means the request may have reached the serving
// backend, but no complete response proved its result. Consumers must preserve
// possible effect and must not take compatibility fallbacks reserved for a
// definitely unreachable endpoint.
var errServingOutcomeUnknown = errors.New("serving request outcome unknown")

// errServingQueued records an explicit 202 response. The backend accepted work
// but did not prove its effect synchronously, so protected callers retain the
// dispatch obligation and must not stamp success metadata or retry the POST.
var errServingQueued = errors.New("serving request accepted asynchronously")

type definiteServingUnreachableError struct{ cause error }

func (e *definiteServingUnreachableError) Error() string {
	return errStackUnreachable.Error() + ": " + e.cause.Error()
}

func (e *definiteServingUnreachableError) Unwrap() []error {
	return []error{errStackUnreachable, e.cause}
}

// errAdapterAbsent means the serving stack answered and reported the named adapter is NOT
// loaded. For an EVICTION this is the goal state already met, not a failure — treating it as
// an error made adapter-rotate fail forever on a stale detector flag (the flag naming an
// adapter vLLM never had), which starved every other AI move on that pod. See adapterRotateHandler.
var errAdapterAbsent = errors.New("adapter not loaded on the serving stack")

// vLLMClient is the serving-stack control plane. Default impl = vLLM HTTP API. Swap for Triton/TGI.
type vLLMClient interface {
	// ModelReady reports whether the served model is LOADED + healthy at ep (warm-pool readiness).
	// Returns errStackUnreachable only when the request definitely could not reach a
	// stack, so callers may use the documented non-GPU compatibility fallback.
	ModelReady(ctx context.Context, ep servingEndpoint) (bool, error)
	// ResetPrefixCache flushes the prefix/KV cache in-process WITHOUT restarting (kv-reset).
	// Nil requires one bounded synchronous backend acknowledgement with exact success:true.
	ResetPrefixCache(ctx context.Context, ep servingEndpoint) error
	// UnloadAdapter unloads a named LoRA/adapter (vLLM /v1/unload_lora_adapter; adapter-rotate).
	UnloadAdapter(ctx context.Context, ep servingEndpoint, adapter string) error
	// AdapterLoaded observes exact adapter membership through the configured models inventory.
	// A false result is authoritative only when the bounded response is valid and unambiguous.
	AdapterLoaded(ctx context.Context, ep servingEndpoint, adapter string) (bool, error)
	// LoadAdapter loads a named LoRA/adapter from a (trusted, pinned) source path/uri.
	LoadAdapter(ctx context.Context, ep servingEndpoint, adapter, source string) error
	// DrainRequests stops admitting + aborts/finishes in-flight requests, returning the count
	// aborted (request-drain; also warm-swap's drain). Best-effort; pair with the K8s readiness flip.
	DrainRequests(ctx context.Context, ep servingEndpoint) (aborted int, err error)
}

// httpVLLM is the REAL vLLM HTTP control-plane client. [PENDING-GPU-VALIDATION] — calibrate the health/
// model/reset routes against the deployed vLLM version; on kind (no vLLM) calls surface errStackUnreachable.
type httpVLLM struct{ hc *http.Client }

func newHTTPVLLM() *httpVLLM { return &httpVLLM{hc: &http.Client{Timeout: 3 * time.Second}} }

func (c *httpVLLM) do(ctx context.Context, method, url, token string) (int, string, error) {
	return c.request(ctx, method, url, token, "", nil)
}

func (c *httpVLLM) doEndpoint(ctx context.Context, ep servingEndpoint, method, route string) (int, string, error) {
	return c.requestWithClient(ctx, ep.client, method, ep.routeURL(route), ep.token, "", nil)
}

// request is the single serving HTTP execution boundary. Redirects are returned
// as their original response so a write accepted by the first server is never
// silently repeated and a later dial failure cannot erase that possible effect.
// The client is copied before installing this policy; shared clients are immutable.
func (c *httpVLLM) request(ctx context.Context, method, rawURL, token, contentType string, body []byte) (int, string, error) {
	return c.requestWithClient(ctx, nil, method, rawURL, token, contentType, body)
}

func (c *httpVLLM) requestWithClient(ctx context.Context, endpointClient *http.Client, method, rawURL, token, contentType string, body []byte) (int, string, error) {
	var requestBody io.Reader
	if body != nil {
		requestBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, requestBody)
	if err != nil {
		return 0, "", err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	hc := endpointClient
	if hc == nil {
		hc = c.hc
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	requestClient := *hc
	trustworthyAttempt := false
	var isolatedTransport *http.Transport
	switch transport := hc.Transport.(type) {
	case nil:
		// A caller may replace the exported DefaultTransport with a custom
		// RoundTripper. Only the standard transport provides the attempt
		// properties this classifier relies on; custom defaults stay unknown.
		if standard, ok := http.DefaultTransport.(*http.Transport); ok {
			isolatedTransport = standard.Clone()
		}
	case *http.Transport:
		isolatedTransport = transport.Clone()
	}
	if isolatedTransport != nil {
		// A new no-keepalive Transport cannot retry a stale pooled connection.
		// This makes the typed dial result the complete attempt history for this
		// request, while preserving TLS and custom DialContext settings. Proxy
		// routing is intentionally cleared below for selected-Pod containment.
		isolatedTransport.DisableKeepAlives = true
		// Serving control requests are bound to the selected Pod IP. Neither
		// HTTP_PROXY nor a configured proxy may receive the request or bearer.
		isolatedTransport.Proxy = nil
		requestClient.Transport = isolatedTransport
		trustworthyAttempt = true
		defer isolatedTransport.CloseIdleConnections()
	}
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := requestClient.Do(req)
	if err != nil {
		if trustworthyAttempt && definitelyUnsentServingRequest(err) {
			return 0, "", &definiteServingUnreachableError{cause: err}
		}
		return 0, "", fmt.Errorf("%w: %w", errServingOutcomeUnknown, err)
	}
	defer resp.Body.Close()
	b, readErr := readServingResponse(resp.Body)
	if readErr != nil {
		return resp.StatusCode, "", fmt.Errorf("%w after HTTP %d: %w", errServingOutcomeUnknown, resp.StatusCode, readErr)
	}
	return resp.StatusCode, b, nil
}

func readServingResponse(body io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(body, servingResponseMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read serving response: %w", err)
	}
	if len(b) > servingResponseMaxBytes {
		return "", fmt.Errorf("serving response exceeds %d bytes", servingResponseMaxBytes)
	}
	return string(b), nil
}

// definitelyUnsentServingRequest accepts only typed failures that occur before
// an HTTP request can reach a server. A standard Transport plus a no-redirect
// client gives a trustworthy single-attempt history. Error strings, generic
// net.Error, timeouts and custom transports are deliberately insufficient.
func definitelyUnsentServingRequest(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound && !dnsErr.IsTimeout {
		return true
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" || opErr.Timeout() {
		return false
	}
	return errors.Is(opErr, syscall.ECONNREFUSED) ||
		errors.Is(opErr, syscall.ENETUNREACH) ||
		errors.Is(opErr, syscall.EHOSTUNREACH)
}

func (c *httpVLLM) ModelReady(ctx context.Context, ep servingEndpoint) (bool, error) {
	var err error
	ep, err = ep.validated()
	if err != nil {
		return false, err
	}
	if !ep.reachable() {
		return false, errStackUnreachable
	}
	code, _, err := c.doEndpoint(ctx, ep, http.MethodGet, ep.healthPath)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, nil
	}
	// health 200 => live; the models route lists the loaded model => model-loaded.
	mcode, body, err := c.doEndpoint(ctx, ep, http.MethodGet, ep.modelsPath)
	if err != nil {
		if errors.Is(err, errStackUnreachable) {
			var unavailable *definiteServingUnreachableError
			if errors.As(err, &unavailable) {
				return false, fmt.Errorf("%w after confirmed health response: %w", errServingOutcomeUnknown, unavailable.cause)
			}
			return false, fmt.Errorf("%w after confirmed health response", errServingOutcomeUnknown)
		}
		return false, err
	}
	if mcode != http.StatusOK {
		return false, nil
	}
	if _, err := parseAdapterInventory([]byte(body), "\x00"); err != nil {
		return false, fmt.Errorf("serving model inventory: invalid bounded response")
	}
	return true, nil
}

func (c *httpVLLM) ResetPrefixCache(ctx context.Context, ep servingEndpoint) error {
	var err error
	ep, err = ep.validated()
	if err != nil {
		return err
	}
	if !ep.reachable() {
		return errStackUnreachable
	}
	code, body, err := c.doEndpoint(ctx, ep, http.MethodPost, ep.resetPath)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("%w: vLLM reset_prefix_cache acknowledgement unavailable after HTTP %d", errServingOutcomeUnknown, code)
	}
	if err := parseResetPrefixCacheAcknowledgement(body); err != nil {
		return fmt.Errorf("%w: vLLM reset_prefix_cache acknowledgement is invalid", errServingOutcomeUnknown)
	}
	return nil
}

// parseResetPrefixCacheAcknowledgement accepts only one complete bounded JSON object
// with the exact lowercase boolean field `success:true`. The vLLM request may have
// changed cache state before any nonconfirming response, so callers treat every parse
// failure as an unknown post-send outcome rather than a clean refusal. Extension fields
// are allowed, but case aliases and duplicate keys cannot override the required field.
func parseResetPrefixCacheAcknowledgement(body string) error {
	data := []byte(body)
	if len(data) == 0 || len(data) > servingResponseMaxBytes {
		return fmt.Errorf("response size must be 1..%d bytes", servingResponseMaxBytes)
	}
	if err := rejectDuplicateJSONFields(data); err != nil {
		return err
	}
	var envelope map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&envelope); err != nil || envelope == nil {
		return fmt.Errorf("expected one JSON object")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing reset acknowledgement data")
	}
	for key := range envelope {
		if strings.EqualFold(key, "success") && key != "success" {
			return fmt.Errorf("ambiguous success field alias")
		}
	}
	raw, present := envelope["success"]
	if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("success:true is required")
	}
	var success bool
	if err := json.Unmarshal(raw, &success); err != nil || !success {
		return fmt.Errorf("success must be boolean true")
	}
	return nil
}

// ---- GPU MIG control plane (NVML/nvidia-smi behind a node runner) ----

// nodeRunner executes a command on a specific node (a privileged DaemonSet exec / GPU-Operator agent
// in production). [PENDING-GPU-VALIDATION] — the default runner is UNCONFIGURED so MIG ops fail-closed
// rather than fabricate a reconfiguration; a deployment injects the real node-exec.
type nodeRunner interface {
	Prepare(ctx context.Context, node string) (preparedNodeRunner, error)
}

type preparedNodeRunner interface {
	Run(ctx context.Context, argv ...string) (stdout string, err error)
}

// migController abstracts the NVML/nvidia-smi MIG reconfiguration. Default impl = nvidiaSMIMIG.
type migController interface {
	// Prepare binds one node-agent identity before the caller mutates the workload.
	Prepare(ctx context.Context, node string) (preparedMIG, error)
}

type preparedMIG interface {
	// Capture is read-only and binds the requested selector to one physical GPU UUID.
	Capture(ctx context.Context, gpuID, targetProfile string) (migGeometry, error)
	// Repartition verifies the new geometry and makes one bounded attempt to restore prior.
	Repartition(ctx context.Context, prior migGeometry, targetProfile string, stillOwned func(context.Context) error) (migEffect, error)
}

type migGI struct {
	ProfileName string `json:"profileName"`
	ProfileID   int    `json:"profileID"`
	InstanceID  int    `json:"instanceID"`
	Start       int    `json:"start"`
	Size        int    `json:"size"`
	CI          migCI  `json:"computeInstance"`
}

type migCI struct {
	ProfileName string `json:"profileName"`
	ProfileID   int    `json:"profileID"`
	InstanceID  int    `json:"instanceID"`
}

// migGeometry deliberately supports only one full compute instance per GI. That is the
// subset nvidia-smi can recreate with -C without guessing a CI profile or placement.
type migGeometry struct {
	GPUUUID string  `json:"gpuUUID"`
	GIs     []migGI `json:"gpuInstances"`
}

type migEffect struct {
	Outcome     string
	OriginalErr error
	RecoveryErr error
	Current     migGeometry
}

// nvidiaSMIMIG is the REAL nvidia-smi MIG controller. The command sequence + ordering is implemented
// and unit-tested via a mock nodeRunner; the live node-exec + GPU are [PENDING-GPU-VALIDATION].
type nvidiaSMIMIG struct{ run nodeRunner }

func (m *nvidiaSMIMIG) Prepare(ctx context.Context, node string) (preparedMIG, error) {
	run, err := m.run.Prepare(ctx, node)
	if err != nil {
		return nil, err
	}
	return &preparedNVIDIASMIMIG{run: run}, nil
}

type preparedNVIDIASMIMIG struct{ run preparedNodeRunner }

var (
	gpuUUIDPattern = regexp.MustCompile(`^GPU-[0-9a-fA-F-]{8,}$`)
	profilePattern = regexp.MustCompile(`^[0-9]+g\.[0-9]+gb(?:\+me)?$`)
	// NVIDIA's -lgi table: GPU, "MIG <name>", profile ID, instance ID, placement start:size.
	giLinePattern = regexp.MustCompile(`^\|\s*(\d+)\s+MIG\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+):(\d+)\s*\|`)
	// NVIDIA's -lci table: GPU, GI ID, "MIG <name>", profile ID, CI ID.
	ciLinePattern            = regexp.MustCompile(`^\|\s*(\d+)\s+(\d+)\s+MIG\s+(\S+)\s+(\d+)\s+(\d+)\s*\|`)
	giProfileLinePattern     = regexp.MustCompile(`^\|\s*\d+\s+MIG\s+(\S+)\s+\d+\s+\d+/\d+\s+`)
	tableBorderPattern       = regexp.MustCompile(`^\+[+-]+\+$`)
	tableContinuationPattern = regexp.MustCompile(`^\|\s{10,}\d+\s+\d+\s+\d+(?:\s+\d+)*\s*\|$`)
)

const maxMIGInstances = 64

func (m *preparedNVIDIASMIMIG) Capture(ctx context.Context, gpuID, targetProfile string) (migGeometry, error) {
	if strings.TrimSpace(gpuID) == "" || strings.ContainsAny(gpuID, ",\n\r") || !profilePattern.MatchString(targetProfile) {
		return migGeometry{}, fmt.Errorf("mig capture: blank or ambiguous GPU selector")
	}
	uuidOut, err := m.run.Run(ctx, "nvidia-smi", "-i", gpuID, "--query-gpu=uuid", "--format=csv,noheader")
	if err != nil {
		return migGeometry{}, fmt.Errorf("mig capture GPU identity: %w", err)
	}
	lines := nonemptyLines(uuidOut)
	if len(lines) != 1 || !gpuUUIDPattern.MatchString(lines[0]) {
		return migGeometry{}, fmt.Errorf("mig capture: selector resolved to invalid or multiple physical GPU UUIDs")
	}
	profiles, err := m.run.Run(ctx, "nvidia-smi", "mig", "-i", lines[0], "-lgip")
	if err != nil {
		return migGeometry{}, fmt.Errorf("list target GPU profiles: %w", err)
	}
	if err := validateMIGTable(profiles, migTableProfiles); err != nil {
		return migGeometry{}, fmt.Errorf("GPU profile inventory: %w", err)
	}
	foundTarget := false
	for _, line := range strings.Split(profiles, "\n") {
		line = strings.TrimSpace(line)
		match := giProfileLinePattern.FindStringSubmatch(line)
		if match != nil {
			if match[1] == targetProfile {
				foundTarget = true
			}
			continue
		}
		if regexp.MustCompile(`^\|\s*\d`).MatchString(line) && !tableContinuationPattern.MatchString(line) {
			return migGeometry{}, fmt.Errorf("malformed GPU profile inventory row")
		}
	}
	if !foundTarget {
		return migGeometry{}, fmt.Errorf("target profile %q unavailable on physical GPU", targetProfile)
	}
	g, ciAbsent, err := m.captureUUID(ctx, lines[0])
	if err == nil && (len(g.GIs) == 0 || ciAbsent) {
		err = fmt.Errorf("unsupported MIG geometry: complete GI and full-CI inventory required")
	}
	return g, err
}

type migTableKind int

const (
	migTableProfiles migTableKind = iota
	migTableGI
	migTableCI
)

func validateMIGTable(out string, kind migTableKind) error {
	if len(out) == 0 || len(out) > 1<<16 {
		return fmt.Errorf("missing or oversized table")
	}
	headers := map[migTableKind][]*regexp.Regexp{
		migTableProfiles: {
			regexp.MustCompile(`^\|\s*GPU instance profiles:\s*\|$`),
			regexp.MustCompile(`^\|\s*GPU\s+Name\s+ID\s+Instances\s+Memory\s+P2P\s+SM\s+DEC\s+ENC.*\|$`),
			regexp.MustCompile(`^\|\s*Free/Total\s+GiB\s+CE\s+JPEG\s+OFA.*\|$`),
		},
		migTableGI: {
			regexp.MustCompile(`^\|\s*GPU instances:\s*\|$`),
			regexp.MustCompile(`^\|\s*GPU\s+Name\s+Profile\s+Instance\s+Placement\s*\|$`),
			regexp.MustCompile(`^\|\s*ID\s+ID\s+Start:Size\s*\|$`),
		},
		migTableCI: {
			regexp.MustCompile(`^\|\s*Compute instances:\s*\|$`),
			regexp.MustCompile(`^\|\s*GPU\s+GPU\s+Name\s+Profile\s+Instance\s*\|$`),
			regexp.MustCompile(`^\|\s*Instance\s+ID\s+ID\s*\|$`),
			regexp.MustCompile(`^\|\s*ID\s*\|$`),
		},
	}
	rows := map[migTableKind]*regexp.Regexp{migTableProfiles: giProfileLinePattern, migTableGI: giLinePattern, migTableCI: ciLinePattern}
	seenHeader := make([]bool, len(headers[kind]))
	border, separator := false, false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if tableBorderPattern.MatchString(line) {
			border = true
			continue
		}
		if strings.HasPrefix(line, "|===") && strings.HasSuffix(line, "|") {
			if separator {
				return fmt.Errorf("duplicate table separator")
			}
			separator = true
			continue
		}
		if !separator {
			matched := false
			for i, pattern := range headers[kind] {
				if pattern.MatchString(line) {
					if seenHeader[i] {
						return fmt.Errorf("duplicate table header")
					}
					seenHeader[i], matched = true, true
					break
				}
			}
			if matched {
				continue
			}
			return fmt.Errorf("unrecognized table header")
		}
		if rows[kind].MatchString(line) {
			continue
		}
		if kind == migTableProfiles && tableContinuationPattern.MatchString(line) && strings.HasSuffix(line, "|") {
			continue
		}
		return fmt.Errorf("unrecognized table data row")
	}
	if !border || !separator {
		return fmt.Errorf("incomplete table frame")
	}
	for _, seen := range seenHeader {
		if !seen {
			return fmt.Errorf("missing required table header")
		}
	}
	return nil
}

func nonemptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func (m *preparedNVIDIASMIMIG) captureUUID(ctx context.Context, uuid string) (migGeometry, bool, error) {
	giOut, err := m.run.Run(ctx, "nvidia-smi", "mig", "-i", uuid, "-lgi")
	if err != nil {
		return migGeometry{}, false, fmt.Errorf("list GPU instances: %w", err)
	}
	ciOut, err := m.run.Run(ctx, "nvidia-smi", "mig", "-i", uuid, "-lci")
	if err != nil {
		return migGeometry{}, false, fmt.Errorf("list compute instances: %w", err)
	}
	if len(giOut) > 1<<16 || len(ciOut) > 1<<16 {
		return migGeometry{}, false, fmt.Errorf("MIG inventory exceeds bounded input size")
	}
	giEmpty := strings.TrimSpace(giOut) == "No GPU instances found"
	ciEmpty := strings.TrimSpace(ciOut) == "No compute instances found"
	if !giEmpty {
		if err := validateMIGTable(giOut, migTableGI); err != nil {
			return migGeometry{}, false, fmt.Errorf("GPU instance inventory: %w", err)
		}
	}
	if !ciEmpty {
		if err := validateMIGTable(ciOut, migTableCI); err != nil {
			return migGeometry{}, false, fmt.Errorf("compute instance inventory: %w", err)
		}
	}
	g := migGeometry{GPUUUID: uuid}
	seenGI := map[int]bool{}
	gpuIndex := -1
	for _, line := range strings.Split(giOut, "\n") {
		line = strings.TrimSpace(line)
		match := giLinePattern.FindStringSubmatch(line)
		if match == nil {
			if regexp.MustCompile(`^\|\s*\d`).MatchString(line) {
				return migGeometry{}, false, fmt.Errorf("malformed GPU instance inventory row")
			}
			continue
		}
		if len(g.GIs) >= maxMIGInstances {
			return migGeometry{}, false, fmt.Errorf("unsupported MIG geometry: too many GPU instances")
		}
		rowGPU, rowGPUErr := strconv.Atoi(match[1])
		if rowGPUErr != nil || rowGPU < 0 {
			return migGeometry{}, false, fmt.Errorf("malformed GPU instance inventory")
		}
		if gpuIndex == -1 {
			gpuIndex = rowGPU
		} else if gpuIndex != rowGPU {
			return migGeometry{}, false, fmt.Errorf("multiple GPUs in GPU instance inventory")
		}
		vals := make([]int, 4)
		for i := range vals {
			vals[i], err = strconv.Atoi(match[i+3])
			if err != nil {
				return migGeometry{}, false, fmt.Errorf("malformed GPU instance inventory")
			}
		}
		if !profilePattern.MatchString(match[2]) || vals[1] < 0 || vals[2] < 0 || vals[3] <= 0 || seenGI[vals[1]] {
			return migGeometry{}, false, fmt.Errorf("unsupported or inconsistent GPU instance inventory")
		}
		seenGI[vals[1]] = true
		g.GIs = append(g.GIs, migGI{ProfileName: match[2], ProfileID: vals[0], InstanceID: vals[1], Start: vals[2], Size: vals[3]})
	}
	if len(g.GIs) == 0 {
		if !giEmpty {
			return migGeometry{}, false, fmt.Errorf("GPU instance inventory empty without unambiguous empty response")
		}
		if !ciEmpty {
			return migGeometry{}, false, fmt.Errorf("compute inventory inconsistent with empty GPU inventory")
		}
		return g, true, nil
	}
	ciAbsent := ciEmpty
	if ciAbsent {
		return g, true, nil
	}
	ciByGI := map[int]migCI{}
	seenCI := map[[2]int]bool{}
	for _, line := range strings.Split(ciOut, "\n") {
		line = strings.TrimSpace(line)
		match := ciLinePattern.FindStringSubmatch(line)
		if match == nil {
			if regexp.MustCompile(`^\|\s*\d`).MatchString(line) {
				return migGeometry{}, false, fmt.Errorf("malformed compute instance inventory row")
			}
			continue
		}
		gpu, e0 := strconv.Atoi(match[1])
		gi, e1 := strconv.Atoi(match[2])
		profileID, e2 := strconv.Atoi(match[4])
		ciID, e3 := strconv.Atoi(match[5])
		if e0 != nil || e1 != nil || e2 != nil || e3 != nil || gpu < 0 || gi < 0 || profileID < 0 || ciID < 0 || !seenGI[gi] || !profilePattern.MatchString(match[3]) {
			return migGeometry{}, false, fmt.Errorf("inconsistent compute instance inventory")
		}
		if gpuIndex != gpu {
			return migGeometry{}, false, fmt.Errorf("multiple GPUs in compute instance inventory")
		}
		key := [2]int{gi, ciID}
		if seenCI[key] {
			return migGeometry{}, false, fmt.Errorf("duplicate compute instance identity")
		}
		seenCI[key] = true
		if _, exists := ciByGI[gi]; exists {
			return migGeometry{}, false, fmt.Errorf("unsupported MIG geometry: multiple compute instances in GPU instance %d", gi)
		}
		ciByGI[gi] = migCI{ProfileName: match[3], ProfileID: profileID, InstanceID: ciID}
	}
	if len(ciByGI) == 0 {
		return migGeometry{}, false, fmt.Errorf("compute instance inventory has no parseable rows")
	}
	for i := range g.GIs {
		ci, ok := ciByGI[g.GIs[i].InstanceID]
		if !ok {
			return migGeometry{}, false, fmt.Errorf("unsupported MIG geometry: GPU instance %d does not contain exactly one full compute instance", g.GIs[i].InstanceID)
		}
		// A full CI is the documented starred profile whose name equals its containing GI.
		// A lone 1c/2c CI is still partial and cannot be recreated with -C equivalently.
		if ci.ProfileName != g.GIs[i].ProfileName {
			return migGeometry{}, false, fmt.Errorf("unsupported MIG geometry: compute profile %q does not fill GPU instance profile %q", ci.ProfileName, g.GIs[i].ProfileName)
		}
		g.GIs[i].CI = ci
	}
	for i := range g.GIs {
		for j := i + 1; j < len(g.GIs); j++ {
			if g.GIs[i].Start < g.GIs[j].Start+g.GIs[j].Size && g.GIs[j].Start < g.GIs[i].Start+g.GIs[i].Size {
				return migGeometry{}, false, fmt.Errorf("overlapping GPU instance placements")
			}
		}
	}
	sort.Slice(g.GIs, func(i, j int) bool { return g.GIs[i].Start < g.GIs[j].Start })
	return g, false, nil
}

func sameMIGGeometry(a, b migGeometry) bool {
	if a.GPUUUID != b.GPUUUID || len(a.GIs) != len(b.GIs) {
		return false
	}
	for i := range a.GIs {
		if a.GIs[i].ProfileID != b.GIs[i].ProfileID || a.GIs[i].Start != b.GIs[i].Start || a.GIs[i].Size != b.GIs[i].Size || a.GIs[i].ProfileName != b.GIs[i].ProfileName || a.GIs[i].CI.ProfileName != b.GIs[i].CI.ProfileName || a.GIs[i].CI.ProfileID != b.GIs[i].CI.ProfileID {
			return false
		}
	}
	return true
}

func sameMIGGIs(a, b migGeometry) bool {
	if a.GPUUUID != b.GPUUUID || len(a.GIs) != len(b.GIs) {
		return false
	}
	for i := range a.GIs {
		if a.GIs[i].ProfileName != b.GIs[i].ProfileName || a.GIs[i].ProfileID != b.GIs[i].ProfileID || a.GIs[i].InstanceID != b.GIs[i].InstanceID || a.GIs[i].Start != b.GIs[i].Start || a.GIs[i].Size != b.GIs[i].Size {
			return false
		}
	}
	return true
}

func validMIGGeometry(g migGeometry) bool {
	if !gpuUUIDPattern.MatchString(g.GPUUUID) || len(g.GIs) == 0 || len(g.GIs) > maxMIGInstances {
		return false
	}
	for i, gi := range g.GIs {
		if !profilePattern.MatchString(gi.ProfileName) || gi.ProfileID < 0 || gi.InstanceID < 0 || gi.Start < 0 || gi.Size <= 0 || gi.Start+gi.Size > maxMIGInstances || gi.CI.ProfileName != gi.ProfileName || gi.CI.ProfileID < 0 || gi.CI.InstanceID < 0 {
			return false
		}
		if i > 0 && g.GIs[i-1].Start+g.GIs[i-1].Size > gi.Start {
			return false
		}
	}
	return true
}

func (m *preparedNVIDIASMIMIG) Repartition(ctx context.Context, prior migGeometry, targetProfile string, stillOwned func(context.Context) error) (migEffect, error) {
	effect := migEffect{Outcome: "no-destructive-effect"}
	if !validMIGGeometry(prior) || !profilePattern.MatchString(targetProfile) {
		return effect, fmt.Errorf("mig repartition: invalid recovery snapshot or target profile")
	}
	steps := [][]string{{"nvidia-smi", "mig", "-i", prior.GPUUUID, "-dci"}, {"nvidia-smi", "mig", "-i", prior.GPUUUID, "-dgi"}, {"nvidia-smi", "mig", "-i", prior.GPUUUID, "-cgi", targetProfile, "-C"}}
	for _, argv := range steps {
		if err := m.mutationGuard(ctx, prior.GPUUUID, stillOwned); err != nil {
			effect.OriginalErr = err
			return effect, err
		}
		effect.Outcome = "unknown"
		if _, err := m.run.Run(ctx, argv...); err != nil {
			effect.OriginalErr = fmt.Errorf("step %v: %w", argv[3:], err)
			return m.compensate(ctx, prior, effect, stillOwned)
		}
	}
	current, ciAbsent, err := m.captureUUID(ctx, prior.GPUUUID)
	effect.Current = current
	if err == nil && !ciAbsent && len(current.GIs) == 1 && current.GIs[0].ProfileName == targetProfile {
		effect.Outcome = "new-geometry-verified"
		return effect, nil
	}
	effect.OriginalErr = fmt.Errorf("target geometry readback not verified: %w", err)
	return m.compensate(ctx, prior, effect, stillOwned)
}

func (m *preparedNVIDIASMIMIG) mutationGuard(ctx context.Context, uuid string, stillOwned func(context.Context) error) error {
	if stillOwned == nil {
		return fmt.Errorf("MIG operation ownership guard unavailable")
	}
	if err := stillOwned(ctx); err != nil {
		return fmt.Errorf("MIG operation ownership lost: %w", err)
	}
	out, err := m.run.Run(ctx, "nvidia-smi", "-i", uuid, "--query-gpu=uuid", "--format=csv,noheader")
	if err != nil || len(nonemptyLines(out)) != 1 || nonemptyLines(out)[0] != uuid {
		return fmt.Errorf("physical GPU identity changed or unavailable: %w", err)
	}
	return nil
}

func (m *preparedNVIDIASMIMIG) compensate(ctx context.Context, prior migGeometry, effect migEffect, stillOwned func(context.Context) error) (migEffect, error) {
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	current, ciAbsent, readErr := m.captureUUID(recoveryCtx, prior.GPUUUID)
	if readErr != nil {
		effect.Outcome, effect.RecoveryErr = "unknown", fmt.Errorf("recovery inventory unavailable: %w", readErr)
		return effect, errors.Join(effect.OriginalErr, effect.RecoveryErr)
	}
	if readErr == nil && sameMIGGeometry(current, prior) {
		effect.Outcome, effect.Current = "prior-geometry-restored", current
		return effect, effect.OriginalErr
	}
	if ciAbsent && sameMIGGIs(current, prior) {
		for i, gi := range prior.GIs {
			if err := m.mutationGuard(recoveryCtx, prior.GPUUUID, stillOwned); err != nil {
				effect.Outcome, effect.RecoveryErr = "unknown", err
				return effect, errors.Join(effect.OriginalErr, err)
			}
			if _, err := m.run.Run(recoveryCtx, "nvidia-smi", "mig", "-i", prior.GPUUUID, "-cci", strconv.Itoa(gi.CI.ProfileID), "-gi", strconv.Itoa(current.GIs[i].InstanceID)); err != nil {
				effect.Outcome, effect.RecoveryErr = "partial-unrestored", err
				return effect, errors.Join(effect.OriginalErr, fmt.Errorf("CI-only recovery: %w", err))
			}
		}
		current, ciAbsent, readErr = m.captureUUID(recoveryCtx, prior.GPUUUID)
		if readErr == nil && !ciAbsent && sameMIGGeometry(current, prior) {
			effect.Outcome, effect.Current = "prior-geometry-restored", current
			return effect, effect.OriginalErr
		}
		effect.Outcome, effect.RecoveryErr = "unknown", fmt.Errorf("CI-only recovery readback not verified: %w", readErr)
		return effect, errors.Join(effect.OriginalErr, effect.RecoveryErr)
	}
	// Never erase unexplained geometry. Recovery proceeds only from an observed empty layout.
	if readErr == nil && len(current.GIs) != 0 {
		effect.Outcome, effect.RecoveryErr = "partial-unrestored", fmt.Errorf("foreign or unexplained GPU instances present")
		return effect, errors.Join(effect.OriginalErr, effect.RecoveryErr)
	}
	for _, gi := range prior.GIs {
		if err := m.mutationGuard(recoveryCtx, prior.GPUUUID, stillOwned); err != nil {
			effect.Outcome, effect.RecoveryErr = "unknown", err
			return effect, errors.Join(effect.OriginalErr, err)
		}
		spec := fmt.Sprintf("%d:%d", gi.ProfileID, gi.Start)
		if _, err := m.run.Run(recoveryCtx, "nvidia-smi", "mig", "-i", prior.GPUUUID, "-cgi", spec, "-C"); err != nil {
			effect.Outcome, effect.RecoveryErr = "partial-unrestored", err
			return effect, errors.Join(effect.OriginalErr, fmt.Errorf("recovery: %w", err))
		}
	}
	current, ciAbsent, err := m.captureUUID(recoveryCtx, prior.GPUUUID)
	effect.Current = current
	if err != nil || ciAbsent || !sameMIGGeometry(current, prior) {
		effect.Outcome, effect.RecoveryErr = "unknown", fmt.Errorf("recovery readback: %w", err)
		return effect, errors.Join(effect.OriginalErr, effect.RecoveryErr)
	}
	effect.Outcome = "prior-geometry-restored"
	return effect, effect.OriginalErr
}

// ---- EnactCtx resolution: handlers use the injected client or the real package default ----

var pkgVLLM vLLMClient = newHTTPVLLM()

func (ec EnactCtx) vllm() vLLMClient {
	if ec.VLLM != nil {
		return ec.VLLM
	}
	return pkgVLLM
}

// mig resolves the GPU MIG controller: an injected mock, else the REAL client-aware controller whose
// nvidia-smi commands run through an operation-scoped prepared runner. pkgNodeRunner remains nil and
// fail-closed until a deployment supplies an explicit policy and wires it.
func (ec EnactCtx) mig() migController {
	if ec.MIG != nil {
		return ec.MIG
	}
	if pkgNodeRunner == nil {
		return &nvidiaSMIMIG{run: unwiredNodeRunner{}}
	}
	return &nvidiaSMIMIG{run: *pkgNodeRunner}
}
