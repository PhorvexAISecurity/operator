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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// ---- serving-stack control plane (vLLM default; Triton/TGI swappable) ----

// servingEndpoint identifies a model-serving pod's reachable HTTP control plane.
type servingEndpoint struct {
	podIP      string
	port       int
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
}

func (e servingEndpoint) reachable() bool { return e.podIP != "" && e.port > 0 }
func (e servingEndpoint) base() string    { return fmt.Sprintf("http://%s:%d", e.podIP, e.port) }

const (
	// Pod annotations let an operator declare the serving stack per workload without code change.
	annoServingPort  = "phorvex.ai/serving-port"  // default 8000 (vLLM OpenAI server)
	annoResetPath    = "phorvex.ai/kv-reset-path" // default vLLM prefix-cache reset
	annoHealthPath   = "phorvex.ai/health-path"   // default /health (liveness probe)
	annoModelsPath   = "phorvex.ai/models-path"   // default /v1/models (loaded-model list)
	annoServingTok   = "phorvex.ai/serving-token" // optional admin bearer (prefer a Secret ref in prod)
	defaultServePort = 8000
	// [PENDING-GPU-VALIDATION] confirm EVERY route against the deployed vLLM version: recent vLLM exposes
	// the prefix-cache reset on the engine; the exact routes differ by version/flag. All configurable via
	// the phorvex.ai/* annotations above (no hardcoded literal reaches the wire).
	defaultResetPath  = "/reset_prefix_cache"
	defaultHealthPath = "/health"
	defaultModelsPath = "/v1/models"
)

// endpointForPod derives the serving endpoint from a running pod (IP + declared port/path).
func endpointForPod(pod *corev1.Pod) servingEndpoint {
	ep := servingEndpoint{podIP: pod.Status.PodIP, port: defaultServePort, resetPath: defaultResetPath, healthPath: defaultHealthPath, modelsPath: defaultModelsPath}
	if v := pod.Annotations[annoServingPort]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ep.port = n
		}
	}
	if v := pod.Annotations[annoResetPath]; v != "" {
		ep.resetPath = v
	}
	if v := pod.Annotations[annoHealthPath]; v != "" {
		ep.healthPath = v
	}
	if v := pod.Annotations[annoModelsPath]; v != "" {
		ep.modelsPath = v
	}
	ep.token = pod.Annotations[annoServingTok]
	// P-ACTUATOR-SET-COMPLETE routes (annotation-overridable, vLLM-shaped defaults).
	ep = ep.withRoutes(pod.Annotations[annoUnloadPath], pod.Annotations[annoLoadPath],
		pod.Annotations[annoDrainPath], pod.Annotations[annoGuardrailPath], pod.Annotations[annoKVInvalidate])
	return ep
}

// errStackUnreachable signals case (b): no serving stack answered (connection refused/timeout/no IP)
// — distinct from a reachable-but-failing endpoint (case c, fail-closed).
var errStackUnreachable = errors.New("serving endpoint unreachable [PENDING-GPU-VALIDATION]")

// errAdapterAbsent means the serving stack answered and reported the named adapter is NOT
// loaded. For an EVICTION this is the goal state already met, not a failure — treating it as
// an error made adapter-rotate fail forever on a stale detector flag (the flag naming an
// adapter vLLM never had), which starved every other AI move on that pod. See adapterRotateHandler.
var errAdapterAbsent = errors.New("adapter not loaded on the serving stack")

// vLLMClient is the serving-stack control plane. Default impl = vLLM HTTP API. Swap for Triton/TGI.
type vLLMClient interface {
	// ModelReady reports whether the served model is LOADED + healthy at ep (warm-pool readiness).
	// Returns errStackUnreachable when no stack answers (so callers can fall back honestly on kind).
	ModelReady(ctx context.Context, ep servingEndpoint) (bool, error)
	// ResetPrefixCache flushes the prefix/KV cache in-process WITHOUT restarting (kv-reset).
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
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// connection refused / no route / timeout => unreachable (no serving stack here).
		var ne net.Error
		if errors.As(err, &ne) || strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "no such host") {
			return 0, "", errStackUnreachable
		}
		return 0, "", err
	}
	defer resp.Body.Close()
	b, readErr := io.ReadAll(io.LimitReader(resp.Body, servingResponseMaxBytes+1))
	if readErr != nil {
		return 0, "", fmt.Errorf("read serving response: %w", readErr)
	}
	if len(b) > servingResponseMaxBytes {
		return 0, "", fmt.Errorf("serving response exceeds %d bytes", servingResponseMaxBytes)
	}
	return resp.StatusCode, string(b), nil
}

func (c *httpVLLM) ModelReady(ctx context.Context, ep servingEndpoint) (bool, error) {
	if !ep.reachable() {
		return false, errStackUnreachable
	}
	code, _, err := c.do(ctx, http.MethodGet, ep.base()+ep.healthPath, ep.token)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, nil
	}
	// health 200 => live; the models route lists the loaded model => model-loaded.
	mcode, body, err := c.do(ctx, http.MethodGet, ep.base()+ep.modelsPath, ep.token)
	if err != nil {
		return false, err
	}
	return mcode == http.StatusOK && strings.Contains(body, "\"data\""), nil
}

func (c *httpVLLM) ResetPrefixCache(ctx context.Context, ep servingEndpoint) error {
	if !ep.reachable() {
		return errStackUnreachable
	}
	code, body, err := c.do(ctx, http.MethodPost, ep.base()+ep.resetPath, ep.token)
	if err != nil {
		return err
	}
	if code != http.StatusOK && code != http.StatusNoContent {
		return fmt.Errorf("vLLM reset_prefix_cache: HTTP %d %s", code, strings.TrimSpace(body))
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
