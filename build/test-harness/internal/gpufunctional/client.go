package gpufunctional

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxResponseBytes = 1 << 20
	modelName        = "facebook/opt-125m"
	primerPrompt     = "A short synthetic GPU metrics primer."
)

var metricNames = []string{
	"vllm:gpu_prefix_cache_hit_rate",
	"vllm:num_requests_running",
	"vllm:num_requests_waiting",
	"vllm:gpu_cache_usage_perc",
	"vllm:prompt_tokens_total",
}

// Observation retains bounded response metadata and a digest, never bearer
// material or prompt text.
type Observation struct {
	Path       string `json:"path"`
	Status     int    `json:"status"`
	MediaType  string `json:"mediaType"`
	Bytes      int    `json:"bytes"`
	SHA256     string `json:"sha256"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	// Body retains bounded safe control-plane JSON for independent replay. It is
	// deliberately omitted from inference observations, whose generated text is
	// reduced to a digest in Inference.
	Body string `json:"body,omitempty"`
}

type Capability struct {
	Schema                  string `json:"schema"`
	Capability              string `json:"capability"`
	PodUID                  string `json:"pod_uid"`
	LedgerID                string `json:"ledger_id"`
	ProxyBootID             string `json:"proxy_boot_id"`
	EngineBootID            string `json:"engine_boot_id"`
	IncarnationDigest       string `json:"incarnation_digest"`
	ProxySource             string `json:"proxy_source"`
	EngineSource            string `json:"engine_source"`
	EngineMode              string `json:"engine_mode"`
	VirtualEngineIDs        []int  `json:"virtual_engine_ids"`
	GenerationHighWater     string `json:"generation_high_water"`
	NextOperationGeneration string `json:"next_operation_generation"`
	Admission               string `json:"admission"`
}

type Inference struct {
	ID           string         `json:"id"`
	Model        string         `json:"model"`
	TextSHA256   string         `json:"textSHA256"`
	FinishReason string         `json:"finishReason"`
	Usage        map[string]any `json:"usage"`
	Observation  Observation    `json:"observation"`
}

type Metrics struct {
	Values                      map[string]float64 `json:"values"`
	RequestSuccessMetricPresent bool               `json:"requestSuccessMetricPresent"`
	RawBody                     string             `json:"rawBody"`
	Observation                 Observation        `json:"observation"`
}

type Reset struct {
	Success     bool        `json:"success"`
	Observation Observation `json:"observation"`
}

type Client struct {
	base  *url.URL
	token string
	http  *http.Client
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

func New(baseURL, token string, client *http.Client) (*Client, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "http" || base.Host == "" || base.Path != "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("GPU functional probe requires an exact loopback HTTP origin")
	}
	host := base.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return nil, errors.New("GPU functional probe refuses a non-loopback origin")
	}
	if strings.TrimSpace(token) != token || len(token) < 32 {
		return nil, errors.New("GPU functional bearer is absent or unexpectedly short")
	}
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: base, token: token, http: &copyClient, now: time.Now, sleep: sleepContext}, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) request(ctx context.Context, method, path string, body any, auth bool) (Observation, []byte, error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return Observation{}, nil, errors.New("invalid probe path")
	}
	var rawBody []byte
	var err error
	if body != nil {
		rawBody, err = json.Marshal(body)
		if err != nil {
			return Observation{}, nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, bytes.NewReader(rawBody))
	if err != nil {
		return Observation{}, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	started := c.now().UTC()
	resp, err := c.http.Do(req)
	if err != nil {
		return Observation{Path: path, StartedAt: started.Format(time.RFC3339Nano), FinishedAt: c.now().UTC().Format(time.RFC3339Nano)}, nil, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	finished := c.now().UTC()
	mediaType, _, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	obs := Observation{Path: path, Status: resp.StatusCode, MediaType: strings.ToLower(mediaType), Bytes: len(raw), SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), StartedAt: started.Format(time.RFC3339Nano), FinishedAt: finished.Format(time.RFC3339Nano)}
	if readErr != nil {
		return obs, raw, readErr
	}
	if len(raw) > MaxResponseBytes {
		return obs, raw[:MaxResponseBytes], errors.New("GPU functional response exceeds byte bound")
	}
	if mediaErr != nil {
		return obs, raw, fmt.Errorf("invalid response content type: %w", mediaErr)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return obs, raw, fmt.Errorf("redirect refused: HTTP %d", resp.StatusCode)
	}
	return obs, raw, nil
}

func strictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := decodeValue(dec)
	if err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("JSON contains a trailing value")
		}
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return err
	}
	typed := json.NewDecoder(bytes.NewReader(canonical))
	typed.DisallowUnknownFields()
	if err := typed.Decode(dst); err != nil {
		return err
	}
	return nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			out := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("JSON object key is not a string")
				}
				if _, exists := out[key]; exists {
					return nil, fmt.Errorf("duplicate JSON key %q", key)
				}
				child, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				out[key] = child
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid JSON object terminator")
			}
			return out, nil
		case '[':
			out := []any{}
			for dec.More() {
				child, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				out = append(out, child)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid JSON array terminator")
			}
			return out, nil
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	case json.Number:
		if _, err := strconv.ParseFloat(string(value), 64); err != nil {
			return nil, err
		}
		return value, nil
	case string, bool, nil:
		return value, nil
	default:
		return nil, fmt.Errorf("unsupported JSON token %T", value)
	}
}

func requireJSON(obs Observation, raw []byte, wantStatus int, dst any) error {
	if obs.Status != wantStatus {
		return fmt.Errorf("%s returned HTTP %d, want %d", obs.Path, obs.Status, wantStatus)
	}
	if obs.MediaType != "application/json" {
		return fmt.Errorf("%s returned media type %q", obs.Path, obs.MediaType)
	}
	return strictJSON(raw, dst)
}

func (c *Client) Capability(ctx context.Context) (Capability, Observation, error) {
	obs, raw, err := c.request(ctx, http.MethodGet, "/v1/drain/capability", nil, true)
	obs.Body = string(raw)
	if err != nil {
		return Capability{}, obs, err
	}
	var cap Capability
	if err := requireJSON(obs, raw, http.StatusOK, &cap); err != nil {
		return Capability{}, obs, err
	}
	if cap.Schema != "phorvex.drain.v1" || cap.Capability != "operation-bound-quiescence-v1" || cap.EngineMode != "v0-frontend-multiprocessing" || len(cap.VirtualEngineIDs) != 1 || cap.VirtualEngineIDs[0] != 0 || !hexPattern(32).MatchString(cap.EngineBootID) || !hexPattern(64).MatchString(cap.IncarnationDigest) || !hexPattern(64).MatchString(cap.EngineSource) || cap.Admission != "OPEN" && cap.Admission != "CLOSED" {
		return Capability{}, obs, errors.New("drain capability identity or supported mode differs")
	}
	if cap.PodUID == "" || cap.ProxyBootID == "" || cap.LedgerID == "" || cap.ProxySource == "" {
		return Capability{}, obs, errors.New("drain capability omitted runtime identity")
	}
	if _, err := strconv.ParseUint(cap.NextOperationGeneration, 10, 64); err != nil {
		return Capability{}, obs, errors.New("drain capability next generation is invalid")
	}
	return cap, obs, nil
}

func hexPattern(n int) *regexp.Regexp { return regexp.MustCompile(fmt.Sprintf(`^[0-9a-f]{%d}$`, n)) }

func (c *Client) Inference(ctx context.Context, prompt string, maxTokens int) (Inference, error) {
	if prompt == "" || len(prompt) > 8192 || maxTokens < 1 || maxTokens > 256 {
		return Inference{}, errors.New("inference input exceeds fixed bounds")
	}
	body := map[string]any{"model": modelName, "prompt": prompt, "max_tokens": maxTokens, "temperature": 0, "seed": 1}
	obs, raw, err := c.request(ctx, http.MethodPost, "/v1/completions", body, true)
	if err != nil {
		return Inference{Observation: obs}, err
	}
	var wire struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
		Choices []struct {
			Index          int    `json:"index"`
			Text           string `json:"text"`
			Logprobs       any    `json:"logprobs"`
			FinishReason   string `json:"finish_reason"`
			StopReason     any    `json:"stop_reason"`
			PromptLogprobs any    `json:"prompt_logprobs"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := requireJSON(obs, raw, http.StatusOK, &wire); err != nil {
		return Inference{Observation: obs}, err
	}
	if wire.Object != "text_completion" || wire.Model != modelName || wire.Created <= 0 || len(wire.Choices) != 1 || wire.Choices[0].Index != 0 || wire.ID == "" || wire.Choices[0].Text == "" {
		return Inference{Observation: obs}, errors.New("inference response differs from exact completion contract")
	}
	for _, field := range []string{"prompt_tokens", "total_tokens", "completion_tokens"} {
		if _, ok := wire.Usage[field].(float64); !ok {
			return Inference{Observation: obs}, fmt.Errorf("inference usage omitted numeric %s", field)
		}
	}
	return Inference{ID: wire.ID, Model: wire.Model, TextSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(wire.Choices[0].Text))), FinishReason: wire.Choices[0].FinishReason, Usage: wire.Usage, Observation: obs}, nil
}

func (c *Client) Reset(ctx context.Context) (Reset, error) {
	obs, raw, err := c.request(ctx, http.MethodPost, "/reset_prefix_cache", map[string]any{}, true)
	obs.Body = string(raw)
	if err != nil {
		return Reset{Observation: obs}, err
	}
	var body struct {
		Success bool `json:"success"`
	}
	if err := requireJSON(obs, raw, http.StatusOK, &body); err != nil {
		return Reset{Observation: obs}, err
	}
	return Reset{Success: body.Success, Observation: obs}, nil
}

func (c *Client) Metrics(ctx context.Context) (Metrics, error) {
	return c.metrics(ctx, true)
}

func (c *Client) coldMetrics(ctx context.Context) (Metrics, error) {
	return c.metrics(ctx, false)
}

func (c *Client) metrics(ctx context.Context, requireRequestSuccess bool) (Metrics, error) {
	obs, raw, err := c.request(ctx, http.MethodGet, "/metrics", nil, false)
	if err != nil {
		return Metrics{Observation: obs}, err
	}
	if obs.Status != http.StatusOK || obs.MediaType != "text/plain" {
		return Metrics{Observation: obs}, fmt.Errorf("metrics boundary returned HTTP %d media type %q", obs.Status, obs.MediaType)
	}
	if len(raw) > 256<<10 {
		return Metrics{Observation: obs}, errors.New("metrics response exceeds 256KiB evidence bound")
	}
	values, requestSuccessPresent, err := parseMetricsMode(raw, requireRequestSuccess)
	return Metrics{Values: values, RequestSuccessMetricPresent: requestSuccessPresent, RawBody: string(raw), Observation: obs}, err
}

func parseMetrics(raw []byte) (map[string]float64, error) {
	values, _, err := parseMetricsMode(raw, true)
	return values, err
}

func parseMetricsMode(raw []byte, requireRequestSuccess bool) (map[string]float64, bool, error) {
	text := string(raw)
	values := map[string]float64{}
	for _, name := range metricNames {
		pattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `(\{[^\n]*\})?\s+([-+0-9.eE]+)$`)
		matches := pattern.FindAllStringSubmatch(text, -1)
		labels, labelErr := parseMetricLabels(singleMetricLabels(matches))
		if len(matches) != 1 || labelErr != nil || len(labels) != 1 || labels["model_name"] != modelName {
			return nil, false, fmt.Errorf("metric %s did not have one exact model series", name)
		}
		value, err := strconv.ParseFloat(matches[0][2], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, false, fmt.Errorf("metric %s is non-finite", name)
		}
		values[name] = value
	}
	completedPattern := regexp.MustCompile(`(?m)^vllm:request_success_total(\{[^\n]*\})\s+([-+0-9.eE]+)$`)
	matches := completedPattern.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		if regexp.MustCompile(`(?m)^vllm:request_success_total(?:\{|\s)`).MatchString(text) {
			return nil, false, errors.New("request success metric is malformed")
		}
		if requireRequestSuccess {
			return nil, false, errors.New("request success metric is absent")
		}
		return values, false, nil
	}
	seen := map[string]bool{}
	for _, match := range matches {
		labels, err := parseMetricLabels(match[1])
		if err != nil || len(labels) != 2 || labels["model_name"] != modelName || labels["finished_reason"] == "" {
			return nil, false, errors.New("request success metric has unexpected labels")
		}
		finishReason := labels["finished_reason"]
		if seen[finishReason] {
			return nil, false, errors.New("duplicate request success finish reason")
		}
		seen[finishReason] = true
		value, err := strconv.ParseFloat(match[2], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, false, errors.New("request success metric is non-finite")
		}
		values["vllm:request_success_total"] += value
	}
	return values, true, nil
}

func singleMetricLabels(matches [][]string) string {
	if len(matches) != 1 {
		return ""
	}
	return matches[0][1]
}

func parseMetricLabels(raw string) (map[string]string, error) {
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return nil, errors.New("metric labels are absent")
	}
	content := raw[1 : len(raw)-1]
	if content == "" {
		return nil, errors.New("metric labels are empty")
	}
	labels := map[string]string{}
	labelPattern := regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)="([^"\\]*)"$`)
	for _, item := range strings.Split(content, ",") {
		match := labelPattern.FindStringSubmatch(item)
		if match == nil {
			return nil, errors.New("metric label syntax is unsupported")
		}
		if _, duplicate := labels[match[1]]; duplicate {
			return nil, errors.New("metric label is duplicated")
		}
		labels[match[1]] = match[2]
	}
	return labels, nil
}

func (c *Client) waitMetrics(ctx context.Context, bound time.Duration, predicate func(map[string]float64) bool) (Metrics, error) {
	deadline := c.now().Add(bound)
	var last Metrics
	for attempts := 0; attempts < 40 && c.now().Before(deadline); attempts++ {
		m, err := c.Metrics(ctx)
		last = m
		if err != nil {
			return last, err
		}
		if predicate(m.Values) {
			return m, nil
		}
		if err := c.sleep(ctx, 250*time.Millisecond); err != nil {
			return last, err
		}
	}
	return last, errors.New("fresh metric predicate was not observed within bound")
}

// PrefixReceipt is progressively filled so callers retain valid observations
// if a later boundary fails.
type PrefixReceipt struct {
	CapabilityObservation Observation  `json:"capabilityObservation"`
	EngineBootID          string       `json:"engineBootID"`
	Cold                  Metrics      `json:"cold"`
	Primer                Inference    `json:"primer"`
	Baseline              Metrics      `json:"baseline"`
	First                 Inference    `json:"first"`
	Second                Inference    `json:"second"`
	Populated             Metrics      `json:"populated"`
	Reset                 *Reset       `json:"reset,omitempty"`
	Cleared               *Metrics     `json:"cleared,omitempty"`
	FirstAfterReset       *Inference   `json:"firstAfterReset,omitempty"`
	FirstMiss             *Metrics     `json:"firstMiss,omitempty"`
	SecondAfterReset      *Inference   `json:"secondAfterReset,omitempty"`
	Repopulated           *Metrics     `json:"repopulated,omitempty"`
	Busy                  *BusyReceipt `json:"busy,omitempty"`
}

type BusyReceipt struct {
	ActiveMetrics   Metrics `json:"activeMetrics"`
	Reset           Reset   `json:"reset"`
	StreamAccepted  bool    `json:"streamAccepted"`
	StreamRequestID string  `json:"streamRequestID,omitempty"`
	StreamFinished  bool    `json:"streamFinished"`
}

func (c *Client) RunPrefix(ctx context.Context, direct bool) (PrefixReceipt, error) {
	var receipt PrefixReceipt
	cap, capObs, err := c.Capability(ctx)
	receipt.CapabilityObservation = capObs
	receipt.EngineBootID = cap.EngineBootID
	if err != nil {
		return receipt, err
	}
	if cap.Admission != "OPEN" {
		return receipt, errors.New("prefix fixture admission is not open")
	}
	receipt.Cold, err = c.coldMetrics(ctx)
	if err != nil {
		return receipt, err
	}
	if !idle(receipt.Cold.Values) {
		return receipt, errors.New("prefix fixture was not idle before metrics primer")
	}
	coldPrompt := receipt.Cold.Values["vllm:prompt_tokens_total"]
	coldCompleted := receipt.Cold.Values["vllm:request_success_total"]
	receipt.Primer, err = c.Inference(ctx, primerPrompt, 1)
	if err != nil {
		return receipt, err
	}
	receipt.Baseline, err = c.waitMetrics(ctx, 15*time.Second, func(v map[string]float64) bool {
		completedAdvanced := v["vllm:request_success_total"] >= 1
		if receipt.Cold.RequestSuccessMetricPresent {
			completedAdvanced = v["vllm:request_success_total"] >= coldCompleted+1
		}
		return idle(v) && v["vllm:prompt_tokens_total"] > coldPrompt && completedAdvanced
	})
	if err != nil {
		return receipt, err
	}
	prompt := strings.TrimSpace(strings.Repeat("one two three four five six seven eight ", 20))
	receipt.First, err = c.Inference(ctx, prompt, 1)
	if err != nil {
		return receipt, err
	}
	receipt.Second, err = c.Inference(ctx, prompt, 1)
	if err != nil {
		return receipt, err
	}
	p0 := receipt.Baseline.Values["vllm:prompt_tokens_total"]
	c0 := receipt.Baseline.Values["vllm:request_success_total"]
	receipt.Populated, err = c.waitMetrics(ctx, 15*time.Second, func(v map[string]float64) bool {
		return v["vllm:prompt_tokens_total"] > p0 && v["vllm:request_success_total"] >= c0+2 && v["vllm:gpu_prefix_cache_hit_rate"] > 0
	})
	if err != nil || !direct {
		return receipt, err
	}
	reset, err := c.Reset(ctx)
	receipt.Reset = &reset
	if err != nil {
		return receipt, err
	}
	if !reset.Success {
		return receipt, errors.New("idle prefix reset was refused")
	}
	cleared, err := c.waitMetrics(ctx, 15*time.Second, func(v map[string]float64) bool { return idle(v) && v["vllm:gpu_prefix_cache_hit_rate"] == 0 })
	receipt.Cleared = &cleared
	if err != nil {
		return receipt, err
	}
	first, err := c.Inference(ctx, prompt, 1)
	receipt.FirstAfterReset = &first
	if err != nil {
		return receipt, err
	}
	p1, c1 := cleared.Values["vllm:prompt_tokens_total"], cleared.Values["vllm:request_success_total"]
	miss, err := c.waitMetrics(ctx, 15*time.Second, func(v map[string]float64) bool {
		return v["vllm:prompt_tokens_total"] > p1 && v["vllm:request_success_total"] >= c1+1 && v["vllm:gpu_prefix_cache_hit_rate"] == 0
	})
	receipt.FirstMiss = &miss
	if err != nil {
		return receipt, err
	}
	second, err := c.Inference(ctx, prompt, 1)
	receipt.SecondAfterReset = &second
	if err != nil {
		return receipt, err
	}
	p2, c2 := miss.Values["vllm:prompt_tokens_total"], miss.Values["vllm:request_success_total"]
	repop, err := c.waitMetrics(ctx, 15*time.Second, func(v map[string]float64) bool {
		return v["vllm:prompt_tokens_total"] > p2 && v["vllm:request_success_total"] >= c2+1 && v["vllm:gpu_prefix_cache_hit_rate"] > 0
	})
	receipt.Repopulated = &repop
	if err != nil {
		return receipt, err
	}
	busy, err := c.runBusyRefusal(ctx)
	receipt.Busy = &busy
	return receipt, err
}

func idle(v map[string]float64) bool {
	return v["vllm:num_requests_running"] == 0 && v["vllm:num_requests_waiting"] == 0
}

func (c *Client) runBusyRefusal(ctx context.Context) (receipt BusyReceipt, retErr error) {
	stream := c.startStream(ctx)
	defer func() { retErr = errors.Join(retErr, stream.stop()) }()
	select {
	case <-stream.accepted:
		receipt.StreamAccepted = true
		receipt.StreamRequestID = stream.identity()
	case <-stream.finished:
		return receipt, fmt.Errorf("busy request finished before operation: %w", stream.result())
	case <-time.After(10 * time.Second):
		return receipt, errors.New("busy request admission was not observed")
	case <-ctx.Done():
		return receipt, ctx.Err()
	}
	active, err := c.waitMetrics(ctx, 5*time.Second, func(v map[string]float64) bool {
		return v["vllm:num_requests_running"]+v["vllm:num_requests_waiting"] > 0
	})
	receipt.ActiveMetrics = active
	if err != nil {
		return receipt, err
	}
	select {
	case <-stream.finished:
		return receipt, fmt.Errorf("busy control stream finished after active sample and before reset: %w", stream.result())
	default:
	}
	reset, err := c.Reset(ctx)
	receipt.Reset = reset
	if err != nil {
		return receipt, err
	}
	if reset.Success {
		select {
		case <-stream.finished:
			receipt.StreamFinished = true
			return receipt, errors.New("busy control became inconclusive because the stream finished during reset")
		default:
			return receipt, errors.New("prefix reset acknowledged while correlated owned inference was active")
		}
	}
	select {
	case <-stream.finished:
		receipt.StreamFinished = true
		return receipt, stream.result()
	case <-time.After(30 * time.Second):
		return receipt, errors.New("busy inference exceeded declared bound")
	case <-ctx.Done():
		return receipt, ctx.Err()
	}
}

type streamExecution struct {
	accepted    chan struct{}
	finished    chan struct{}
	cancel      context.CancelFunc
	mu          sync.Mutex
	id          string
	err         error
	joinTimeout time.Duration
}

func (c *Client) startStream(ctx context.Context) *streamExecution {
	streamCtx, cancel := context.WithCancel(ctx)
	run := &streamExecution{accepted: make(chan struct{}), finished: make(chan struct{}), cancel: cancel, joinTimeout: 2 * time.Second}
	go func() {
		err := c.stream(streamCtx, run)
		run.mu.Lock()
		run.err = err
		run.mu.Unlock()
		close(run.finished)
	}()
	return run
}

func (s *streamExecution) identity() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id
}

func (s *streamExecution) result() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *streamExecution) stop() error {
	s.cancel()
	select {
	case <-s.finished:
		return nil
	case <-time.After(s.joinTimeout):
		return errors.New("owned inference stream did not stop within cleanup bound")
	}
}

func (c *Client) stream(ctx context.Context, run *streamExecution) error {
	body, _ := json.Marshal(map[string]any{"model": modelName, "prompt": strings.TrimSpace(strings.Repeat("one two three four five six seven eight ", 12)), "max_tokens": 128, "temperature": 0, "seed": 1, "stream": true, "ignore_eos": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+"/v1/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || mediaType != "text/event-stream" {
		return fmt.Errorf("busy stream HTTP %d media type %q", resp.StatusCode, mediaType)
	}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, MaxResponseBytes+1))
	scanner.Buffer(make([]byte, 4096), 1<<16)
	once := sync.Once{}
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
			continue
		}
		var event struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
			Model   string `json:"model"`
			Choices []struct {
				Index        int    `json:"index"`
				Text         string `json:"text"`
				Logprobs     any    `json:"logprobs"`
				FinishReason any    `json:"finish_reason"`
				StopReason   any    `json:"stop_reason"`
			} `json:"choices"`
			Usage any `json:"usage,omitempty"`
		}
		if err := strictJSON([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			return err
		}
		if event.ID == "" || event.Object != "text_completion" || event.Created <= 0 || event.Model != modelName || len(event.Choices) != 1 || event.Choices[0].Index != 0 {
			return errors.New("invalid busy stream event")
		}
		once.Do(func() {
			run.mu.Lock()
			run.id = event.ID
			run.mu.Unlock()
			close(run.accepted)
		})
	}
	return scanner.Err()
}

func randomHex16() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
