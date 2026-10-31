package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	prometheusRunEvidenceSchema = "phorvex.prometheus-run-evidence.v1"
	prometheusRunEvidenceFile   = "prometheus-evidence.json"
	prometheusResponseLimit     = 512 << 10
)

// PrometheusRunEvidenceConfig is deployment-owned. None of these values are
// accepted from a catalogue launch request.
type PrometheusRunEvidenceConfig struct {
	Enabled        bool
	URL            string
	Environment    string
	SettleDelay    time.Duration
	RequestTimeout time.Duration
	RangeStep      time.Duration
}

type PrometheusSample struct {
	Time  float64 `json:"time"`
	Value float64 `json:"value"`
}

type PrometheusSeries struct {
	Labels  map[string]string  `json:"labels"`
	Samples []PrometheusSample `json:"samples"`
}

type PrometheusDelta struct {
	Labels          map[string]string `json:"labels"`
	BaselinePresent bool              `json:"baselinePresent"`
	FinalPresent    bool              `json:"finalPresent"`
	Baseline        float64           `json:"baseline"`
	Final           float64           `json:"final"`
	Delta           float64           `json:"delta"`
	CounterReset    bool              `json:"counterReset"`
}

type PrometheusMetricEvidence struct {
	Key             string                     `json:"key"`
	Query           string                     `json:"query"`
	QuerySHA256     string                     `json:"querySHA256"`
	Baseline        []PrometheusSeries         `json:"baseline"`
	Final           []PrometheusSeries         `json:"final,omitempty"`
	Range           []PrometheusSeries         `json:"range,omitempty"`
	BaselineCapture *PrometheusResponseCapture `json:"baselineCapture,omitempty"`
	FinalCapture    *PrometheusResponseCapture `json:"finalCapture,omitempty"`
	RawCapture      *PrometheusResponseCapture `json:"rawCapture,omitempty"`
	Deltas          []PrometheusDelta          `json:"deltas,omitempty"`
	Errors          []string                   `json:"errors,omitempty"`
}

type PrometheusResponseCapture struct {
	CapturedAt    time.Time         `json:"capturedAt"`
	Path          string            `json:"path"`
	Parameters    map[string]string `json:"parameters"`
	SHA256        string            `json:"sha256"`
	RawBodySHA256 string            `json:"rawBodySHA256"`
	ResponseBody  string            `json:"responseBody"`
	Payload       json.RawMessage   `json:"payload"`
}

// PrometheusRunEvidence is the durable, replayable telemetry slice for one
// catalogue run. The raw samples and exact PromQL remain available after
// Prometheus retention expires; summaries are derived only from those samples.
type PrometheusRunEvidence struct {
	Schema         string                     `json:"schema"`
	RunID          string                     `json:"runID"`
	CatalogueID    string                     `json:"catalogueID"`
	Family         string                     `json:"family,omitempty"`
	Tenant         string                     `json:"tenant"`
	Environment    string                     `json:"environment"`
	ExpectedAction string                     `json:"expectedAction"`
	ExecutionMode  AttackCatalogExecutionMode `json:"executionMode"`
	TriggerMode    AttackCatalogTriggerMode   `json:"triggerMode"`
	// ObservedDecisionModes is derived from positive selected-action counter
	// deltas, never from the requested console switch. Empty means no selected
	// reactive/proactive decision was observed in this run's evidence window.
	ObservedDecisionModes []string                   `json:"observedDecisionModes"`
	Status                string                     `json:"status"` // BASELINE_CAPTURED | COMPLETE | PARTIAL
	StartedAt             time.Time                  `json:"startedAt"`
	BaselineAt            time.Time                  `json:"baselineAt"`
	FinishedAt            *time.Time                 `json:"finishedAt,omitempty"`
	CapturedAt            *time.Time                 `json:"capturedAt,omitempty"`
	RangeStep             string                     `json:"rangeStep"`
	Metrics               []PrometheusMetricEvidence `json:"metrics"`
	Errors                []string                   `json:"errors,omitempty"`
}

type prometheusAPIResponse struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string                `json:"resultType"`
		Result     []prometheusAPISeries `json:"result"`
	} `json:"data"`
}

type prometheusAPISeries struct {
	Metric map[string]string   `json:"metric"`
	Value  []json.RawMessage   `json:"value"`
	Values [][]json.RawMessage `json:"values"`
}

type prometheusRunQuery struct{ key, query string }

func prometheusRunQueries(tenant, environment, action string) []prometheusRunQuery {
	selector := `tenant=` + strconv.Quote(tenant) + `,environment=` + strconv.Quote(environment)
	actionSelector := selector + `,action=` + strconv.Quote(action)
	return []prometheusRunQuery{
		{key: "telemetry-source-fresh", query: `(time() - max(timestamp(phorvex_decisions_total{environment=` + strconv.Quote(environment) + `}))) < bool 90`},
		{key: "selected-action", query: `sum by (mode) (phorvex_decisions_total{` + actionSelector + `,selected="true"})`},
		{key: "accepted-actuation", query: `sum(phorvex_actuations_total{` + actionSelector + `})`},
		{key: "actuation-attempts", query: `sum by (outcome) (phorvex_actuation_attempts_total{` + actionSelector + `})`},
		{key: "noop", query: `sum by (mode,selected) (phorvex_decisions_total{` + selector + `,action="noop"})`},
		{key: "candidate-gates", query: `sum by (first_gate) (phorvex_candidates_gated_total{` + actionSelector + `})`},
		{key: "candidate-exclusions", query: `sum by (reason) (phorvex_candidates_excluded_total{` + actionSelector + `})`},
		{key: "trusted-events", query: `sum by (trust) (phorvex_security_events_first_seen_total{namespace=` + strconv.Quote(tenant) + `,environment=` + strconv.Quote(environment) + `})`},
	}
}

func (c PrometheusRunEvidenceConfig) normalized() PrometheusRunEvidenceConfig {
	if c.SettleDelay <= 0 {
		c.SettleDelay = 35 * time.Second
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 10 * time.Second
	}
	if c.RangeStep <= 0 {
		c.RangeStep = 15 * time.Second
	}
	c.URL = strings.TrimRight(strings.TrimSpace(c.URL), "/")
	c.Environment = strings.TrimSpace(c.Environment)
	return c
}

func (c PrometheusRunEvidenceConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	c = c.normalized()
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("run Prometheus evidence URL must be one server-owned HTTP(S) origin")
	}
	if c.Environment == "" {
		return errors.New("run Prometheus evidence environment is required")
	}
	return nil
}

// Validate rejects an unsafe deployment-owned telemetry source before the
// service starts. It is exported only for the shared console/attacks launcher.
func (c PrometheusRunEvidenceConfig) Validate() error { return c.validate() }

func (s *Server) beginPrometheusRunEvidence(ctx context.Context, runID, catalogueID, family, tenant, action string, executionMode AttackCatalogExecutionMode, triggerMode AttackCatalogTriggerMode, started time.Time) (*PrometheusRunEvidence, error) {
	cfg := s.cfg.RunPrometheusEvidence.normalized()
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	evidence := &PrometheusRunEvidence{
		Schema: prometheusRunEvidenceSchema, RunID: runID, CatalogueID: catalogueID,
		Family: family, Tenant: tenant, Environment: cfg.Environment, ExpectedAction: action, ExecutionMode: executionMode, TriggerMode: triggerMode,
		ObservedDecisionModes: []string{}, Status: "BASELINE_CAPTURED", StartedAt: started.UTC(), BaselineAt: time.Now().UTC(),
		RangeStep: cfg.RangeStep.String(), Metrics: []PrometheusMetricEvidence{},
	}
	for _, query := range prometheusRunQueries(tenant, cfg.Environment, action) {
		querySum := sha256.Sum256([]byte(query.query))
		metric := PrometheusMetricEvidence{Key: query.key, Query: query.query,
			QuerySHA256: hex.EncodeToString(querySum[:]), Baseline: []PrometheusSeries{}}
		series, capture, err := prometheusQuery(ctx, cfg, "/api/v1/query", url.Values{
			"query": {query.query}, "time": {formatPrometheusTime(evidence.BaselineAt)},
		}, "vector", evidence.BaselineAt)
		metric.BaselineCapture = capture
		if err != nil {
			metric.Errors = append(metric.Errors, "baseline: "+err.Error())
			evidence.Errors = append(evidence.Errors, query.key+": baseline: "+err.Error())
		} else {
			metric.Baseline = series
			if query.key == "telemetry-source-fresh" && !prometheusFresh(series) {
				metric.Errors = append(metric.Errors, "baseline: staging decision telemetry is absent or older than 90s")
				evidence.Errors = append(evidence.Errors, query.key+": baseline: staging decision telemetry is absent or older than 90s")
			}
		}
		evidence.Metrics = append(evidence.Metrics, metric)
	}
	if len(evidence.Errors) > 0 {
		evidence.Status = "PARTIAL"
	}
	if err := s.persistPrometheusRunEvidence(evidence); err != nil {
		return evidence, fmt.Errorf("persist Prometheus baseline: %w", err)
	}
	if len(evidence.Errors) > 0 {
		return evidence, fmt.Errorf("Prometheus baseline capture incomplete: %s", strings.Join(evidence.Errors, "; "))
	}
	return evidence, nil
}

func (s *Server) completePrometheusRunEvidence(ctx context.Context, evidence *PrometheusRunEvidence, finished time.Time) error {
	if evidence == nil {
		return nil
	}
	cfg := s.cfg.RunPrometheusEvidence.normalized()
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.SettleDelay > 0 {
		timer := time.NewTimer(cfg.SettleDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	finishedAt := finished.UTC()
	capturedAt := time.Now().UTC()
	evidence.FinishedAt = &finishedAt
	evidence.CapturedAt = &capturedAt
	evidence.Errors = nil
	start := evidence.BaselineAt.Add(-cfg.RangeStep)
	for i := range evidence.Metrics {
		metric := &evidence.Metrics[i]
		metric.Errors = nil
		finalAt := time.Now().UTC()
		final, finalCapture, err := prometheusQuery(ctx, cfg, "/api/v1/query", url.Values{
			"query": {metric.Query}, "time": {formatPrometheusTime(finalAt)},
		}, "vector", finalAt)
		metric.FinalCapture = finalCapture
		if err != nil {
			metric.Errors = append(metric.Errors, "final: "+err.Error())
			evidence.Errors = append(evidence.Errors, metric.Key+": final: "+err.Error())
		} else {
			metric.Final = final
			metric.Deltas = prometheusDeltas(metric.Baseline, final)
			if metric.Key == "telemetry-source-fresh" && !prometheusFresh(final) {
				metric.Errors = append(metric.Errors, "final: staging decision telemetry is absent or older than 90s")
				evidence.Errors = append(evidence.Errors, metric.Key+": final: staging decision telemetry is absent or older than 90s")
			}
		}
		steps := math.Ceil(finalAt.Sub(evidence.BaselineAt).Seconds() / cfg.RangeStep.Seconds())
		start = finalAt.Add(-time.Duration(steps) * cfg.RangeStep)
		rawAt := time.Now().UTC()
		rangeSeries, rawCapture, rangeErr := prometheusQuery(ctx, cfg, "/api/v1/query_range", url.Values{
			"query": {metric.Query}, "start": {formatPrometheusTime(start)},
			"end": {formatPrometheusTime(rawAt)}, "step": {strconv.FormatFloat(cfg.RangeStep.Seconds(), 'f', -1, 64)},
		}, "matrix", rawAt)
		metric.RawCapture = rawCapture
		if rangeErr != nil {
			metric.Errors = append(metric.Errors, "range: "+rangeErr.Error())
			evidence.Errors = append(evidence.Errors, metric.Key+": range: "+rangeErr.Error())
		} else {
			metric.Range = rangeSeries
		}
	}
	evidence.ObservedDecisionModes = observedPrometheusDecisionModes(evidence.Metrics)
	evidence.Status = "COMPLETE"
	if len(evidence.Errors) > 0 {
		evidence.Status = "PARTIAL"
	}
	if err := s.persistPrometheusRunEvidence(evidence); err != nil {
		return fmt.Errorf("persist Prometheus terminal evidence: %w", err)
	}
	if len(evidence.Errors) > 0 {
		return fmt.Errorf("Prometheus terminal capture incomplete: %s", strings.Join(evidence.Errors, "; "))
	}
	return nil
}

func observedPrometheusDecisionModes(metrics []PrometheusMetricEvidence) []string {
	seen := map[string]bool{}
	for _, metric := range metrics {
		if metric.Key != "selected-action" {
			continue
		}
		for _, delta := range metric.Deltas {
			mode := strings.TrimSpace(delta.Labels["mode"])
			if mode != "" && delta.FinalPresent && delta.Delta > 0 {
				seen[mode] = true
			}
		}
	}
	modes := make([]string, 0, len(seen))
	for mode := range seen {
		modes = append(modes, mode)
	}
	sort.Strings(modes)
	return modes
}

func (s *Server) persistPrometheusRunEvidence(evidence *PrometheusRunEvidence) error {
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	if len(raw)+1 > consoleStateRecordLimit {
		return fmt.Errorf("Prometheus run evidence is %d bytes; limit is %d", len(raw)+1, consoleStateRecordLimit)
	}
	return atomicWriteState(filepath.Join(s.cfg.runOutputPath(evidence.RunID), prometheusRunEvidenceFile), append(raw, '\n'))
}

func (rm *RunManager) PrometheusRunEvidence(id string) (*PrometheusRunEvidence, error) {
	rm.mu.Lock()
	st, ok := rm.runs[id]
	out := rm.runOut[id]
	rm.mu.Unlock()
	if !ok || st.ExecutionKind != attackCatalogExecutionKind {
		return nil, nil
	}
	path := filepath.Join(rm.cfg.runOutputPath(out), prometheusRunEvidenceFile)
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > consoleStateRecordLimit {
		return nil, fmt.Errorf("Prometheus run evidence exceeds %d bytes", consoleStateRecordLimit)
	}
	raw, err := os.ReadFile(path)
	// Runs retained before this feature was enabled have no telemetry artifact.
	// New opted-in runs fail their own preflight/finalization instead of relying
	// on this reader to infer when an absent legacy file should have existed.
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var evidence PrometheusRunEvidence
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&evidence); err != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("Prometheus run evidence is malformed")
	}
	if evidence.Schema != prometheusRunEvidenceSchema || evidence.RunID != id || evidence.CatalogueID != st.Config ||
		evidence.Tenant == "" || evidence.Environment == "" || evidence.ExpectedAction == "" || evidence.StartedAt.IsZero() ||
		(evidence.ExecutionMode == "") != (evidence.TriggerMode == "") ||
		(evidence.ExecutionMode != "" && !validAttackCatalogModes(evidence.ExecutionMode, evidence.TriggerMode)) ||
		(evidence.Status != "BASELINE_CAPTURED" && evidence.Status != "COMPLETE" && evidence.Status != "PARTIAL") {
		return nil, errors.New("Prometheus run evidence identity or envelope is invalid")
	}
	return &evidence, nil
}

func validatePrometheusReleaseEvidence(evidence *PrometheusRunEvidence, result AttackCatalogResult) error {
	if evidence == nil {
		return errors.New("complete raw Prometheus evidence is not enabled")
	}
	if evidence.Schema != prometheusRunEvidenceSchema || evidence.RunID != result.RunID ||
		evidence.CatalogueID != result.CatalogueID || evidence.Family != result.Family || evidence.ExpectedAction != result.ExpectedAction ||
		evidence.ExecutionMode != result.ExecutionMode || evidence.TriggerMode != result.TriggerMode {
		return errors.New("Prometheus evidence identity, action, or runtime modes differ from the run")
	}
	if evidence.Status != "COMPLETE" || len(evidence.Errors) != 0 || len(evidence.Metrics) == 0 {
		return errors.New("Prometheus evidence is incomplete")
	}
	for _, metric := range evidence.Metrics {
		querySum := sha256.Sum256([]byte(metric.Query))
		if metric.Key == "" || metric.Query == "" || metric.QuerySHA256 != hex.EncodeToString(querySum[:]) || len(metric.Errors) != 0 {
			return fmt.Errorf("Prometheus metric %q query contract is incomplete", metric.Key)
		}
		captures := []*PrometheusResponseCapture{metric.BaselineCapture, metric.FinalCapture, metric.RawCapture}
		for _, capture := range captures {
			if err := validatePrometheusResponseCapture(capture, result.StartedAt, result.FinishedAt); err != nil {
				return fmt.Errorf("Prometheus metric %q: %w", metric.Key, err)
			}
		}
		if !metric.BaselineCapture.CapturedAt.Before(metric.FinalCapture.CapturedAt) ||
			metric.RawCapture.CapturedAt.Before(metric.FinalCapture.CapturedAt) {
			return fmt.Errorf("Prometheus metric %q capture timestamps are not monotonic", metric.Key)
		}
		if len(metric.Range) == 0 {
			return fmt.Errorf("Prometheus metric %q has no raw range series", metric.Key)
		}
		if !prometheusRangeQueryCoversCaptures(metric.RawCapture, metric.BaselineCapture, metric.FinalCapture) {
			return fmt.Errorf("Prometheus metric %q raw query window does not cover baseline and final", metric.Key)
		}
		var first, last float64
		found := false
		for _, series := range metric.Range {
			for _, sample := range series.Samples {
				if !found || sample.Time < first {
					first = sample.Time
				}
				if !found || sample.Time > last {
					last = sample.Time
				}
				found = true
			}
		}
		if !found || !prometheusRangeCoversCaptures(first, last,
			metric.BaselineCapture.CapturedAt, metric.FinalCapture.CapturedAt, len(metric.Baseline) > 0) {
			return fmt.Errorf("Prometheus metric %q raw range does not cover baseline and final", metric.Key)
		}
	}
	return nil
}

// A counter can be absent at baseline and be born during the run. In that case
// the first returned sample is correctly after the baseline capture, even though
// the raw query window started before it. Existing baseline series must still
// have a sample at or before baseline, and every series must reach final.
// Prometheus serializes sample timestamps at millisecond precision, so permit
// only that serialization loss at either required boundary.
func prometheusRangeCoversCaptures(first, last float64, baselineAt, finalAt time.Time, baselinePresent bool) bool {
	const tolerance = float64(time.Millisecond) / float64(time.Second)
	baseline := float64(baselineAt.UnixNano()) / float64(time.Second)
	final := float64(finalAt.UnixNano()) / float64(time.Second)
	return (!baselinePresent || first <= baseline+tolerance) && last+tolerance >= final
}

func prometheusRangeQueryCoversCaptures(raw, baseline, final *PrometheusResponseCapture) bool {
	if raw == nil || baseline == nil || final == nil || raw.Path != "/api/v1/query_range" ||
		baseline.Path != "/api/v1/query" || final.Path != "/api/v1/query" ||
		raw.Parameters["query"] == "" || raw.Parameters["query"] != baseline.Parameters["query"] ||
		raw.Parameters["query"] != final.Parameters["query"] {
		return false
	}
	start, startErr := strconv.ParseFloat(raw.Parameters["start"], 64)
	end, endErr := strconv.ParseFloat(raw.Parameters["end"], 64)
	step, stepErr := strconv.ParseFloat(raw.Parameters["step"], 64)
	baselineQuery, baselineErr := strconv.ParseFloat(baseline.Parameters["time"], 64)
	finalQuery, finalErr := strconv.ParseFloat(final.Parameters["time"], 64)
	if startErr != nil || endErr != nil || stepErr != nil || baselineErr != nil || finalErr != nil ||
		math.IsNaN(start) || math.IsNaN(end) || math.IsNaN(step) || math.IsNaN(baselineQuery) || math.IsNaN(finalQuery) ||
		math.IsInf(start, 0) || math.IsInf(end, 0) || math.IsInf(step, 0) || math.IsInf(baselineQuery, 0) || math.IsInf(finalQuery, 0) ||
		step <= 0 || start > end {
		return false
	}
	const tolerance = float64(time.Millisecond) / float64(time.Second)
	baselineCaptured := float64(baseline.CapturedAt.UnixNano()) / float64(time.Second)
	finalCaptured := float64(final.CapturedAt.UnixNano()) / float64(time.Second)
	return math.Abs(baselineQuery-baselineCaptured) <= tolerance &&
		math.Abs(finalQuery-finalCaptured) <= tolerance &&
		start <= baselineQuery+tolerance && end+tolerance >= finalQuery
}

func validatePrometheusResponseCapture(capture *PrometheusResponseCapture, startedAt, finishedAt time.Time) error {
	if capture == nil || capture.CapturedAt.Before(startedAt) || capture.CapturedAt.After(finishedAt) ||
		capture.Path == "" || len(capture.Parameters) == 0 || len(capture.Payload) == 0 || capture.ResponseBody == "" {
		return errors.New("raw response capture envelope is incomplete")
	}
	payloadSHA, err := canonicalJSONSHA256(capture.Payload)
	if err != nil || payloadSHA != capture.SHA256 {
		return errors.New("raw response payload hash does not match")
	}
	rawSHA := sha256.Sum256([]byte(capture.ResponseBody))
	if capture.RawBodySHA256 != hex.EncodeToString(rawSHA[:]) {
		return errors.New("raw response body hash does not match")
	}
	return nil
}

func prometheusQuery(parent context.Context, cfg PrometheusRunEvidenceConfig, path string, values url.Values, wantType string, capturedAt time.Time) ([]PrometheusSeries, *PrometheusResponseCapture, error) {
	ctx, cancel := context.WithTimeout(parent, cfg.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.URL+path+"?"+values.Encode(), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, prometheusResponseLimit+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > prometheusResponseLimit {
		return nil, nil, fmt.Errorf("Prometheus response exceeds %d bytes", prometheusResponseLimit)
	}
	rawSum := sha256.Sum256(raw)
	payloadDigest, digestErr := canonicalJSONSHA256(json.RawMessage(raw))
	parameters := make(map[string]string, len(values))
	for key := range values {
		parameters[key] = values.Get(key)
	}
	capture := &PrometheusResponseCapture{CapturedAt: capturedAt.UTC(), Path: path, Parameters: parameters,
		RawBodySHA256: hex.EncodeToString(rawSum[:]), ResponseBody: string(raw)}
	if digestErr == nil {
		capture.SHA256 = payloadDigest
		capture.Payload = append(json.RawMessage(nil), raw...)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, capture, fmt.Errorf("Prometheus HTTP %d", resp.StatusCode)
	}
	var envelope prometheusAPIResponse
	if err = json.Unmarshal(raw, &envelope); err != nil {
		return nil, capture, errors.New("Prometheus response is not valid JSON")
	}
	if envelope.Status != "success" {
		return nil, capture, fmt.Errorf("Prometheus %s: %s", envelope.ErrorType, envelope.Error)
	}
	if envelope.Data.ResultType != wantType {
		return nil, capture, fmt.Errorf("Prometheus result type %q, want %q", envelope.Data.ResultType, wantType)
	}
	result := make([]PrometheusSeries, 0, len(envelope.Data.Result))
	for _, item := range envelope.Data.Result {
		series := PrometheusSeries{Labels: cloneStringMap(item.Metric), Samples: []PrometheusSample{}}
		if wantType == "vector" {
			sample, err := decodePrometheusSample(item.Value)
			if err != nil {
				return nil, capture, err
			}
			series.Samples = append(series.Samples, sample)
		} else {
			for _, pair := range item.Values {
				sample, err := decodePrometheusSample(pair)
				if err != nil {
					return nil, capture, err
				}
				series.Samples = append(series.Samples, sample)
			}
		}
		result = append(result, series)
	}
	sort.Slice(result, func(i, j int) bool { return labelKey(result[i].Labels) < labelKey(result[j].Labels) })
	return result, capture, nil
}

func decodePrometheusSample(pair []json.RawMessage) (PrometheusSample, error) {
	if len(pair) != 2 {
		return PrometheusSample{}, errors.New("Prometheus sample must contain timestamp and value")
	}
	var timestamp float64
	var valueText string
	if json.Unmarshal(pair[0], &timestamp) != nil || json.Unmarshal(pair[1], &valueText) != nil {
		return PrometheusSample{}, errors.New("Prometheus sample has invalid timestamp or value")
	}
	value, err := strconv.ParseFloat(valueText, 64)
	if err != nil || math.IsNaN(timestamp) || math.IsInf(timestamp, 0) || math.IsNaN(value) || math.IsInf(value, 0) {
		return PrometheusSample{}, errors.New("Prometheus sample is non-finite")
	}
	return PrometheusSample{Time: timestamp, Value: value}, nil
}

func prometheusFresh(series []PrometheusSeries) bool {
	return len(series) == 1 && len(series[0].Samples) == 1 && series[0].Samples[0].Value == 1
}

func prometheusDeltas(baseline, final []PrometheusSeries) []PrometheusDelta {
	type point struct {
		labels  map[string]string
		value   float64
		present bool
	}
	before, after := map[string]point{}, map[string]point{}
	for _, series := range baseline {
		if len(series.Samples) > 0 {
			before[labelKey(series.Labels)] = point{labels: series.Labels, value: series.Samples[len(series.Samples)-1].Value, present: true}
		}
	}
	for _, series := range final {
		if len(series.Samples) > 0 {
			after[labelKey(series.Labels)] = point{labels: series.Labels, value: series.Samples[len(series.Samples)-1].Value, present: true}
		}
	}
	keys := make([]string, 0, len(before)+len(after))
	seen := map[string]bool{}
	for key := range before {
		seen[key], keys = true, append(keys, key)
	}
	for key := range after {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	deltas := make([]PrometheusDelta, 0, len(keys))
	for _, key := range keys {
		b, f := before[key], after[key]
		labels := b.labels
		if labels == nil {
			labels = f.labels
		}
		delta := PrometheusDelta{Labels: cloneStringMap(labels), BaselinePresent: b.present, FinalPresent: f.present, Baseline: b.value, Final: f.value}
		if f.present {
			delta.Delta = f.value - b.value
			if b.present && delta.Delta < 0 {
				delta.CounterReset, delta.Delta = true, f.value
			}
		}
		deltas = append(deltas, delta)
	}
	return deltas
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func labelKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(labels[key])
		b.WriteByte(0)
	}
	return b.String()
}

func formatPrometheusTime(t time.Time) string {
	// Preserve the capture boundary: millisecond rounding can move a fast range
	// endpoint behind the instant sample that the strict coverage gate binds.
	return strconv.FormatFloat(float64(t.UnixNano())/float64(time.Second), 'f', 9, 64)
}
