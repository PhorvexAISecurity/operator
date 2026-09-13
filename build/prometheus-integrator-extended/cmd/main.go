/*
 * Copyright (C) 2024 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	amtdv1beta1client "github.com/r6security/prometheus-integrator/clients"
	seceventclient "github.com/r6security/prometheus-integrator/clients/securityevent"
	"github.com/r6security/prometheus-integrator/delivery"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
)

// DefaultPort is the default port to use if one is not specified by the SERVER_PORT environment variable
const DefaultPort = "33337"
const MAX_BODY_SIZE = 1048576

// DetectorPrefix prefixes every SecurityEvent name and the identity digest domain.
const DetectorPrefix = "prometheus"

// maxReportedProblems bounds how many per-alert validation problems one 400 lists.
const maxReportedProblems = 10

func getServerPort() string {
	port := os.Getenv("SERVER_PORT")
	if port != "" {
		return port
	}

	return DefaultPort
}

// getAPITimeout reads SECURITYEVENT_API_TIMEOUT (Go duration) bounding each
// downstream Create/Get; unset selects delivery.DefaultTimeout.
func getAPITimeout() (time.Duration, error) {
	raw := os.Getenv("SECURITYEVENT_API_TIMEOUT")
	if raw == "" {
		return delivery.DefaultTimeout, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("SECURITYEVENT_API_TIMEOUT %q is not a positive duration", raw)
	}
	return d, nil
}

type PrometheusBackend struct {
	client *seceventclient.SecurityEventInterface
	// ctx is the server's base context; once it is done new deliveries are refused.
	ctx context.Context
	// apiTimeout bounds each downstream API call (0 selects delivery.DefaultTimeout).
	apiTimeout time.Duration
}

type PrometheusResponse struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`        // key identifying the group of alerts (e.g. to deduplicate)
	TruncatedAlerts   int               `json:"truncatedAlerts"` // how many alerts have been truncated due to "max_alerts"
	Status            string            `json:"status"`          // "resolved" or "firing"
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"` // backlink to the Alertmanager
	Alerts            []Alert           `json:"alerts"`
}

type Alert struct {
	Status       string            `json:"status"` // "resolved" or "firing"
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`     // RFC3339 format
	EndsAt       time.Time         `json:"endsAt"`       // RFC3339 format
	GeneratorURL string            `json:"generatorURL"` // URL of the entity that generated the alert
	Fingerprint  string            `json:"fingerprint"`  // Unique fingerprint of the alert
}

// rawBatch re-reads the same body keeping each alert as raw JSON so the per-alert
// identity is derived from the alert's complete canonical content, not from the
// typed subset or its batch position.
type rawBatch struct {
	Alerts []json.RawMessage `json:"alerts"`
}

// batchCounts aggregates per-item outcomes.
type batchCounts struct {
	Total     int `json:"total"`
	Accepted  int `json:"accepted"`
	Duplicate int `json:"duplicate"`
	Conflict  int `json:"conflict"`
	Failed    int `json:"failed"`
}

// batchItem is one alert's wire outcome.
type batchItem struct {
	Index int `json:"index"`
	// Fingerprint is the Alertmanager alert fingerprint (upstream identity, for correlation only).
	Fingerprint string `json:"fingerprint"`
	delivery.Result
}

// prometheusResponse is the wire body for every reply; always valid JSON.
type prometheusResponse struct {
	// Status: accepted (every alert accepted or proven identical) | failed | conflict | invalid
	Status  string       `json:"status"`
	Counts  *batchCounts `json:"counts,omitempty"`
	Items   []batchItem  `json:"items,omitempty"`
	Reason  string       `json:"reason,omitempty"`
	Message string       `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("cannot write response: %v", err)
	}
}

func writeInvalid(w http.ResponseWriter, status int, reason, message string) {
	writeJSON(w, status, prometheusResponse{Status: "invalid", Reason: reason, Message: message})
}

// preparedAlert is one validated alert with its deterministic event.
type preparedAlert struct {
	index       int
	fingerprint string
	event       *amtdapi.SecurityEvent
}

// validateAlert names every missing/invalid required identity field of one alert.
func validateAlert(alert Alert) []string {
	var problems []string
	if alert.StartsAt.IsZero() {
		problems = append(problems, "missing or zero startsAt")
	}
	if alert.Fingerprint == "" {
		problems = append(problems, "missing fingerprint")
	}
	if alert.Labels["alertname"] == "" {
		problems = append(problems, "missing labels.alertname")
	}
	ns, pod := alert.Labels["namespace"], alert.Labels["pod"]
	if ns == "" {
		problems = append(problems, "missing labels.namespace")
	} else if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
		problems = append(problems, "invalid labels.namespace: "+errs[0])
	}
	if pod == "" {
		problems = append(problems, "missing labels.pod")
	} else if errs := validation.IsDNS1123Subdomain(pod); len(errs) > 0 {
		problems = append(problems, "invalid labels.pod: "+errs[0])
	}
	return problems
}

// prepareBatch validates the COMPLETE batch before any API write and derives each
// alert's deterministic event (identity from the alert's canonical content; spec
// from the unchanged Phase 7 normalization). A truncated or empty batch and any
// invalid alert reject the whole request. Returns (reason, message) on refusal.
func prepareBatch(body []byte) ([]preparedAlert, string, string) {
	var response PrometheusResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, "invalid_input", "malformed JSON: " + jsonErr(err)
	}
	var raw rawBatch
	if err := json.Unmarshal(body, &raw); err != nil || len(raw.Alerts) != len(response.Alerts) {
		return nil, "invalid_input", "malformed JSON: alerts must be an array of objects"
	}
	if response.TruncatedAlerts != 0 {
		return nil, "truncated_batch", fmt.Sprintf("truncatedAlerts=%d: the batch is incomplete and cannot be acknowledged as delivered; send untruncated notifications (max_alerts: 0)", response.TruncatedAlerts)
	}
	if len(response.Alerts) == 0 {
		return nil, "empty_batch", "alerts is empty; nothing to deliver"
	}
	var problems []string
	prepared := make([]preparedAlert, 0, len(response.Alerts))
	for i, alert := range response.Alerts {
		if p := validateAlert(alert); len(p) > 0 {
			problems = append(problems, fmt.Sprintf("alerts[%d]: %s", i, strings.Join(p, ", ")))
			continue
		}
		canonical, err := delivery.CanonicalJSON(raw.Alerts[i])
		if err != nil {
			problems = append(problems, fmt.Sprintf("alerts[%d]: malformed JSON: %s", i, jsonErr(err)))
			continue
		}
		id := delivery.Derive(DetectorPrefix, canonical)
		event := &amtdapi.SecurityEvent{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
			// Phase 7: NORMALIZE the alert's native labels onto the shared canonical
			// vocabulary + carry an AnomalyScore (alert-supplied if present, else a
			// severity-derived PROXY) and the raw labels in Metrics (see normalize.go).
			Spec: buildPrometheusSpec(alert),
		}
		delivery.Stamp(event, DetectorPrefix, id)
		prepared = append(prepared, preparedAlert{index: i, fingerprint: alert.Fingerprint, event: event})
	}
	if len(problems) > 0 {
		if len(problems) > maxReportedProblems {
			problems = append(problems[:maxReportedProblems], fmt.Sprintf("… %d more", len(problems)-maxReportedProblems))
		}
		return nil, "invalid_input", strings.Join(problems, "; ")
	}
	return prepared, "", ""
}

// jsonErr keeps decoder errors short and free of payload echoes.
func jsonErr(err error) string {
	msg := err.Error()
	if len(msg) > 160 {
		msg = msg[:160]
	}
	return msg
}

// Use the webhook feature in prometheus to get prometheus trigger alerts.
// The Alertmanager will send HTTP POST requests in the following JSON format to the configured endpoint:
/*
	{
	"version": "4",
	"groupKey": <string>,              // key identifying the group of alerts (e.g. to deduplicate)
	"truncatedAlerts": <int>,          // how many alerts have been truncated due to "max_alerts"
	"status": "<resolved|firing>",
	"receiver": <string>,
	"groupLabels": <object>,
	"commonLabels": <object>,
	"commonAnnotations": <object>,
	"externalURL": <string>,           // backlink to the Alertmanager.
	"alerts": [
		{
		"status": "<resolved|firing>",
		"labels": <object>,
		"annotations": <object>,
		"startsAt": "<rfc3339>",
		"endsAt": "<rfc3339>",
		"generatorURL": <string>,      // identifies the entity that caused the alert
		"fingerprint": <string>        // fingerprint to identify the alert
		},
		...
	]
	}
*/
// PrometheusHandler validates the whole batch before its first API write, delivers
// each alert in order through the real client, and replies with explicit per-item
// outcomes and counts: 200 only when every alert was accepted or proven identical,
// 503 if any alert failed (prior accepted alerts stay stored; a whole-batch retry
// re-verifies them as duplicates and retries the failures), 409 if the only
// non-success is an unverified collision, 400/405/413 before any write for
// invalid input. A non-2xx never itself guarantees that Alertmanager retries.
func (pb PrometheusBackend) PrometheusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeInvalid(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is accepted")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MAX_BODY_SIZE)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeInvalid(w, http.StatusRequestEntityTooLarge, "body_too_large", fmt.Sprintf("request body exceeds %d bytes", MAX_BODY_SIZE))
			return
		}
		log.Printf("Cannot read body %v", err)
		writeInvalid(w, http.StatusBadRequest, "unreadable_body", "cannot read request body")
		return
	}

	prepared, reason, message := prepareBatch(body)
	if reason != "" {
		log.Printf("Rejecting alert batch (%s): %s", reason, message)
		writeInvalid(w, http.StatusBadRequest, reason, message)
		return
	}

	if pb.ctx != nil {
		select {
		case <-pb.ctx.Done():
			writeJSON(w, http.StatusServiceUnavailable, prometheusResponse{Status: string(delivery.Failed),
				Reason: "shutting_down", Message: "server is shutting down; not attempted"})
			return
		default:
		}
	}

	deliverer := delivery.Deliverer{Client: *pb.client, Timeout: pb.apiTimeout}
	counts := batchCounts{Total: len(prepared)}
	items := make([]batchItem, 0, len(prepared))
	for _, alert := range prepared {
		log.Printf("Delivering SecurityEvent %s (%s) for alert %s", alert.event.Name, alert.event.Annotations[delivery.FingerprintAnnotation], alert.fingerprint)
		res := deliverer.Deliver(r.Context(), alert.event)
		switch res.Outcome {
		case delivery.Accepted:
			counts.Accepted++
		case delivery.Duplicate:
			counts.Duplicate++
		case delivery.Conflict:
			counts.Conflict++
		default:
			counts.Failed++
		}
		if res.Outcome == delivery.Accepted || res.Outcome == delivery.Duplicate {
			log.Printf("SecurityEvent %s %s", res.Event, res.Outcome)
		} else {
			log.Printf("SecurityEvent %s %s (%s): %s", res.Event, res.Outcome, res.Reason, res.Message)
		}
		items = append(items, batchItem{Index: alert.index, Fingerprint: alert.fingerprint, Result: res})
	}

	status, overall := http.StatusOK, string(delivery.Accepted)
	switch {
	case counts.Failed > 0:
		status, overall = delivery.HTTPStatus(delivery.Failed), string(delivery.Failed)
	case counts.Conflict > 0:
		status, overall = delivery.HTTPStatus(delivery.Conflict), string(delivery.Conflict)
	}
	writeJSON(w, status, prometheusResponse{Status: overall, Counts: &counts, Items: items})
}

func main() {
	log.Print("Loading configuration")
	cfg := ctrl.GetConfigOrDie()
	client, err := amtdv1beta1client.NewClient(cfg)
	if err != nil {
		log.Panic(err)
	}
	apiTimeout, err := getAPITimeout()
	if err != nil {
		log.Fatal(err)
	}
	secEventClient := client.SecurityEvents()
	prometheusBackend := PrometheusBackend{
		client:     &secEventClient,
		ctx:        context.Background(),
		apiTimeout: apiTimeout,
	}
	port := getServerPort()
	log.Println("Starting server, listening on port " + port)

	http.HandleFunc("/", prometheusBackend.PrometheusHandler)
	http.ListenAndServe(":"+port, nil)
}
