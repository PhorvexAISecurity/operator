/*
 * Copyright (C) 2023 R6 Security, Inc.
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

	amtdv1beta1client "github.com/r6security/falco-integrator/clients"
	seceventclient "github.com/r6security/falco-integrator/clients/securityevent"
	"github.com/r6security/falco-integrator/delivery"
	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
)

// DefaultPort is the default port to use if one is not specified by the SERVER_PORT environment variable
const DefaultPort = "33333"
const MAX_BODY_SIZE = 1048576

// DetectorPrefix prefixes every SecurityEvent name and the identity digest domain.
const DetectorPrefix = "falco"

// The message structure from falco webhook
type Response struct {
	Time         time.Time            `json:"time,omitempty"`
	Priority     string               `json:"priority,omitempty"`
	Rule         string               `json:"rule,omitempty"`
	Output       string               `json:"output,omitempty"`
	Hostname     string               `json:"hostname,omitempty"`
	Source       string               `json:"source,omitempty"`
	Tags         []string             `json:"tags,omitempty"`
	OutputFields ResponseOutputFields `json:"output_fields,omitempty"`
}

type ResponseOutputFields struct {
	ContainerID    string `json:"container.id,omitempty"`
	ContainerImage string `json:"container.image.repository,omitempty"`
	EventFlags     string `json:"evt.arg.flags,omitempty"`
	//EventTime      time.Time `json:"evt.time,omitempty"`
	Namespace string `json:"k8s.ns.name,omitempty"`
	Pod       string `json:"k8s.pod.name,omitempty"`
}

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

type FalcoBackend struct {
	client *seceventclient.SecurityEventInterface
	// ctx is the server's base context; once it is done new deliveries are refused.
	ctx context.Context
	// apiTimeout bounds each downstream API call (0 selects delivery.DefaultTimeout).
	apiTimeout time.Duration
}

// falcoResponse is the wire body for every reply; always valid JSON.
type falcoResponse struct {
	// Status: accepted | duplicate | conflict | failed | invalid
	Status              string `json:"status"`
	Event               string `json:"event,omitempty"`
	DeliveryFingerprint string `json:"deliveryFingerprint,omitempty"`
	Reason              string `json:"reason,omitempty"`
	Message             string `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("cannot write response: %v", err)
	}
}

func writeInvalid(w http.ResponseWriter, status int, reason, message string) {
	writeJSON(w, status, falcoResponse{Status: "invalid", Reason: reason, Message: message})
}

// buildFalcoEvent validates the supported Falco payload and derives the
// deterministic event: identity from the canonical form of the complete body
// (see docs/DELIVERY.md), spec from the unchanged Phase 7 normalization.
func buildFalcoEvent(body []byte) (*amtdapi.SecurityEvent, delivery.Identity, error) {
	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, delivery.Identity{}, fmt.Errorf("malformed JSON: %s", jsonErr(err))
	}
	var problems []string
	if response.Time.IsZero() {
		problems = append(problems, "missing or zero time")
	}
	if response.Rule == "" {
		problems = append(problems, "missing rule")
	}
	ns, pod := response.OutputFields.Namespace, response.OutputFields.Pod
	if ns == "" {
		problems = append(problems, "missing output_fields.k8s.ns.name")
	} else if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
		problems = append(problems, "invalid output_fields.k8s.ns.name: "+errs[0])
	}
	if pod == "" {
		problems = append(problems, "missing output_fields.k8s.pod.name")
	} else if errs := validation.IsDNS1123Subdomain(pod); len(errs) > 0 {
		problems = append(problems, "invalid output_fields.k8s.pod.name: "+errs[0])
	}
	if len(problems) > 0 {
		return nil, delivery.Identity{}, errors.New(strings.Join(problems, "; "))
	}
	canonical, err := delivery.CanonicalJSON(body)
	if err != nil {
		return nil, delivery.Identity{}, fmt.Errorf("malformed JSON: %s", jsonErr(err))
	}
	id := delivery.Derive(DetectorPrefix, canonical)
	event := &amtdapi.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		// Phase 7: NORMALIZE Falco's native Priority/rule-name onto the shared canonical
		// vocabulary + attach a severity-derived PROXY AnomalyScore (see normalize.go).
		Spec: buildFalcoSpec(response),
	}
	delivery.Stamp(event, DetectorPrefix, id)
	return event, id, nil
}

// jsonErr keeps decoder errors short and free of payload echoes.
func jsonErr(err error) string {
	msg := err.Error()
	if len(msg) > 160 {
		msg = msg[:160]
	}
	return msg
}

// FalcoHandler accepts one Falco webhook POST and replies with the honest delivery
// outcome: 200 only when the SecurityEvent was persisted in this request or read
// back as a proven identical retry; 409 for an unverified name collision; 503 when
// the API rejected, timed out or could not be verified; 400/405/413 before any API
// write for invalid input.
func (fb FalcoBackend) FalcoHandler(w http.ResponseWriter, r *http.Request) {
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

	event, id, err := buildFalcoEvent(body)
	if err != nil {
		log.Printf("Rejecting falco payload: %v", err)
		writeInvalid(w, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}

	if fb.ctx != nil {
		select {
		case <-fb.ctx.Done():
			writeJSON(w, http.StatusServiceUnavailable, falcoResponse{Status: string(delivery.Failed), Event: id.Name,
				DeliveryFingerprint: id.Fingerprint, Reason: "shutting_down", Message: "server is shutting down; not attempted"})
			return
		default:
		}
	}

	log.Printf("Delivering secevent %s (%s)", id.Name, id.Fingerprint)
	res := delivery.Deliverer{Client: *fb.client, Timeout: fb.apiTimeout}.Deliver(r.Context(), event)
	if res.Outcome == delivery.Accepted || res.Outcome == delivery.Duplicate {
		log.Printf("secevent %s %s", res.Event, res.Outcome)
	} else {
		log.Printf("secevent %s %s (%s): %s", res.Event, res.Outcome, res.Reason, res.Message)
	}
	writeJSON(w, delivery.HTTPStatus(res.Outcome), falcoResponse{
		Status:              string(res.Outcome),
		Event:               res.Event,
		DeliveryFingerprint: res.DeliveryFingerprint,
		Reason:              res.Reason,
		Message:             res.Message,
	})
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
	falcoBackend := FalcoBackend{
		client:     &secEventClient,
		ctx:        context.Background(),
		apiTimeout: apiTimeout,
	}
	port := getServerPort()

	log.Println("starting server, listening on port " + port)

	http.HandleFunc("/", falcoBackend.FalcoHandler)
	http.ListenAndServe(":"+port, nil)
}
