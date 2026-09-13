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

// V3-M164 delivery tests: the ACTUAL FalcoHandler drives the ACTUAL custom REST
// client (clients.NewClient) against apiFixture over HTTP. Every assertion about
// persistence reads the fixture's store or recorded requests; every assertion
// about acknowledgement reads the wire status and JSON body.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	amtdv1beta1client "github.com/r6security/falco-integrator/clients"
	"github.com/r6security/falco-integrator/delivery"
	"k8s.io/client-go/rest"
)

func newFalcoBackend(t *testing.T, api *apiFixture, timeout time.Duration) FalcoBackend {
	t.Helper()
	client, err := amtdv1beta1client.NewClient(&rest.Config{Host: api.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c := client.SecurityEvents()
	return FalcoBackend{client: &c, ctx: context.Background(), apiTimeout: timeout}
}

type falcoOpts struct {
	rule, ns, pod, time, priority string
}

func falcoJSON(o falcoOpts) string {
	if o.rule == "" {
		o.rule = "Container Drift Detected (open+create)"
	}
	if o.ns == "" {
		o.ns = "prod"
	}
	if o.pod == "" {
		o.pod = "web-1"
	}
	if o.time == "" {
		o.time = "2026-09-10T16:00:00.123456789Z"
	}
	if o.priority == "" {
		o.priority = "Critical"
	}
	return `{"hostname":"node-1","output":"16:00:00.123456789: ` + o.priority + ` ` + o.rule + ` (user=root)","priority":"` + o.priority +
		`","rule":"` + o.rule + `","source":"syscall","tags":["container","filesystem"],"time":"` + o.time +
		`","output_fields":{"container.id":"abc123","container.image.repository":"nginx","evt.arg.flags":"O_WRONLY|O_CREAT","k8s.ns.name":"` + o.ns + `","k8s.pod.name":"` + o.pod + `"}}`
}

func do(fb FalcoBackend, method, body string) *httptest.ResponseRecorder {
	return doCtx(context.Background(), fb, method, body)
}

func doCtx(ctx context.Context, fb FalcoBackend, method, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/", strings.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	fb.FalcoHandler(rec, req)
	return rec
}

func decodeReply(t *testing.T, rec *httptest.ResponseRecorder) falcoResponse {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q", ct)
	}
	var reply falcoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("reply %q is not valid JSON: %v", rec.Body.String(), err)
	}
	return reply
}

func expect(t *testing.T, rec *httptest.ResponseRecorder, code int, status, reason string) falcoResponse {
	t.Helper()
	reply := decodeReply(t, rec)
	if rec.Code != code || reply.Status != status || reply.Reason != reason {
		t.Fatalf("got %d %s reason=%q msg=%q; want %d %s reason=%q", rec.Code, reply.Status, reply.Reason, reply.Message, code, status, reason)
	}
	return reply
}

func TestFalcoDelivery_AcceptedIsPersistedThroughClusterScopedREST(t *testing.T) {
	api := newAPIFixture(t)
	fb := newFalcoBackend(t, api, 0)
	rec := do(fb, http.MethodPost, falcoJSON(falcoOpts{}))
	reply := expect(t, rec, 200, "accepted", "")

	if got := api.methods(); !reflect.DeepEqual(got, []string{"POST "}) {
		t.Fatalf("requests=%v want exactly one POST to %s", got, securityEventsPath)
	}
	store := api.stored()
	raw, ok := store[reply.Event]
	if len(store) != 1 || !ok {
		t.Fatalf("store=%v; want exactly the acknowledged event %q", store, reply.Event)
	}
	ev := decodeStored(t, raw)
	if ev.Kind != "SecurityEvent" || ev.APIVersion != "amtd.r6security.com/v1beta1" {
		t.Errorf("wire object kind/apiVersion = %q/%q", ev.Kind, ev.APIVersion)
	}
	if ev.Metadata.Namespace != "" {
		t.Errorf("Cluster-scoped object carried metadata.namespace=%q", ev.Metadata.Namespace)
	}
	if !strings.HasPrefix(ev.Metadata.Name, "falco-") || len(ev.Metadata.Name) != len("falco-")+delivery.NameDigestLength {
		t.Errorf("name %q is not falco-<%d hex>", ev.Metadata.Name, delivery.NameDigestLength)
	}
	if ev.Metadata.Annotations[delivery.FingerprintAnnotation] != reply.DeliveryFingerprint || !strings.HasPrefix(reply.DeliveryFingerprint, "sha256:") {
		t.Errorf("fingerprint annotation %q vs reply %q", ev.Metadata.Annotations[delivery.FingerprintAnnotation], reply.DeliveryFingerprint)
	}
	if ev.Metadata.Annotations[delivery.IdentityAnnotation] != "falco/"+delivery.IdentityVersion {
		t.Errorf("identity annotation = %q", ev.Metadata.Annotations[delivery.IdentityAnnotation])
	}
	// Normalization positive control (unchanged Phase 7 math) observed on the wire.
	if !reflect.DeepEqual(ev.Spec.Targets, []string{"prod/web-1"}) || ev.Spec.Rule["type"] != "drift" ||
		ev.Spec.Rule["threatLevel"] != "critical" || ev.Spec.Rule["source"] != "FalcoIntegrator" || ev.Spec.Score != "0.95" ||
		ev.Spec.Metrics["falco.rule"] != "Container Drift Detected (open+create)" {
		t.Errorf("normalized spec on the wire = %+v", ev.Spec)
	}
}

func TestFalcoDelivery_DownstreamRejectionIsNotAcknowledged(t *testing.T) {
	for _, tc := range []struct {
		code   int
		reason string
	}{{403, "api:Forbidden"}, {429, "api:TooManyRequests"}, {500, "api:InternalError"}, {503, "api:ServiceUnavailable"}, {422, "api:Invalid"}} {
		t.Run(tc.reason, func(t *testing.T) {
			api := newAPIFixture(t)
			api.CreateStatus = tc.code
			fb := newFalcoBackend(t, api, 0)
			rec := do(fb, http.MethodPost, falcoJSON(falcoOpts{}))
			reply := expect(t, rec, 503, "failed", tc.reason)
			if len(api.stored()) != 0 || len(api.methods()) != 1 {
				t.Fatalf("store=%v requests=%v; want nothing stored and a single Create attempt (no retry loop)", api.stored(), api.methods())
			}
			if !strings.Contains(reply.Message, "create rejected") || len(reply.Message) > 300 {
				t.Errorf("message=%q", reply.Message)
			}
		})
	}
}

func TestFalcoDelivery_DeadlineIsBoundedAndUnacknowledged(t *testing.T) {
	api := newAPIFixture(t)
	api.HangCreate = true
	fb := newFalcoBackend(t, api, 150*time.Millisecond)
	start := time.Now()
	rec := do(fb, http.MethodPost, falcoJSON(falcoOpts{}))
	expect(t, rec, 503, "failed", "timeout")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("deadline not enforced: %v", elapsed)
	}
	if got := api.methods(); !reflect.DeepEqual(got, []string{"POST "}) {
		t.Fatalf("requests=%v; want one bounded attempt", got)
	}
}

func TestFalcoDelivery_ReplayIsVerifiedDuplicateNotSecondEvent(t *testing.T) {
	api := newAPIFixture(t)
	fb := newFalcoBackend(t, api, 0)
	first := expect(t, do(fb, http.MethodPost, falcoJSON(falcoOpts{})), 200, "accepted", "")
	second := expect(t, do(fb, http.MethodPost, falcoJSON(falcoOpts{})), 200, "duplicate", "")
	if first.Event != second.Event || first.DeliveryFingerprint != second.DeliveryFingerprint {
		t.Fatalf("replay identity changed: %+v vs %+v", first, second)
	}
	if got := api.methods(); !reflect.DeepEqual(got, []string{"POST ", "POST ", "GET /" + first.Event}) {
		t.Fatalf("requests=%v; want create, AlreadyExists create, exact-name readback", got)
	}
	if len(api.stored()) != 1 {
		t.Fatalf("store=%v; replay must not create a second event", api.stored())
	}
	// Same content with different key order / whitespace is the same delivery.
	reordered := `{ "output_fields" : {"k8s.pod.name":"web-1","k8s.ns.name":"prod","evt.arg.flags":"O_WRONLY|O_CREAT","container.image.repository":"nginx","container.id":"abc123"},
	  "time":"2026-09-10T16:00:00.123456789Z","tags":["container","filesystem"],"source":"syscall","rule":"Container Drift Detected (open+create)",
	  "priority":"Critical","output":"16:00:00.123456789: Critical Container Drift Detected (open+create) (user=root)","hostname":"node-1"}`
	third := expect(t, do(fb, http.MethodPost, reordered), 200, "duplicate", "")
	if third.Event != first.Event || len(api.stored()) != 1 {
		t.Fatalf("reordered replay: event=%q store=%d", third.Event, len(api.stored()))
	}
}

func TestFalcoDelivery_AmbiguousCreateResolvesOnRetry(t *testing.T) {
	api := newAPIFixture(t)
	api.CreateStatus, api.PersistBeforeFail = 500, true
	fb := newFalcoBackend(t, api, 0)
	expect(t, do(fb, http.MethodPost, falcoJSON(falcoOpts{})), 503, "failed", "api:InternalError")
	if len(api.stored()) != 1 {
		t.Fatalf("fixture should have persisted before failing; store=%d", len(api.stored()))
	}
	api.CreateStatus = 0 // API healthy again; the retry must find and verify the stored object
	reply := expect(t, do(fb, http.MethodPost, falcoJSON(falcoOpts{})), 200, "duplicate", "")
	if got := api.methods(); !reflect.DeepEqual(got, []string{"POST ", "POST ", "GET /" + reply.Event}) || len(api.stored()) != 1 {
		t.Fatalf("requests=%v store=%d", got, len(api.stored()))
	}
}

func TestFalcoDelivery_ReadbackDenialIsNotSuccess(t *testing.T) {
	api := newAPIFixture(t)
	fb := newFalcoBackend(t, api, 0)
	first := expect(t, do(fb, http.MethodPost, falcoJSON(falcoOpts{})), 200, "accepted", "")
	for _, tc := range []struct {
		get    int
		hang   bool
		reason string
	}{{403, false, "readback_failed"}, {404, false, "readback_failed"}, {0, true, "readback_failed"}} {
		api.GetStatus, api.HangGet = tc.get, tc.hang
		fb.apiTimeout = 150 * time.Millisecond
		reply := expect(t, do(fb, http.MethodPost, falcoJSON(falcoOpts{})), 503, "failed", tc.reason)
		if reply.Event != first.Event || !strings.Contains(reply.Message, "readback failed") {
			t.Errorf("get=%d hang=%v: %+v", tc.get, tc.hang, reply)
		}
	}
	if len(api.stored()) != 1 {
		t.Fatalf("store=%d; readback failures must not write", len(api.stored()))
	}
}

func TestFalcoDelivery_CollisionWithDifferentObjectIsRefusedWithoutMutation(t *testing.T) {
	api := newAPIFixture(t)
	fb := newFalcoBackend(t, api, 0)
	first := expect(t, do(fb, http.MethodPost, falcoJSON(falcoOpts{})), 200, "accepted", "")
	stored := string(api.stored()[first.Event])

	cases := map[string]string{
		"foreign object without fingerprint":  `{"apiVersion":"amtd.r6security.com/v1beta1","kind":"SecurityEvent","metadata":{"name":"` + first.Event + `"},"spec":{"targets":["prod/web-1"],"description":"x","rule":{"type":"drift","threatLevel":"critical","source":"FalcoIntegrator"}}}`,
		"same fingerprint, different targets": strings.Replace(stored, `"targets":["prod/web-1"]`, `"targets":["staging/web-1"]`, 1),
		"same spec, different fingerprint":    strings.Replace(stored, first.DeliveryFingerprint, "sha256:"+strings.Repeat("0", 64), 1),
	}
	for name, replaced := range cases {
		t.Run(name, func(t *testing.T) {
			if replaced == stored {
				t.Fatalf("test setup did not alter the stored object")
			}
			api.Replace(first.Event, replaced)
			before := len(api.methods())
			reply := expect(t, do(fb, http.MethodPost, falcoJSON(falcoOpts{})), 409, "conflict", "readback_mismatch")
			if reply.Event != first.Event {
				t.Errorf("event=%q", reply.Event)
			}
			after := api.methods()[before:]
			if !reflect.DeepEqual(after, []string{"POST ", "GET /" + first.Event}) {
				t.Fatalf("requests=%v; want no PUT/PATCH/DELETE and no adoption", after)
			}
			if string(api.stored()[first.Event]) != replaced {
				t.Fatalf("stored object was mutated")
			}
		})
	}
}

func TestFalcoDelivery_DistinctContentSamePodSecondIsDistinct(t *testing.T) {
	api := newAPIFixture(t)
	fb := newFalcoBackend(t, api, 0)
	base := falcoOpts{}
	variants := []falcoOpts{
		base,
		{rule: "Terminal shell in container"},
		{time: "2026-09-10T16:00:00.123456788Z"}, // same second, one nanosecond earlier
		{ns: "staging"},                          // same pod name, different logical namespace
		{priority: "Warning"},
	}
	seen := map[string]bool{}
	for _, v := range variants {
		reply := expect(t, do(fb, http.MethodPost, falcoJSON(v)), 200, "accepted", "")
		if seen[reply.Event] {
			t.Fatalf("variant %+v collided on %s", v, reply.Event)
		}
		seen[reply.Event] = true
	}
	if len(api.stored()) != len(variants) {
		t.Fatalf("stored %d, want %d distinct events", len(api.stored()), len(variants))
	}
}

func TestFalcoDelivery_InvalidInputIsRefusedBeforeAnyWrite(t *testing.T) {
	cases := []struct {
		name   string
		method string
		body   string
		code   int
		reason string
		msg    string
	}{
		{"wrong method", http.MethodGet, "", 405, "method_not_allowed", "only POST"},
		{"malformed json", http.MethodPost, `{"rule":`, 400, "invalid_input", "malformed JSON"},
		{"trailing data", http.MethodPost, falcoJSON(falcoOpts{}) + `{"x":1}`, 400, "invalid_input", "malformed JSON"},
		{"missing time", http.MethodPost, strings.Replace(falcoJSON(falcoOpts{}), `"time":"2026-09-10T16:00:00.123456789Z",`, "", 1), 400, "invalid_input", "zero time"},
		{"invalid time", http.MethodPost, falcoJSON(falcoOpts{time: "yesterday"}), 400, "invalid_input", "malformed JSON"},
		{"missing rule", http.MethodPost, strings.Replace(falcoJSON(falcoOpts{}), `"rule":"Container Drift Detected (open+create)",`, "", 1), 400, "invalid_input", "missing rule"},
		{"missing namespace", http.MethodPost, strings.Replace(falcoJSON(falcoOpts{}), `"k8s.ns.name":"prod",`, "", 1), 400, "invalid_input", "missing output_fields.k8s.ns.name"},
		{"invalid namespace", http.MethodPost, falcoJSON(falcoOpts{ns: "Prod_NS"}), 400, "invalid_input", "invalid output_fields.k8s.ns.name"},
		{"missing pod", http.MethodPost, strings.Replace(falcoJSON(falcoOpts{}), `,"k8s.pod.name":"web-1"`, "", 1), 400, "invalid_input", "missing output_fields.k8s.pod.name"},
		{"invalid pod", http.MethodPost, falcoJSON(falcoOpts{pod: "web 1"}), 400, "invalid_input", "invalid output_fields.k8s.pod.name"},
		{"oversize body", http.MethodPost, `{"pad":"` + strings.Repeat("x", MAX_BODY_SIZE+1) + `"}`, 413, "body_too_large", "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newAPIFixture(t)
			fb := newFalcoBackend(t, api, 0)
			rec := do(fb, tc.method, tc.body)
			reply := expect(t, rec, tc.code, "invalid", tc.reason)
			if !strings.Contains(reply.Message, tc.msg) {
				t.Errorf("message=%q want substring %q", reply.Message, tc.msg)
			}
			if tc.code == 405 && rec.Header().Get("Allow") != "POST" {
				t.Errorf("Allow=%q", rec.Header().Get("Allow"))
			}
			if n := len(api.methods()); n != 0 {
				t.Fatalf("%d API request(s) were made for invalid input", n)
			}
		})
	}
}

func TestFalcoDelivery_CancelledRequestIsNotAcknowledged(t *testing.T) {
	t.Run("cancelled before delivery", func(t *testing.T) {
		api := newAPIFixture(t)
		fb := newFalcoBackend(t, api, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		expect(t, doCtx(ctx, fb, http.MethodPost, falcoJSON(falcoOpts{})), 503, "failed", "canceled")
		if len(api.methods()) != 0 {
			t.Fatalf("requests=%v; a dead request must not be attempted", api.methods())
		}
	})
	t.Run("cancelled during create", func(t *testing.T) {
		api := newAPIFixture(t)
		api.HangCreate = true
		fb := newFalcoBackend(t, api, 5*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(100 * time.Millisecond); cancel() }()
		expect(t, doCtx(ctx, fb, http.MethodPost, falcoJSON(falcoOpts{})), 503, "failed", "canceled")
		if got := api.methods(); !reflect.DeepEqual(got, []string{"POST "}) {
			t.Fatalf("requests=%v", got)
		}
	})
	t.Run("server shutting down", func(t *testing.T) {
		api := newAPIFixture(t)
		fb := newFalcoBackend(t, api, 0)
		base, cancel := context.WithCancel(context.Background())
		cancel()
		fb.ctx = base
		expect(t, do(fb, http.MethodPost, falcoJSON(falcoOpts{})), 503, "failed", "shutting_down")
		if len(api.methods()) != 0 {
			t.Fatalf("requests=%v", api.methods())
		}
	})
}

func TestGetAPITimeout(t *testing.T) {
	t.Setenv("SECURITYEVENT_API_TIMEOUT", "")
	if d, err := getAPITimeout(); err != nil || d != delivery.DefaultTimeout {
		t.Fatalf("default: %v %v", d, err)
	}
	t.Setenv("SECURITYEVENT_API_TIMEOUT", "2s")
	if d, err := getAPITimeout(); err != nil || d != 2*time.Second {
		t.Fatalf("2s: %v %v", d, err)
	}
	for _, bad := range []string{"0", "-1s", "soon"} {
		t.Setenv("SECURITYEVENT_API_TIMEOUT", bad)
		if _, err := getAPITimeout(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
