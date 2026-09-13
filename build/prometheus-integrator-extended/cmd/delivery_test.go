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

// V3-M164 delivery tests: the ACTUAL PrometheusHandler drives the ACTUAL custom
// REST client (clients.NewClient) against apiFixture over HTTP. Persistence is
// asserted from the fixture's store and recorded requests; acknowledgement from
// the wire status and JSON body (per-item outcomes and counts).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/r6security/prometheus-integrator/delivery"

	amtdv1beta1client "github.com/r6security/prometheus-integrator/clients"
	"k8s.io/client-go/rest"
)

func newPrometheusBackend(t *testing.T, api *apiFixture, timeout time.Duration) PrometheusBackend {
	t.Helper()
	client, err := amtdv1beta1client.NewClient(&rest.Config{Host: api.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c := client.SecurityEvents()
	return PrometheusBackend{client: &c, ctx: context.Background(), apiTimeout: timeout}
}

type alertOpts struct {
	pod, ns, alertname, fingerprint, startsAt, status string
	extraLabels                                       string // raw JSON members appended to labels, e.g. `,"anomaly_score":"0.7"`
}

func alertJSON(o alertOpts) string {
	if o.pod == "" {
		o.pod = "web-1"
	}
	if o.ns == "" {
		o.ns = "prod"
	}
	if o.alertname == "" {
		o.alertname = "HighGPU"
	}
	if o.fingerprint == "" {
		o.fingerprint = "f-" + o.alertname + "-" + o.pod
	}
	if o.startsAt == "" {
		o.startsAt = "2026-09-10T16:00:00.123456789Z"
	}
	if o.status == "" {
		o.status = "firing"
	}
	return `{"status":"` + o.status + `","labels":{"alertname":"` + o.alertname + `","namespace":"` + o.ns + `","pod":"` + o.pod +
		`","severity":"critical","type":"drift","threatlevel":"high"` + o.extraLabels + `},"annotations":{"summary":"` + o.alertname + ` on ` + o.pod +
		`"},"startsAt":"` + o.startsAt + `","endsAt":"0001-01-01T00:00:00Z","generatorURL":"http://prometheus:9090/graph?g0.expr=up","fingerprint":"` + o.fingerprint + `"}`
}

func batchJSON(truncated int, alerts ...string) string {
	return `{"version":"4","groupKey":"{}:{alertname=\"HighGPU\"}","truncatedAlerts":` + itoa(truncated) +
		`,"status":"firing","receiver":"phorvex","groupLabels":{"alertname":"HighGPU"},"commonLabels":{"severity":"critical"},"commonAnnotations":{},"externalURL":"http://alertmanager:9093","alerts":[` +
		strings.Join(alerts, ",") + `]}`
}

func itoa(n int) string { return strconv.Itoa(n) }

func do(pb PrometheusBackend, method, body string) *httptest.ResponseRecorder {
	return doCtx(context.Background(), pb, method, body)
}

func doCtx(ctx context.Context, pb PrometheusBackend, method, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/", strings.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	pb.PrometheusHandler(rec, req)
	return rec
}

func decodeReply(t *testing.T, rec *httptest.ResponseRecorder) prometheusResponse {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q", ct)
	}
	var reply prometheusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("reply %q is not valid JSON: %v", rec.Body.String(), err)
	}
	return reply
}

// expect checks status/overall and, when counts is non-nil, the aggregate counts.
func expect(t *testing.T, rec *httptest.ResponseRecorder, code int, status string, counts *batchCounts) prometheusResponse {
	t.Helper()
	reply := decodeReply(t, rec)
	if rec.Code != code || reply.Status != status {
		t.Fatalf("got %d %s reason=%q msg=%q body=%s; want %d %s", rec.Code, reply.Status, reply.Reason, reply.Message, rec.Body.String(), code, status)
	}
	if counts != nil && (reply.Counts == nil || *reply.Counts != *counts) {
		t.Fatalf("counts=%+v want %+v (items=%+v)", reply.Counts, *counts, reply.Items)
	}
	if reply.Counts != nil && len(reply.Items) != reply.Counts.Total {
		t.Fatalf("items=%d total=%d", len(reply.Items), reply.Counts.Total)
	}
	return reply
}

func outcomes(reply prometheusResponse) []string {
	out := make([]string, 0, len(reply.Items))
	for _, it := range reply.Items {
		out = append(out, string(it.Outcome)+":"+it.Reason)
	}
	return out
}

func TestPrometheusDelivery_FullBatchIsPersistedThroughClusterScopedREST(t *testing.T) {
	api := newAPIFixture(t)
	pb := newPrometheusBackend(t, api, 0)
	rec := do(pb, http.MethodPost, batchJSON(0, alertJSON(alertOpts{pod: "web-1", extraLabels: `,"anomaly_score":"0.7"`}), alertJSON(alertOpts{pod: "web-2"})))
	reply := expect(t, rec, 200, "accepted", &batchCounts{Total: 2, Accepted: 2})

	if got := api.methods(); !reflect.DeepEqual(got, []string{"POST ", "POST "}) {
		t.Fatalf("requests=%v", got)
	}
	store := api.stored()
	if len(store) != 2 {
		t.Fatalf("store=%d", len(store))
	}
	for i, it := range reply.Items {
		if it.Index != i || it.Fingerprint != "f-HighGPU-web-"+itoa(i+1) || it.Outcome != delivery.Accepted {
			t.Errorf("item %d = %+v", i, it)
		}
		raw, ok := store[it.Event]
		if !ok {
			t.Fatalf("acknowledged event %q is not stored", it.Event)
		}
		ev := decodeStored(t, raw)
		if ev.Kind != "SecurityEvent" || ev.APIVersion != "amtd.r6security.com/v1beta1" || ev.Metadata.Namespace != "" {
			t.Errorf("wire object = %q/%q namespace=%q", ev.Kind, ev.APIVersion, ev.Metadata.Namespace)
		}
		if !strings.HasPrefix(ev.Metadata.Name, "prometheus-") || len(ev.Metadata.Name) != len("prometheus-")+delivery.NameDigestLength {
			t.Errorf("name %q", ev.Metadata.Name)
		}
		if ev.Metadata.Annotations[delivery.FingerprintAnnotation] != it.DeliveryFingerprint || ev.Metadata.Annotations[delivery.IdentityAnnotation] != "prometheus/"+delivery.IdentityVersion {
			t.Errorf("annotations=%v item=%+v", ev.Metadata.Annotations, it)
		}
		// Normalization positive control (unchanged Phase 7 math) observed on the wire.
		wantScore, wantSource := "0.8", "severity-proxy"
		if i == 0 {
			wantScore, wantSource = "0.7", "alert"
		}
		if !reflect.DeepEqual(ev.Spec.Targets, []string{"prod/web-" + itoa(i+1)}) || ev.Spec.Rule["type"] != "drift" || ev.Spec.Rule["threatLevel"] != "high" ||
			ev.Spec.Rule["source"] != "PrometheusIntegrator" || ev.Spec.Score != wantScore || ev.Spec.Metrics["anomaly_score.source"] != wantSource ||
			ev.Spec.Metrics["alertname"] != "HighGPU" || !strings.Contains(ev.Spec.Description, it.Fingerprint) {
			t.Errorf("normalized spec on the wire = %+v", ev.Spec)
		}
	}
}

func TestPrometheusDelivery_AllFailedIsNotAcknowledged(t *testing.T) {
	api := newAPIFixture(t)
	api.CreateStatus = 403
	pb := newPrometheusBackend(t, api, 0)
	reply := expect(t, do(pb, http.MethodPost, batchJSON(0, alertJSON(alertOpts{pod: "web-1"}), alertJSON(alertOpts{pod: "web-2"}))), 503, "failed", &batchCounts{Total: 2, Failed: 2})
	if got := outcomes(reply); !reflect.DeepEqual(got, []string{"failed:api:Forbidden", "failed:api:Forbidden"}) {
		t.Fatalf("outcomes=%v", got)
	}
	if len(api.stored()) != 0 || len(api.methods()) != 2 {
		t.Fatalf("store=%d requests=%v; want nothing stored, one attempt per alert", len(api.stored()), api.methods())
	}
}

func TestPrometheusDelivery_PartialFailureThenWholeBatchRetry(t *testing.T) {
	api := newAPIFixture(t)
	api.CreateStatus, api.FailNthCreate = 503, 2
	pb := newPrometheusBackend(t, api, 0)
	batch := batchJSON(0, alertJSON(alertOpts{pod: "web-1"}), alertJSON(alertOpts{pod: "web-2"}), alertJSON(alertOpts{pod: "web-3"}))

	first := expect(t, do(pb, http.MethodPost, batch), 503, "failed", &batchCounts{Total: 3, Accepted: 2, Failed: 1})
	if got := outcomes(first); !reflect.DeepEqual(got, []string{"accepted:", "failed:api:ServiceUnavailable", "accepted:"}) {
		t.Fatalf("outcomes=%v", got)
	}
	if len(api.stored()) != 2 {
		t.Fatalf("store=%d; the two accepted alerts must stay stored", len(api.stored()))
	}

	api.CreateStatus = 0
	before := len(api.methods())
	second := expect(t, do(pb, http.MethodPost, batch), 200, "accepted", &batchCounts{Total: 3, Accepted: 1, Duplicate: 2})
	if got := outcomes(second); !reflect.DeepEqual(got, []string{"duplicate:", "accepted:", "duplicate:"}) {
		t.Fatalf("outcomes=%v", got)
	}
	want := []string{"POST ", "GET /" + first.Items[0].Event, "POST ", "POST ", "GET /" + first.Items[2].Event}
	if got := api.methods()[before:]; !reflect.DeepEqual(got, want) {
		t.Fatalf("retry requests=%v want %v", got, want)
	}
	if len(api.stored()) != 3 {
		t.Fatalf("store=%d; want 3 with no duplicates", len(api.stored()))
	}
	for i := range first.Items {
		if first.Items[i].Event != second.Items[i].Event {
			t.Errorf("item %d identity changed across retry: %q vs %q", i, first.Items[i].Event, second.Items[i].Event)
		}
	}
}

func TestPrometheusDelivery_ReorderedReplayIsAllDuplicates(t *testing.T) {
	api := newAPIFixture(t)
	pb := newPrometheusBackend(t, api, 0)
	a, b := alertJSON(alertOpts{pod: "web-1"}), alertJSON(alertOpts{pod: "web-2"})
	first := expect(t, do(pb, http.MethodPost, batchJSON(0, a, b)), 200, "accepted", &batchCounts{Total: 2, Accepted: 2})
	// Reordered entries, reordered keys inside an alert, different batch metadata.
	bReordered := `{ "fingerprint":"f-HighGPU-web-2","generatorURL":"http://prometheus:9090/graph?g0.expr=up","endsAt":"0001-01-01T00:00:00Z","startsAt":"2026-09-10T16:00:00.123456789Z","annotations":{"summary":"HighGPU on web-2"},"labels":{"threatlevel":"high","type":"drift","severity":"critical","pod":"web-2","namespace":"prod","alertname":"HighGPU"},"status":"firing" }`
	replay := strings.Replace(batchJSON(0, bReordered, a), `"receiver":"phorvex"`, `"receiver":"phorvex-2"`, 1)
	second := expect(t, do(pb, http.MethodPost, replay), 200, "accepted", &batchCounts{Total: 2, Duplicate: 2})
	if second.Items[0].Event != first.Items[1].Event || second.Items[1].Event != first.Items[0].Event {
		t.Fatalf("identity must follow alert content, not batch position: %+v vs %+v", first.Items, second.Items)
	}
	if len(api.stored()) != 2 {
		t.Fatalf("store=%d", len(api.stored()))
	}
}

func TestPrometheusDelivery_IdenticalAlertsWithinOneBatch(t *testing.T) {
	api := newAPIFixture(t)
	pb := newPrometheusBackend(t, api, 0)
	a := alertJSON(alertOpts{pod: "web-1"})
	reply := expect(t, do(pb, http.MethodPost, batchJSON(0, a, a)), 200, "accepted", &batchCounts{Total: 2, Accepted: 1, Duplicate: 1})
	if reply.Items[0].Event != reply.Items[1].Event || len(api.stored()) != 1 {
		t.Fatalf("items=%+v store=%d", reply.Items, len(api.stored()))
	}
}

func TestPrometheusDelivery_CollisionAndReadbackFailures(t *testing.T) {
	api := newAPIFixture(t)
	pb := newPrometheusBackend(t, api, 0)
	batch := batchJSON(0, alertJSON(alertOpts{pod: "web-1"}), alertJSON(alertOpts{pod: "web-2"}))
	first := expect(t, do(pb, http.MethodPost, batch), 200, "accepted", &batchCounts{Total: 2, Accepted: 2})
	stored0 := string(api.stored()[first.Items[0].Event])

	t.Run("readback denied is failed", func(t *testing.T) {
		api.GetStatus = 403
		defer func() { api.GetStatus = 0 }()
		reply := expect(t, do(pb, http.MethodPost, batch), 503, "failed", &batchCounts{Total: 2, Failed: 2})
		if got := outcomes(reply); !reflect.DeepEqual(got, []string{"failed:readback_failed", "failed:readback_failed"}) {
			t.Fatalf("outcomes=%v", got)
		}
	})
	t.Run("replaced object is conflict 409", func(t *testing.T) {
		api.Replace(first.Items[0].Event, strings.Replace(stored0, `"targets":["prod/web-1"]`, `"targets":["staging/web-1"]`, 1))
		before := len(api.methods())
		reply := expect(t, do(pb, http.MethodPost, batch), 409, "conflict", &batchCounts{Total: 2, Duplicate: 1, Conflict: 1})
		if got := outcomes(reply); !reflect.DeepEqual(got, []string{"conflict:readback_mismatch", "duplicate:"}) {
			t.Fatalf("outcomes=%v", got)
		}
		for _, m := range api.methods()[before:] {
			if !strings.HasPrefix(m, "POST ") && !strings.HasPrefix(m, "GET ") {
				t.Fatalf("unexpected mutation request %q", m)
			}
		}
		if len(api.stored()) != 2 {
			t.Fatalf("store=%d", len(api.stored()))
		}
	})
	t.Run("conflict plus failure is 503", func(t *testing.T) {
		api.CreateStatus, api.FailName = 500, first.Items[1].Event
		defer func() { api.CreateStatus, api.FailName = 0, "" }()
		reply := expect(t, do(pb, http.MethodPost, batch), 503, "failed", &batchCounts{Total: 2, Conflict: 1, Failed: 1})
		if got := outcomes(reply); !reflect.DeepEqual(got, []string{"conflict:readback_mismatch", "failed:api:InternalError"}) {
			t.Fatalf("outcomes=%v", got)
		}
	})
}

func TestPrometheusDelivery_CancellationAndDeadline(t *testing.T) {
	t.Run("deadline on first alert; rest still attempted honestly", func(t *testing.T) {
		api := newAPIFixture(t)
		api.HangCreate = true
		pb := newPrometheusBackend(t, api, 150*time.Millisecond)
		reply := expect(t, do(pb, http.MethodPost, batchJSON(0, alertJSON(alertOpts{pod: "web-1"}), alertJSON(alertOpts{pod: "web-2"}))), 503, "failed", &batchCounts{Total: 2, Failed: 2})
		if got := outcomes(reply); !reflect.DeepEqual(got, []string{"failed:timeout", "failed:timeout"}) {
			t.Fatalf("outcomes=%v", got)
		}
		if len(api.methods()) != 2 {
			t.Fatalf("requests=%v; one bounded attempt per alert", api.methods())
		}
	})
	t.Run("request cancelled mid-batch: remaining alerts not attempted", func(t *testing.T) {
		api := newAPIFixture(t)
		pb := newPrometheusBackend(t, api, 5*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for len(api.methods()) < 2 { // cancel while the fixture is holding the second Create
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
		}()
		api.mu.Lock()
		api.FailNthCreate = 0
		api.mu.Unlock()
		// Hang only the second create: the first is stored, the second blocks until cancel.
		hangSecond := &hangSecondCreate{inner: api}
		srv := httptest.NewServer(hangSecond)
		defer srv.Close()
		client, err := amtdv1beta1client.NewClient(&rest.Config{Host: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		c := client.SecurityEvents()
		pb.client = &c
		reply := expect(t, doCtx(ctx, pb, http.MethodPost, batchJSON(0, alertJSON(alertOpts{pod: "web-1"}), alertJSON(alertOpts{pod: "web-2"}), alertJSON(alertOpts{pod: "web-3"}))),
			503, "failed", &batchCounts{Total: 3, Accepted: 1, Failed: 2})
		if got := outcomes(reply); !reflect.DeepEqual(got, []string{"accepted:", "failed:canceled", "failed:canceled"}) {
			t.Fatalf("outcomes=%v", got)
		}
		if !strings.Contains(reply.Items[2].Message, "not attempted") {
			t.Errorf("third item should report not attempted: %+v", reply.Items[2])
		}
		if len(api.stored()) != 1 {
			t.Fatalf("store=%d", len(api.stored()))
		}
	})
	t.Run("server shutting down", func(t *testing.T) {
		api := newAPIFixture(t)
		pb := newPrometheusBackend(t, api, 0)
		base, cancel := context.WithCancel(context.Background())
		cancel()
		pb.ctx = base
		reply := expect(t, do(pb, http.MethodPost, batchJSON(0, alertJSON(alertOpts{}))), 503, "failed", nil)
		if reply.Reason != "shutting_down" || len(api.methods()) != 0 {
			t.Fatalf("reply=%+v requests=%v", reply, api.methods())
		}
	})
}

// hangSecondCreate wraps apiFixture: the second POST blocks until the client goes away.
type hangSecondCreate struct {
	inner *apiFixture
	posts int
}

func (h *hangSecondCreate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.inner.mu.Lock()
		h.posts++
		n := h.posts
		h.inner.mu.Unlock()
		if n == 2 {
			io.ReadAll(r.Body) // let the server notice the client leaving (background read)
			h.inner.mu.Lock()
			h.inner.Requests = append(h.inner.Requests, recordedRequest{Method: r.Method, Path: r.URL.Path})
			h.inner.mu.Unlock()
			<-r.Context().Done()
			return
		}
	}
	h.inner.ServeHTTP(w, r)
}

func TestPrometheusDelivery_DistinctContentSamePodSecondIsDistinct(t *testing.T) {
	api := newAPIFixture(t)
	pb := newPrometheusBackend(t, api, 0)
	variants := []string{
		alertJSON(alertOpts{}),
		alertJSON(alertOpts{alertname: "CacheMissSpike"}),
		alertJSON(alertOpts{startsAt: "2026-09-10T16:00:00.123456788Z"}), // same second, one nanosecond earlier
		alertJSON(alertOpts{ns: "staging"}),                              // same pod name, different logical namespace
		alertJSON(alertOpts{status: "resolved"}),
		alertJSON(alertOpts{fingerprint: "other"}),
	}
	reply := expect(t, do(pb, http.MethodPost, batchJSON(0, variants...)), 200, "accepted", &batchCounts{Total: len(variants), Accepted: len(variants)})
	seen := map[string]bool{}
	for _, it := range reply.Items {
		if seen[it.Event] {
			t.Fatalf("collision on %s: %+v", it.Event, reply.Items)
		}
		seen[it.Event] = true
	}
	if len(api.stored()) != len(variants) {
		t.Fatalf("stored %d want %d", len(api.stored()), len(variants))
	}
}

func TestPrometheusDelivery_InvalidBatchIsRefusedBeforeAnyWrite(t *testing.T) {
	valid := alertJSON(alertOpts{pod: "web-1"})
	cases := []struct {
		name   string
		method string
		body   string
		code   int
		reason string
		msg    string
	}{
		{"wrong method", http.MethodGet, "", 405, "method_not_allowed", "only POST"},
		{"malformed json", http.MethodPost, `{"alerts":[`, 400, "invalid_input", "malformed JSON"},
		{"alerts not objects", http.MethodPost, `{"alerts":["x"]}`, 400, "invalid_input", "malformed JSON"},
		{"truncated batch", http.MethodPost, batchJSON(3, valid), 400, "truncated_batch", "truncatedAlerts=3"},
		{"empty batch", http.MethodPost, batchJSON(0), 400, "empty_batch", "alerts is empty"},
		{"second alert missing pod: first is NOT created", http.MethodPost, batchJSON(0, valid, strings.Replace(alertJSON(alertOpts{pod: "web-2"}), `"pod":"web-2",`, "", 1)), 400, "invalid_input", "alerts[1]: missing labels.pod"},
		{"missing namespace", http.MethodPost, batchJSON(0, strings.Replace(valid, `"namespace":"prod",`, "", 1)), 400, "invalid_input", "missing labels.namespace"},
		{"invalid namespace", http.MethodPost, batchJSON(0, alertJSON(alertOpts{ns: "Prod_NS"})), 400, "invalid_input", "invalid labels.namespace"},
		{"invalid pod", http.MethodPost, batchJSON(0, alertJSON(alertOpts{pod: "web 1"})), 400, "invalid_input", "invalid labels.pod"},
		{"missing startsAt", http.MethodPost, batchJSON(0, strings.Replace(valid, `"startsAt":"2026-09-10T16:00:00.123456789Z",`, "", 1)), 400, "invalid_input", "zero startsAt"},
		{"invalid startsAt", http.MethodPost, batchJSON(0, alertJSON(alertOpts{startsAt: "now"})), 400, "invalid_input", "malformed JSON"},
		{"missing fingerprint", http.MethodPost, batchJSON(0, strings.Replace(valid, `,"fingerprint":"f-HighGPU-web-1"`, "", 1)), 400, "invalid_input", "missing fingerprint"},
		{"missing alertname", http.MethodPost, batchJSON(0, strings.Replace(valid, `"alertname":"HighGPU",`, "", 1)), 400, "invalid_input", "missing labels.alertname"},
		{"oversize body", http.MethodPost, `{"pad":"` + strings.Repeat("x", MAX_BODY_SIZE+1) + `"}`, 413, "body_too_large", "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newAPIFixture(t)
			pb := newPrometheusBackend(t, api, 0)
			rec := do(pb, tc.method, tc.body)
			reply := expect(t, rec, tc.code, "invalid", nil)
			if reply.Reason != tc.reason || !strings.Contains(reply.Message, tc.msg) {
				t.Errorf("reason=%q message=%q want %q / %q", reply.Reason, reply.Message, tc.reason, tc.msg)
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
