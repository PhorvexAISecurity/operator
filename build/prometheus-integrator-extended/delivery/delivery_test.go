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

package delivery

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestCanonicalJSON(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		same bool
	}{
		{"key order is irrelevant", `{"b":1,"a":{"d":2,"c":3}}`, `{"a":{"c":3,"d":2},"b":1}`, true},
		{"whitespace is irrelevant", "{ \"a\" : [1, 2] }\n", `{"a":[1,2]}`, true},
		{"array order is content", `{"a":[1,2]}`, `{"a":[2,1]}`, false},
		{"number literal precision is preserved", `{"score":0.10}`, `{"score":0.1}`, false},
		{"exponent form is preserved", `{"n":1e2}`, `{"n":100}`, false},
		{"large integers do not round", `{"n":9007199254740993}`, `{"n":9007199254740992}`, false},
		{"nanosecond timestamps are content", `{"t":"2026-09-10T16:00:00.123456789Z"}`, `{"t":"2026-09-10T16:00:00.123456788Z"}`, false},
		{"strings are content", `{"rule":"a"}`, `{"rule":"b"}`, false},
		{"html-ish characters are stable", `{"o":"<a&b>"}`, `{ "o" : "<a&b>" }`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := CanonicalJSON([]byte(tc.a))
			if err != nil {
				t.Fatalf("a: %v", err)
			}
			cb, err := CanonicalJSON([]byte(tc.b))
			if err != nil {
				t.Fatalf("b: %v", err)
			}
			if (string(ca) == string(cb)) != tc.same {
				t.Fatalf("canonical(a)=%s canonical(b)=%s same=%v want %v", ca, cb, string(ca) == string(cb), tc.same)
			}
		})
	}
	if got, _ := CanonicalJSON([]byte(`{"o":"<a&b>","n":1.50}`)); string(got) != `{"n":1.50,"o":"<a&b>"}` {
		t.Fatalf("canonical form = %s", got)
	}
	for _, bad := range []string{``, `{`, `{"a":1} trailing`, `{"a":1}{"b":2}`, `nul`} {
		if _, err := CanonicalJSON([]byte(bad)); err == nil {
			t.Errorf("CanonicalJSON(%q) accepted malformed input", bad)
		}
	}
}

func TestDeriveIdentity(t *testing.T) {
	canonical, _ := CanonicalJSON([]byte(`{"rule":"Terminal shell in container","time":"2026-09-10T16:00:00.123456789Z","output_fields":{"k8s.ns.name":"prod","k8s.pod.name":"web-1"}}`))
	id := Derive("prometheus", canonical)
	if !regexp.MustCompile(`^prometheus-[0-9a-f]{40}$`).MatchString(id.Name) {
		t.Fatalf("name %q is not <prefix>-<40 hex>", id.Name)
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(id.Fingerprint) {
		t.Fatalf("fingerprint %q is not sha256:<64 hex>", id.Fingerprint)
	}
	if !strings.HasPrefix(strings.TrimPrefix(id.Fingerprint, "sha256:"), strings.TrimPrefix(id.Name, "prometheus-")) {
		t.Fatalf("name digest %q must be a prefix of the fingerprint %q", id.Name, id.Fingerprint)
	}
	if errs := validation.IsDNS1123Subdomain(id.Name); len(errs) > 0 {
		t.Fatalf("name %q is not a valid Kubernetes object name: %v", id.Name, errs)
	}
	if errs := validation.IsDNS1123Label(id.Name); len(errs) > 0 {
		t.Fatalf("name %q should also fit a 63-char label: %v", id.Name, errs)
	}
	if again := Derive("prometheus", canonical); again != id {
		t.Fatalf("identity is not deterministic: %+v vs %+v", id, again)
	}
	if other := Derive("falco", canonical); other.Name == id.Name || other.Fingerprint == id.Fingerprint {
		t.Fatalf("identical content under a different detector prefix must not share identity")
	}
	changed, _ := CanonicalJSON([]byte(`{"rule":"Terminal shell in container","time":"2026-09-10T16:00:00.123456788Z","output_fields":{"k8s.ns.name":"prod","k8s.pod.name":"web-1"}}`))
	if Derive("prometheus", changed).Name == id.Name {
		t.Fatalf("one nanosecond of difference must change the identity")
	}
	ns, _ := CanonicalJSON([]byte(`{"rule":"Terminal shell in container","time":"2026-09-10T16:00:00.123456789Z","output_fields":{"k8s.ns.name":"staging","k8s.pod.name":"web-1"}}`))
	if Derive("prometheus", ns).Name == id.Name {
		t.Fatalf("a different logical target namespace must change the identity")
	}
}

func TestStampAndHTTPStatus(t *testing.T) {
	ev := &amtdapi.SecurityEvent{}
	ev.Namespace = "prod" // a namespaced object would be silently rewritten by a Cluster-scoped API; Stamp clears it.
	id := Derive("prometheus", []byte(`{}`))
	Stamp(ev, "prometheus", id)
	if ev.Name != id.Name || ev.Namespace != "" {
		t.Fatalf("Stamp: name=%q namespace=%q", ev.Name, ev.Namespace)
	}
	if ev.Annotations[FingerprintAnnotation] != id.Fingerprint || ev.Annotations[IdentityAnnotation] != "prometheus/"+IdentityVersion {
		t.Fatalf("Stamp annotations = %v", ev.Annotations)
	}
	for o, want := range map[Outcome]int{Accepted: 200, Duplicate: 200, Conflict: 409, Failed: 503, Outcome("weird"): 503} {
		if got := HTTPStatus(o); got != want {
			t.Errorf("HTTPStatus(%s)=%d want %d", o, got, want)
		}
	}
}

func TestMismatch(t *testing.T) {
	score := "0.95"
	base := func() *amtdapi.SecurityEvent {
		ev := &amtdapi.SecurityEvent{Spec: amtdapi.SecurityEventSpec{
			Targets: []string{"prod/web-1"}, Description: "d", AnomalyScore: &score,
			Rule:    amtdapi.Rule{Type: "drift", ThreatLevel: "critical", Source: "PrometheusIntegrator"},
			Metrics: map[string]string{"alertname": "r"},
		}}
		Stamp(ev, "prometheus", Derive("prometheus", []byte(`{"x":1}`)))
		return ev
	}
	if why := mismatch(base(), base()); why != "" {
		t.Fatalf("identical events mismatch: %s", why)
	}
	sameContent := base()
	sameContent.Spec.Metrics = map[string]string{"alertname": "r"} // same content, distinct map instance
	if why := mismatch(sameContent, base()); why != "" {
		t.Fatalf("equal content in distinct maps mismatched: %s", why)
	}
	cases := map[string]func(*amtdapi.SecurityEvent){
		"name differs":                 func(e *amtdapi.SecurityEvent) { e.Name = "prometheus-other" },
		"delivery fingerprint differs": func(e *amtdapi.SecurityEvent) { e.Annotations[FingerprintAnnotation] = "sha256:00" },
		"delivery identity scheme differs": func(e *amtdapi.SecurityEvent) {
			e.Annotations[IdentityAnnotation] = "prometheus/v0"
		},
		"spec differs": func(e *amtdapi.SecurityEvent) { e.Spec.Targets = []string{"staging/web-1"} },
	}
	for want, mutate := range cases {
		stored := base()
		mutate(stored)
		if why := mismatch(stored, base()); why != want {
			t.Errorf("mismatch=%q want %q", why, want)
		}
	}
	missing := base()
	missing.Annotations = nil
	if why := mismatch(missing, base()); why != "delivery fingerprint differs" {
		t.Errorf("an unfingerprinted stored object must not be adopted: %q", why)
	}
}

func TestClassify(t *testing.T) {
	gr := schema.GroupResource{Group: "amtd.r6security.com", Resource: "securityevents"}
	ctx := context.Background()
	if r, m := classify(ctx, apierrors.NewForbidden(gr, "x", errors.New("denied"))); r != "api:Forbidden" || !strings.Contains(m, "denied") {
		t.Errorf("forbidden -> %q %q", r, m)
	}
	if r, _ := classify(ctx, apierrors.NewTooManyRequests("slow down", 1)); r != "api:TooManyRequests" {
		t.Errorf("429 -> %q", r)
	}
	if r, _ := classify(ctx, apierrors.NewInternalError(errors.New("etcd"))); r != "api:InternalError" {
		t.Errorf("500 -> %q", r)
	}
	if r, _ := classify(ctx, context.DeadlineExceeded); r != "timeout" {
		t.Errorf("deadline -> %q", r)
	}
	if r, _ := classify(ctx, errors.New("dial tcp: connection refused")); r != "transport" {
		t.Errorf("transport -> %q", r)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if r, _ := classify(canceled, errors.New("anything")); r != "canceled" {
		t.Errorf("parent canceled -> %q", r)
	}
	long := strings.Repeat("x", 1000)
	if got := bound(long); len(got) > maxMessage+len("…") {
		t.Errorf("bound did not bound: %d bytes", len(got))
	}
}
