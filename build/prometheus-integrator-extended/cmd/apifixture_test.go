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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// apiFixture is an isolated HTTP Kubernetes API for the cluster-scoped
// securityevents resource. The real custom REST client talks to it over HTTP; it
// records every request and persists accepted objects so tests can prove what
// actually reached storage rather than trusting a mocked client flag. Fault
// controls model the API server, never the integrator.
const securityEventsPath = "/apis/amtd.r6security.com/v1beta1/securityevents"

type recordedRequest struct {
	Method string
	Path   string
	Body   []byte
}

type apiFixture struct {
	mu       sync.Mutex
	URL      string
	Requests []recordedRequest
	Store    map[string]json.RawMessage

	// CreateStatus, when non-zero, fails POSTs with that HTTP status (see reasons).
	CreateStatus int
	// FailNthCreate limits CreateStatus to the Nth POST (1-based); 0 means every POST.
	FailNthCreate int
	// FailName limits CreateStatus to POSTs of that object name.
	FailName string
	// PersistBeforeFail stores the object and then fails: an ambiguous Create whose
	// response was lost.
	PersistBeforeFail bool
	// GetStatus, when non-zero, fails GETs with that HTTP status.
	GetStatus int
	// HangCreate/HangGet block the response until the client gives up.
	HangCreate, HangGet bool
	// CreateReply, when set, replaces a successful Create's status/body after the
	// object was stored: "empty-200" (200 {}), "foreign-name" (201 with another
	// object's name), "drop-fingerprint" (201 without the fingerprint annotation),
	// "other-targets" (201 whose spec.targets differ). The store is untouched, so
	// a readback still sees the real object.
	CreateReply string
	// PruneOptionalSpec models a legacy CRD schema without spec.anomalyScore,
	// spec.metrics and spec.evidence: they are dropped from what is stored AND
	// from every response, exactly like an API server pruning unknown fields.
	PruneOptionalSpec bool

	creates int
}

var statusReasons = map[int]string{
	403: "Forbidden", 409: "AlreadyExists", 404: "NotFound", 422: "Invalid",
	429: "TooManyRequests", 500: "InternalError", 503: "ServiceUnavailable", 504: "Timeout",
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	f := &apiFixture{Store: map[string]json.RawMessage{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}

func (f *apiFixture) writeStatus(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":%q,"reason":%q,"code":%d}`,
		message, statusReasons[code], code)
}

func (f *apiFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.Requests = append(f.Requests, recordedRequest{r.Method, r.URL.Path, body})
	hangCreate, hangGet := f.HangCreate, f.HangGet
	f.mu.Unlock()
	if (r.Method == http.MethodPost && hangCreate) || (r.Method == http.MethodGet && hangGet) {
		<-r.Context().Done()
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == securityEventsPath:
		f.creates++
		var obj struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(body, &obj); err != nil || obj.Metadata.Name == "" {
			f.writeStatus(w, 422, "fixture: metadata.name is required")
			return
		}
		if obj.Metadata.Namespace != "" {
			// A real Cluster-scoped API silently clears metadata.namespace; the fixture
			// refuses it so the integrator's wire object is proven namespace-free.
			f.writeStatus(w, 422, "fixture: metadata.namespace is not allowed on a Cluster-scoped resource")
			return
		}
		if f.CreateStatus != 0 && (f.FailNthCreate == 0 || f.FailNthCreate == f.creates) && (f.FailName == "" || f.FailName == obj.Metadata.Name) {
			if f.PersistBeforeFail {
				if _, exists := f.Store[obj.Metadata.Name]; !exists {
					f.Store[obj.Metadata.Name] = json.RawMessage(body)
				}
			}
			f.writeStatus(w, f.CreateStatus, "fixture: create failed with "+statusReasons[f.CreateStatus])
			return
		}
		if _, exists := f.Store[obj.Metadata.Name]; exists {
			f.writeStatus(w, 409, `securityevents.amtd.r6security.com "`+obj.Metadata.Name+`" already exists`)
			return
		}
		stored := body
		if f.PruneOptionalSpec {
			stored = pruneOptionalSpec(stored)
		}
		f.Store[obj.Metadata.Name] = json.RawMessage(stored)
		status, reply := http.StatusCreated, stored
		switch f.CreateReply {
		case "empty-200":
			status, reply = http.StatusOK, []byte(`{}`)
		case "foreign-name":
			reply = rewriteJSON(stored, func(m map[string]any) { m["metadata"].(map[string]any)["name"] = "not-this-one" })
		case "drop-fingerprint":
			reply = rewriteJSON(stored, func(m map[string]any) {
				delete(m["metadata"].(map[string]any)["annotations"].(map[string]any), "amtd.r6security.com/delivery-fingerprint")
			})
		case "other-targets":
			reply = rewriteJSON(stored, func(m map[string]any) { m["spec"].(map[string]any)["targets"] = []any{"elsewhere/other"} })
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(reply)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, securityEventsPath+"/"):
		name := strings.TrimPrefix(r.URL.Path, securityEventsPath+"/")
		if f.GetStatus != 0 {
			f.writeStatus(w, f.GetStatus, "fixture: get failed with "+statusReasons[f.GetStatus])
			return
		}
		obj, ok := f.Store[name]
		if !ok {
			f.writeStatus(w, 404, `securityevents.amtd.r6security.com "`+name+`" not found`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(obj)
	default:
		f.writeStatus(w, 404, "fixture: unhandled "+r.Method+" "+r.URL.Path)
	}
}

// Replace overwrites a stored object with different content under the same name
// (an operator-edited or foreign object occupying this delivery's name).
func (f *apiFixture) Replace(name string, obj string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Store[name] = json.RawMessage(obj)
}

func (f *apiFixture) snapshot() ([]recordedRequest, map[string]json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reqs := append([]recordedRequest(nil), f.Requests...)
	store := map[string]json.RawMessage{}
	for k, v := range f.Store {
		store[k] = v
	}
	return reqs, store
}

func (f *apiFixture) methods() []string {
	reqs, _ := f.snapshot()
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Method+" "+strings.TrimPrefix(r.Path, securityEventsPath))
	}
	return out
}

func (f *apiFixture) stored() map[string]json.RawMessage {
	_, s := f.snapshot()
	return s
}

// storedEvent decodes one persisted object's metadata and spec.
type storedEvent struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Metadata   struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Targets     []string          `json:"targets"`
		Description string            `json:"description"`
		Rule        map[string]string `json:"rule"`
		Score       string            `json:"anomalyScore"`
		Metrics     map[string]string `json:"metrics"`
	} `json:"spec"`
}

func decodeStored(t *testing.T, raw json.RawMessage) storedEvent {
	t.Helper()
	var ev storedEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("stored object is not a SecurityEvent: %v", err)
	}
	return ev
}

// rewriteJSON applies an in-place edit to a decoded JSON object and re-encodes it.
func rewriteJSON(raw []byte, edit func(map[string]any)) []byte {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return out
}

// pruneOptionalSpec drops the fields a pre-anomalyScore SecurityEvent CRD does
// not declare (the chart shipped them missing until V3-M164 synchronized it).
func pruneOptionalSpec(raw []byte) []byte {
	return rewriteJSON(raw, func(m map[string]any) {
		if spec, ok := m["spec"].(map[string]any); ok {
			delete(spec, "anomalyScore")
			delete(spec, "metrics")
			delete(spec, "evidence")
		}
	})
}
