package cataloguev1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

type chromaTestRecorder struct {
	intents []Intent
	events  []Event
}

func (r *chromaTestRecorder) Intent(v Intent) error           { r.intents = append(r.intents, v); return nil }
func (r *chromaTestRecorder) Event(v Event) error             { r.events = append(r.events, v); return nil }
func (r *chromaTestRecorder) Metric(Metric) error             { return nil }
func (r *chromaTestRecorder) MetricRaw(json.RawMessage) error { return nil }
func (r *chromaTestRecorder) Result(Result) error             { return nil }

type chromaTestTransport struct {
	server               *httptest.Server
	calls                int
	snapshots            int
	failSnapshotAt       int
	afterCreateError     bool
	replaceBeforeCleanup bool
	wrongHash            bool
	deleteError          bool
}

func (t *chromaTestTransport) snapshot(context.Context, ChromaRuntime) (chromaAuthority, error) {
	t.snapshots++
	if t.snapshots == t.failSnapshotAt {
		return chromaAuthority{}, errors.New("pre-dispatch authority failed")
	}
	return chromaAuthority{PodName: "chroma-1", PodUID: "pod-uid", ContainerID: "containerd://one", ImageID: chromaImageID, DeploymentUID: "deploy", ReplicaSetUID: "rs", ServiceUID: "svc", SliceUID: "slice", PodIP: "10.0.0.1"}, nil
}
func (t *chromaTestTransport) sourcePin(context.Context, ChromaRuntime, chromaAuthority) error {
	return nil
}
func (t *chromaTestTransport) call(ctx context.Context, _ ChromaRuntime, _ chromaAuthority, method, path string, body []byte) (chromaResponse, error) {
	t.calls++
	if t.deleteError && method == http.MethodDelete {
		return chromaResponse{}, errors.New("unknown DELETE result")
	}
	req, err := http.NewRequestWithContext(ctx, method, t.server.URL+path, bytes.NewReader(body))
	if err != nil {
		return chromaResponse{}, err
	}
	resp, err := t.server.Client().Do(req)
	if err != nil {
		return chromaResponse{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return chromaResponse{}, err
	}
	if t.afterCreateError && method == http.MethodPost && path == chromaBase {
		return chromaResponse{}, errors.New("lost CREATE response")
	}
	return chromaResponse{Status: resp.StatusCode, Body: raw}, nil
}

const chromaTestID = "a7b11032-835c-4c27-ae53-8917d5b8e03d"
const chromaReplacementID = "b7b11032-835c-4c27-ae53-8917d5b8e03d"

func chromaTestFixture(t *testing.T, transport *chromaTestTransport) (*chromaTestRecorder, JobContext, func()) {
	t.Helper()
	var name, nonce, docID, document string
	created, added := false, false
	collectionID := chromaTestID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v2/version" && r.Method == http.MethodGet {
			io.WriteString(w, `"0.5.23"`)
			return
		}
		if r.URL.Path == chromaBase && r.Method == http.MethodPost {
			var body struct {
				Name        string            `json:"name"`
				Metadata    map[string]string `json:"metadata"`
				GetOrCreate bool              `json:"get_or_create"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.GetOrCreate || !strings.HasPrefix(body.Name, "cat-chroma-") || body.Metadata["catalogue_case"] != chromaCase {
				t.Errorf("invalid CREATE body")
				w.WriteHeader(400)
				return
			}
			name, nonce = body.Name, body.Metadata["catalogue_owner_nonce"]
			created = true
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"id": collectionID, "name": name, "metadata": body.Metadata})
			return
		}
		if strings.HasPrefix(r.URL.Path, chromaBase+"/cat-chroma-") && r.Method == http.MethodGet {
			requested := strings.TrimPrefix(r.URL.Path, chromaBase+"/")
			if requested != name || !created {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"error": "InvalidCollection", "message": "Collection " + requested + " does not exist."})
				return
			}
			if transport.replaceBeforeCleanup && added {
				collectionID = chromaReplacementID
			}
			json.NewEncoder(w).Encode(map[string]any{"id": collectionID, "name": name, "metadata": map[string]string{"catalogue_owner_nonce": nonce, "catalogue_case": chromaCase}})
			return
		}
		if strings.HasPrefix(r.URL.Path, chromaBase+"/cat-chroma-") && r.Method == http.MethodDelete {
			created = false
			io.WriteString(w, "null")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/add") && r.Method == http.MethodPost {
			var body struct {
				IDs        []string            `json:"ids"`
				Embeddings [][]float64         `json:"embeddings"`
				Documents  []string            `json:"documents"`
				Metadatas  []map[string]string `json:"metadatas"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.IDs) != 1 || len(body.Embeddings) != 1 || len(body.Documents) != 1 || len(body.Metadatas) != 1 || body.Metadatas[0]["catalogue_owner_nonce"] != nonce || body.Embeddings[0][0] != 0.1 {
				t.Errorf("invalid ADD body")
				w.WriteHeader(400)
				return
			}
			docID, document = body.IDs[0], body.Documents[0]
			added = true
			w.WriteHeader(201)
			io.WriteString(w, "true")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/get") && r.Method == http.MethodPost {
			var body struct {
				IDs     []string `json:"ids"`
				Include []string `json:"include"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if len(body.IDs) != 1 || body.IDs[0] != docID || len(body.Include) != 3 {
				t.Errorf("invalid GET body")
				w.WriteHeader(400)
				return
			}
			got := document
			if transport.wrongHash {
				got = "wrong document"
			}
			json.NewEncoder(w).Encode(map[string]any{"ids": []string{docID}, "documents": []string{got}, "metadatas": []map[string]string{{"catalogue_owner_nonce": nonce}}, "embeddings": [][]float64{{0.1, 0.2, 0.3}}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/query") && r.Method == http.MethodPost {
			var body struct {
				QueryEmbeddings [][]float64 `json:"query_embeddings"`
				NResults        int         `json:"n_results"`
				Include         []string    `json:"include"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if len(body.QueryEmbeddings) != 1 || body.NResults != 1 || len(body.Include) != 3 {
				t.Errorf("invalid QUERY body")
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"ids": [][]string{{docID}}, "documents": [][]string{{document}}, "metadatas": [][]map[string]string{{{"catalogue_owner_nonce": nonce}}}, "distances": [][]float64{{0}}})
			return
		}
		t.Errorf("unexpected Chroma HTTP %s %s", r.Method, r.URL.Path)
		w.WriteHeader(404)
	}))
	transport.server = server
	runtime := ChromaRuntime{Enabled: true, Namespace: "document-store", Deployment: "chroma", Service: "chroma", Container: "chroma", Port: 8000, ExpectedImageID: chromaImageID, ExpectedVersionSourceSHA256: chromaVersionSHA, ExpectedServerSourceSHA256: chromaServerSHA, ExpectedSchemaSourceSHA256: chromaSchemaSHA}
	recorder := &chromaTestRecorder{}
	return recorder, JobContext{Runtime: Runtime{Chroma: runtime}, Recorder: recorder}, server.Close
}

func TestChromaHTTPControlLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name    string
		alter   func(*chromaTestTransport)
		want    Outcome
		cleanup bool
		delete  bool
	}{
		{"accepted", nil, OutcomeFunctionalPass, true, true},
		{"ambiguous-create", func(x *chromaTestTransport) { x.afterCreateError = true }, OutcomeInconclusive, false, false},
		{"same-name-replacement", func(x *chromaTestTransport) { x.replaceBeforeCleanup = true }, OutcomeInconclusive, false, false},
		{"wrong-document-hash", func(x *chromaTestTransport) { x.wrongHash = true }, OutcomeInconclusive, true, true},
		{"unknown-delete", func(x *chromaTestTransport) { x.deleteError = true }, OutcomeInconclusive, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &chromaTestTransport{}
			if tc.alter != nil {
				tc.alter(transport)
			}
			recorder, jc, closeServer := chromaTestFixture(t, transport)
			defer closeServer()
			result := runChroma(context.Background(), jc, transport, Result{Outcome: OutcomeInconclusive, Evidence: map[string]string{}, Cleanup: Cleanup{Status: "not-started"}})
			if result.Outcome != tc.want || result.Cleanup.Verified != tc.cleanup {
				t.Fatalf("result=%+v", result)
			}
			deleted := false
			for _, v := range recorder.intents {
				if v.Step == "chroma.delete" {
					deleted = true
				}
			}
			if deleted != tc.delete {
				t.Fatalf("DELETE intent=%v", deleted)
			}
			if result.Evidence["requestCount"] == "0" {
				t.Fatal("request count not recorded")
			}
		})
	}
}

func TestChromaPreDispatchFailuresDoNotInventUnknownMutation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		snapshot  int
		wantCalls int
		cleanup   bool
	}{
		{"before-create", 6, 2, true},
		{"before-add", 10, 7, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &chromaTestTransport{failSnapshotAt: tc.snapshot}
			_, jc, closeServer := chromaTestFixture(t, transport)
			defer closeServer()
			result := runChroma(context.Background(), jc, transport, Result{Outcome: OutcomeInconclusive, Evidence: map[string]string{}})
			if result.Outcome != OutcomeInconclusive || result.Cleanup.Verified != tc.cleanup || result.UnsafeToRetry || transport.calls != tc.wantCalls {
				t.Fatalf("pre-dispatch result=%+v calls=%d", result, transport.calls)
			}
		})
	}
}

func TestChromaExactOracles(t *testing.T) {
	if chromaExactAbsent(chromaResponse{Status: 400, Body: []byte(`{"error":"InvalidCollection","message":"Collection someone-else does not exist."}`)}, "cat-chroma-abc") {
		t.Fatal("accepted unrelated absence")
	}
	if chromaAllowedRoute(http.MethodDelete, chromaBase+"/customer") || chromaAllowedRoute(http.MethodGet, chromaBase) || chromaAllowedRoute(http.MethodPost, "/api/v2/collections") {
		t.Fatal("unsafe route accepted")
	}
	if ValidateChromaRuntime(ChromaRuntime{}) == nil {
		t.Fatal("disabled runtime accepted")
	}
}

func TestChromaRunnerPersistsRealProtocolAndConsumerArtifacts(t *testing.T) {
	transport := &chromaTestTransport{}
	_, fixture, closeServer := chromaTestFixture(t, transport)
	defer closeServer()
	kube, _ := chromaKubeFixture()
	runtime := Runtime{StateDir: t.TempDir(), ConfigSHA256: strings.Repeat("d", 64), Chroma: fixture.Runtime.Chroma, Kube: kube.runtime.Kube, RESTConfig: &rest.Config{Host: "https://kubernetes.invalid"}}
	handler := chromaHandler{newTransport: func(Runtime) (chromaTransport, error) { return transport, nil }}
	runner, err := New(runtime, handler)
	if err != nil {
		t.Fatal(err)
	}
	definitionHash, err := DefinitionSHA256(handler.Definition())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(runtime.StateDir, "runs", "v1run-1")
	if err = os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	job := Job{Version: JobVersion, RunID: "v1run-1", Profile: ChromaOwnedVector, OutputDir: dir, DefinitionSHA256: definitionHash, OwnerDigest: strings.Repeat("a", 64), ResolvedTarget: "default", ResolvedTenant: "document-store", RuntimeConfigSHA256: runtime.ConfigSHA256, CreatedAt: time.Now().UTC(), Deadline: time.Now().UTC().Add(3 * time.Minute)}
	bad := job
	bad.ResolvedTenant = "foreign"
	if rejected := runner.Execute(context.Background(), bad); rejected.Outcome != OutcomeTestFailed || transport.calls != 0 {
		t.Fatalf("foreign tenant dispatched: %+v calls=%d", rejected, transport.calls)
	}
	bad = job
	bad.ResolvedTarget = "foreign"
	if rejected := runner.Execute(context.Background(), bad); rejected.Outcome != OutcomeTestFailed || transport.calls != 0 {
		t.Fatalf("foreign target dispatched: %+v calls=%d", rejected, transport.calls)
	}
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeFunctionalPass {
		t.Fatalf("runner result: %+v", result)
	}
	if err = ValidateTerminalArtifacts(job, result, filepath.Join(dir, "metrics.jsonl")); err != nil {
		t.Fatal(err)
	}
	journal, err := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(journal, []byte(`"step":"chroma.create"`)) || !bytes.Contains(journal, []byte(chromaTestID)) || !bytes.Contains(journal, []byte(`"step":"chroma.final-absence"`)) || !bytes.Contains(journal, []byte(`"status":"verified"`)) {
		t.Fatalf("durable Chroma mutation or cleanup receipts absent: %s", journal)
	}
	parsed, err := loadJournal(filepath.Join(dir, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if cleanup := handler.Reconcile(context.Background(), JobContext{}, parsed); !cleanup.Verified {
		t.Fatalf("valid journal cleanup rejected: %+v", cleanup)
	}
	final := parsed.Records[len(parsed.Records)-1]
	if cleanup := handler.Reconcile(context.Background(), JobContext{}, Journal{Records: []JournalRecord{final}}); cleanup.Verified {
		t.Fatalf("lone final marker accepted: %+v", cleanup)
	}
	final.Event.Identity["collectionID"] = chromaReplacementID
	parsed.Records[len(parsed.Records)-1] = final
	if cleanup := handler.Reconcile(context.Background(), JobContext{}, parsed); cleanup.Verified {
		t.Fatalf("mismatched final UUID accepted: %+v", cleanup)
	}
}
