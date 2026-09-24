package cataloguev1

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	chromaImageID    = "docker.io/chromadb/chroma@sha256:18e67eecc172abbcd9413d751bde64983b3d167fe497c98f979083eb24c0c942"
	chromaVersionSHA = "5458a79347d19a5d15966a76a3a5e02bdac384ef670ff0612cc93fc788c41f44"
	chromaServerSHA  = "8dae4ea1f3357edf75ac446bbe0e3973151a542dc6de184c7be3b6be82925c41"
	chromaSchemaSHA  = "2b6ec7c5796309be91f9af97e3bb4379a42652550146b2dda226c801894570b1"
	chromaBase       = "/api/v2/tenants/default_tenant/databases/default_database/collections"
	chromaCase       = "chroma-owned-vector"
)

var chromaUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ChromaRuntime is deployment-owned. None of these values is launch input.
type ChromaRuntime struct {
	Enabled                     bool   `json:"enabled"`
	Namespace                   string `json:"namespace"`
	Deployment                  string `json:"deployment"`
	Service                     string `json:"service"`
	Container                   string `json:"container"`
	Port                        int32  `json:"port"`
	ExpectedImageID             string `json:"expectedImageID"`
	ExpectedVersionSourceSHA256 string `json:"expectedVersionSourceSHA256"`
	ExpectedServerSourceSHA256  string `json:"expectedServerSourceSHA256"`
	ExpectedSchemaSourceSHA256  string `json:"expectedSchemaSourceSHA256"`
}

func ValidateChromaRuntime(c ChromaRuntime) error {
	if !c.Enabled || c.Namespace != "document-store" || c.Deployment != "chroma" || c.Service != "chroma" || c.Container != "chroma" || c.Port != 8000 || c.ExpectedImageID != chromaImageID || c.ExpectedVersionSourceSHA256 != chromaVersionSHA || c.ExpectedServerSourceSHA256 != chromaServerSHA || c.ExpectedSchemaSourceSHA256 != chromaSchemaSHA {
		return errors.New("Chroma runtime disabled or differs from reviewed installed 0.5.23 contract")
	}
	return nil
}

type chromaHandler struct {
	newTransport func(Runtime) (chromaTransport, error)
}

func NewChromaHandler() Handler                { return chromaHandler{newTransport: newChromaKubeTransport} }
func (h chromaHandler) Definition() Definition { d, _ := DefinitionFor(ChromaOwnedVector); return d }
func (h chromaHandler) Validate(r Runtime) error {
	if err := ValidateChromaRuntime(r.Chroma); err != nil {
		return err
	}
	if r.Kube == nil || r.RESTConfig == nil {
		return errors.New("Chroma Kubernetes authority unavailable")
	}
	return nil
}

type chromaAuthority struct {
	PodName, PodUID, ContainerID, ImageID                     string
	RestartCount                                              int32
	DeploymentUID, ReplicaSetUID, ServiceUID, SliceUID, PodIP string
	DeploymentGeneration                                      int64
}

func (a chromaAuthority) fingerprint() string {
	b, _ := json.Marshal(a)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type chromaResponse struct {
	Status int
	Body   []byte
}
type chromaTransport interface {
	snapshot(context.Context, ChromaRuntime) (chromaAuthority, error)
	sourcePin(context.Context, ChromaRuntime, chromaAuthority) error
	call(context.Context, ChromaRuntime, chromaAuthority, string, string, []byte) (chromaResponse, error)
}

func (h chromaHandler) Run(ctx context.Context, jc JobContext) (out Result) {
	out = Result{Outcome: OutcomeInconclusive, Summary: "Chroma owned vector control incomplete", StartedAt: time.Now().UTC(), Evidence: map[string]string{"securityOutcome": "NOT_EVALUATED", "installedDefense": "NOT_EVALUATED", "brainEvidence": "NOT_EVALUATED", "actuatorEvidence": "NOT_EVALUATED", "eventMode": "none; direct protocol control", "securityEvent": "none", "requestCount": "0"}, Limits: []string{h.Definition().ClaimLimits}, Cleanup: Cleanup{Status: "not-started"}}
	defer func() { out.FinishedAt = time.Now().UTC() }()
	if err := h.Validate(jc.Runtime); err != nil {
		out.Summary = "Chroma runtime authority unavailable"
		return
	}
	if jc.Recorder == nil {
		out.Summary = "Chroma private journal unavailable"
		return
	}
	t, err := h.newTransport(jc.Runtime)
	if err != nil {
		out.Summary = "Chroma transport unavailable"
		return
	}
	return runChroma(ctx, jc, t, out)
}

func runChroma(ctx context.Context, jc JobContext, t chromaTransport, initial Result) (out Result) {
	out = initial
	requests := 0
	defer func() { out.Evidence["requestCount"] = fmt.Sprint(requests) }()
	cfg := jc.Runtime.Chroma
	base, err := t.snapshot(ctx, cfg)
	if err != nil || t.sourcePin(ctx, cfg, base) != nil {
		out.Summary = "Chroma target or installed source preflight unavailable"
		return out
	}
	out.Evidence["targetPodUID"] = base.PodUID
	out.Evidence["authoritySHA256"] = base.fingerprint()
	out.Evidence["sourceVersion"] = "installed-0.5.23-hash-pinned"
	out.Evidence["targetRoute"] = "document-store/chroma exact Pod localhost:8000"
	out.Evidence["sourceSHA256"] = chromaVersionSHA + "," + chromaServerSHA + "," + chromaSchemaSHA
	var nonceBytes [12]byte
	if _, err = rand.Read(nonceBytes[:]); err != nil {
		out.Summary = "Chroma nonce unavailable"
		return out
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	name, docID := "cat-chroma-"+nonce, "cat-doc-"+nonce
	document := "owned synthetic vector " + nonce
	docHash := sha256.Sum256([]byte(document))
	path := chromaBase + "/" + name
	identity := map[string]string{"targetPodUID": base.PodUID, "collectionName": name, "ownerNonce": nonce, "documentID": docID, "documentSHA256": hex.EncodeToString(docHash[:])}
	// The private recorder is the durable intent log. Never send a mutation if it fails.
	if jc.Recorder.Intent(Intent{Step: "chroma.owned-state", At: time.Now().UTC(), Identity: identity}) != nil {
		out.Summary = "Chroma ownership intent unavailable"
		return out
	}
	var collectionID string
	var createAttempted, mutationUnknown, oracle, lastDispatched bool
	step := func(label, method, route string, payload any, mutation bool) (chromaResponse, error) {
		lastDispatched = false
		if requests >= 10 {
			return chromaResponse{}, errors.New("request bound")
		}
		current, e := t.snapshot(ctx, cfg)
		if e != nil || current.fingerprint() != base.fingerprint() || t.sourcePin(ctx, cfg, current) != nil {
			return chromaResponse{}, errors.New("Chroma target/source changed before request")
		}
		if e = jc.Recorder.Intent(Intent{Step: label, Mutation: mutation, At: time.Now().UTC(), Identity: map[string]string{"targetPodUID": base.PodUID, "collectionName": name, "collectionID": collectionID}}); e != nil {
			return chromaResponse{}, errors.New("request intent unavailable")
		}
		var body []byte
		if payload != nil {
			body, e = json.Marshal(payload)
			if e != nil {
				return chromaResponse{}, e
			}
		}
		requests++
		lastDispatched = true
		if label == "chroma.create" {
			createAttempted = true
		}
		out.Evidence[label+"Status"] = "unknown"
		response, e := t.call(ctx, cfg, base, method, route, body)
		if e != nil {
			return chromaResponse{}, e
		}
		sum := sha256.Sum256(response.Body)
		receipt := map[string]string{"responseSHA256": hex.EncodeToString(sum[:]), "responseBytes": fmt.Sprint(len(response.Body))}
		if label == "chroma.create" {
			collectionID = chromaReceivedID(response)
			if collectionID != "" {
				receipt["collectionID"] = collectionID
				receipt["collectionName"] = name
				receipt["ownerNonce"] = nonce
			}
		}
		if e = jc.Recorder.Event(Event{Step: label, Status: fmt.Sprintf("http-%d", response.Status), At: time.Now().UTC(), Identity: receipt}); e != nil {
			return chromaResponse{}, errors.New("request receipt unavailable")
		}
		out.Evidence[label+"Status"] = fmt.Sprintf("http-%d", response.Status)
		current, e = t.snapshot(ctx, cfg)
		if e != nil || current.fingerprint() != base.fingerprint() || t.sourcePin(ctx, cfg, current) != nil {
			return chromaResponse{}, errors.New("Chroma target/source changed after request")
		}
		return response, nil
	}
	version, err := step("chroma.version", http.MethodGet, "/api/v2/version", nil, false)
	if err != nil || version.Status != 200 || string(version.Body) != `"0.5.23"` {
		out.Summary = "Chroma installed API version differs"
		return out
	}
	absence, err := step("chroma.initial-absence", http.MethodGet, path, nil, false)
	if err != nil || !chromaExactAbsent(absence, name) {
		out.Summary = "Owned collection name not proven absent"
		return out
	}
	createBody := map[string]any{"name": name, "metadata": map[string]string{"catalogue_owner_nonce": nonce, "catalogue_case": chromaCase}, "get_or_create": false}
	created, err := step("chroma.create", http.MethodPost, chromaBase, createBody, true)
	if err != nil {
		mutationUnknown = lastDispatched
		if lastDispatched {
			out.Summary = "Chroma CREATE outcome unknown"
		} else {
			out.Summary = "Chroma CREATE not dispatched"
		}
		goto cleanup
	}
	// The CREATE receipt, including any returned UUID, was persisted before postflight.
	if !chromaOwnedCollection(created, name, nonce, collectionID) {
		mutationUnknown = true
		out.Summary = "Chroma CREATE acknowledgement differs"
		goto cleanup
	}
	{
		readback, e := step("chroma.created-readback", http.MethodGet, path, nil, false)
		if e != nil || !chromaOwnedCollection(readback, name, nonce, collectionID) {
			out.Summary = "Chroma created collection readback differs"
			goto cleanup
		}
	}
	{
		addBody := map[string]any{"ids": []string{docID}, "embeddings": [][]float64{{0.1, 0.2, 0.3}}, "documents": []string{document}, "metadatas": []map[string]string{{"catalogue_owner_nonce": nonce}}}
		added, e := step("chroma.add", http.MethodPost, chromaBase+"/"+collectionID+"/add", addBody, true)
		if e != nil {
			mutationUnknown = lastDispatched
			if lastDispatched {
				out.Summary = "Chroma ADD outcome unknown"
			} else {
				out.Summary = "Chroma ADD not dispatched"
			}
			goto cleanup
		}
		if (added.Status != 200 && added.Status != 201) || strings.TrimSpace(string(added.Body)) != "true" {
			mutationUnknown = true
			out.Summary = "Chroma ADD acknowledgement differs"
			goto cleanup
		}
	}
	{
		got, e := step("chroma.get", http.MethodPost, chromaBase+"/"+collectionID+"/get", map[string]any{"ids": []string{docID}, "include": []string{"documents", "metadatas", "embeddings"}}, false)
		if e != nil || !chromaExactGet(got, docID, hex.EncodeToString(docHash[:]), nonce) {
			out.Summary = "Chroma exact ID readback differs"
			goto cleanup
		}
		queried, e := step("chroma.query", http.MethodPost, chromaBase+"/"+collectionID+"/query", map[string]any{"query_embeddings": [][]float64{{0.1, 0.2, 0.3}}, "n_results": 1, "include": []string{"documents", "metadatas", "distances"}}, false)
		if e != nil || !chromaExactQuery(queried, docID, hex.EncodeToString(docHash[:]), nonce) {
			out.Summary = "Chroma exact vector query differs"
			goto cleanup
		}
		oracle = true
	}
cleanup:
	out.Evidence["requestCount"] = fmt.Sprint(requests)
	if !createAttempted {
		out.Cleanup = Cleanup{Status: "not-needed", Verified: true}
		return out
	}
	out.UnsafeToRetry = true
	out.Cleanup = Cleanup{Attempted: false, Verified: false, Status: "unconfirmed-owned-state", UnsafeToRetry: true}
	if mutationUnknown || collectionID == "" {
		out.Summary += "; mutation not replayed; exact cleanup withheld"
		return out
	}
	// The v2 DELETE is name-based. Recheck the UUID/nonce on this exact Pod before
	// one deletion; a changed name or owner never authorizes deletion.
	owned, err := step("chroma.cleanup-preflight", http.MethodGet, path, nil, false)
	if err != nil || !chromaOwnedCollection(owned, name, nonce, collectionID) {
		out.Summary += "; exact cleanup ownership changed"
		return out
	}
	if jc.Recorder.Event(Event{Step: "chroma.cleanup-preflight-verified", Status: "verified", At: time.Now().UTC(), Identity: map[string]string{"collectionName": name, "collectionID": collectionID, "ownerNonce": nonce}}) != nil {
		out.Summary += "; exact cleanup ownership proof unavailable"
		return out
	}
	out.Cleanup.Attempted = true
	deleted, err := step("chroma.delete", http.MethodDelete, path, nil, true)
	if err != nil || (deleted.Status != 200 && deleted.Status != 204) || (deleted.Status == 200 && strings.TrimSpace(string(deleted.Body)) != "null") || (deleted.Status == 204 && len(deleted.Body) != 0) {
		out.Summary += "; DELETE outcome unconfirmed"
		return out
	}
	final, err := step("chroma.final-absence", http.MethodGet, path, nil, false)
	if err != nil || !chromaExactAbsent(final, name) {
		out.Summary += "; final exact-name absence unconfirmed"
		return out
	}
	if jc.Recorder.Event(Event{Step: "chroma.final-absence", Status: "verified", At: time.Now().UTC(), Identity: map[string]string{"collectionName": name, "collectionID": collectionID, "ownerNonce": nonce}}) != nil {
		out.Summary += "; final absence proof unavailable"
		return out
	}
	out.Evidence["requestCount"] = fmt.Sprint(requests)
	out.Cleanup = Cleanup{Attempted: true, Verified: true, Status: "exact-name-absence-confirmed"}
	out.UnsafeToRetry = false
	if oracle {
		out.Outcome = OutcomeFunctionalPass
		out.Summary = "Owned Chroma document and exact vector query verified; cleanup confirmed"
	}
	return out
}

func chromaObject(r chromaResponse) map[string]json.RawMessage {
	if len(r.Body) > 8192 {
		return nil
	}
	var v map[string]json.RawMessage
	if json.Unmarshal(r.Body, &v) != nil {
		return nil
	}
	return v
}
func chromaExactAbsent(r chromaResponse, name string) bool {
	if r.Status != 400 {
		return false
	}
	v := chromaObject(r)
	if len(v) != 2 {
		return false
	}
	var code, message string
	return json.Unmarshal(v["error"], &code) == nil && json.Unmarshal(v["message"], &message) == nil && code == "InvalidCollection" && message == "Collection "+name+" does not exist."
}
func chromaReceivedID(r chromaResponse) string {
	v := chromaObject(r)
	var id string
	if json.Unmarshal(v["id"], &id) != nil || !chromaUUID.MatchString(id) {
		return ""
	}
	return id
}
func chromaOwnedCollection(r chromaResponse, name, nonce, id string) bool {
	if r.Status != 200 && r.Status != 201 || id == "" {
		return false
	}
	v := chromaObject(r)
	if len(v) > 12 {
		return false
	}
	var gotName, gotID string
	var metadata map[string]string
	if json.Unmarshal(v["name"], &gotName) != nil || json.Unmarshal(v["id"], &gotID) != nil || json.Unmarshal(v["metadata"], &metadata) != nil {
		return false
	}
	return gotName == name && gotID == id && len(metadata) <= 8 && metadata["catalogue_owner_nonce"] == nonce && metadata["catalogue_case"] == chromaCase
}
func chromaExactGet(r chromaResponse, id, hash, nonce string) bool {
	if r.Status != 200 {
		return false
	}
	v := chromaObject(r)
	var ids, docs []string
	var metadata []map[string]string
	var embedding [][]float64
	if json.Unmarshal(v["ids"], &ids) != nil || json.Unmarshal(v["documents"], &docs) != nil || json.Unmarshal(v["metadatas"], &metadata) != nil || json.Unmarshal(v["embeddings"], &embedding) != nil {
		return false
	}
	if len(ids) != 1 || len(docs) != 1 || len(metadata) != 1 || len(embedding) != 1 || len(embedding[0]) != 3 || ids[0] != id || len(docs[0]) > 256 || len(metadata[0]) > 8 || metadata[0]["catalogue_owner_nonce"] != nonce {
		return false
	}
	s := sha256.Sum256([]byte(docs[0]))
	if hex.EncodeToString(s[:]) != hash {
		return false
	}
	for i, x := range embedding[0] {
		if math.IsNaN(x) || math.IsInf(x, 0) || math.Abs(x-[]float64{0.1, 0.2, 0.3}[i]) > 1e-5 {
			return false
		}
	}
	return true
}
func chromaExactQuery(r chromaResponse, id, hash, nonce string) bool {
	if r.Status != 200 {
		return false
	}
	v := chromaObject(r)
	var ids, docs [][]string
	var metadata [][]map[string]string
	var distances [][]float64
	if json.Unmarshal(v["ids"], &ids) != nil || json.Unmarshal(v["documents"], &docs) != nil || json.Unmarshal(v["metadatas"], &metadata) != nil || json.Unmarshal(v["distances"], &distances) != nil {
		return false
	}
	if len(ids) != 1 || len(docs) != 1 || len(metadata) != 1 || len(distances) != 1 || len(ids[0]) != 1 || len(docs[0]) != 1 || len(metadata[0]) != 1 || len(distances[0]) != 1 || ids[0][0] != id || len(docs[0][0]) > 256 || len(metadata[0][0]) > 8 || metadata[0][0]["catalogue_owner_nonce"] != nonce {
		return false
	}
	s := sha256.Sum256([]byte(docs[0][0]))
	d := distances[0][0]
	return hex.EncodeToString(s[:]) == hash && !math.IsNaN(d) && !math.IsInf(d, 0) && d >= 0 && d <= 1e-4
}

func (h chromaHandler) Reconcile(_ context.Context, _ JobContext, j Journal) Cleanup {
	var name, nonce, id, pod string
	phase := 0
	for _, rec := range j.Records {
		switch phase {
		case 0:
			if rec.Intent != nil && rec.Intent.Step == "chroma.owned-state" {
				v := rec.Intent.Identity
				name, nonce, pod = v["collectionName"], v["ownerNonce"], v["targetPodUID"]
				if strings.HasPrefix(name, "cat-chroma-") && len(name) == len("cat-chroma-")+24 && nonce == strings.TrimPrefix(name, "cat-chroma-") && strings.Trim(nonce, "0123456789abcdef") == "" && pod != "" {
					phase = 1
				}
			}
		case 1:
			if rec.Intent != nil && rec.Intent.Step == "chroma.create" && rec.Intent.Mutation && rec.Intent.Identity["collectionName"] == name && rec.Intent.Identity["targetPodUID"] == pod && rec.Intent.Identity["collectionID"] == "" {
				phase = 2
			}
		case 2:
			if rec.Event != nil && rec.Event.Step == "chroma.create" && (rec.Event.Status == "http-200" || rec.Event.Status == "http-201") {
				v := rec.Event.Identity
				id = v["collectionID"]
				if chromaUUID.MatchString(id) && v["collectionName"] == name && v["ownerNonce"] == nonce {
					phase = 3
				}
			}
		case 3:
			if rec.Event != nil && rec.Event.Step == "chroma.cleanup-preflight-verified" && rec.Event.Status == "verified" && chromaSameIdentity(rec.Event.Identity, name, nonce, id) {
				phase = 4
			}
		case 4:
			if rec.Intent != nil && rec.Intent.Step == "chroma.delete" && rec.Intent.Mutation && rec.Intent.Identity["collectionName"] == name && rec.Intent.Identity["collectionID"] == id && rec.Intent.Identity["targetPodUID"] == pod {
				phase = 5
			}
		case 5:
			if rec.Event != nil && rec.Event.Step == "chroma.delete" && (rec.Event.Status == "http-200" || rec.Event.Status == "http-204") {
				phase = 6
			}
		case 6:
			if rec.Intent != nil && rec.Intent.Step == "chroma.final-absence" && rec.Intent.Identity["collectionName"] == name && rec.Intent.Identity["collectionID"] == id && rec.Intent.Identity["targetPodUID"] == pod {
				phase = 7
			}
		case 7:
			if rec.Event != nil && rec.Event.Step == "chroma.final-absence" && rec.Event.Status == "http-400" {
				phase = 8
			}
		case 8:
			if rec.Event != nil && rec.Event.Step == "chroma.final-absence" && rec.Event.Status == "verified" && chromaSameIdentity(rec.Event.Identity, name, nonce, id) {
				return Cleanup{Attempted: true, Verified: true, Status: "previously-confirmed-no-replay"}
			}
		}
	}
	return Cleanup{Attempted: true, Verified: false, Status: "exact-collection-cleanup-unconfirmed-no-replay", UnsafeToRetry: true}
}

func chromaSameIdentity(v map[string]string, name, nonce, id string) bool {
	return v["collectionName"] == name && v["ownerNonce"] == nonce && v["collectionID"] == id
}
