package audittransport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeMathLab struct {
	files map[string][]byte
	last  MathLabSnapshotQuery
}

func (f *fakeMathLab) IndexJSON(q MathLabSnapshotQuery) ([]byte, error) {
	f.last = q
	return []byte(`{"schema":"math-lab.snapshot-index.v1","entries":[]}`), nil
}

func (f *fakeMathLab) Read(digest string) ([]byte, error) {
	if b, ok := f.files[digest]; ok {
		return b, nil
	}
	return nil, errors.New("missing")
}

func TestMathLabEndpointsAreReadOnlyBoundedAndContentAddressed(t *testing.T) {
	body := []byte("snapshot-bytes")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	src := &fakeMathLab{files: map[string][]byte{digest: body}}
	h := ServerConfig{MathLab: src}.Handler()

	do := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	if rec := do(http.MethodGet, "/v1/math-lab/snapshots?policyUID=u1&since=2026-10-09T00:00:00Z&limit=10"); rec.Code != http.StatusOK || src.last.PolicyUID != "u1" || src.last.Limit != 10 || src.last.Since.IsZero() {
		t.Fatalf("index: %d %+v", rec.Code, src.last)
	}
	for _, bad := range []string{"limit=0", "limit=99999", "since=yesterday"} {
		if rec := do(http.MethodGet, "/v1/math-lab/snapshots?"+bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", bad, rec.Code)
		}
	}
	rec := do(http.MethodGet, "/v1/math-lab/snapshots/"+digest)
	if rec.Code != http.StatusOK || rec.Body.String() != string(body) || rec.Header().Get("X-Snapshot-Digest") != digest {
		t.Fatalf("snapshot read: %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(http.MethodGet, "/v1/math-lab/snapshots/"+strings.Repeat("0", 64)); rec.Code != http.StatusNotFound {
		t.Fatalf("missing snapshot: %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/v1/math-lab/snapshots/..%2f..%2fetc"); rec.Code == http.StatusOK {
		t.Fatal("traversal-shaped digest served")
	}
	if rec := do(http.MethodPost, "/v1/math-lab/snapshots"); rec.Code == http.StatusOK {
		t.Fatal("write method accepted")
	}
	off := ServerConfig{}.Handler()
	rec = httptest.NewRecorder()
	off.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/math-lab/snapshots", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled capture served the index: %d", rec.Code)
	}
}
