package audittransport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// MathLabMaxSnapshotBytes bounds one snapshot read over the audit transport.
const MathLabMaxSnapshotBytes = 64 << 20

// MathLabMaxIndexBytes bounds a snapshot listing across either transport.
const MathLabMaxIndexBytes = 32 << 20

var mathLabDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MathLabSnapshotQuery narrows a snapshot listing. Zero values mean "no constraint".
type MathLabSnapshotQuery struct {
	PolicyUID string
	Namespace string
	Policy    string
	Since     time.Time
	Until     time.Time
	Limit     int
}

// MathLabSnapshotSource is the read-only snapshot store served by the audit listener.
// It is an interface so this package does not import the decision engine.
type MathLabSnapshotSource interface {
	IndexJSON(MathLabSnapshotQuery) ([]byte, error)
	Read(digest string) ([]byte, error)
}

// ValidateMathLabSnapshotQuery applies the same bounds to remote typed reads.
// A zero limit has the HTTP endpoint's default meaning, not an unbounded list.
func ValidateMathLabSnapshotQuery(q MathLabSnapshotQuery) (MathLabSnapshotQuery, error) {
	for _, value := range []string{q.PolicyUID, q.Namespace, q.Policy} {
		if len(value) > 253 {
			return q, errors.New("query value too long")
		}
	}
	if q.Limit == 0 {
		q.Limit = 500
	}
	if q.Limit < 1 || q.Limit > 5000 {
		return q, errors.New("limit must be in [1,5000]")
	}
	if !q.Since.IsZero() && !q.Until.IsZero() && q.Until.Before(q.Since) {
		return q, errors.New("until precedes since")
	}
	return q, nil
}

func ValidMathLabSnapshotDigest(digest string) bool { return mathLabDigest.MatchString(digest) }

func parseMathLabQuery(v url.Values) (MathLabSnapshotQuery, error) {
	q := MathLabSnapshotQuery{PolicyUID: v.Get("policyUID"), Namespace: v.Get("namespace"), Policy: v.Get("policy"), Limit: 500}
	for _, s := range []string{q.PolicyUID, q.Namespace, q.Policy} {
		if len(s) > 253 {
			return q, errors.New("query value too long")
		}
	}
	for name, dst := range map[string]*time.Time{"since": &q.Since, "until": &q.Until} {
		if raw := v.Get(name); raw != "" {
			t, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return q, fmt.Errorf("invalid %s", name)
			}
			*dst = t
		}
	}
	if raw := v.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 5000 {
			return q, errors.New("limit must be in [1,5000]")
		}
		q.Limit = n
	}
	return q, nil
}

func (c ServerConfig) mathLabHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/math-lab/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if c.MathLab == nil {
			http.Error(w, "math-lab capture is not enabled", http.StatusNotFound)
			return
		}
		q, err := parseMathLabQuery(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		raw, err := c.MathLab.IndexJSON(q)
		if err != nil {
			http.Error(w, "math-lab index unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})
	mux.HandleFunc("GET /v1/math-lab/snapshots/{digest}", func(w http.ResponseWriter, r *http.Request) {
		if c.MathLab == nil {
			http.Error(w, "math-lab capture is not enabled", http.StatusNotFound)
			return
		}
		digest := r.PathValue("digest")
		if !mathLabDigest.MatchString(digest) {
			http.Error(w, "invalid snapshot digest", http.StatusBadRequest)
			return
		}
		raw, err := c.MathLab.Read(digest)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Snapshot-Digest", digest)
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
		_, _ = w.Write(raw)
	})
}

// MathLabSnapshots returns the raw JSON snapshot index.
func (c *Client) MathLabSnapshots(ctx context.Context, q MathLabSnapshotQuery) ([]byte, error) {
	v := url.Values{}
	for k, s := range map[string]string{"policyUID": q.PolicyUID, "namespace": q.Namespace, "policy": q.Policy} {
		if s != "" {
			v.Set(k, s)
		}
	}
	if !q.Since.IsZero() {
		v.Set("since", q.Since.UTC().Format(time.RFC3339Nano))
	}
	if !q.Until.IsZero() {
		v.Set("until", q.Until.UTC().Format(time.RFC3339Nano))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	path := "/v1/math-lab/snapshots"
	if len(v) > 0 {
		path += "?" + v.Encode()
	}
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("math-lab index: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

// MathLabSnapshot fetches one snapshot and verifies its content address.
func (c *Client) MathLabSnapshot(ctx context.Context, digest string) ([]byte, error) {
	if !mathLabDigest.MatchString(digest) {
		return nil, errors.New("invalid snapshot digest")
	}
	resp, err := c.get(ctx, "/v1/math-lab/snapshots/"+digest)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("math-lab snapshot: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MathLabMaxSnapshotBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MathLabMaxSnapshotBytes {
		return nil, errors.New("math-lab snapshot exceeds the transport bound")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, errors.New("math-lab snapshot failed its content-address check")
	}
	return raw, nil
}
