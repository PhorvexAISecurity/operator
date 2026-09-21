/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package epssmeta defines the small, canonical provenance document stored beside
// the legacy-compatible EPSS cache.  It is intentionally independent of both the
// producer and platform packages so they validate exactly the same wire contract.
package epssmeta

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

var namespacePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
var repositoryPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9./:_-]*[a-z0-9])?$`)

const (
	SchemaVersion    = "phorvex.ai/epss-feed-metadata/v1"
	MaxNamespaces    = 32
	MaxDigests       = 256
	MaxValidity      = 7 * 24 * time.Hour
	MaxMetadataBytes = 16 << 10
	MaxCacheBytes    = 1 << 20
	MaxCacheEntries  = 4096
	MaxJSONDepth     = 32
)

type Scope struct {
	Namespaces []string
	Digests    []string
}

func (s Scope) Canonical() (Scope, error) {
	if len(s.Namespaces) == 0 || len(s.Namespaces) > MaxNamespaces || len(s.Digests) == 0 || len(s.Digests) > MaxDigests {
		return Scope{}, fmt.Errorf("EPSS scope requires 1..%d namespaces and 1..%d exact digests", MaxNamespaces, MaxDigests)
	}
	out := Scope{Namespaces: append([]string(nil), s.Namespaces...), Digests: append([]string(nil), s.Digests...)}
	sort.Strings(out.Namespaces)
	sort.Strings(out.Digests)
	for i, ns := range out.Namespaces {
		if len(ns) > 63 || !namespacePattern.MatchString(ns) || (i > 0 && ns == out.Namespaces[i-1]) {
			return Scope{}, fmt.Errorf("invalid or duplicate EPSS scope namespace %q", ns)
		}
	}
	for i, d := range out.Digests {
		at := strings.LastIndex(d, "@sha256:")
		if at <= 0 || !repositoryPattern.MatchString(d[:at]) || strings.Contains(d, "://") || len(d[at+8:]) != 64 || strings.ToLower(d) != d || !isHex(d[at+8:]) || (i > 0 && d == out.Digests[i-1]) {
			return Scope{}, fmt.Errorf("invalid or duplicate exact image digest %q", d)
		}
	}
	return out, nil
}

func (s Scope) Digest() (string, error) {
	c, err := s.Canonical()
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(struct {
		Namespaces []string `json:"namespaces"`
		Digests    []string `json:"digests"`
	}{c.Namespaces, c.Digests})
	return SHA256(b), nil
}

// Metadata authenticates the bare cache bytes and the complete authority used to
// produce them.  ConfigMap identity is deliberately absent: it is known only after
// the API write and is supplied by the readback receipt/snapshot.
type Metadata struct {
	SchemaVersion     string    `json:"schemaVersion"`
	ScopeSHA256       string    `json:"scopeSHA256"`
	CacheSHA256       string    `json:"cacheSHA256"`
	ProducerSource    string    `json:"producerSource"`
	GeneratedAt       time.Time `json:"generatedAt"`
	ValidUntil        time.Time `json:"validUntil"`
	ObservedPods      int       `json:"observedPods"`
	RunningContainers int       `json:"runningContainers"`
	UniqueImages      int       `json:"uniqueImages"`
	ScannedImages     int       `json:"scannedImages"`
	FailedImages      int       `json:"failedImages"`
	Complete          bool      `json:"complete"`
}

func (m Metadata) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported EPSS metadata schema %q", m.SchemaVersion)
	}
	if !validSHA(m.ScopeSHA256) || !validSHA(m.CacheSHA256) {
		return fmt.Errorf("EPSS metadata requires lowercase SHA-256 digests")
	}
	if !((len(m.ProducerSource) == 40 || len(m.ProducerSource) == 64) && isHex(m.ProducerSource) && strings.ToLower(m.ProducerSource) == m.ProducerSource) {
		return fmt.Errorf("EPSS metadata requires an exact producer source hash")
	}
	if m.GeneratedAt.IsZero() || m.ValidUntil.IsZero() || !m.ValidUntil.After(m.GeneratedAt) || m.ValidUntil.Sub(m.GeneratedAt) > MaxValidity {
		return fmt.Errorf("invalid EPSS metadata validity interval")
	}
	if m.ObservedPods < 0 || m.RunningContainers < 0 || m.UniqueImages < 0 || m.ScannedImages < 0 || m.FailedImages < 0 || m.ScannedImages+m.FailedImages != m.UniqueImages || m.Complete != (m.FailedImages == 0) {
		return fmt.Errorf("inconsistent EPSS metadata counts")
	}
	return nil
}

func Marshal(m Metadata) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func Parse(b []byte) (Metadata, error) {
	var m Metadata
	if len(b) > MaxMetadataBytes {
		return m, fmt.Errorf("EPSS metadata exceeds %d bytes", MaxMetadataBytes)
	}
	if err := RejectDuplicateJSON(b); err != nil {
		return m, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("decode EPSS metadata: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return m, err
	}
	if err := m.Validate(); err != nil {
		return m, err
	}
	return m, nil
}

// RejectDuplicateJSON closes encoding/json's last-key-wins ambiguity at both
// provenance and cache authority boundaries.
func RejectDuplicateJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > MaxJSONDepth {
			return fmt.Errorf("EPSS JSON exceeds maximum depth %d", MaxJSONDepth)
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate or invalid EPSS metadata field")
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return fmt.Errorf("invalid EPSS metadata JSON delimiter")
		}
	}
	if err := value(1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing EPSS metadata data")
	}
	return nil
}

func SHA256(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func validSHA(s string) bool { return len(s) == 64 && strings.ToLower(s) == s && isHex(s) }
func isHex(s string) bool    { _, err := hex.DecodeString(s); return err == nil }
func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing EPSS metadata value")
		}
		return err
	}
	return nil
}
