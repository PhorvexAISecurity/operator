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

// Package delivery implements retry-safe SecurityEvent delivery for a detector
// webhook (V3-M164): a deterministic event identity derived from the canonical
// form of the supported payload, a bounded Create through the real cluster-scoped
// REST client, and a verified readback on AlreadyExists so that a retried
// identical payload is acknowledged without creating a second event while any
// other collision or failure is reported honestly. See docs/DELIVERY.md.
package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

// CanonicalJSON re-encodes one JSON value deterministically: object keys sorted,
// number literals preserved verbatim (no float round-trip), strings re-escaped
// without HTML escaping, and no insignificant whitespace. Trailing data after the
// value is an error. Two payloads that differ only in key order or whitespace
// therefore canonicalize identically; any difference in content does not.
func CanonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// IdentityVersion names the identity scheme. Bump it if the canonical preimage
// changes so old and new names can never be confused with each other.
const IdentityVersion = "v1"

// NameDigestLength is how many hex digits of the digest go into the object name
// (160 bits). The full 256-bit digest is carried in the fingerprint annotation.
const NameDigestLength = 40

// Identity is the deterministic delivery identity of one event.
type Identity struct {
	// Name is the Kubernetes object name: "<prefix>-<NameDigestLength hex>".
	Name string
	// Fingerprint is the full digest, "sha256:<64 hex>", of the domain-separated
	// canonical payload; it is stored on the object and compared exactly on readback.
	Fingerprint string
}

// Derive computes the identity for a detector prefix and canonical payload. The
// digest preimage is domain-separated by prefix and IdentityVersion so identical
// content from different detectors or identity versions never shares a name.
func Derive(prefix string, canonical []byte) Identity {
	h := sha256.New()
	h.Write([]byte(prefix + "/" + IdentityVersion + "\n"))
	h.Write(canonical)
	digest := hex.EncodeToString(h.Sum(nil))
	return Identity{
		Name:        prefix + "-" + digest[:NameDigestLength],
		Fingerprint: "sha256:" + digest,
	}
}
