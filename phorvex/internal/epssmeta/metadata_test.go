package epssmeta

import (
	"strings"
	"testing"
	"time"
)

func TestScopeCanonicalRejectsTagsShortAndDuplicates(t *testing.T) {
	valid := "registry.example/a@sha256:" + strings.Repeat("a", 64)
	if _, err := (Scope{Namespaces: []string{"b", "a"}, Digests: []string{valid}}).Digest(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Scope{
		{Namespaces: []string{"a"}, Digests: []string{"registry.example/a:latest"}},
		{Namespaces: []string{"a"}, Digests: []string{"registry.example/a@sha256:abc"}},
		{Namespaces: []string{"a", "a"}, Digests: []string{valid}},
		{Namespaces: []string{"a"}, Digests: []string{valid, valid}},
	} {
		if _, err := bad.Canonical(); err == nil {
			t.Fatalf("bad scope accepted: %+v", bad)
		}
	}
}

func TestMetadataStrictCanonicalValidation(t *testing.T) {
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	m := Metadata{SchemaVersion: SchemaVersion, ScopeSHA256: strings.Repeat("a", 64), CacheSHA256: strings.Repeat("b", 64), ProducerSource: strings.Repeat("c", 40), GeneratedAt: now, ValidUntil: now.Add(time.Hour), UniqueImages: 1, ScannedImages: 1, Complete: true}
	b, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(b), `"complete":true`, `"complete":true,"complete":false`, 1)
	if _, err := Parse([]byte(duplicate)); err == nil {
		t.Fatal("duplicate field accepted")
	}
	m.ValidUntil = now.Add(MaxValidity + time.Second)
	if _, err := Marshal(m); err == nil {
		t.Fatal("overlong validity accepted")
	}
	m.ValidUntil = now.Add(time.Hour)
	m.FailedImages, m.ScannedImages, m.Complete = 1, 0, true
	if _, err := Marshal(m); err == nil {
		t.Fatal("complete metadata with failed images accepted")
	}
}

func TestMetadataRejectsOversizedAndDeepJSON(t *testing.T) {
	if _, err := Parse([]byte(strings.Repeat(" ", MaxMetadataBytes+1))); err == nil {
		t.Fatal("oversized metadata accepted")
	}
	deep := strings.Repeat("[", MaxJSONDepth+1) + "0" + strings.Repeat("]", MaxJSONDepth+1)
	if err := RejectDuplicateJSON([]byte(deep)); err == nil {
		t.Fatal("over-deep JSON accepted")
	}
}
