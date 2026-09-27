package voicerefundpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalAppendAndStrictPair(t *testing.T) {
	base := Rule{Version: 1, DeploymentUID: "11111111-1111-4111-8111-111111111111", PolicyUID: "22222222-2222-4222-8222-222222222222", SourceSHA256: strings.Repeat("a", 64), Entries: []Entry{}}
	if got, err := Parse(string(base.Bytes())); err != nil || got.SHA256() != base.SHA256() {
		t.Fatalf("canonical base rejected: %v", err)
	}
	first, err := Append(base, Entry{AssertedCallerSHA256: strings.Repeat("b", 64), OrderSHA256: strings.Repeat("c", 64)}, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Append(first, Entry{AssertedCallerSHA256: strings.Repeat("b", 64), OrderSHA256: strings.Repeat("c", 64)}, strings.Repeat("e", 64)); err == nil {
		t.Fatal("duplicate pair accepted")
	}
	second, err := Append(first, Entry{AssertedCallerSHA256: strings.Repeat("a", 64), OrderSHA256: strings.Repeat("c", 64)}, strings.Repeat("e", 64))
	if err != nil || second.Revision != 2 || len(second.Entries) != 2 || second.Entries[0].AssertedCallerSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("append failed: %+v %v", second, err)
	}
	if _, err := Parse(string(second.Bytes())); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(base.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		string(base.Bytes()) + " ",
		strings.Replace(string(base.Bytes()), `"version":1`, `"version":1,"Version":1`, 1),
		strings.Replace(string(base.Bytes()), `"entries":[]`, `"entries":null`, 1),
		strings.Replace(string(first.Bytes()), `"revision":1`, `"revision":9007199254740992`, 1),
		strings.Replace(string(first.Bytes()), `"revision":1`, `"revision":2`, 1),
	} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("noncanonical rule accepted: %s", raw)
		}
	}
}
