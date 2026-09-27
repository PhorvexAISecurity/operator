package voiceoutputpolicy

import (
	"strings"
	"testing"
)

func TestVoiceOutputCanonicalAppendAndMutationRefusal(t *testing.T) {
	r := Rule{Version: 1, ConfigMapUID: "11111111-1111-4111-8111-111111111111", DeploymentUID: "22222222-2222-4222-8222-222222222222", PolicyUID: "33333333-3333-4333-8333-333333333333", SourceSHA256: strings.Repeat("a", 64), Entries: []Entry{}}
	if !r.Valid() {
		t.Fatal("initial rule invalid")
	}
	got, e := Parse(string(r.Bytes()))
	if e != nil || got.SHA256() != r.SHA256() {
		t.Fatalf("canonical parse failed: %v", e)
	}
	one, e := Append(r, strings.Repeat("b", 64), strings.Repeat("c", 64))
	if e != nil || one.Revision != 1 || one.OperationID != strings.Repeat("c", 64) {
		t.Fatalf("append failed: %+v %v", one, e)
	}
	two, e := Append(one, strings.Repeat("1", 64), strings.Repeat("d", 64))
	if e != nil || two.Entries[0].MarkerSHA256 != strings.Repeat("1", 64) || one.Revision != 1 {
		t.Fatalf("append reordered or mutated prior: %+v %v", two, e)
	}
	if _, e = Append(two, strings.Repeat("b", 64), strings.Repeat("e", 64)); e == nil {
		t.Fatal("duplicate marker admitted")
	}
	for _, raw := range []string{strings.Replace(string(r.Bytes()), `"version":1`, `"Version":1`, 1), strings.Replace(string(r.Bytes()), `"version":1`, `"version":1,"version":1`, 1), string(r.Bytes()) + "\n"} {
		if _, e = Parse(raw); e == nil {
			t.Fatalf("noncanonical rule accepted: %q", raw)
		}
	}
}
