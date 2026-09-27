package voicememorypolicy

import (
	"strings"
	"testing"
)

func testRule() Rule {
	return Rule{Version: 1, DeploymentUID: "11111111-1111-4111-8111-111111111111", PolicyUID: "22222222-2222-4222-8222-222222222222", SourceSHA256: strings.Repeat("a", 64), Entries: []Entry{}}
}

func TestCanonicalAppendPreservesEarlierRevocations(t *testing.T) {
	initial := testRule()
	parsed, err := Parse(string(initial.Bytes()))
	if err != nil || parsed.SHA256() != initial.SHA256() {
		t.Fatalf("canonical rev0 invalid: %v", err)
	}
	first, err := Append(initial, Entry{CallerID: "+15551234567", NoteSHA256: strings.Repeat("b", 64)}, strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Append(first, Entry{CallerID: "+15551234568", NoteSHA256: strings.Repeat("d", 64)}, strings.Repeat("e", 64))
	if err != nil || second.Revision != 2 || len(second.Entries) != 2 || second.Entries[0] != first.Entries[0] {
		t.Fatalf("second append erased prior entry: %+v %v", second, err)
	}
	if _, err := Append(second, Entry{CallerID: first.Entries[0].CallerID, NoteSHA256: first.Entries[0].NoteSHA256}, strings.Repeat("f", 64)); err == nil {
		t.Fatal("duplicate caller and note accepted")
	}
	if _, err := Parse(`{"deploymentUID":"11111111-1111-4111-8111-111111111111","entries":[],"operationId":"","policyUID":"22222222-2222-4222-8222-222222222222","revision":0,"sourceSHA256":"` + strings.Repeat("a", 64) + `","version":1,"version":1}`); err == nil {
		t.Fatal("duplicate key accepted")
	}
	corrupt := second
	corrupt.Entries = append([]Entry(nil), second.Entries...)
	corrupt.Entries[0].NoteSHA256 = strings.Repeat("0", 64)
	if corrupt.SHA256() == second.SHA256() {
		t.Fatal("entry mutation did not change rule digest")
	}
}

func TestCanonicalRuleRejectsNoncanonicalAndCapacity(t *testing.T) {
	initial := testRule()
	if _, err := Parse(" " + string(initial.Bytes())); err == nil {
		t.Fatal("noncanonical leading space accepted")
	}
	if _, err := Parse(string(initial.Bytes()) + "\n"); err == nil {
		t.Fatal("noncanonical trailing newline accepted")
	}
	if _, err := Append(initial, Entry{CallerID: "not-e164", NoteSHA256: strings.Repeat("b", 64)}, strings.Repeat("c", 64)); err == nil {
		t.Fatal("invalid caller accepted")
	}
	r := initial
	for i := 0; i < MaxEntries; i++ {
		var err error
		r, err = Append(r, Entry{CallerID: "+15551234567", NoteSHA256: strings.Repeat(string('a'+rune(i%6)), 63) + string('0'+rune(i/6))}, strings.Repeat("c", 64))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if _, err := Append(r, Entry{CallerID: "+15551234568", NoteSHA256: strings.Repeat("f", 64)}, strings.Repeat("d", 64)); err == nil {
		t.Fatal("33rd entry accepted")
	}
}
