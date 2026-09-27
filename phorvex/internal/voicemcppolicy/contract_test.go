package voicemcppolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func testRule() Rule {
	return Rule{Version: 1, DeploymentUID: "11111111-1111-1111-1111-111111111111", PolicyUID: "22222222-2222-2222-2222-222222222222",
		SourceSHA256: strings.Repeat("a", 64), Entries: []Entry{}}
}

func TestKnownGoodDescriptorDigestsAndAppendOnlyRule(t *testing.T) {
	for _, tc := range []struct{ tool, canonical, want string }{
		{StoreDirectory, `{"description":"Look up store directory information: opening hours, store locations, or which\ndepartment handles a given topic. Valid topics include 'hours', 'locations', 'returns'.","name":"store_directory","properties":{"topic":{"type":"string"}},"required":["topic"]}`, StoreDirectoryGoodSHA256},
		{CheckPromotions, `{"description":"Return the current promotions and any active discount codes.","name":"check_promotions","properties":{},"required":[]}`, CheckPromotionsGoodSHA256},
	} {
		h := sha256.Sum256([]byte(tc.canonical))
		if got := hex.EncodeToString(h[:]); got != tc.want || GoodDescriptorSHA256(tc.tool) != tc.want {
			t.Fatalf("%s known-good descriptor digest drift: %s", tc.tool, got)
		}
	}
	prior := testRule()
	if !prior.Valid() {
		t.Fatal("rev0 invalid")
	}
	first, err := Append(prior, StoreDirectory, strings.Repeat("b", 64))
	if err != nil || first.Revision != 1 || len(first.Entries) != 1 || first.Entries[0].GoodDescriptorSHA256 != StoreDirectoryGoodSHA256 {
		t.Fatalf("first pin=%+v err=%v", first, err)
	}
	second, err := Append(first, CheckPromotions, strings.Repeat("c", 64))
	if err != nil || second.Revision != 2 || len(second.Entries) != 2 || second.Entries[0].ToolName != CheckPromotions || second.Entries[1].ToolName != StoreDirectory {
		t.Fatalf("second pin=%+v err=%v", second, err)
	}
	parsed, err := Parse(string(second.Bytes()))
	if err != nil || parsed.SHA256() != second.SHA256() {
		t.Fatalf("canonical roundtrip=%+v err=%v", parsed, err)
	}
	if _, err := Append(second, StoreDirectory, strings.Repeat("d", 64)); err == nil {
		t.Fatal("existing tool overwritten")
	}
}

func TestRuleRejectsWrongDigestAndNoncanonicalAliases(t *testing.T) {
	rule, err := Append(testRule(), StoreDirectory, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	bad := rule
	bad.Entries = append([]Entry(nil), rule.Entries...)
	bad.Entries[0].GoodDescriptorSHA256 = strings.Repeat("d", 64)
	if bad.Valid() {
		t.Fatal("event-controlled replacement digest accepted")
	}
	raw := string(rule.Bytes())
	for _, edited := range []string{
		strings.Replace(raw, `"version":1`, `"version":1,"Version":1`, 1),
		strings.Replace(raw, `"revision":1`, `"revision":0`, 1),
		strings.Replace(raw, `"toolName":"store_directory"`, `"toolName":"arbitrary"`, 1),
	} {
		if _, err := Parse(edited); err == nil {
			t.Fatalf("noncanonical or wrong rule accepted: %s", edited)
		}
	}
}
