package outputpolicy

import (
	"strings"
	"testing"
	"time"
)

func testLiteRule(nonce, objective string) LiteRule {
	return LiteRule{Version: 2, ObjectiveID: objective, RunNonce: nonce,
		Method: "POST", Path: "/v1/chat/completions", FieldPath: []any{"choices", float64(0), "message", "content"},
		MaxResponseBytes: 131072, ProtectedSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64),
		ServiceUID: "service-uid", DeploymentUID: "deployment-uid", TargetPodUID: "pod-a", PeerPodUID: "pod-b",
		ContextSecretUID: "secret-uid", ContextSeedSHA256: strings.Repeat("c", 64)}
}

func TestLiteOutputV2ObservationRejectsAmbiguousOrCrossObjectiveAssertion(t *testing.T) {
	r := testLiteRule(strings.Repeat("3", 32), LitePromptObjective)
	o := LiteObservation{Version: 2, ObjectiveID: r.ObjectiveID, RunNonce: r.RunNonce, RuleSHA256: r.SHA256(),
		ProtectedSHA256: r.ProtectedSHA256, SourceSHA256: r.SourceSHA256, RuleConfigMapName: LiteRuleSlotName(0), RuleConfigMapUID: "rule-uid", PolicyConfigMapUID: "policy-cm-uid",
		ServiceUID: r.ServiceUID, DeploymentUID: r.DeploymentUID, TargetPodUID: r.TargetPodUID, PeerPodUID: r.PeerPodUID,
		ContextSecretUID: r.ContextSecretUID, ContextSeedSHA256: r.ContextSeedSHA256, PolicyName: "litellm-defense", PolicyUID: "policy-uid",
		PolicyGeneration: 1, RequestSHA256: strings.Repeat("d", 64), OriginalCompletionSHA256: strings.Repeat("e", 64), ObservedAt: time.Now().UTC()}
	if _, err := ParseLiteObservation(string(o.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseLiteObservation(strings.Replace(string(o.Bytes()), `"version":2`, `"version":2,"version":2`, 1)); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := ParseLiteObservation(strings.Replace(string(o.Bytes()), `"version":2`, `"extra":true,"version":2`, 1)); err == nil {
		t.Fatal("unreviewed event field accepted")
	}
	bad := o
	bad.ObjectiveID = "ai2-unbounded-consumption"
	if _, err := ParseLiteObservation(string(bad.Bytes())); err == nil {
		t.Fatal("unrelated objective accepted")
	}
	bad = o
	bad.OriginalCompletionSHA256 = ""
	if _, err := ParseLiteObservation(string(bad.Bytes())); err == nil {
		t.Fatal("original completion digest absent")
	}
}

func TestLiteOutputRuleSlotsAreExactlyBounded(t *testing.T) {
	for i := 0; i < LiteMaxEntries; i++ {
		if name := LiteRuleSlotName(i); !LiteValidRuleSlotName(name) {
			t.Fatalf("slot %d invalid: %s", i, name)
		}
	}
	for _, name := range []string{"", LiteRulePrefix + "32", LiteRulePrefix + "-1", LiteRulePrefix + "0", LiteRulePrefix + strings.Repeat("a", 32)} {
		if LiteValidRuleSlotName(name) {
			t.Fatalf("unreviewed rule slot accepted: %s", name)
		}
	}
}

func TestLiteOutputImmutableAllocationBindsOriginalAndRule(t *testing.T) {
	rule := testLiteRule(strings.Repeat("1", 32), LiteDocumentObjective)
	at := time.Now().UTC().Truncate(time.Microsecond)
	allocation := LiteAllocation{Version: 1, RunID: "atk-abc123", ObjectiveID: rule.ObjectiveID,
		RunNonce: rule.RunNonce, RuleSHA256: rule.SHA256(),
		OriginalCompletionSHA256: strings.Repeat("e", 64), ObservedAt: at}
	data := map[string]string{LiteRuleKey: string(rule.Bytes()), LiteAllocationKey: string(allocation.Bytes())}
	if err := ValidateLiteAllocation(data, rule, allocation.OriginalCompletionSHA256, at); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]map[string]string{
		"missing-allocation": {LiteRuleKey: data[LiteRuleKey]},
		"changed-rule":       {LiteRuleKey: data[LiteRuleKey] + " ", LiteAllocationKey: data[LiteAllocationKey]},
		"extra-data":         {LiteRuleKey: data[LiteRuleKey], LiteAllocationKey: data[LiteAllocationKey], "extra": "x"},
	} {
		if err := ValidateLiteAllocation(changed, rule, allocation.OriginalCompletionSHA256, at); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	if err := ValidateLiteAllocation(data, rule, strings.Repeat("f", 64), at); err == nil {
		t.Fatal("accepted different original completion")
	}
	if err := ValidateLiteAllocation(data, rule, allocation.OriginalCompletionSHA256, at.Add(time.Second)); err == nil {
		t.Fatal("accepted different observation time")
	}
}

func TestLiteOutputV2RuleCanonicalAndDistinctObjectives(t *testing.T) {
	for _, objective := range []string{LiteDocumentObjective, LitePromptObjective} {
		rule := testLiteRule(strings.Repeat("1", 32), objective)
		if !strings.HasPrefix(string(rule.Bytes()), `{"contextSecretUID":`) ||
			!strings.Contains(string(rule.Bytes()), `,"fieldPath":["choices",0,"message","content"],`) {
			t.Fatalf("rule does not match sorted gateway JSON: %s", rule.Bytes())
		}
		parsed, err := ParseLiteRule(string(rule.Bytes()))
		if err != nil || parsed.SHA256() != rule.SHA256() {
			t.Fatalf("reviewed %s rule refused: %v", objective, err)
		}
		if _, err := ParseLiteRule(string(rule.Bytes()) + " "); err == nil {
			t.Fatal("noncanonical whitespace accepted")
		}
		if _, err := ParseLiteRule(strings.Replace(string(rule.Bytes()), `"version":2`, `"version":2,"version":2`, 1)); err == nil {
			t.Fatal("duplicate version accepted")
		}
		bad := rule
		bad.FieldPath = []any{"choices", float64(1), "message", "content"}
		if _, err := ParseLiteRule(string(bad.Bytes())); err == nil {
			t.Fatal("wrong response field accepted")
		}
		bad = rule
		bad.ContextSecretUID = ""
		if _, err := ParseLiteRule(string(bad.Bytes())); err == nil {
			t.Fatal("unbound private source accepted")
		}
	}
}

func TestLiteOutputV2AppendPreservesPriorAndRefusesDuplicateOrCapacity(t *testing.T) {
	empty := LiteState{Version: 2, Revision: 0, Entries: []LiteEntry{}}
	if string(empty.Bytes()) != `{"entries":[],"revision":0,"version":2}` {
		t.Fatalf("initial canonical bytes changed: %s", empty.Bytes())
	}
	if _, err := ParseLiteState(string(empty.Bytes())); err != nil {
		t.Fatal(err)
	}
	ruleB := testLiteRule(strings.Repeat("2", 32), LitePromptObjective)
	ruleA := testLiteRule(strings.Repeat("1", 32), LiteDocumentObjective)
	entry := func(r LiteRule, op string) LiteEntry {
		return LiteEntry{ObjectiveID: r.ObjectiveID, RunNonce: r.RunNonce, RuleSHA256: r.SHA256(),
			ProtectedSHA256: r.ProtectedSHA256, OperationID: op, ServiceUID: r.ServiceUID, DeploymentUID: r.DeploymentUID,
			TargetPodUID: r.TargetPodUID, PeerPodUID: r.PeerPodUID, SourceSHA256: r.SourceSHA256,
			ContextSecretUID: r.ContextSecretUID, ContextSeedSHA256: r.ContextSeedSHA256}
	}
	one, err := empty.Append(entry(ruleB, strings.Repeat("d", 64)))
	if err != nil {
		t.Fatal(err)
	}
	two, err := one.Append(entry(ruleA, strings.Repeat("e", 64)))
	if err != nil {
		t.Fatal(err)
	}
	if two.Revision != 2 || two.Entries[0].ObjectiveID != LiteDocumentObjective || two.Entries[1] != one.Entries[0] {
		t.Fatal("append lost prior rule or order")
	}
	if _, err := two.Append(entry(ruleA, strings.Repeat("f", 64))); err == nil {
		t.Fatal("duplicate objective/nonce accepted")
	}
	if _, err := ParseLiteState(strings.Replace(string(two.Bytes()), `"revision":2`, `"revision":1`, 1)); err == nil {
		t.Fatal("revision drift accepted")
	}
	full := empty
	for i := 0; i < LiteMaxEntries; i++ {
		r := testLiteRule(strings.Repeat("0", 24)+strings.ToLower(hex8(i)), LiteDocumentObjective)
		full, err = full.Append(entry(r, strings.Repeat("a", 56)+hex8(i)))
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if _, err = full.Append(entry(ruleB, strings.Repeat("f", 64))); err == nil {
		t.Fatal("policy capacity silently replaced a prior rule")
	}
}

func hex8(i int) string {
	const digits = "0123456789abcdef"
	b := []byte("00000000")
	for n := 7; n >= 0; n-- {
		b[n] = digits[i&15]
		i >>= 4
	}
	return string(b)
}
