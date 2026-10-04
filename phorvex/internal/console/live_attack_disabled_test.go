package console

import "testing"

func TestLiveAttackDisabledMatchesNamespaceAndWildcard(t *testing.T) {
	c := Config{LiveAttackDisabled: map[string]bool{
		"vllm/foothold":         true,
		"vllm/warm-swap":        true,
		"*/ai2-cross-refund":    true,
		"voice/ai2-mcp-tool-poisoning": true,
	}}
	cases := []struct {
		ns, id string
		want   bool
	}{
		{"vllm", "foothold", true},
		{"vllm", "warm-swap", true},
		{"voice", "foothold", false},       // not retired in voice by this set
		{"litellm", "ai2-cross-refund", true}, // wildcard matches any namespace
		{"voice", "ai2-mcp-tool-poisoning", true},
		{"vllm", "kvcache", false}, // a real actuator; never retired
	}
	for _, tc := range cases {
		if got := c.liveAttackDisabled(tc.ns, tc.id); got != tc.want {
			t.Fatalf("liveAttackDisabled(%q,%q)=%v want %v", tc.ns, tc.id, got, tc.want)
		}
	}
	if (Config{}).liveAttackDisabled("vllm", "foothold") {
		t.Fatal("nil disable set must retire nothing")
	}
}
