package litellmclient

import (
	"strings"
	"testing"
)

func TestOwnedClientPolicyAppendOnlyMultipleRuns(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	base := `{"entries":[],"revision":0,"version":2}`
	prior, e := ParseState(base)
	if e != nil {
		t.Fatal(e)
	}
	first, e := prior.Append(b, "decision-1")
	if e != nil {
		t.Fatal(e)
	}
	second, e := first.Append(a, "decision-2")
	if e != nil || len(second.Entries) != 2 || second.Entries[0].ClientSHA256 != a ||
		second.Entries[1].ClientSHA256 != b || second.Revision != 2 {
		t.Fatalf("sorted append/preserved prior: %+v %v", second, e)
	}
	encoded, e := EncodeState(second)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := ParseState(encoded)
	if e != nil || parsed.Entries[1].OperationID != "decision-1" {
		t.Fatalf("old denial lost: %+v %v", parsed, e)
	}
	if _, e := second.Append(a, "decision-3"); e == nil {
		t.Fatal("same client silently overwritten")
	}
	if _, e := second.Append(strings.Repeat("c", 64), "decision-1"); e == nil {
		t.Fatal("same selected decision reused")
	}
	for _, bad := range []string{
		base + "\n",
		strings.Replace(base, `"revision":0`, `"revision":1`, 1),
		strings.Replace(base, `"entries":[]`, `"Entries":[]`, 1),
		strings.Replace(base, `"entries":[]`, `"entries":[],"entries":[]`, 1),
		strings.Replace(encoded, `"active":true`, `"active":false`, 1),
	} {
		if _, e := ParseState(bad); e == nil {
			t.Fatalf("policy mutation accepted: %q", bad)
		}
	}
	clients := `{"modelAlias":"gpt-4o-mini","seedSHA256":"` + a + `","version":2}`
	if _, e := ParseClients(clients); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseClients(strings.Replace(clients, `"version":2`, `"version":1`, 1)); e == nil {
		t.Fatal("old credential registry accepted")
	}
}

func TestOwnedClientObservationExactObjectiveAndIdentity(t *testing.T) {
	raw := `{"version":2,"clientSHA256":"` + strings.Repeat("a", 64) + `","configMapUID":"cm","clientsConfigMapUID":"clients","seedSHA256":"` + strings.Repeat("b", 64) + `","serviceUID":"svc","targetPodUID":"pod-1","peerPodUID":"pod-2","requestPath":"/v1/chat/completions","objective":"ai2-query-extraction","observedAt":"2026-09-27T10:00:00Z","policyName":"policy","policyUID":"policy-uid","policyGeneration":1}`
	if _, e := ParseObservation(raw); e != nil {
		t.Fatal(e)
	}
	for _, changed := range []string{
		strings.Replace(raw, "ai2-query-extraction", "invented-case", 1),
		strings.Replace(raw, `"peerPodUID":"pod-2"`, `"peerPodUID":"pod-1"`, 1),
		strings.Replace(raw, `"clientSHA256":`, `"ClientSHA256":"x","clientSHA256":`, 1),
		strings.Replace(raw, `"version":2`, `"version":2,"version":2`, 1),
		strings.Replace(raw, `"requestPath":"/v1/chat/completions"`, `"requestPath":"/v1/models"`, 1),
	} {
		if _, e := ParseObservation(changed); e == nil {
			t.Fatalf("invalid observation accepted: %s", changed)
		}
	}
}
