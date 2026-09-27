package litellmclient

import (
	"strings"
	"testing"
)

func TestOwnedClientPolicyStrictSingleHash(t *testing.T) {
	attacker := strings.Repeat("a", 64)
	control := strings.Repeat("b", 64)
	base := `{"active":false,"clientSHA256":"` + attacker + `","operationId":"","revision":0,"version":1}`
	if _, e := ParseState(base); e != nil {
		t.Fatalf("inactive canonical state: %v", e)
	}
	for _, raw := range []string{
		base + "\n",
		strings.Replace(base, `"revision":0`, `"revision":0,"revision":0`, 1),
		strings.Replace(base, `"active":false`, `"Active":true,"active":false`, 1),
		strings.Replace(base, `"clientSHA256":"`+attacker+`"`, `"clientSHA256":"`+control+`"`, 1),
	} {
		if raw == base {
			continue
		}
		if strings.Contains(raw, `"clientSHA256":"`+control+`"`) {
			// A different hash is syntactically valid; the live inventory join rejects it.
			continue
		}
		if _, e := ParseState(raw); e == nil {
			t.Fatalf("invalid policy accepted: %q", raw)
		}
	}
	active := State{Version: 1, Active: true, Revision: 1, OperationID: "decision-1", ClientSHA256: attacker}
	encoded, e := EncodeState(active)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := ParseState(encoded)
	if e != nil || parsed != active {
		t.Fatalf("active round trip: %+v %v", parsed, e)
	}
	if _, e := ParseState(strings.Replace(encoded, `"revision":1`, `"revision":2`, 1)); e == nil {
		t.Fatal("unreviewed second revision accepted")
	}
	if _, e := ParseState(strings.Replace(encoded, `"operationId":"decision-1"`, `"operationId":"other"`, 1)); e != nil {
		// Another operation is syntactically valid, but the journal/readback joins must reject it.
		t.Fatal(e)
	}
	clients := `{"attackerSHA256":"` + attacker + `","controlSHA256":"` + control + `","modelAlias":"gpt-4o-mini","version":1}`
	if _, e := ParseClients(clients); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseClients(strings.Replace(clients, control, attacker, 1)); e == nil {
		t.Fatal("identical attacker/control accepted")
	}
}

func TestOwnedClientObservationExactObjectiveAndIdentity(t *testing.T) {
	raw := `{"version":1,"clientSHA256":"` + strings.Repeat("a", 64) + `","configMapUID":"cm","serviceUID":"svc","targetPodUID":"pod-1","peerPodUID":"pod-2","requestPath":"/v1/chat/completions","objective":"ai2-query-extraction","observedAt":"2026-09-27T10:00:00Z","policyName":"policy","policyUID":"policy-uid","policyGeneration":1}`
	if _, e := ParseObservation(raw); e != nil {
		t.Fatal(e)
	}
	for _, changed := range []string{
		strings.Replace(raw, "ai2-query-extraction", "invented-case", 1),
		strings.Replace(raw, `"peerPodUID":"pod-2"`, `"peerPodUID":"pod-1"`, 1),
		strings.Replace(raw, `"clientSHA256":`, `"ClientSHA256":"x","clientSHA256":`, 1),
		strings.Replace(raw, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(raw, `"requestPath":"/v1/chat/completions"`, `"requestPath":"/v1/models"`, 1),
	} {
		if _, e := ParseObservation(changed); e == nil {
			t.Fatalf("invalid observation accepted: %s", changed)
		}
	}
}
