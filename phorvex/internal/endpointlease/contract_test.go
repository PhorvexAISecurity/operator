package endpointlease

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixtureState() State {
	return State{Version: 1, Revision: 0,
		ServiceUID:         "11111111-1111-4111-8111-111111111111",
		ProxySourceSHA256:  strings.Repeat("c", 64),
		SecretUID:          "22222222-2222-4222-8222-222222222222",
		SeedSHA256:         strings.Repeat("e", 64),
		AllowedClientHMACs: []string{strings.Repeat("a", 64), strings.Repeat("b", 64)},
		RevokedClientHMACs: []string{}, LastOperationID: ""}
}

func TestCanonicalStateAndOneRevoke(t *testing.T) {
	before := fixtureState()
	raw, err := EncodeState(before)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseState(raw); err != nil {
		t.Fatal(err)
	}
	next, err := before.Revoke(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("d", 32))
	if err != nil {
		t.Fatal(err)
	}
	if next.Revision != 1 || next.LastOperationID != strings.Repeat("d", 32) ||
		len(next.AllowedClientHMACs) != 1 || next.AllowedClientHMACs[0] != strings.Repeat("b", 64) ||
		len(next.RevokedClientHMACs) != 1 || next.RevokedClientHMACs[0] != strings.Repeat("a", 64) {
		t.Fatalf("wrong precise cutover: %+v", next)
	}
	encoded, err := EncodeState(next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseState(encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := next.Revoke(strings.Repeat("b", 64), strings.Repeat("a", 64), strings.Repeat("e", 32)); err == nil {
		t.Fatal("revoked A must not qualify as the retained client")
	}
}

func TestStateRejectsAliasDuplicateReorderAndOverlap(t *testing.T) {
	raw, _ := EncodeState(fixtureState())
	bad := []string{
		strings.Replace(raw, `"allowedClientHMACs":["`+strings.Repeat("a", 64)+`","`+strings.Repeat("b", 64)+`"]`, `"allowedClientHMACs":["`+strings.Repeat("a", 64)+`","`+strings.Repeat("b", 64)+`","`+strings.Repeat("c", 64)+`"]`, 1),
		strings.Replace(raw, `"revokedClientHMACs":[]`, `"revokedClientHMACs":null`, 1),
		strings.Replace(raw, `"version":1`, `"version":1,"Version":1`, 1),
		strings.Replace(raw, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(raw, `"revision":0`, `"revision":0.0`, 1),
		strings.Replace(raw, strings.Repeat("a", 64)+`","`+strings.Repeat("b", 64), strings.Repeat("b", 64)+`","`+strings.Repeat("a", 64), 1),
		strings.Replace(raw, `"revokedClientHMACs":[]`, `"revokedClientHMACs":["`+strings.Repeat("a", 64)+`"]`, 1),
		strings.Replace(raw, `"secretUID":"22222222-2222-4222-8222-222222222222"`, `"secretUID":"22222222-2222-4222-8222-222222222223"`, 1) + " ",
	}
	for i, sample := range bad {
		if _, err := ParseState(sample); err == nil {
			t.Errorf("noncanonical/adverse state %d accepted", i)
		}
	}
}

func TestSourceAndStatusFixture(t *testing.T) {
	if got, want := SourceSHA256([]byte("p"), []byte("d"), []byte("l"), []byte("v"), []byte("i")), SHA256([]byte("p\x00d\x00l\x00v\x00i")); got != want {
		t.Fatalf("source digest %s != %s", got, want)
	}
	state := fixtureState()
	next, _ := state.Revoke(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("d", 32))
	nextRaw, _ := EncodeState(next)
	status := Status{Version: 1, PodUID: "44444444-4444-4444-8444-444444444444",
		ServiceUID: next.ServiceUID, ProxySourceSHA256: next.ProxySourceSHA256,
		PolicyConfigMapUID: "33333333-3333-4333-8333-333333333333", SecretUID: next.SecretUID,
		SeedSHA256: next.SeedSHA256, Revision: next.Revision, LastOperationID: next.LastOperationID,
		StateSHA256: SHA256([]byte(nextRaw)), RevokedClientHMAC: strings.Repeat("a", 64),
		RetainedClientHMAC: strings.Repeat("b", 64), RevokedClientAllowed: false,
		RetainedClientAllowed: true, OldRevisionInFlight: 0, Ready: true}
	obj, _ := json.Marshal(status)
	var values map[string]any
	_ = json.Unmarshal(obj, &values)
	raw, _ := json.Marshal(values)
	if _, err := ParseStatus(string(raw)); err != nil {
		t.Fatal(err)
	}
	values["StateSHA256"] = values["stateSHA256"]
	raw, _ = json.Marshal(values)
	if _, err := ParseStatus(string(raw)); err == nil {
		t.Fatal("case alias in status accepted")
	}
	delete(values, "StateSHA256")
	values["oldRevisionInFlight"] = float64(MaxRevision + 1)
	raw, _ = json.Marshal(values)
	if _, err := ParseStatus(string(raw)); err == nil {
		t.Fatal("status in-flight count above canonical integer bound accepted")
	}
}
