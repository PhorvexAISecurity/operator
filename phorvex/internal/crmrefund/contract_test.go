package crmrefund

import "testing"

func TestAppGuardEncodesSortedActiveOrders(t *testing.T) {
	g := Guard{}
	g, err := g.Append("OR-5002", "op-1")
	if err != nil {
		t.Fatal(err)
	}
	g, err = g.Append("OR-5001", "op-2")
	if err != nil {
		t.Fatal(err)
	}
	if got := g.EncodeAppGuard(); got != `{"denied_order_ids":["OR-5001","OR-5002"]}` {
		t.Fatalf("app guard = %s", got)
	}
}

func TestAppendRefusesRepeatOrderAndReusedOperation(t *testing.T) {
	g, err := (Guard{}).Append("OR-5002", "op-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Append("OR-5002", "op-2"); err == nil {
		t.Fatal("repeated order accepted")
	}
	if _, err := g.Append("OR-5003", "op-1"); err == nil {
		t.Fatal("reused operation id accepted")
	}
	if _, err := (Guard{}).Append("not-an-order", "op-3"); err == nil {
		t.Fatal("malformed order id accepted")
	}
}

func TestStateRoundTripIsCanonical(t *testing.T) {
	g, _ := (Guard{}).Append("OR-5002", "op-1")
	raw, err := EncodeState(g)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseState(raw)
	if err != nil || back.Revision != 1 || len(back.Entries) != 1 || back.Entries[0].OrderID != "OR-5002" {
		t.Fatalf("round trip = %+v err=%v", back, err)
	}
	if _, err := ParseState(` ` + raw); err == nil {
		t.Fatal("non-canonical state accepted")
	}
}

func TestParseObservationRejectsSameAccountAndBadFields(t *testing.T) {
	good := `{"version":1,"orderId":"OR-5002","orderAccountId":"AC-1002","callerAccountId":"AC-1001",` +
		`"guardConfigMapUID":"u1","serviceUID":"u2","targetPodUID":"p1","peerPodUID":"p2",` +
		`"objective":"ai2-cross-record-refund","observedAt":"2026-10-01T00:00:00Z","policyName":"crm-defense",` +
		`"policyUID":"pu","policyGeneration":3}`
	if _, err := ParseObservation(good); err != nil {
		t.Fatalf("valid observation rejected: %v", err)
	}
	same := `{"version":1,"orderId":"OR-5002","orderAccountId":"AC-1001","callerAccountId":"AC-1001",` +
		`"guardConfigMapUID":"u1","serviceUID":"u2","targetPodUID":"p1","peerPodUID":"p2",` +
		`"objective":"ai2-cross-record-refund","observedAt":"2026-10-01T00:00:00Z","policyName":"crm-defense",` +
		`"policyUID":"pu","policyGeneration":3}`
	if _, err := ParseObservation(same); err == nil {
		t.Fatal("same-account observation accepted (not cross-record)")
	}
	if _, err := ParseObservation(`{"version":1,"orderId":"OR-5002"}`); err == nil {
		t.Fatal("partial observation accepted")
	}
}

// The guard is first installed by hand as YAML, so its app bytes are formatted differently
// from the actuator's canonical encoding. Formatting must not read as an out-of-band writer;
// a different deny set, a duplicate or an unknown key must.
func TestAppGuardMatchesMeaningNotBytes(t *testing.T) {
	empty := Guard{Version: 2, Entries: []Entry{}}
	for _, raw := range []string{`{"denied_order_ids":[]}`, "{\"denied_order_ids\": []}\n", "{ \"denied_order_ids\" : [ ] }"} {
		if !AppGuardMatches(raw, empty) {
			t.Fatalf("installed empty guard %q must match the empty ledger", raw)
		}
	}
	one, err := empty.Append("OR-5002", "decision-1")
	if err != nil {
		t.Fatal(err)
	}
	if !AppGuardMatches(one.EncodeAppGuard(), one) || !AppGuardMatches(`{"denied_order_ids": ["OR-5002"]}`, one) {
		t.Fatal("canonical and reformatted single-order guards must match")
	}
	for _, raw := range []string{
		`{"denied_order_ids":[]}`,                       // ledger revoked an order the app does not deny
		`{"denied_order_ids":["OR-5002","OR-5002"]}`,   // duplicate
		`{"denied_order_ids":["OR-5003"]}`,             // different order
		`{"denied_order_ids":["OR-5002"],"extra":true}`, // unknown key
		`{"denied_order_ids":null}`, `not json`, `{"denied_order_ids":["OR-5002"]} {}`,
	} {
		if AppGuardMatches(raw, one) {
			t.Fatalf("%q must disagree with the one-order ledger", raw)
		}
	}
}
