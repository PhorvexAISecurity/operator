package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-logr/logr"
)

func TestMaintenanceAuditPersistsIdentityAndFailure(t *testing.T) {
	var out bytes.Buffer
	l := New(logr.Discard(), &out)
	l.Maintenance("receipt", "warm-swap", "tenant", "ns", "policy", "policy-uid", "old", "pod-uid", "partial", "route removed", errors.New("delete denied"))
	var fields map[string]any
	if err := json.Unmarshal(out.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if fields["schemaVersion"] != SchemaVersionCurrent || fields["kind"] != "phorvex.maintenance" || fields["receipt"] != "receipt" || fields["policyUID"] != "policy-uid" || fields["targetUID"] != "pod-uid" || fields["outcome"] != "partial" || fields["error"] != "delete denied" {
		t.Fatalf("maintenance audit lost identity/outcome: %+v", fields)
	}
	var parsed Record
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil || parsed.Kind != "phorvex.maintenance" {
		t.Fatalf("audit reader cannot skip maintenance kind: %+v %v", parsed.Kind, err)
	}
}
