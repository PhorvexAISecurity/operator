package audit_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

// TestM137LeadClaimBuildIdentityRedactionGap is a separate, pre-existing RED.
// It is deliberately excluded from the T24 guard-equivalence overlays. The
// nested trace and top-level claim derive from the same build identity, but
// only DecisionTraceV2.MarshalJSON currently applies credential redaction.
func TestM137LeadClaimBuildIdentityRedactionGap(t *testing.T) {
	const (
		image  = "registry.example/team/credential:s3cr3t-token"
		secret = "s3cr3t-token"
	)
	for _, testCase := range []struct {
		name  string
		claim *model.ClaimScope
	}{
		{name: "trace-fallback"},
		{name: "runtime-explicit-claim", claim: func() *model.ClaimScope {
			claim := model.NewClaimScope([]string{"detector-safe"}, true, image, "git-safe")
			return &claim
		}()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			trace := &model.DecisionTraceV2{
				SchemaVersion: model.DecisionTraceSchemaV2,
				DecisionID: "decision-safe", BrainImage: image, GitSHA: "git-safe",
			}
			decision := model.Decision{
				Tenant: "tenant-safe", Namespace: "ns-safe", Pod: "pod-safe",
				Action: model.ActionNoop, Selected: true, DecidedAt: time.Unix(11, 0).UTC(),
				Trace: trace, Claim: testCase.claim,
			}
			var sink bytes.Buffer
			if err := audit.New(logr.Discard(), &sink).Record(decision); err != nil {
				t.Fatal(err)
			}
			var record audit.Record
			if err := json.Unmarshal(bytes.TrimSpace(sink.Bytes()), &record); err != nil {
				t.Fatal(err)
			}
			if record.DecisionTrace == nil || strings.Contains(record.DecisionTrace.BrainImage, secret) {
				t.Fatalf("fixture did not reach the nested trace redaction boundary: %+v", record.DecisionTrace)
			}
			if record.Claim == nil {
				t.Fatal("record dropped claim")
			}
			if strings.Contains(record.Claim.BrainImage, secret) {
				t.Fatalf("top-level claim leaked build-identity credential pattern: %q", record.Claim.BrainImage)
			}
		})
	}
}

func TestLeadM181OrdinaryClaimIdentityUnchanged(t *testing.T) {
 const image = "registry.example/team/brain:v1.2.3"
 const sha = "0123456789abcdef"
 for _, explicit := range []bool{false,true} {
  trace:= &model.DecisionTraceV2{SchemaVersion:model.DecisionTraceSchemaV2, BrainImage:image,GitSHA:sha}
  d:=model.Decision{Trace:trace,Action:model.ActionNoop,DecidedAt:time.Unix(11,0).UTC()}
  if explicit {c:=model.NewClaimScope([]string{"z","a","z"},true,image,sha);d.Claim=&c}
  var sink bytes.Buffer
  if err:=audit.New(logr.Discard(),&sink).Record(d);err!=nil {t.Fatal(err)}
  var got audit.Record
  if err:=json.Unmarshal(bytes.TrimSpace(sink.Bytes()),&got);err!=nil {t.Fatal(err)}
  if got.Claim==nil || got.Claim.BrainImage!=image || got.Claim.GitSHA!=sha || got.DecisionTrace.BrainImage!=image || trace.BrainImage!=image {t.Fatalf("ordinary identity changed: %+v",got)}
 }
}
