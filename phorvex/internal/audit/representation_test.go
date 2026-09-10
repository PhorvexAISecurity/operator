package audit

import (
	"bytes"
	"encoding/json"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/representation"
	"testing"
)

func TestM100HistoricalAbsentAndReadOnlyProjection(t *testing.T) {
	var r Record
	if err := json.Unmarshal([]byte(`{"pod":"old","action":"noop"}`), &r); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(r)
	projection := RepresentationForRead(r)
	after, _ := json.Marshal(r)
	if !bytes.Equal(before, after) || bytes.Contains(after, []byte(`"representation"`)) || projection.Snapshot.Claim != nil || projection.CoverageShare.Share.Present {
		t.Fatal("historical metadata backfilled")
	}
}
func TestM100AuditRepresentationDoesNotAlias(t *testing.T) {
	c := model.NewClaimScope([]string{"old"}, true, "b", "s")
	d := model.Decision{Representation: representation.Build(model.RepresentationSnapshot{Claim: &c})}
	r := ToRecord(d)
	d.Representation.Snapshot.Claim.DetectorSet[0] = "later"
	if r.Representation.Snapshot.Claim.DetectorSet[0] != "old" {
		t.Fatal("audit aliases report")
	}
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	var read Record
	if e = json.Unmarshal(b, &read); e != nil || read.Representation == nil {
		t.Fatal("audit replay lost representation", e)
	}
}
