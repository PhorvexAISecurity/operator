package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	m158ConfigureRuntimeVocabulary = func(ctx context.Context, m *Manager, reader client.Reader, now time.Time) error {
		m.VocabularyReader = reader
		return nil
	}
	m158AssertFailedReadTrace = func(t *testing.T, m *Manager, entry *policyEntry, snap *ingest.Snapshot, sink *bytes.Buffer, knownTrace *model.DecisionTraceV2) {
		t.Helper()
		known := knownTrace.PolicyActionVocabulary
		if known == nil || !known.Known || known.UID != "old-schema" || known.ResourceVersion != "17" {
			t.Fatalf("known decision lacks schema evidence: %+v", known)
		}
		m.VocabularyReader = failureReader{err: errors.New("forbidden")}
		failed := m.refreshVocabulary(context.Background(), time.Now().Add(vocabularyRefreshInterval))
		if failed.Known || failed.UID != "old-schema" {
			t.Fatalf("failed read reused verified state: %+v", failed)
		}
		sink.Reset()
		snap.Now = snap.Now.Add(vocabularyRefreshInterval)
		m.processTenant(context.Background(), snap, entry, false)
		decoder := json.NewDecoder(sink)
		for {
			var record audit.Record
			if err := decoder.Decode(&record); err != nil {
				if err == io.EOF {
					break
				}
				t.Fatal(err)
			}
			if record.DecisionTrace == nil {
				continue
			}
			observation := record.DecisionTrace.PolicyActionVocabulary
			if observation == nil || observation.Known || observation.UID != "old-schema" || !strings.Contains(observation.Error, "forbidden") {
				t.Fatalf("decision trace hid unverified historical schema: %+v", observation)
			}
			for _, row := range record.DecisionTrace.ActionStatus {
				if row.Action == string(model.ActionQuarantine) && row.Status == model.ActionStatusNotInstallable {
					t.Fatalf("unknown discovery fabricated absence: %+v", row)
				}
			}
			return
		}
		t.Fatal("failed-read tick produced no decision trace")
	}
}
