package audit

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/model"
)

type m181LogCapture struct {
	mu      sync.Mutex
	records [][]any
}

type m181LogSink struct {
	capture *m181LogCapture
	values  []any
}

func (s *m181LogSink) Init(logr.RuntimeInfo) {}

func (s *m181LogSink) Enabled(int) bool { return true }

func (s *m181LogSink) Info(_ int, _ string, keysAndValues ...any) {
	values := append(append([]any(nil), s.values...), keysAndValues...)
	s.capture.mu.Lock()
	s.capture.records = append(s.capture.records, values)
	s.capture.mu.Unlock()
}

func (s *m181LogSink) Error(_ error, _ string, keysAndValues ...any) {
	s.Info(0, "", keysAndValues...)
}

func (s *m181LogSink) WithValues(keysAndValues ...any) logr.LogSink {
	return &m181LogSink{capture: s.capture, values: append(append([]any(nil), s.values...), keysAndValues...)}
}

func (s *m181LogSink) WithName(string) logr.LogSink {
	return &m181LogSink{capture: s.capture, values: append([]any(nil), s.values...)}
}

func (c *m181LogCapture) value(key string) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, record := range c.records {
		for i := 0; i+1 < len(record); i += 2 {
			if record[i] == key {
				return record[i+1]
			}
		}
	}
	return nil
}

func TestM181LoggerRedactsClaimBuildMetadataAtBothProducerShapes(t *testing.T) {
	tests := []struct {
		name      string
		image     string
		sha       string
		wantImage string
		wantSHA   string
		secrets   []string
	}{
		{
			name: "authorization", image: "brain Authorization: Basic fixture-auth", sha: "ordinary-sha",
			wantImage: "brain Authorization:[REDACTED]", wantSHA: "ordinary-sha", secrets: []string{"fixture-auth"},
		},
		{
			name: "bearer", image: "brain Bearer fixture.bearer-token", sha: "ordinary-sha",
			wantImage: "brain Bearer [REDACTED]", wantSHA: "ordinary-sha", secrets: []string{"fixture.bearer-token"},
		},
		{
			name: "secret key value", image: "registry.example/team/credential:fixture-image-token", sha: "api-key=fixture-sha-token",
			wantImage: "registry.example/team/credential:[REDACTED]", wantSHA: "api-key=[REDACTED]", secrets: []string{"fixture-image-token", "fixture-sha-token"},
		},
		{
			name: "unicode case folds", image: "registry.example/team/paſſword:fixture-unicode", sha: "api-Key=fixture-kelvin",
			wantImage: "registry.example/team/paſſword:[REDACTED]", wantSHA: "api-Key=[REDACTED]", secrets: []string{"fixture-unicode", "fixture-kelvin"},
		},
		{
			name: "URI userinfo", image: "https://fixture-user:fixture-pass@registry.example/team/brain:v1", sha: "ordinary-sha",
			wantImage: "https://[REDACTED]@registry.example/team/brain:v1", wantSHA: "ordinary-sha", secrets: []string{"fixture-user", "fixture-pass"},
		},
	}

	for _, tc := range tests {
		for _, explicit := range []bool{false, true} {
			shape := "trace-fallback"
			if explicit {
				shape = "explicit-claim"
			}
			t.Run(tc.name+"/"+shape, func(t *testing.T) {
				trace := &model.DecisionTraceV2{
					SchemaVersion: model.DecisionTraceSchemaV2,
					DecisionID:    "decision-ordinary",
					BrainImage:    tc.image,
					GitSHA:        tc.sha,
				}
				decision := model.Decision{
					Tenant: "tenant-fixture", Namespace: "namespace-fixture", Pod: "pod-fixture",
					Action: model.ActionNoop, Selected: true, DecidedAt: time.Unix(11, 0).UTC(),
					Trace: trace,
				}
				var inputClaim *model.ClaimScope
				if explicit {
					claim := model.ClaimScope{
						Scope: "modeled", DetectorSet: []string{"detector-z", "detector-a", "detector-z"},
						DetectorSetKnown: true, RecallCap: "detector-bounded", Note: "fixture-note",
						BrainImage: tc.image, GitSHA: tc.sha,
					}
					inputClaim = &claim
					decision.Claim = inputClaim
				}
				beforeTrace := *trace
				var beforeClaim *model.ClaimScope
				if inputClaim != nil {
					copyClaim := *inputClaim
					copyClaim.DetectorSet = append([]string(nil), inputClaim.DetectorSet...)
					beforeClaim = &copyClaim
				}

				var jsonl bytes.Buffer
				capture := &m181LogCapture{}
				logger := New(logr.New(&m181LogSink{capture: capture}), &jsonl)
				if err := logger.Record(decision); err != nil {
					t.Fatal(err)
				}

				var record Record
				if err := json.Unmarshal(bytes.TrimSpace(jsonl.Bytes()), &record); err != nil {
					t.Fatal(err)
				}
				if record.Claim == nil || record.Claim.BrainImage != tc.wantImage || record.Claim.GitSHA != tc.wantSHA {
					t.Fatalf("JSONL claim not redacted: %+v", record.Claim)
				}
				if record.DecisionTrace == nil || record.DecisionTrace.BrainImage != tc.wantImage || record.DecisionTrace.GitSHA != tc.wantSHA {
					t.Fatalf("nested trace not redacted: %+v", record.DecisionTrace)
				}
				for _, secret := range tc.secrets {
					if bytes.Contains(jsonl.Bytes(), []byte(secret)) {
						t.Fatalf("JSONL retained synthetic secret %q: %s", secret, jsonl.Bytes())
					}
				}

				loggedClaim, ok := capture.value("claim").(*model.ClaimScope)
				if !ok || loggedClaim == nil {
					t.Fatalf("structured logger did not carry typed claim: %T", capture.value("claim"))
				}
				if loggedClaim.BrainImage != tc.wantImage || loggedClaim.GitSHA != tc.wantSHA {
					t.Fatalf("structured logger claim not redacted: %+v", loggedClaim)
				}
				for _, secret := range tc.secrets {
					if strings.Contains(loggedClaim.BrainImage, secret) || strings.Contains(loggedClaim.GitSHA, secret) {
						t.Fatalf("structured logger retained synthetic secret %q: %+v", secret, loggedClaim)
					}
				}
				if explicit && !reflect.DeepEqual(record.Claim.DetectorSet, []string{"detector-a", "detector-z"}) {
					t.Fatalf("detector set is not canonical: %v", record.Claim.DetectorSet)
				}
				if !reflect.DeepEqual(*trace, beforeTrace) {
					t.Fatal("logger mutated trace producer")
				}
				if inputClaim != nil && !reflect.DeepEqual(inputClaim, beforeClaim) {
					t.Fatal("logger mutated explicit claim producer")
				}
				if inputClaim != nil {
					inputClaim.DetectorSet[0] = "changed-after-record"
					if !reflect.DeepEqual(loggedClaim.DetectorSet, []string{"detector-a", "detector-z"}) {
						t.Fatalf("structured claim aliases producer detectors: %v", loggedClaim.DetectorSet)
					}
				}
			})
		}
	}
}

func TestM181LoggerPreservesOrdinaryClaimBuildMetadata(t *testing.T) {
	const image = "registry.example/team/brain:v1.2.3"
	const sha = "0123456789abcdef0123456789abcdef01234567"
	claim := model.NewClaimScope([]string{"detector"}, true, image, sha)
	decision := model.Decision{
		Action: model.ActionNoop, Selected: true,
		Trace: &model.DecisionTraceV2{SchemaVersion: model.DecisionTraceSchemaV2, BrainImage: image, GitSHA: sha},
		Claim: &claim,
	}
	var jsonl bytes.Buffer
	if err := New(logr.Discard(), &jsonl).Record(decision); err != nil {
		t.Fatal(err)
	}
	var record Record
	if err := json.Unmarshal(bytes.TrimSpace(jsonl.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record.Claim == nil || record.Claim.BrainImage != image || record.Claim.GitSHA != sha {
		t.Fatalf("ordinary claim metadata changed: %+v", record.Claim)
	}
}
