package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
)

// telemetry_degraded_test.go — PHORVEXSEC-200 / M-113 (c)(d)(f): a whole-source outage is a
// condition, a counter and exactly one ERROR line per transition; recovery clears it with one line.

type fakeSource struct {
	name   string
	health ingest.SourceHealth
	err    error
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) PodMetrics(context.Context, string, []string) (map[string]model.Telemetry, error) {
	return map[string]model.Telemetry{}, f.err
}
func (f *fakeSource) LastHealth() ingest.SourceHealth { return f.health }

func TestSourceOutageLogsOnceAndSetsCondition(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "tel", Name: "policy"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.PhorvexPolicy{}).WithObjects(policy).Build()

	var errLines, infoLines int
	log := funcr.New(func(prefix, args string) {
		if strings.Contains(args, "unreachable") && strings.Contains(args, "every signal query failed") {
			errLines++
		}
		if strings.Contains(args, "telemetry source recovered") {
			infoLines++
		}
	}, funcr.Options{Verbosity: 0})
	src := &fakeSource{name: "prometheus-http"}
	m := &Manager{Client: c, Log: log, MetricsSource: src}
	e := &policyEntry{key: types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}, namespace: "tel", tenant: "t"}

	// (f) 100 consecutive failed ticks → exactly one ERROR line.
	src.err = errors.New("reqRate: 500\nconnCount: 500")
	src.health = ingest.SourceHealth{Source: src.name, Total: 2, Failed: 2, Reason: model.ReasonSourceUnreachable}
	for i := 0; i < 100; i++ {
		m.observeSourceHealth(e, m.sensor().Telemetry(context.Background(), sensorapi.TelemetryRequest{Namespace: e.namespace}))
	}
	if errLines != 1 {
		t.Fatalf("ERROR lines over 100 failed ticks = %d, want exactly 1 (old code: one per tick)", errLines)
	}
	if _, st := m.sourceOutageState(); !st.Down || st.Reason != model.ReasonSourceUnreachable || st.Since.IsZero() {
		t.Fatalf("outage state = %+v, want down since a timestamp", st)
	}
	// (c) condition set on the policy within the same tick's status write.
	m.updateStatus(context.Background(), e, 1, 0, 0, false, time.Now())
	var got v1.PhorvexPolicy
	if err := c.Get(context.Background(), e.key, &got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionTelemetryDegraded)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "SourceUnreachable" || !strings.Contains(cond.Message, "prometheus-http") {
		t.Fatalf("TelemetryDegraded condition = %+v, want True/SourceUnreachable naming the source", cond)
	}

	// (d) recovery → cleared, exactly one recovery line; a partial failure afterwards is not an outage.
	src.err = nil
	src.health = ingest.SourceHealth{Source: src.name, Total: 2, Failed: 0}
	m.observeSourceHealth(e, m.sensor().Telemetry(context.Background(), sensorapi.TelemetryRequest{Namespace: e.namespace}))
	m.observeSourceHealth(e, m.sensor().Telemetry(context.Background(), sensorapi.TelemetryRequest{Namespace: e.namespace}))
	if infoLines != 1 {
		t.Fatalf("recovery lines = %d, want exactly 1", infoLines)
	}
	if _, st := m.sourceOutageState(); st.Down {
		t.Fatalf("outage not cleared: %+v", st)
	}
	m.updateStatus(context.Background(), e, 1, 0, 0, false, time.Now())
	if err := c.Get(context.Background(), e.key, &got); err != nil {
		t.Fatal(err)
	}
	cond = meta.FindStatusCondition(got.Status.Conditions, ConditionTelemetryDegraded)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "Healthy" {
		t.Fatalf("TelemetryDegraded after recovery = %+v, want False/Healthy", cond)
	}
	src.err = errors.New("reqRate: 500")
	src.health = ingest.SourceHealth{Source: src.name, Total: 2, Failed: 1}
	m.observeSourceHealth(e, m.sensor().Telemetry(context.Background(), sensorapi.TelemetryRequest{Namespace: e.namespace}))
	if _, st := m.sourceOutageState(); st.Down || errLines != 1 {
		t.Fatalf("a partial failure must not be an outage: down=%v errLines=%d", st.Down, errLines)
	}
}
