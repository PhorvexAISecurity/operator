package servingbudget_test

import (
	"context"
	b "github.com/phorvex/phorvex/internal/servingbudget"
	bt "github.com/phorvex/phorvex/internal/servingbudget/budgettest"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"testing"
	"time"
)

// Simulated API admission only: no production creator stamp is supplied by DetectOnce.
type stampingClient struct {
	client.Client
	now *time.Time
	t   *testing.T
}

func (c stampingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if ev, ok := obj.(*amtd.SecurityEvent); ok {
		if ev.Annotations["phorvex.ai/creator-identity"] != "" {
			c.t.Fatal("detector self-stamped")
		}
		ev.Annotations["phorvex.ai/creator-identity"] = b.DetectorIdentity
		ev.CreationTimestamp = metav1.NewTime(*c.now)
	}
	return c.Client.Create(ctx, obj, opts...)
}
func TestDetectorDedupesAndLabelsReapableEvents(t *testing.T) {
	t.Setenv("PHORVEX_THROTTLE_SOURCE_SHA256", bt.SHA)
	t.Setenv("PHORVEX_THROTTLE_PROXY_IMAGE", bt.Image)
	c, _ := bt.Fixture()
	now := time.Now()
	st, err := b.ReadStatus(t.Context(), c, bt.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	d := &b.Detector{Now: func() time.Time { return now }}
	stamped := stampingClient{c, &now, t}
	counts := []int{}
	for i := 0; i <= 60; i++ {
		if i > 0 {
			now = now.Add(5 * time.Second)
			st.Abusive.Attempted += 9105
		}
		st.UpdatedAt = now
		var cm core.ConfigMap
		_ = c.Get(t.Context(), client.ObjectKey{Namespace: bt.Namespace, Name: b.StatusName}, &cm)
		cm.Data[b.Key] = b.Encode(st)
		if err = c.Update(t.Context(), &cm); err != nil {
			t.Fatal(err)
		}
		if err = b.DetectOnce(t.Context(), stamped, d, bt.Namespace, "cost-defense"); err != nil {
			t.Fatal(err)
		}
		var events amtd.SecurityEventList
		_ = c.List(t.Context(), &events, client.MatchingLabels{b.EventLabel: "true"})
		if len(events.Items) > len(counts) {
			counts = append(counts, i*5)
		}
		for _, ev := range events.Items {
			if ev.Labels["app.kubernetes.io/managed-by"] != "phorvex" {
				t.Fatal("event cannot be reaped by console TTL sweeper")
			}
		}
	}
	if len(counts) != 9 {
		t.Fatalf("300s sustained load emitted at %v; want 60,90,...,300", counts)
	}
	for i := 1; i < len(counts); i++ {
		if counts[i]-counts[i-1] < 30 {
			t.Fatal(counts)
		}
	}
	t.Logf("300s sustained drive: emission seconds=%v; <=1 event/Pod/30s; managed-by label binds existing 15m TTL sweeper", counts)
}
