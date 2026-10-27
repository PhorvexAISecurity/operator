package servingbudget_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	b "github.com/phorvex/phorvex/internal/servingbudget"
	bt "github.com/phorvex/phorvex/internal/servingbudget/budgettest"
	core "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A periodic proxy write can occur during Validate's preceding authority reads.
type publishingStatusReader struct{ client.Client }

func (r publishingStatusReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Client.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if key.Name == b.StatusName {
		cm := obj.(*core.ConfigMap)
		var s b.Status
		if err := json.Unmarshal([]byte(cm.Data[b.Key]), &s); err != nil {
			return err
		}
		s.UpdatedAt = time.Now()
		cm.Data[b.Key] = b.Encode(s)
	}
	return nil
}

func TestValidateLiveFreshnessAtStatusRead(t *testing.T) {
	t.Setenv("PHORVEX_THROTTLE_SOURCE_SHA256", bt.SHA)
	t.Setenv("PHORVEX_THROTTLE_PROXY_IMAGE", bt.Image)
	c, o := bt.Fixture()
	if _, err := b.Validate(t.Context(), publishingStatusReader{c}, bt.Namespace, "cost-target-test", o); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSnapshotFreshnessBoundedAndDeterministic(t *testing.T) {
	t.Setenv("PHORVEX_THROTTLE_SOURCE_SHA256", bt.SHA)
	t.Setenv("PHORVEX_THROTTLE_PROXY_IMAGE", bt.Image)
	frozen := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		lag   time.Duration
		valid bool
	}{
		{-10 * time.Second, false}, {-10*time.Second + time.Nanosecond, true},
		{-300 * time.Millisecond, true}, {50 * time.Millisecond, true}, {900 * time.Millisecond, true},
		{2 * time.Second, true}, {2*time.Second + time.Nanosecond, false},
	} {
		t.Run(tc.lag.String(), func(t *testing.T) {
			c, o := bt.Fixture()
			var cm core.ConfigMap
			if err := c.Get(t.Context(), client.ObjectKey{Namespace: bt.Namespace, Name: b.StatusName}, &cm); err != nil {
				t.Fatal(err)
			}
			var status b.Status
			if err := json.Unmarshal([]byte(cm.Data[b.Key]), &status); err != nil {
				t.Fatal(err)
			}
			status.UpdatedAt = frozen.Add(tc.lag)
			cm.Data[b.Key] = b.Encode(status)
			if err := c.Update(t.Context(), &cm); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				_, err := b.Validate(t.Context(), c, bt.Namespace, "cost-target-test", o, frozen)
				if (err == nil) != tc.valid {
					t.Fatalf("lag=%v valid=%t err=%v", tc.lag, tc.valid, err)
				}
			}
		})
	}
}
