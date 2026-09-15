package runner

import (
	"fmt"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestM019FailureCooldownIdentityAndBound(t *testing.T) {
	var f actionFailures
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	k := failureKey{"uid\x00policy-a", "ns", "pod-1", model.ActionGuardrailRotate}
	if r := f.observe(k, now); r.consecutive != 1 || !r.retry.IsZero() {
		t.Fatalf("first transient failure cooled: %+v", r)
	}
	if _, excluded := f.exclusion(k, now); excluded {
		t.Fatal("first failure excluded")
	}
	r := f.observe(k, now.Add(time.Second))
	if got := r.retry.Sub(r.last); got != 30*time.Second {
		t.Fatalf("initial cooldown %v", got)
	}
	if _, excluded := f.exclusion(k, r.retry.Add(-time.Nanosecond)); !excluded {
		t.Fatal("cooldown absent before retry deadline")
	}
	if _, excluded := f.exclusion(k, r.retry); excluded {
		t.Fatal("cooldown did not expire")
	}
	for i := 0; i < 20; i++ {
		r = f.observe(k, now.Add(time.Duration(i+2)*time.Second))
	}
	if got := r.retry.Sub(r.last); got != 5*time.Minute {
		t.Fatalf("cooldown cap %v", got)
	}
	for _, other := range []failureKey{
		{"uid\x00policy-b", "ns", "pod-1", model.ActionGuardrailRotate},
		{"uid\x00policy-a", "ns", "pod-2", model.ActionGuardrailRotate},
		{"uid\x00policy-a", "ns", "pod-1", model.ActionRotate},
	} {
		if _, excluded := f.exclusion(other, now); excluded {
			t.Fatalf("failure leaked to %+v", other)
		}
	}
	f.retain(k.owner, map[string]struct{}{"ns\x00pod-2": {}})
	if len(f.at) != 0 {
		t.Fatal("retired Pod UID kept failure history")
	}
	for i := 0; i < maxFailureRecords+5; i++ {
		f.observe(failureKey{k.owner, "ns", fmt.Sprintf("pod-%d", i), model.ActionRotate}, now.Add(time.Duration(i)*time.Second))
	}
	if len(f.at) != maxFailureRecords {
		t.Fatalf("unbounded failure state: %d", len(f.at))
	}
	f.forgetOwner(k.owner)
	if len(f.at) != 0 {
		t.Fatal("owner retirement leaked failure state")
	}
}
