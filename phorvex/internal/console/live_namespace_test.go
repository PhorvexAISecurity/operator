package console

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// liveBody streams /api/live with the given query until the first live-tail tick has run,
// then returns the SSE body. Records are pre-written so replay (tail) covers them and the
// tick has nothing new; ctx is bounded so the handler's tail loop returns.
func liveBody(t *testing.T, path, query string, p *Principal) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	w := httptest.NewRecorder()
	NewServer(Config{AuditPath: path}).live(w, withTestPrincipal(httptest.NewRequest("GET", "/api/live?"+query, nil).WithContext(ctx), p))
	return w.Body.String()
}

func TestLiveNamespaceFilterScopesOperatorStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	inTarget := historyRecord(0, false)
	inTarget.Namespace, inTarget.Pod = "voice-prod", "voice-a"
	other := historyRecord(1, false)
	other.Namespace, other.Pod = "litellm", "litellm-a"
	appended := historyRecord(2, false)
	appended.Namespace, appended.Pod = "voice-prod", "voice-b"
	writeHistory(t, path, inTarget, other)

	// Live tail must honour the filter too, not only the replay: append after the replay
	// offset is taken by making the record visible only through the ticker path.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rec := &historyFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
	appendedOnce := false
	rec.onFlush = func() {
		body := rec.Body.String()
		if strings.Contains(body, `"pod":"voice-b"`) {
			cancel()
			return
		}
		if !appendedOnce && strings.Contains(body, `"pod":"voice-a"`) {
			appendedOnce = true
			writeHistory(t, path, other, appended)
		}
	}
	NewServer(Config{AuditPath: path}).live(rec, withTestPrincipal(httptest.NewRequest("GET", "/api/live?lens=operator&tail=0&namespace=voice-prod", nil).WithContext(ctx), testOperatorPrincipal()))
	body := rec.Body.String()
	if !strings.Contains(body, `"pod":"voice-a"`) || !strings.Contains(body, `"pod":"voice-b"`) {
		t.Fatalf("target-namespace records missing from filtered stream: %s", body)
	}
	if strings.Contains(body, `"pod":"litellm-a"`) {
		t.Fatalf("record outside ?namespace= leaked into the operator stream: %s", body)
	}

	// No filter: everything streams, as before.
	all := liveBody(t, path, "lens=operator&tail=0", testOperatorPrincipal())
	for _, pod := range []string{"voice-a", "litellm-a", "voice-b"} {
		if !strings.Contains(all, `"pod":"`+pod+`"`) {
			t.Fatalf("unfiltered stream lost %s: %s", pod, all)
		}
	}
}

func TestLiveNamespaceFilterNeverWidensOwnerLens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	acted := historyRecord(0, false)
	acted.Namespace, acted.Pod, acted.Selected = "voice-prod", "voice-a", true
	writeHistory(t, path, acted)

	// Owner without ?tenant= streams nothing, and ?namespace= must not stand in for it.
	if body := liveBody(t, path, "lens=owner&tail=0&namespace=voice-prod", testOwnerPrincipal("acme")); strings.Contains(body, `"voice-a"`) {
		t.Fatalf("owner stream opened by ?namespace= without a tenant: %s", body)
	}
	// Owner with the right tenant still sees its action even when ?namespace= names
	// another namespace: the owner projection is tenant-scoped, the filter is ignored.
	if body := liveBody(t, path, "lens=owner&tail=0&tenant=acme&namespace=elsewhere", testOwnerPrincipal("acme")); !strings.Contains(body, `"voice-a"`) {
		t.Fatalf("owner lost its own tenant's action because of an unrelated ?namespace=: %s", body)
	}
}
