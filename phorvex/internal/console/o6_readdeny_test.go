/*
 * Phorvex — P-VCLUSTER O6: cross-tenant READ denial on the owner stream. The owner SSE streams ONLY the
 * caller's tenant; another tenant's records never appear. The data-level filter proven here is now
 * paired with the identity binding under M-136: the ?tenant= must name a tenant the verified subject
 * is granted, so residual R3 (self-asserting ?tenant=B) is closed rather than disclosed.
 * The grant-level refusal is asserted in auth_boundary_test.go.
 */

package console

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func TestO6_OwnerStreamCrossTenantReadDenied(t *testing.T) {
	mk := func(tenant, pod string) []byte {
		r := audit.ToRecord(model.Decision{Tenant: tenant, Namespace: tenant, Pod: pod, Action: model.ActionRotate, Selected: true})
		r.Kind = "phorvex.decision"
		r.Selected = true
		b, _ := json.Marshal(r)
		return append(b, '\n')
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	body := append(mk("acme", "acme-pod"), mk("other", "other-secret-pod")...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	s := NewServer(Config{AuditPath: path})
	ctx, cancel := context.WithCancel(context.Background())
	// [M-136] The ?tenant= is now BOUND to a verified grant: this principal is granted acme and
	// nothing else, so the residual R3 this test disclosed (a self-asserted ?tenant=B) is closed.
	req := withTestPrincipal(httptest.NewRequest("GET", "/live?lens=owner&tenant=acme", nil).WithContext(ctx), testOwnerPrincipal("acme"))
	w := newLiveTestRecorder()
	go func() { time.Sleep(250 * time.Millisecond); cancel() }()
	s.live(w, req)

	out := w.Body.String()
	if !strings.Contains(out, "acme-pod") {
		t.Errorf("O6: acme's own record must stream to acme: %q", out)
	}
	if strings.Contains(out, "other-secret-pod") || strings.Contains(out, "other") {
		t.Errorf("O6 LEAK: another tenant's record reached acme's owner stream:\n%s", out)
	}
}
