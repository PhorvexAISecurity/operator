/*
 * Phorvex — P-VCLUSTER O6: cross-tenant READ denial on the owner stream. The owner SSE streams ONLY the
 * caller's tenant; another tenant's records never appear. (PASS-1 proves the data-level filter; binding
 * the ?tenant= to a VERIFIED identity so an attacker cannot self-assert ?tenant=B is the deferred Pass-2
 * OIDC work — disclosed residual R3.)
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
	req := httptest.NewRequest("GET", "/live?lens=owner&tenant=acme", nil).WithContext(ctx)
	w := httptest.NewRecorder()
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
