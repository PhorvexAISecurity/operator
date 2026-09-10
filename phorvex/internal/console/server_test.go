/*
 * Phorvex Console — role boundary tests through the REAL router (M-136).
 *
 * The old version of this file asserted that a self-declared X-Phorvex-Lens header decided
 * access: lens=operator got 200, lens=owner got 403. That is the defect. These tests assert the
 * replacement: access follows the server-side GRANT for a verified subject, and the header is
 * only a narrowing hint.
 */

package console

import (
	"net/http"
	"strings"
	"testing"
)

func testServer() *Server { return NewServer(Config{Root: "."}) }

// A console constructed with no authenticator has no trust boundary, so it serves no API at all.
// This is the state the old build called "demo-trust dev mode".
func TestNoAuthConfigured_APIIsClosed(t *testing.T) {
	srv := testServer().Handler()
	for _, path := range []string{"/api/effectiveness", "/api/owner/events", "/api/policy/edit", "/api/live"} {
		w := doGet(t, srv, path)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s with no authenticator: got %d, want 503 (fail closed)", path, w.Code)
		}
	}
}

// Vendor data follows the GRANT, not the header. A header-only caller is unauthenticated.
func TestVendorDataRequiresGrantedRole(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."},
		operatorGrant("op", []string{"acme"}, []string{defaultTargetID}),
		investorGrant("inv", []string{"acme"}, []string{defaultTargetID}),
		ownerGrant("own", []string{"acme"}),
	)

	// (a) no credential at all — the header cannot substitute for one.
	req := f.albReq(t, http.MethodGet, "/api/effectiveness", "")
	req.Header.Del(ALBDataHeader)
	req.Header.Set("X-Phorvex-Lens", "operator")
	if w := f.do(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("self-asserted lens with no credential: got %d, want 401\n%s", w.Code, w.Body.String())
	}

	// (b) a VERIFIED subject with no grant is authenticated and authorized for nothing.
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/effectiveness", "", "stranger")); w.Code != http.StatusForbidden {
		t.Fatalf("verified but ungranted subject: got %d, want 403", w.Code)
	}

	// (c) the granted roles decide.
	cases := []struct {
		subject string
		want    int
	}{
		{"op", http.StatusOK},
		{"inv", http.StatusOK},
		{"own", http.StatusForbidden}, // an owner grant is IP-walled out of vendor data
	}
	for _, c := range cases {
		if w := f.do(f.albReqAs(t, http.MethodGet, "/api/effectiveness", "", c.subject)); w.Code != c.want {
			t.Fatalf("/api/effectiveness as %s: got %d, want %d\n%s", c.subject, w.Code, c.want, w.Body.String())
		}
	}

	// (d) an owner-granted subject asking for the operator lens does NOT become an operator.
	req = f.albReqAs(t, http.MethodGet, "/api/effectiveness?lens=operator", "", "own")
	req.Header.Set("X-Phorvex-Lens", "operator")
	if w := f.do(req); w.Code != http.StatusForbidden {
		t.Fatalf("owner grant + operator lens: got %d, want 403 (a lens must never widen a grant)", w.Code)
	}
}

// TestOwnerEndpointNoIPLeak — the owner endpoint's JSON body contains NONE of the redacted IP
// field names, for every granted role (it always projects via ToOwnerEvent, never a Record).
func TestOwnerEndpointNoIPLeak(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."},
		operatorGrant("op", []string{"acme"}, []string{defaultTargetID}),
		investorGrant("inv", []string{"acme"}, []string{defaultTargetID}),
		ownerGrant("own", []string{"acme"}),
	)
	for _, subject := range []string{"own", "op", "inv"} {
		w := f.do(f.albReqAs(t, http.MethodGet, "/api/owner/events?tenant=acme", "", subject))
		if w.Code != http.StatusOK {
			t.Fatalf("/api/owner/events as %s: got %d %s", subject, w.Code, w.Body.String())
		}
		body := strings.ToLower(w.Body.String())
		for _, n := range redactedFieldNames {
			if strings.Contains(body, strings.Trim(n, `"`)) {
				t.Fatalf("/api/owner/events as %s leaked IP token %q\nbody=%s", subject, n, body)
			}
		}
	}
}

// An owner may only name a tenant its grant covers; another tenant is refused before any record
// is read, so neither the events nor the counts can disclose it.
func TestOwnerEventsCrossTenantRefused(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, ownerGrant("own", []string{"acme"}))
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/owner/events?tenant=other", "", "own")); w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant owner read: got %d, want 403\n%s", w.Code, w.Body.String())
	}
	// An OMITTED tenant is not "all tenants" either.
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/owner/events", "", "own")); w.Code != http.StatusBadRequest {
		t.Fatalf("omitted tenant: got %d, want 400 (never an unscoped read)\n%s", w.Code, w.Body.String())
	}
}
