/*
 * Phorvex Console — IP-WALL SCOPE GATE tests (the §C.1 default-deny fix).
 * Asserts a vendor endpoint rejects the owner/missing lens (no IP leak by an absent header)
 * and that the owner endpoint's response carries none of the redacted IP field names.
 */

package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testServer() *Server { return NewServer(Config{Root: "."}) }

// TestScopedDefaultDeny — vendor data is reachable ONLY by investor/operator; owner and a
// missing/unknown lens get 403 (default-deny). This is the fix for the scoped() NO-OP bug.
func TestScopedDefaultDeny(t *testing.T) {
	srv := testServer().Handler()
	cases := []struct {
		lens string
		want int
	}{
		{"operator", 200}, {"investor", 200},
		{"owner", 403},   // owner cannot reach vendor data
		{"", 403},        // MISSING header must NOT default to operator
		{"bogus", 403},   // unknown lens => least privilege => denied
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/api/effectiveness", nil)
		if c.lens != "" {
			r.Header.Set("X-Phorvex-Lens", c.lens)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Fatalf("/api/effectiveness lens=%q: got %d, want %d", c.lens, w.Code, c.want)
		}
	}
}

// TestOwnerEndpointNoIPLeak — the owner endpoint's JSON body contains NONE of the redacted
// IP field names, for any lens (it always projects via ToOwnerEvent, never marshals a Record).
func TestOwnerEndpointNoIPLeak(t *testing.T) {
	srv := testServer().Handler()
	for _, lens := range []string{"owner", "operator", "", "bogus"} {
		r := httptest.NewRequest("GET", "/api/owner/events", nil)
		if lens != "" {
			r.Header.Set("X-Phorvex-Lens", lens)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("/api/owner/events lens=%q: got %d", lens, w.Code)
		}
		body := strings.ToLower(w.Body.String())
		for _, n := range redactedFieldNames {
			if strings.Contains(body, strings.Trim(n, `"`)) {
				t.Fatalf("/api/owner/events lens=%q leaked IP token %q\nbody=%s", lens, n, body)
			}
		}
	}
}