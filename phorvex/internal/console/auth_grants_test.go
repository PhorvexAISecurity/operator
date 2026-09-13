/*
 * Phorvex Console — subject grant table tests (M-136).
 *
 * Grants are DevOps policy. These tests hold the two properties that keep them from becoming
 * something the console invents: a malformed table is an error rather than a permissive default,
 * and an absent binding authorizes nothing at all.
 */

package console

import (
	"strings"
	"testing"
)

func TestGrantPolicy_ValidBindingsLoad(t *testing.T) {
	raw := []byte(`{
	  "version": 1,
	  "subjects": [
	    {"issuer":"https://idp","subject":"alice","roles":["operator"],"tenants":["vllm","litellm"],"targets":["default"],"note":"platform on-call"},
	    {"issuer":"https://idp","subject":"iris","roles":["investor"],"tenants":["*"],"targets":["*"]},
	    {"issuer":"https://idp","subject":"olivia","roles":["owner"],"tenants":["acme"]}
	  ]
	}`)
	tbl, err := ParseGrantPolicy(raw)
	if err != nil {
		t.Fatalf("a well-formed policy must load: %v", err)
	}
	if tbl.Size() != 3 {
		t.Fatalf("size = %d, want 3", tbl.Size())
	}

	alice, ok := tbl.Lookup("https://idp", "alice")
	if !ok || !alice.CanOperate() || !alice.AllowsTenant("vllm") || alice.AllowsTenant("evilcorp") {
		t.Fatalf("alice = %+v (ok=%v)", alice, ok)
	}
	if !alice.AllowsTarget("") || !alice.AllowsTarget(defaultTargetID) || alice.AllowsTarget("prod-eks") {
		t.Fatal("alice's target scope must be exactly the default cluster")
	}

	iris, _ := tbl.Lookup("https://idp", "iris")
	if !iris.CanRead() || iris.CanOperate() {
		t.Fatal("an investor grant must read and never operate")
	}
	if !iris.TenantWildcard() || !iris.AllowsTenant("anything") {
		t.Fatal("an explicit wildcard must widen the tenant scope")
	}

	olivia, _ := tbl.Lookup("https://idp", "olivia")
	if olivia.CanRead() || olivia.CanOperate() {
		t.Fatal("an owner grant reaches neither the vendor read group nor the controls")
	}
	// An owner with no explicit targets reaches no cluster target: scope is never implied.
	if olivia.AllowsTarget("") || olivia.AllowsTarget(defaultTargetID) {
		t.Fatal("an omitted target list must grant nothing, not the default cluster")
	}

	// A lookup MISS is the whole point: it authorizes nothing.
	if _, ok := tbl.Lookup("https://idp", "mallory"); ok {
		t.Fatal("an unbound subject must not resolve")
	}
	// The issuer is part of the key, so two IdPs cannot collide on one subject string.
	if _, ok := tbl.Lookup("https://other-idp", "alice"); ok {
		t.Fatal("a grant must not apply across issuers")
	}
}

// A returned grant is a copy: a handler cannot mutate the shared table through it.
func TestGrantLookupReturnsACopy(t *testing.T) {
	tbl := grantTable(t, operatorGrant("op", []string{"vllm"}, []string{defaultTargetID}))
	first, _ := tbl.Lookup(testALBIssuer, "op")
	first.Roles = append(first.Roles, RoleInvestor)
	first.Tenants = append(first.Tenants, wildcardScope)
	second, _ := tbl.Lookup(testALBIssuer, "op")
	if second.HasRole(RoleInvestor) || second.TenantWildcard() {
		t.Fatalf("the grant table was mutated through a lookup result: %+v", second)
	}
}

// A malformed table stops the deployment. None of these may degrade into a usable table.
func TestGrantPolicy_MalformedIsAnError(t *testing.T) {
	cases := map[string]string{
		"not json":           `{`,
		"missing version":    `{"subjects":[]}`,
		"future version":     `{"version":2,"subjects":[]}`,
		"unknown field":      `{"version":1,"subjects":[],"allowEveryone":true}`,
		"no issuer":          `{"version":1,"subjects":[{"subject":"a","roles":["operator"]}]}`,
		"no subject":         `{"version":1,"subjects":[{"issuer":"https://idp","roles":["operator"]}]}`,
		"wildcard subject":   `{"version":1,"subjects":[{"issuer":"https://idp","subject":"*","roles":["operator"]}]}`,
		"wildcard issuer":    `{"version":1,"subjects":[{"issuer":"*","subject":"a","roles":["operator"]}]}`,
		"no roles":           `{"version":1,"subjects":[{"issuer":"https://idp","subject":"a","roles":[]}]}`,
		"unknown role":       `{"version":1,"subjects":[{"issuer":"https://idp","subject":"a","roles":["admin"]}]}`,
		"empty tenant entry": `{"version":1,"subjects":[{"issuer":"https://idp","subject":"a","roles":["owner"],"tenants":[" "]}]}`,
		"duplicate binding":  `{"version":1,"subjects":[{"issuer":"https://idp","subject":"a","roles":["owner"]},{"issuer":"https://idp","subject":"a","roles":["operator"]}]}`,
	}
	for name, raw := range cases {
		if _, err := ParseGrantPolicy([]byte(raw)); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

// An empty table is valid and grants nothing — the visible fail-closed rollout state.
func TestEmptyGrantTableAuthorizesNobody(t *testing.T) {
	tbl, err := ParseGrantPolicy([]byte(`{"version":1,"subjects":[]}`))
	if err != nil {
		t.Fatalf("an empty table is a legitimate (fail-closed) state: %v", err)
	}
	if tbl.Size() != 0 {
		t.Fatal("size must be 0")
	}
	if _, ok := tbl.Lookup("https://idp", "anyone"); ok {
		t.Fatal("an empty table must resolve nobody")
	}
	if EmptyGrantTable().Size() != 0 {
		t.Fatal("EmptyGrantTable must be empty")
	}
}

// A grant file that cannot be read or parsed is a startup error, never an empty-but-running one.
func TestAuthenticatorRejectsABrokenGrantFile(t *testing.T) {
	keys := newKeyServer()
	fx := newALBFixture(t, keys)
	_, err := NewAuthenticator(AuthConfig{ALB: fx.config(), GrantsPath: "/nonexistent/grants.json", Transport: keys, Now: testNow})
	if err == nil {
		t.Fatal("an unreadable grant file must be a startup error")
	}
	if !strings.Contains(err.Error(), "grants") {
		t.Fatalf("the error must name the grant file: %v", err)
	}
}

// A console with no credential path configured must refuse to be built at all.
func TestAuthenticatorRequiresACredentialPath(t *testing.T) {
	if _, err := NewAuthenticator(AuthConfig{}); err == nil {
		t.Fatal("no ALB and no bearer configuration must be a startup error, not a demo-trust console")
	}
}

// A wildcard origin is not a trust boundary and is refused as configuration.
func TestTrustedOriginsAreExactOrigins(t *testing.T) {
	keys := newKeyServer()
	fx := newALBFixture(t, keys)
	bad := []string{"*", "https://console.example/path", "console.example", "ftp://console.example", ""}
	for _, o := range bad {
		_, err := NewAuthenticator(AuthConfig{ALB: fx.config(), TrustedOrigins: []string{o}, Transport: keys, Now: testNow})
		if err == nil {
			t.Errorf("origin %q must be rejected as configuration", o)
		}
	}
	a, err := NewAuthenticator(AuthConfig{ALB: fx.config(), TrustedOrigins: []string{"https://console.example:443/"}, Transport: keys, Now: testNow})
	if err != nil {
		t.Fatalf("a well-formed origin must load: %v", err)
	}
	if !a.originTrusted("https://console.example:443") || a.originTrusted("https://console.example") {
		t.Fatal("origin matching must be exact, including the port as written")
	}
}
