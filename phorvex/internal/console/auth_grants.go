/*
 * Phorvex Console — the subject grant table (M-136).
 *
 * Authorization is an explicit, server-controlled binding from a VERIFIED issuer+subject to
 * roles and a tenant/target scope. It is DevOps policy, supplied per deployment — the console
 * never infers it. In particular:
 *
 *   - a signed-in user with no binding is authenticated but authorized for NOTHING;
 *   - no binding is ever derived from an email address, a name, a group claim or the mere fact
 *     that the identity provider let the user in;
 *   - an empty/absent table means there are no authorized data or control users at all. That is
 *     the fail-closed state, and it is reported (loudly at startup, and through /api/session) so
 *     a missing rollout prerequisite is visible rather than silent.
 *
 * Cross-tenant reach ("*") has to be written out. An omitted scope list grants nothing.
 */

package console

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// SubjectGrant binds one verified issuer+subject to roles and scope.
type SubjectGrant struct {
	Issuer  string   `json:"issuer"`            // exact token issuer this subject is trusted from
	Subject string   `json:"subject"`           // exact verified `sub`
	Roles   []string `json:"roles"`             // owner | investor | operator
	Tenants []string `json:"tenants,omitempty"` // tenant/namespace ids; ["*"] = every tenant
	Targets []string `json:"targets,omitempty"` // cluster target ids; "default" = this cluster; ["*"] = all
	Note    string   `json:"note,omitempty"`    // free text for the operator of the deployment
}

// GrantPolicy is the on-disk document DevOps supplies (a file or a mounted ConfigMap key).
type GrantPolicy struct {
	Version  int            `json:"version"`
	Subjects []SubjectGrant `json:"subjects"`
}

// GrantTable is the parsed, validated lookup built from a GrantPolicy.
type GrantTable struct {
	byKey map[string]*Principal
}

func grantKey(issuer, subject string) string { return issuer + "\x00" + subject }

var validRoles = map[string]Role{
	string(RoleOwner):    RoleOwner,
	string(RoleInvestor): RoleInvestor,
	string(RoleOperator): RoleOperator,
}

// ParseGrantPolicy validates the document and builds the lookup. Any structural problem is an
// error: a malformed policy must stop the deployment, never degrade into a permissive default.
func ParseGrantPolicy(raw []byte) (*GrantTable, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var doc GrantPolicy
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("grants: parse: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("grants: unsupported version %d (want 1)", doc.Version)
	}
	t := &GrantTable{byKey: map[string]*Principal{}}
	for i, g := range doc.Subjects {
		issuer := strings.TrimSpace(g.Issuer)
		subject := strings.TrimSpace(g.Subject)
		if issuer == "" || subject == "" {
			return nil, fmt.Errorf("grants: entry %d: issuer and subject are required", i)
		}
		if issuer == wildcardScope || subject == wildcardScope {
			return nil, fmt.Errorf("grants: entry %d: issuer/subject must be exact, not %q", i, wildcardScope)
		}
		key := grantKey(issuer, subject)
		if _, dup := t.byKey[key]; dup {
			return nil, fmt.Errorf("grants: entry %d: duplicate binding for issuer %q subject %q", i, issuer, subject)
		}
		if len(g.Roles) == 0 {
			return nil, fmt.Errorf("grants: entry %d (%s): at least one role is required", i, subject)
		}
		var roles []Role
		seen := map[Role]bool{}
		for _, name := range g.Roles {
			role, ok := validRoles[strings.TrimSpace(name)]
			if !ok {
				return nil, fmt.Errorf("grants: entry %d (%s): unknown role %q (owner|investor|operator)", i, subject, name)
			}
			if !seen[role] {
				seen[role] = true
				roles = append(roles, role)
			}
		}
		tenants, err := cleanScope(g.Tenants)
		if err != nil {
			return nil, fmt.Errorf("grants: entry %d (%s): tenants: %w", i, subject, err)
		}
		targets, err := cleanScope(g.Targets)
		if err != nil {
			return nil, fmt.Errorf("grants: entry %d (%s): targets: %w", i, subject, err)
		}
		t.byKey[key] = &Principal{
			Issuer: issuer, Subject: subject,
			Roles: roles, Tenants: tenants, Targets: targets,
		}
	}
	return t, nil
}

func cleanScope(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		v := strings.TrimSpace(s)
		if v == "" {
			return nil, fmt.Errorf("empty scope entry")
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}

// LoadGrantFile reads and validates a grant policy from disk.
func LoadGrantFile(path string) (*GrantTable, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("grants: read %s: %w", path, err)
	}
	return ParseGrantPolicy(raw)
}

// EmptyGrantTable is the fail-closed table: authenticated callers, zero authorizations.
func EmptyGrantTable() *GrantTable { return &GrantTable{byKey: map[string]*Principal{}} }

// Size reports how many subjects are bound (0 = the deployment prerequisite is unmet).
func (t *GrantTable) Size() int {
	if t == nil {
		return 0
	}
	return len(t.byKey)
}

// Lookup returns a COPY of the grant for a verified issuer+subject. A miss authorizes nothing.
func (t *GrantTable) Lookup(issuer, subject string) (*Principal, bool) {
	if t == nil || issuer == "" || subject == "" {
		return nil, false
	}
	g, ok := t.byKey[grantKey(issuer, subject)]
	if !ok {
		return nil, false
	}
	cp := *g
	cp.Roles = append([]Role(nil), g.Roles...)
	cp.Tenants = append([]string(nil), g.Tenants...)
	cp.Targets = append([]string(nil), g.Targets...)
	return &cp, true
}
