/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package graph

import "strings"

// rbac.go resolves Kubernetes RBAC into the LATERAL-MOVEMENT capabilities Phorvex's
// blast-radius graph cares about: a pod whose ServiceAccount can write pods, exec
// into pods, read secrets, or impersonate can REACH other workloads through the API
// even with no network path. This is the RBAC half of the reachability graph (PRD
// §5.2 "RBAC scope, reachability graph"). The projection types are plain structs so
// the resolution is unit-testable without importing k8s RBAC types.

// PolicyRule is a projected rbac PolicyRule (apiGroups/resources/verbs).
type PolicyRule struct {
	APIGroups []string
	Resources []string
	Verbs     []string
}

// Role is a projected (Cluster)Role. Cluster=true marks a ClusterRole.
type Role struct {
	Namespace string
	Name      string
	Cluster   bool
	Rules     []PolicyRule
}

// Subject is a projected binding subject (only ServiceAccount subjects matter here).
type Subject struct {
	Kind      string
	Namespace string
	Name      string
}

// RoleBinding is a projected (Cluster)RoleBinding. Cluster=true marks a
// ClusterRoleBinding (cluster-wide grant).
type RoleBinding struct {
	Namespace   string
	Name        string
	Cluster     bool
	RoleRefKind string // "Role" | "ClusterRole"
	RoleRefName string
	Subjects    []Subject
}

// SubjectPerms is the resolved lateral-movement capability of one ServiceAccount.
type SubjectPerms struct {
	PodsWrite   bool // create/delete/patch/update pods (spawn/replace workloads)
	PodsExec    bool // pods/exec, pods/attach (code execution in other pods)
	SecretsRead bool // get/list secrets (steal credentials -> lateral)
	Impersonate bool // assume other identities
	ClusterWide bool // granted via a ClusterRoleBinding (reaches all namespaces)
	// Namespaces is the set of namespaces reachable via namespaced bindings.
	Namespaces map[string]struct{}
}

// HasLateral reports whether the SA has ANY lateral-movement capability.
func (p SubjectPerms) HasLateral() bool {
	return p.PodsWrite || p.PodsExec || p.SecretsRead || p.Impersonate
}

// saKey is the canonical ServiceAccount key.
func saKey(ns, name string) string { return ns + "/" + name }

// ResolveRBAC walks bindings -> roles and returns per-ServiceAccount lateral perms.
// roles is keyed for lookup: namespaced Role by "ns/name", ClusterRole by "name".
func ResolveRBAC(roles []Role, bindings []RoleBinding) map[string]SubjectPerms {
	nsRole := map[string]Role{}
	clusterRole := map[string]Role{}
	for _, r := range roles {
		if r.Cluster {
			clusterRole[r.Name] = r
		} else {
			nsRole[r.Namespace+"/"+r.Name] = r
		}
	}

	out := map[string]SubjectPerms{}
	add := func(ns, name string, perms SubjectPerms, clusterBinding bool, bindingNS string) {
		k := saKey(ns, name)
		cur := out[k]
		if cur.Namespaces == nil {
			cur.Namespaces = map[string]struct{}{}
		}
		cur.PodsWrite = cur.PodsWrite || perms.PodsWrite
		cur.PodsExec = cur.PodsExec || perms.PodsExec
		cur.SecretsRead = cur.SecretsRead || perms.SecretsRead
		cur.Impersonate = cur.Impersonate || perms.Impersonate
		if clusterBinding {
			cur.ClusterWide = true
		} else {
			cur.Namespaces[bindingNS] = struct{}{}
		}
		out[k] = cur
	}

	for _, b := range bindings {
		var role Role
		var ok bool
		switch b.RoleRefKind {
		case "ClusterRole":
			role, ok = clusterRole[b.RoleRefName]
		case "Role":
			// A namespaced RoleBinding references a Role in the binding's namespace.
			role, ok = nsRole[b.Namespace+"/"+b.RoleRefName]
		}
		if !ok {
			continue
		}
		perms := rulePerms(role.Rules)
		if perms == (rawPerms{}) {
			continue
		}
		sp := SubjectPerms{
			PodsWrite:   perms.podsWrite,
			PodsExec:    perms.podsExec,
			SecretsRead: perms.secretsRead,
			Impersonate: perms.impersonate,
		}
		for _, s := range b.Subjects {
			if s.Kind != "ServiceAccount" {
				continue
			}
			sns := s.Namespace
			if sns == "" {
				sns = b.Namespace
			}
			add(sns, s.Name, sp, b.Cluster, b.Namespace)
		}
	}
	return out
}

type rawPerms struct {
	podsWrite, podsExec, secretsRead, impersonate bool
}

func rulePerms(rules []PolicyRule) rawPerms {
	var p rawPerms
	for _, r := range rules {
		coreGroup := containsAny(r.APIGroups, "", "*")
		for _, res := range r.Resources {
			res = strings.ToLower(res)
			switch {
			case res == "*" && coreGroup:
				if hasWriteVerb(r.Verbs) {
					p.podsWrite = true
				}
				if hasVerb(r.Verbs, "get", "list", "*") {
					p.secretsRead = true
				}
				if hasVerb(r.Verbs, "create", "*") {
					p.podsExec = true
				}
			case res == "pods" && coreGroup:
				if hasWriteVerb(r.Verbs) {
					p.podsWrite = true
				}
			case (res == "pods/exec" || res == "pods/attach") && coreGroup:
				if hasVerb(r.Verbs, "create", "*") {
					p.podsExec = true
				}
			case res == "secrets" && coreGroup:
				if hasVerb(r.Verbs, "get", "list", "watch", "*") {
					p.secretsRead = true
				}
			}
		}
		// impersonation: verb "impersonate" on users/groups/serviceaccounts.
		if hasVerb(r.Verbs, "impersonate") {
			p.impersonate = true
		}
	}
	return p
}

func hasWriteVerb(verbs []string) bool {
	return hasVerb(verbs, "create", "delete", "patch", "update", "deletecollection", "*")
}

func hasVerb(verbs []string, want ...string) bool {
	for _, v := range verbs {
		lv := strings.ToLower(v)
		for _, w := range want {
			if lv == w {
				return true
			}
		}
	}
	return false
}

func containsAny(hay []string, want ...string) bool {
	for _, h := range hay {
		for _, w := range want {
			if h == w {
				return true
			}
		}
	}
	return false
}
