/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 *
 * Real CEL SEMANTIC evaluation of the SHIPPED ValidatingAdmissionPolicy expressions (parsed
 * from config/admission/codeexec-ephemeral-vap.yaml) with cel-go: the compliant debugger and
 * custom-inject requests are ALLOWED (every validation true), and each isolated violation is
 * DENIED by its own validation (attributable). This exercises the expressions, not string
 * matches. It is NOT real API-server admission (that is L3) — it evaluates the same CEL text
 * the API server would, over crafted object/oldObject/request/variables activations.
 */

package codeexec

import (
	"context"
	"testing"

	"github.com/google/cel-go/cel"
)

func celEnv(t *testing.T) *cel.Env {
	t.Helper()
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
		cel.Variable("variables", cel.DynType),
	)
	if err != nil {
		t.Fatalf("cel env: %v", err)
	}
	return env
}

func celEval(t *testing.T, env *cel.Env, expr string, act map[string]any) any {
	t.Helper()
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("compile %q: %v", expr, iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program %q: %v", expr, err)
	}
	out, _, err := prg.Eval(act)
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	return out.Value()
}

// policyExprs pulls the shipped variable + validation expressions from the config manifest.
func policyExprs(t *testing.T) (vars map[string]string, validations []string) {
	t.Helper()
	raw := repoFile(t, "config/admission/codeexec-ephemeral-vap.yaml")
	p, _, err := ParseContract([]byte(raw))
	if err != nil {
		t.Fatalf("parse config manifest: %v", err)
	}
	vars = map[string]string{}
	for _, v := range p.Spec.Variables {
		vars[v.Name] = v.Expression
	}
	for _, val := range p.Spec.Validations {
		validations = append(validations, val.Expression)
	}
	if len(validations) != 9 || len(vars) != 3 {
		t.Fatalf("unexpected manifest shape: %d validations, %d variables", len(validations), len(vars))
	}
	return vars, validations
}

const managerSAName = "system:serviceaccount:phorvex-system:phorvex-phorvex-manager"
const approvedImg = "busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"

func hardenedSC() map[string]any {
	return map[string]any{
		"privileged": false, "allowPrivilegeEscalation": false, "runAsNonRoot": true,
		"runAsUser": int64(65534), "runAsGroup": int64(65534), "readOnlyRootFilesystem": true,
		"capabilities":   map[string]any{"drop": []any{"ALL"}},
		"seccompProfile": map[string]any{"type": "RuntimeDefault"},
	}
}

func debuggerContainer() map[string]any {
	return map[string]any{"name": "phorvex-debugger", "image": approvedImg, "securityContext": hardenedSC(), "targetContainerName": "web", "command": []any{"sleep", "300"}}
}

func customContainer() map[string]any {
	c := map[string]any{"name": "phorvex-custom", "image": approvedImg, "securityContext": hardenedSC()}
	c["command"] = []any{"sh", "-c"}
	c["args"] = []any{"echo phorvex-custom-action; sleep 1"}
	return c
}

// activation builds object/oldObject/request/variables for a request that ADDS `containers`
// (oldObject has none — first injection), submitted by `user`.
func activation(t *testing.T, env *cel.Env, vars map[string]string, user string, containers ...map[string]any) map[string]any {
	t.Helper()
	ecs := make([]any, len(containers))
	for i, c := range containers {
		ecs[i] = c
	}
	object := map[string]any{"spec": map[string]any{"ephemeralContainers": ecs, "containers": []any{map[string]any{"name": "web"}}}}
	oldObject := map[string]any{"spec": map[string]any{}} // no ephemeralContainers => all are new
	base := map[string]any{"object": object, "oldObject": oldObject}
	managerSA := celEval(t, env, vars["managerSA"], base)
	approvedImage := celEval(t, env, vars["approvedImage"], base)
	newContainers := celEval(t, env, vars["newContainers"], base)
	return map[string]any{
		"object":    object,
		"oldObject": oldObject,
		"request":   map[string]any{"userInfo": map[string]any{"username": user}},
		"variables": map[string]any{"managerSA": managerSA, "approvedImage": approvedImage, "newContainers": newContainers},
	}
}

func allValidationsTrue(t *testing.T, env *cel.Env, validations []string, act map[string]any) (allTrue bool, firstFalse int) {
	t.Helper()
	firstFalse = -1
	allTrue = true
	for i, expr := range validations {
		if celEval(t, env, expr, act).(bool) != true {
			allTrue = false
			if firstFalse < 0 {
				firstFalse = i
			}
		}
	}
	return
}

func TestCELAllowsCompliantRequests(t *testing.T) {
	env := celEnv(t)
	vars, validations := policyExprs(t)
	for _, tc := range []struct {
		name string
		c    map[string]any
	}{
		{"debugger", debuggerContainer()},
		{"custom-inject", customContainer()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			act := activation(t, env, vars, managerSAName, tc.c)
			if ok, ff := allValidationsTrue(t, env, validations, act); !ok {
				t.Fatalf("compliant %s must be ALLOWED; validation[%d] denied", tc.name, ff)
			}
		})
	}
	// A request that ADDS NOTHING (no new containers) passes (migration / non-injection).
	act := activation(t, env, vars, "someone:else")
	if ok, _ := allValidationsTrue(t, env, validations, act); !ok {
		t.Fatal("a request adding no new ephemeral container must be allowed")
	}
}

func TestCELDeniesEachViolationIsolated(t *testing.T) {
	env := celEnv(t)
	vars, validations := policyExprs(t)
	// validations index -> the rule expected to deny (in shipped order):
	// 0 identity, 1 name, 2 image, 3 securityContext core, 4 capabilities, 5 seccomp,
	// 6 securityContext-extra, 7 forbidden fields, 8 command/args.
	cases := []struct {
		name    string
		user    string
		mutate  func(map[string]any)
		wantIdx int
	}{
		{"wrong-identity", "attacker:evil", func(map[string]any) {}, 0},
		{"wrong-name", managerSAName, func(c map[string]any) { c["name"] = "evil" }, 1},
		{"wrong-image", managerSAName, func(c map[string]any) { c["image"] = "busybox:1.36" }, 2},
		{"privileged", managerSAName, func(c map[string]any) { c["securityContext"].(map[string]any)["privileged"] = true }, 3},
		{"root-user", managerSAName, func(c map[string]any) { c["securityContext"].(map[string]any)["runAsUser"] = int64(0) }, 3},
		{"caps-not-dropped", managerSAName, func(c map[string]any) {
			c["securityContext"].(map[string]any)["capabilities"] = map[string]any{"drop": []any{}}
		}, 4},
		{"seccomp-unconfined", managerSAName, func(c map[string]any) {
			c["securityContext"].(map[string]any)["seccompProfile"] = map[string]any{"type": "Unconfined"}
		}, 5},
		{"apparmor-extra", managerSAName, func(c map[string]any) {
			c["securityContext"].(map[string]any)["appArmorProfile"] = map[string]any{"type": "Unconfined"}
		}, 6},
		{"procmount-extra", managerSAName, func(c map[string]any) { c["securityContext"].(map[string]any)["procMount"] = "Unmasked" }, 6},
		{"tty-set", managerSAName, func(c map[string]any) { c["tty"] = true }, 7},
		{"env-set", managerSAName, func(c map[string]any) { c["env"] = []any{map[string]any{"name": "X", "value": "y"}} }, 7},
		{"debugger-with-command", managerSAName, func(c map[string]any) { c["command"] = []any{"sh"} }, 8},
		{"debugger-wrong-duration", managerSAName, func(c map[string]any) { c["command"] = []any{"sleep", "600"} }, 8},
		{"debugger-target-absent", managerSAName, func(c map[string]any) { c["targetContainerName"] = "missing" }, 7},
		{"debugger-target-empty", managerSAName, func(c map[string]any) { c["targetContainerName"] = "" }, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := debuggerContainer()
			tc.mutate(c)
			act := activation(t, env, vars, tc.user, c)
			if celEval(t, env, validations[tc.wantIdx], act).(bool) {
				t.Fatalf("%s: validation[%d] must DENY but returned true", tc.name, tc.wantIdx)
			}
			// And the overall request is not allowed.
			if ok, _ := allValidationsTrue(t, env, validations, act); ok {
				t.Fatalf("%s: request must be denied overall", tc.name)
			}
		})
	}
	// custom-inject with wrong args is denied by the command rule (index 8).
	t.Run("custom-wrong-args", func(t *testing.T) {
		c := customContainer()
		c["args"] = []any{"echo pwned"}
		act := activation(t, env, vars, managerSAName, c)
		if celEval(t, env, validations[8], act).(bool) {
			t.Fatal("custom-inject wrong args must be denied by the command rule")
		}
	})
}

// TestCELNewContainersIgnoresPreexisting proves the oldObject boundary: a container already in
// oldObject is NOT re-validated (migration), while a genuinely new one still is.
func TestCELNewContainersIgnoresPreexisting(t *testing.T) {
	env := celEnv(t)
	vars, _ := policyExprs(t)
	preexisting := map[string]any{"name": "legacy", "image": "whatever:latest"}
	added := debuggerContainer()
	// oldObject already has "legacy"; object has "legacy" + a new debugger. Only the debugger is new.
	object := map[string]any{"spec": map[string]any{"ephemeralContainers": []any{preexisting, added}}}
	oldObject := map[string]any{"spec": map[string]any{"ephemeralContainers": []any{preexisting}}}
	nc := celEval(t, env, vars["newContainers"], map[string]any{"object": object, "oldObject": oldObject})
	// Evaluate size() over the computed list via CEL (its runtime list type is not []any).
	sz := celEval(t, env, "size(variables.newContainers)", map[string]any{"variables": map[string]any{"newContainers": nc}})
	if sz.(int64) != 1 {
		t.Fatalf("only the newly-added container must be in newContainers, got size %v", sz)
	}
	// And a request whose only container is pre-existing yields an EMPTY new set.
	obj2 := map[string]any{"spec": map[string]any{"ephemeralContainers": []any{preexisting}}}
	nc2 := celEval(t, env, vars["newContainers"], map[string]any{"object": obj2, "oldObject": oldObject})
	sz2 := celEval(t, env, "size(variables.newContainers)", map[string]any{"variables": map[string]any{"newContainers": nc2}})
	if sz2.(int64) != 0 {
		t.Fatalf("a pre-existing-only request must yield no new containers, got size %v", sz2)
	}
	_ = context.Background()
}
