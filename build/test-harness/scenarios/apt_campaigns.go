package scenarios

// apt_campaigns.go registers marker simulations derived from the P-REDTEAM
// narrative catalogue. Every row executes the same bounded persistence-marker
// fixture. Operation names, phases and technique IDs are context, not executed
// attack stages or claims of technique/GPU coverage.

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"k8s.io/apimachinery/pkg/types"
)

type aptSpec struct {
	id, op    string
	product   string
	killChain []string
	ttps      []string
	gpu       bool
}

type aptCampaign struct {
	spec      aptSpec
	app       string
	targetUID types.UID
}

func (c *aptCampaign) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               c.spec.id + "-apt",
		Category:           core.CategoryR6Claimed,
		Source:             "P-REDTEAM narrative catalogue: " + c.spec.op,
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: c.spec.ttps,
		Realism:            core.RealismMarkerSimulation,
		Mechanism:          "deploy one target pod, exec a bounded in-container persistence marker, then poll marker and pod-UID survival",
		ClaimLimits:        "does not execute the named operation, narrative phases, ATT&CK/ATLAS techniques, GPU behavior, or prove live defensive success",
		OracleDescription:  "marker/target UID remains observable after the fixed response window",
		CleanupDescription: "delete objects owned by the scenario app label and verify teardown",
		R6Justification:    "Marker survival can measure disruption of this fixture only; off-surface narrative objectives and named techniques are not exercised.",
	}
}

func (c *aptCampaign) Setup(ctx context.Context, env *core.Env) error {
	c.app = "apt-" + c.spec.id
	if len(c.app) > 50 {
		c.app = c.app[:50]
	}
	_, err := deployTarget(ctx, env, c.app, "", nil)
	return err
}

func (c *aptCampaign) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, c.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	c.targetUID = pod.UID
	container := firstContainer(pod)
	cmds := plantBackdoor(ctx, env, pod.Name, container)
	if err := stimulusExec(ctx, env.Exec(ctx, pod.Name, container, []string{"sh", "-c", "test -f " + BackdoorMarkerPath})); err != nil {
		return core.AttackResult{Stages: []string{"plant bounded in-container persistence marker"}, Commands: cmds}, err
	}
	notes := map[string]string{"narrativeOperation": c.spec.op, "declaredTechniqueIDs": fmt.Sprintf("%v", c.spec.ttps), "narrativePhaseCount": fmt.Sprintf("%d", len(c.spec.killChain)), "realism": string(core.RealismMarkerSimulation)}
	env.Log.Logf("apt[%s]: executed persistence-marker simulation; narrative operation and mappings were not executed", c.spec.id)
	return core.AttackResult{Stages: []string{"plant bounded in-container persistence marker"}, Commands: cmds, Notes: notes}, nil
}

func (c *aptCampaign) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	observationPause(10 * time.Second)
	pod, err := observationTarget(ctx, env, c.app, c.targetUID)
	if err != nil {
		return core.OracleResult{}, err
	}
	markerPresent, err := observedMarker(ctx, env.Exec(ctx, pod.Name, firstContainer(pod), markerReadCommand(BackdoorMarkerPath)), BackdoorMarker)
	if err != nil {
		return core.OracleResult{}, err
	}
	survived := markerPresent && pod.UID == c.targetUID
	state := fmt.Sprintf("marker simulation [%s]: persistence marker retained past response window = %v", c.spec.product, survived)
	return core.OracleResult{Achieved: survived, ObservedState: state, Evidence: map[string]string{
		"product": c.spec.product, "narrativeOperation": c.spec.op, "narrativePhaseCount": fmt.Sprintf("%d", len(c.spec.killChain)), "realism": string(core.RealismMarkerSimulation), "originalPodUID": string(c.targetUID), "observedPodUID": string(pod.UID),
	}}, nil
}

func (c *aptCampaign) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, c.app)
}

func init() {
	for i := range aptTable {
		core.RegisterScenario(&aptCampaign{spec: aptTable[i]})
	}
}

var aptTable = []aptSpec{
	{id: "c1-c2-exfil", op: "APT data-theft operation", product: "k8s", gpu: false,
		killChain: []string{"recon: enumerate mounted secrets/env + reachable", "initial-access: inherit foothold from prior c1 s", "execution: stage + compress + (modeled) encrypt ", "persistence: re-touching sleeper keeps the C2 ch", "collection: aggregate staged data (T1074)", "exfil: low-and-slow chunked transfer over C2 ins", "impact: extortion marker (T1657)"},
		ttps:      []string{"T1041", "T1071", "T1071.001", "T1567", "T1567.002", "T1029", "T1030", "T1048", "T1560.001", "T1074"}},
	{id: "c1-credtheft-rbac", op: "Cloud-identity pivot", product: "k8s", gpu: false,
		killChain: []string{"recon: read SA token + scan env/secrets/configma", "cred-access: exfiltrate token out of pod (T1528)", "priv-esc: RBAC enumeration to map blast radius +", "lateral: replay valid token from outside pod aga", "collection: dump RBAC-permitted secrets (T1552.0", "persistence: create durable backdoor SA + cluste", "exfil: hand off to C2 channel (T1041)"},
		ttps:      []string{"T1552.007", "T1552.005", "T1552.001", "T1528", "T1078.001", "T1078.004", "T1069.003", "T1550.001", "T1136.003", "T1098.001"}},
	{id: "c1-escape-persist", op: "Container-breakout-to-host-persistence", product: "k8s", gpu: false,
		killChain: []string{"recon: enumerate caps/mounts/runtime socket/host", "initial-access: exec into target container (T105", "priv-esc+escape: runc-overwrite / privileged-mou", "persistence: host-substrate foothold — DaemonSet", "priv-esc: harvest node/kubelet kubeconfig SA cre", "lateral: pivot to co-tenant pods via shared host", "collection+exfil: hand off downstream (T1074/T10"},
		ttps:      []string{"T1610", "T1611", "T1068", "T1543.005", "T1053.003", "T1525", "T1059.013", "T1082", "T1613", "T1552.005"}},
	{id: "c1-fast-attacker", op: "Smash-and-grab / fast-ransomware", product: "k8s", gpu: false,
		killChain: []string{"recon: pre-staged/offline enumeration (T1595)", "initial-access: exploit exposed service (T1190)", "execution: immediate impact — fast exfil / encry", "impact: objective completed before any rotation "},
		ttps:      []string{"T1190", "T1041", "T1486", "T1485", "T1496", "T1595"}},
	{id: "c1-heldout-cve", op: "True zero-day exploitation chain", product: "k8s", gpu: false,
		killChain: []string{"recon: fingerprint vulnerable component without ", "initial-access: exploit held-out CVE for RCE — n", "execution: drop silent foothold (T1059.013)", "persistence: in-pod + host re-seeder, no signatu", "priv-esc: second held-out primitive to escalate ", "lateral: spread to neighbors before a signature ", "collection+exfil: complete objective in the dete"},
		ttps:      []string{"T1190", "T1068", "T1543.005", "T1059.013", "T1595.002", "T1592", "T1021", "T1074", "T1041"}},
	{id: "c1-lateral", op: "East-west propagation", product: "k8s", gpu: false,
		killChain: []string{"recon: real network/service/DNS/port enumeration", "credential-access: reuse stolen SA token / harve", "lateral-move: authenticated reach to pod B (T102", "execution-in-B: run payload in B (T1609/T1610)", "persistence: foothold in B as a new pivot (T1543", "propagation: repeat to C, building a foothold gr", "collection: harvest B's secrets/data (T1074/T155"},
		ttps:      []string{"T1046", "T1018", "T1613", "T1550.001", "T1552.007", "T1021", "T1609", "T1610", "T1543.005", "T1074"}},
	{id: "c1-llm-adaptive", op: "THE centerpiece upgrade and the IP: replace the 1-D timing heuristic w", product: "k8s", gpu: false,
		killChain: []string{"recon: observe defender effects (rotation timing", "model: RL learns the observable-input->PX-rotati", "pre-position: place real foothold on a low-dispe", "execution+persistence: plant foothold on the dur", "adapt: re-train as PX physics re-ground (non-sta", "impact: maximize shaped reward (dwell/objective/"},
		ttps:      []string{"T1595", "T1543.005", "T1070.004", "T1036", "T1497", "T1027"}},
	{id: "c1-stealth-dweller", op: "Long-dwell stealth implant", product: "k8s", gpu: false,
		killChain: []string{"recon: passive read of mounted/visible context o", "execution: deploy dweller masquerading as a syst", "defense-evasion: no telemetry/logs/events + time", "persistence: durable substrate surviving replace", "priv-esc+lateral+collection: low-and-slow, flows", "exfil: paced trickle when objective complete (T1"},
		ttps:      []string{"T1070", "T1070.006", "T1036.005", "T1685", "T1564", "T1592", "T1082", "T1543.005", "T1041"}},
	{id: "c2-c2-disrupt", op: "Full APT C2 lifecycle", product: "k8s", gpu: false,
		killChain: []string{"recon: enumerate egress + locate C2 sink via /pr", "initial-access: establish jittered malleable bea", "execution: deliver heartbeats on a non-periodic ", "persistence: register fallback secondary beacon ", "lateral: multiplex channel keeping ConnCount~Req", "collection: stage data in pod /tmp", "exfil: drip chunks keeping BytesOut/BytesIn in [", "impact: K heartbeats delivered on one surviving "},
		ttps:      []string{"T1071.001", "T1573.001", "T1008", "T1105", "T1030", "T1041", "T1571", "T1102"}},
	{id: "c2-dwell-rotation", op: "Ransomware/APT dwell-maximization", product: "k8s", gpu: false,
		killChain: []string{"recon: enumerate container, downward API, identi", "initial-access: drop /tmp sleeper foothold (T154", "execution: spawn detached re-touch loop (livenes", "persistence: layer a rotation-surviving ConfigMa", "priv-esc: read mounted SA token for re-entry (T1", "collection: stage dwell telemetry (observed gaps", "impact: maximize real survival-to-eviction; laye"},
		ttps:      []string{"T1543.005", "T1053.005", "T1525", "T1552.001", "T1133", "T1078.003", "T1027"}},
	{id: "c2-lateral-disrupt", op: "East-west lateral movement", product: "k8s", gpu: false,
		killChain: []string{"recon: from A, connect-sweep ClusterIP range + A", "initial-access: reuse harvested SA token/app cre", "execution: drive staged multi-step exec in B (T1", "persistence: plant second-hop foothold in B (ret", "priv-esc: harvest B's mounted SA token if higher", "lateral: A->B->discover C (multi-hop, not single", "collection: enumerate B secrets/mounts", "impact: in-flight cross-pod command completes in"},
		ttps:      []string{"T1046", "T1613", "T1550.001", "T1021", "T1609", "T1552.001", "T1570", "T1078.003"}},
	{id: "c2-persistence-evict", op: "Detection-evasion + eviction-survival", product: "k8s", gpu: false,
		killChain: []string{"recon: enumerate pod + map the detector's flagga", "initial-access: plant /tmp sleeper foothold (T15", "execution: detached liveness loop with guardrail", "persistence: layer eviction-surviving substrate ", "priv-esc: harvest SA token for re-entry (T1552.0", "defense-evasion: minimize emitted signal + remov", "impact: race the emit-boundary — re-plant into t"},
		ttps:      []string{"T1543.005", "T1611", "T1059.013", "T1070.004", "T1480", "T1552.001", "T1078.003"}},
	{id: "c2-recon-window", op: "Reconnaissance-persistence", product: "k8s", gpu: false,
		killChain: []string{"recon: enumerate pods/services/endpoints/RBAC/no", "initial-access: pin re-entry on discovered ident", "execution: deploy cheap per-identity heartbeat p", "persistence: store the map in an owned ConfigMap", "priv-esc: flag mapped identities mounting privil", "collection: maintain the living map; re-recon in", "impact: >=K mapped identities still valid+usable"},
		ttps:      []string{"T1613", "T1046", "T1069", "T1526", "T1018", "T1580", "T1078.003"}},
	{id: "c2-stateful-training", op: "Critical-stateful-workload compromise", product: "both", gpu: false,
		killChain: []string{"recon: classify pod stateful (PVC + /work checkp", "initial-access: plant foothold in the training c", "execution: detached liveness loop", "persistence: write into PVC-backed /work (surviv", "priv-esc: harvest training-job SA", "collection: stage in-progress checkpoint for exf", "impact: foothold stays actionable OR defender's "},
		ttps:      []string{"T1543.005", "T1530", "T1005", "T1485", "T1486", "T1496", "T1552.001"}},
	{id: "c2-supplychain-foothold", op: "Software-supply-chain foothold", product: "k8s", gpu: false,
		killChain: []string{"recon: identify pull path + registry + fleet ima", "initial-access: poisoned base image with injecte", "execution: injected layer payload runs (Tampered", "persistence: poisoned image = persistence; impla", "priv-esc: injected layer reads SA token (T1552.0", "defense-evasion: flood target digest to drive Im", "impact: foothold survives past interval (re-pull"},
		ttps:      []string{"T1195.002", "T1204.003", "T1525", "T1610", "T1612", "T1552.001", "T1027.001"}},
	{id: "b-recon-lifetime", op: "Detector-independent recon-validity", product: "k8s", gpu: false,
		killChain: []string{"recon: map at-risk identity tuple (UID/IP/placem", "initial-access: pin foothold + re-entry on mappe", "execution: detached liveness loop", "persistence: maintain + refresh the recon map", "priv-esc: enumerate SA privilege of mapped ident", "collection: cheap UID polling to detect re-ident", "impact: pre-position on the LOWEST-exposure iden"},
		ttps:      []string{"T1590", "T1592", "T1078", "T1018", "T1613", "T1591"}},
	{id: "b-recon-lifetime-ai", op: "AI-asset recon-validity", product: "ai", gpu: false,
		killChain: []string{"recon: fingerprint served model + map endpoint p", "initial-access: fingerprint+endpoint map enables", "execution: backend-identity proxy polling on kin", "persistence: maintain the ML-recon map across th", "collection: stage model-fingerprint + endpoint m", "impact: map stays usable enabling downstream mod"},
		ttps:      []string{"T1590", "T1530", "T1078.004", "AML.T0007", "AML.T0006", "AML.T0040", "AML.T0035", "AML.T0024.002"}},
	{id: "e-dilution-fleet", op: "Budget-dilution + active physics-poisoning", product: "k8s", gpu: false,
		killChain: []string{"recon: enumerate fleet + identify move-cap (1/ti", "initial-access: compromise the high-value at-ris", "persistence: plant foothold on the at-risk asset", "defense-evasion: spawn high-EMR decoys (inflate ", "defense-evasion: flood the at-risk image digest ", "collection: poll at-risk recon validity vs decoy", "impact: at-risk recon stays valid (PX diverted) "},
		ttps:      []string{"T1590", "T1078", "T1496", "T1610", "T1613", "T1499.003"}},
	{id: "c3-admission-bypass", op: "Operator first does RECON of the admission posture using only in-pod L", product: "k8s", gpu: false,
		killChain: []string{"recon: enumerate webhook configs + PSA labels + ", "initial-access: low-priv workload SA with pods/c", "execution: submit policy-bypassing pod (hostPath", "priv-esc: read kubelet client cert + containerd ", "persistence: drop static-pod manifest into kubel", "lateral: kubelet cert reads cross-namespace secr", "collection: stage harvested secrets", "exfil/impact: low-and-slow exfil of secrets to C"},
		ttps:      []string{"T1613", "T1069.002", "T1610", "T1611", "T1068", "T1078.001", "T1543.005", "T1552.001", "T1552.004", "T1610.000"}},
	{id: "c3-cicd", op: "A SolarWinds/Codecov-class build-system compromise", product: "both", gpu: false,
		killChain: []string{"recon: read pipeline-runner SA token + mounted C", "initial-access: poisoned build dependency / comp", "execution: injected step tampers artifact AND si", "persistence: patch the pipeline definition itsel", "priv-esc: harvest runner deploy creds -> kubecon", "lateral: push signed-tampered image to registry ", "collection: stage CI secrets + signing key + dep", "exfil/impact: exfil to C2 sink; every post-compr"},
		ttps:      []string{"T1195.002", "T1213.003", "T1053.007", "T1525", "T1552.001", "T1552.004", "T1606.002", "T1554", "T1078.004", "T1041"}},
	{id: "c3-cryptomining", op: "A TeamTNT/Kinsing-class cryptojacking campaign that EVADES the very si", product: "both", gpu: false,
		killChain: []string{"recon: enumerate node CPU/GPU slack + namespaces", "initial-access: compromised image / exposed kube", "execution: deploy THROTTLED sub-threshold miner ", "priv-esc: SA token enumerates create-pod rights", "lateral: worm replicates many small sub-threshol", "persistence: respawner (cron/static-pod + extern", "collection: accrue CPU-seconds (and GPU-seconds ", "exfil/impact: sustained stolen compute fleet-wid"},
		ttps:      []string{"T1496.001", "T1613", "T1610", "T1059.013", "T1543.005", "T1053.003", "T1525", "AML.T0034", "AML.T0029"}},
	{id: "c3-imds-theft", op: "A Capital-One/ScarletEel-class IMDS-to-cloud-takeover", product: "both", gpu: false,
		killChain: []string{"recon: probe mock IMDS for instance role + enume", "initial-access: SSRF/app foothold reaches IMDS (", "cred-access: steal node/pod role STS token (T155", "priv-esc: sts:AssumeRole role-chain low->high pr", "persistence: create backdoor IAM access key / ro", "lateral: assumed role reads S3 model/data bucket", "collection: stage stolen model/secret bytes + lo", "exfil/impact: low-and-slow exfil to C2 sink insi"},
		ttps:      []string{"T1552.005", "T1528", "T1552.007", "T1078.004", "T1580", "T1098.001", "T1098.003", "T1530", "T1537", "T1041"}},
	{id: "c3-secrets-sprawl", op: "A real secrets-sprawl harvest-and-spray", product: "both", gpu: false,
		killChain: []string{"recon: enumerate all reachable secrets - mounts,", "initial-access: compromised low-priv pod with an", "collection-1/harvest: read every reachable secre", "execution/validate: credential-spray harvested s", "priv-esc: a harvested secret is a high-priv clou", "persistence: over-permissive mount re-created on", "lateral: validated secrets unlock sibling servic", "exfil/impact: bundle + low-and-slow exfil of har"},
		ttps:      []string{"T1552.001", "T1552.004", "T1552.007", "T1528", "T1078", "T1110.003", "T1530", "T1213", "T1041", "AML.T0055"}},
	{id: "c3-sidecar-inject", op: "A malicious mutating-webhook / poisoned-Deployment sidecar injection (", product: "both", gpu: false,
		killChain: []string{"recon: find namespaces with auto-inject mutating", "initial-access: compromise injector config / pat", "execution: injected sidecar steals main-containe", "priv-esc: abuse stolen SA token RBAC to read clu", "persistence: injection lives in spec/webhook -> ", "lateral: sidecar rides mesh mTLS identity to rea", "collection: stage stolen SA token + secrets", "exfil/impact: low-and-slow exfil via sidecar egr"},
		ttps:      []string{"T1610", "T1543.005", "T1525", "T1611", "T1195.002", "T1552.001", "T1552.004", "T1098.001", "T1071.001", "T1041"}},
	{id: "c3-supplychain", op: "A 3CX/XZ-Utils-class image supply-chain compromise", product: "both", gpu: false,
		killChain: []string{"recon: find widely-pulled base image / pushable ", "initial-access: publish tampered image with FORG", "execution: injected layer = dormant loader; on t", "persistence: every pull is backdoored; rotation ", "priv-esc: second-stage steals SA token + IMDS cr", "lateral: backdoored image spreads to every workl", "collection: stage stolen secrets/model", "exfil/impact: second-stage low-and-slow exfil to"},
		ttps:      []string{"T1195.002", "T1525", "T1204.003", "T1610", "T1612", "T1554", "T1606.002", "T1552.005", "T1071.001", "T1041"}},
	{id: "ai1-inference-manipulation", op: "APT-grade adversary-in-the-middle of the inference data plane", product: "ai", gpu: false,
		killChain: []string{"recon: enumerate inference Service/Endpoints + o", "initial-access: co-schedule a proxy sidecar via ", "execution: install in-path proxy rewriting compl", "persistence: bind intercept to STABLE external p", "privilege-escalation: harvest bearer tokens flow", "lateral-movement: pivot to adjacent model servic", "collection: mirror prompts/responses", "exfiltration: low-and-slow drip to C2 within the"},
		ttps:      []string{"T1557", "T1565.002", "T1525", "T1552", "T1041", "T1071.001", "AML.T0040", "AML.T0015", "AML.T0024", "AML.T0047"}},
	{id: "ai1-llm-jacking", op: "Cloud-cost-draining LLM-jacking ring (real 2024-2025 LLMjacking tradec", product: "both", gpu: false,
		killChain: []string{"recon: map inference endpoint + GPU nodes; probe", "initial-access: steal serving cred via IMDS chai", "execution: submit shadow-compute jobs accruing G", "persistence: fan out across many low-rarity deco", "privilege-escalation: reuse stolen serving cred ", "lateral-movement: jack sibling model endpoints w", "collection: meter accrued GPU-seconds across the", "impact: sustained GPU cost-drain / model DoS (T1"},
		ttps:      []string{"T1496.001", "T1496", "T1610", "T1059.013", "T1552.005", "T1528", "T1078.004", "AML.T0011", "AML.T0034", "AML.T0024.001"}},
	{id: "ai1-model-theft", op: "Functional model-weight/IP theft via held endpoint + distillation, the", product: "ai", gpu: false,
		killChain: []string{"recon: fingerprint model digest/endpoint/ModelID", "initial-access: obtain long-lived serving cred (", "execution: direct weights/digest pull (T1530) + ", "persistence: hold stable external endpoint with ", "privilege-escalation: pivot to model registry fo", "lateral-movement: enumerate sibling model endpoi", "collection: assemble replica weights + registry ", "exfiltration: chunked low-and-slow drip to C2 ov"},
		ttps:      []string{"T1530", "T1041", "T1567", "T1030", "T1071.001", "T1552.005", "AML.T0035", "AML.T0024.002", "AML.T0040", "AML.T0037"}},
	{id: "ai1-pillar03-panic-mutation", op: "This is the DEFENSE-VALIDATION scenario inverted into a real evasion t", product: "both", gpu: false,
		killChain: []string{"recon: map multi-node topology + identify 'clean", "initial-access: deliver malicious payload to mod", "execution: split foothold OFF the rotating pod o", "persistence: foothold on a substrate the panic-m", "privilege-escalation: pre-compromise the 'clean'", "lateral-movement: follow the relocated workload ", "collection: continue model-I/O tamper post-reloc", "impact: defeat clean-node relocation by owning t"},
		ttps:      []string{"T1565", "T1610", "T1059.013", "T1611", "T1612", "AML.T0051", "AML.T0020", "AML.T0031"}},
	{id: "ai1-prompt-injection", op: "Indirect prompt-injection escalating to durable control (real RAG/agen", product: "ai", gpu: false,
		killChain: []string{"recon: map retrieval/context sources + session-m", "initial-access: seed injection indirectly via po", "execution: injected instruction overrides behavi", "persistence: escalate override from per-session ", "privilege-escalation: injected instruction calls", "lateral-movement: contaminate shared cross-sessi", "collection: harvest data the overridden agent no", "impact: durable behavioral hijack across session"},
		ttps:      []string{"T1059.013", "T1565", "T1078", "AML.T0051", "AML.T0051.000", "AML.T0051.001", "AML.T0054", "AML.T0061"}},
	{id: "ai2-agent-excessive-agency", op: "Confused-deputy escalation that turns the agent into a durable interna", product: "ai", gpu: false,
		killChain: []string{"recon: enumerate agent tool registry + per-tool ", "initial-access: indirect injection makes the age", "execution: agent invokes a high-privilege tool i", "persistence: deputy grants durable capability on", "privilege-escalation: use minted token to escala", "lateral-movement: drive other tools/services wit", "collection: deputy harvests data via its over-br", "impact: durable internal operator foothold (AML."},
		ttps:      []string{"T1059.013", "T1078", "T1098", "T1543.005", "AML.T0053", "AML.T0048", "AML.T0054"}},
	{id: "ai2-agent-injection-to-persistence", op: "The canonical kill-chain BRIDGE: indirect injection -> durable persist", product: "ai", gpu: false,
		killChain: []string{"recon: rank writable substrates by rotation-surv", "initial-access: indirect injection lands a persi", "execution: injection runs a persistence primitiv", "persistence: plant backdoor on most-survivable s", "privilege-escalation: surviving backdoor re-esta", "lateral-movement: re-pivot from the re-establish", "collection: stage data via agent tools", "exfiltration: drip via tools below the flow band"},
		ttps:      []string{"T1059.013", "T1543.005", "T1546", "AML.T0051", "AML.T0054", "AML.T0061"}},
	{id: "ai2-agent-memory-contamination", op: "Cross-session/cross-tenant memory poisoning for durable, self-propagat", product: "ai", gpu: false,
		killChain: []string{"recon: identify cross-session memory substrate +", "initial-access: indirect delivery via a poisoned", "execution: write adversarial cross-session memor", "persistence: anchor on rotation-surviving substr", "privilege-escalation: contaminated memory steers", "lateral-movement: poison bleeds into other tenan", "collection: biased outputs harvested", "impact: durable, self-propagating cross-session "},
		ttps:      []string{"T1059.013", "T1565", "T1606", "AML.T0051", "AML.T0070", "AML.T0054", "AML.T0061"}},
	{id: "ai2-agent-rogue-tool-persistence", op: "Durable supply-chain-style rogue tool in the agent's tool registry (ro", product: "ai", gpu: false,
		killChain: []string{"recon: enumerate tool-registry source-of-truth +", "initial-access: register rogue tool via deputy/i", "execution: agent calls the rogue tool (exfil/cre", "persistence: anchor in external catalog / rogue ", "privilege-escalation: rogue tool mints creds / c", "lateral-movement: drive other services via the r", "collection: exfil via the rogue tool", "impact: durable malicious capability in the agen"},
		ttps:      []string{"T1059.013", "T1195", "T1543.005", "T1554", "AML.T0053", "AML.T0048", "AML.T0020"}},
	{id: "ai2-excessive-agency", op: "OWASP LLM06 weaponized into a privilege-escalation pivot", product: "both", gpu: false,
		killChain: []string{"recon: catalog over-privileged agent tools", "initial-access: indirect injection induces the o", "execution: agent invokes high-privilege tool (T1", "persistence: durable grant on rotation-surviving", "privilege-escalation: escalate RBAC with minted ", "lateral-movement: drive privileged APIs cluster-", "collection: harvest via over-broad tools", "impact: cluster-level escalation from an app-lay"},
		ttps:      []string{"T1059.013", "T1078", "T1098", "T1552.005", "AML.T0053", "AML.T0048", "AML.T0054"}},
	{id: "ai2-unbounded-consumption", op: "Cost-amplification / economic-DoS at fleet scale (wallet drain)", product: "both", gpu: false,
		killChain: []string{"recon: probe per-request cost amplification + ro", "initial-access: many distributed low-and-slow cl", "execution: aggregate accrual above budget via am", "persistence: fan out across image-flooded decoy ", "privilege-escalation: reuse stolen serving cred ", "lateral-movement: multiply drain across sibling ", "collection: meter aggregate accrued cost", "impact: sustained wallet-drain / availability Do"},
		ttps:      []string{"T1496.001", "T1499", "T1499.004", "T1078.004", "AML.T0034", "AML.T0029", "AML.T0024.002"}},
	{id: "ai2-query-extraction", op: "Query-based model extraction / distillation to a functional clone (the", product: "ai", gpu: false,
		killChain: []string{"recon: fingerprint model; confirm stable externa", "initial-access: obtain serving cred + query foot", "execution: diverse active-learning query budget ", "persistence: hold stable external endpoint; dist", "privilege-escalation: reuse cred for higher quer", "lateral-movement: extract sibling models to buil", "collection: assemble replica weights", "exfiltration: drip replica to C2 below the flow "},
		ttps:      []string{"T1530", "T1041", "T1567", "AML.T0024.000", "AML.T0024.002", "AML.T0035", "AML.T0040"}},
	{id: "ai2-sensitive-info-disclosure", op: "Sensitive-data disclosure escalated into a usable credential foothold", product: "ai", gpu: false,
		killChain: []string{"recon: probe reachable secrets in context + thei", "initial-access: elicit in-request disclosure via", "execution: capture the leaked credential", "persistence: copy the cred to an attacker-contro", "privilege-escalation: replay the leaked cred aga", "lateral-movement: reach data stores / sibling se", "collection: pull sensitive data", "exfiltration: drip to C2 below the flow band (T1"},
		ttps:      []string{"T1530", "T1552", "T1078", "T1041", "AML.T0057", "AML.T0024.000"}},
	{id: "ai2-system-prompt-leakage", op: "System-prompt extraction yielding embedded secrets + guardrail bypass ", product: "ai", gpu: false,
		killChain: []string{"recon: probe for a credential/guardrail-bearing ", "initial-access: extract the system prompt in-req", "execution: parse embedded creds + guardrail/tool", "persistence: copy embedded cred to an external s", "privilege-escalation: replay embedded cred (chai", "lateral-movement: pivot with the replayed cred", "collection: harvest with standing access", "exfiltration: drip to C2 below the band"},
		ttps:      []string{"T1552", "T1530", "T1078", "T1041", "AML.T0056", "AML.T0051"}},
	{id: "ai2-co-location-cross-tenant", op: "APT-grade cross-tenant GPU co-residency tenant-escape,", product: "both", gpu: true,
		killChain: []string{"recon: enumerate GPU scheduler, MIG geometry, na", "initial-access: deploy benign placement-probe te", "execution: brute-force placement until co-reside", "priv-esc: drive cross-tenant timing/contention t", "persistence: pin co-resident slot via PDB+priori", "lateral: pivot via shared node to victim IMDS / ", "collection: reconstruct model fingerprint + memo", "exfil: stage + low-and-slow egress of reconstruc"},
		ttps:      []string{"T1613", "T1580", "T1610", "T1525", "T1552.007", "T1078.004", "T1041", "AML.T0007", "AML.T0024.001", "AML.T0024.002"}},
	{id: "ai2-gpu-side-channel", op: "Model-extraction via GPU microarchitectural side-channel, run as a pat", product: "ai", gpu: true,
		killChain: []string{"recon: locate victim serving endpoint + MIG/MPS ", "initial-access: acquire co-resident measurement ", "execution: timing/contention probes leak per-lay", "execution: query-based extraction fits surrogate", "persistence: cache partial measurements in data-", "collection: assemble architecture + weight appro", "exfil: exfil stolen surrogate model (T1041/AML.T", "impact: IP theft / competitor advantage (AML.T00"},
		ttps:      []string{"T1613", "T1610", "T1530", "T1041", "AML.T0007", "AML.T0024", "AML.T0024.001", "AML.T0035", "AML.T0040", "AML.T0044"}},
	{id: "ai2-data-model-poisoning", op: "Training-data + model poisoning supply-chain attack (real tradecraft: ", product: "both", gpu: false,
		killChain: []string{"recon: map training/fine-tune pipeline, dataset ", "initial-access: typosquat/dependency-confusion a", "execution: inject backdoored training data -> tr", "execution: mutate served registry digest to troj", "persistence: backdoor in weights survives rotati", "priv-esc: trigger fires on attacker inputs (AML.", "impact: targeted misclassification / harmful out"},
		ttps:      []string{"T1213", "T1195.001", "T1199", "T1078", "T1565.001", "T1525", "AML.T0003", "AML.T0019", "AML.T0020", "AML.T0018"}},
	{id: "ai2-embedding-store-tampering", op: "Vector-index tampering for persistent RAG manipulation + retrieval-dri", product: "ai", gpu: false,
		killChain: []string{"recon: discover vector store, write path, auth, ", "initial-access: obtain store write access via ov", "execution: mutate vectors so attacker docs win t", "persistence: tampered vector lives in data-plane", "priv-esc: poisoned doc injects tool-call/secret-", "collection: retrieved poisoned context gathers s", "exfil: each query fire leaks context out of band"},
		ttps:      []string{"T1613", "T1530", "T1078", "T1552.001", "T1190", "T1565", "AML.T0007", "AML.T0020", "AML.T0024", "AML.T0024.001"}},
	{id: "ai2-embedding-vector-weakness", op: "Exploitation of embedding-space weaknesses for cross-tenant/cross-cont", product: "ai", gpu: false,
		killChain: []string{"recon: profile embedding model, distance metric,", "initial-access: gain query access via normal use", "execution: craft adversarial-similarity queries ", "priv-esc: embedding-inversion reconstructs sourc", "persistence: colliding/tampered vector persists ", "collection: crafted-query sweeps harvest cross-c", "exfil: invert embeddings to plaintext + egress (", "impact: cross-tenant data disclosure (AML.T0048)"},
		ttps:      []string{"T1613", "T1078", "T1530", "T1565", "T1213", "T1041", "AML.T0002", "AML.T0007", "AML.T0044", "AML.T0024"}},
	{id: "ai2-kvcache-poisoning-cross-session-leak", op: "KV-cache cross-session leakage + prefix-cache poisoning on a shared in", product: "ai", gpu: true,
		killChain: []string{"recon: identify serving stack, prefix/KV-cache +", "initial-access: obtain normal inference session ", "execution: poison shared KV/prefix cache to serv", "persistence: re-seed poisoned prefix each reques", "priv-esc: harvest leaked cross-session tokens (o", "collection: assemble leaked PII/secrets across s", "exfil: stream harvested content out (T1041)", "impact: cross-tenant confidentiality breach (AML"},
		ttps:      []string{"T1613", "T1078", "T1530", "T1565", "T1041", "AML.T0007", "AML.T0024", "AML.T0024.001", "AML.T0051", "AML.T0035"}},
	{id: "ai2-malicious-model-artifact", op: "Malicious model artifact (pickle/safetensors/Lambda-layer deserializat", product: "both", gpu: false,
		killChain: []string{"recon: identify auto-loaded model artifacts + th", "initial-access: plant malicious artifact in a tr", "execution: deserialization RCE in loader pod (T1", "persistence: drop sleeper / write second-stage t", "priv-esc: steal SA token / IMDS creds from loade", "lateral: pivot with SA token to other namespaces", "collection: stage model weights + secrets (AML.T", "exfil: egress staged artifacts before proactiveF"},
		ttps:      []string{"T1613", "T1195.002", "T1204.003", "T1059", "T1543.005", "T1525", "T1552.007", "T1078.004", "T1021", "T1041"}},
	{id: "ai2-mcp-rogue-server", op: "Rogue MCP server impersonation/hijack for agent-supply-chain compromis", product: "ai", gpu: false,
		killChain: []string{"recon: enumerate agent MCP servers, tool-discove", "initial-access: stand up rogue MCP + bind agent ", "execution: rogue server serves malicious tool ma", "persistence: agent holds rogue DNS binding (surv", "priv-esc: rogue tool invokes high-privilege acti", "lateral: rogue tool pivots to internal services ", "collection: rogue tool exfils agent context + cr", "exfil: egress harvested data (T1041/AML.T0048)"},
		ttps:      []string{"T1613", "T1590", "T1557", "T1199", "T1059.013", "T1021", "T1041", "AML.T0007", "AML.T0010.002", "AML.T0051"}},
	{id: "ai2-mcp-tool-poisoning", op: "MCP tool-poisoning via malicious tool description/schema (real tradecr", product: "ai", gpu: false,
		killChain: []string{"recon: enumerate tool registry, serving MCP serv", "initial-access: gain manifest write/serve contro", "execution: poison tool description with hidden d", "persistence: write poisoned tool into agent-tool", "priv-esc: poisoned tool steers agent to over-pri", "collection: instructed actions read secrets / ga", "exfil: poisoned tool exfils harvested data (T104", "impact: durable agent-behavior subversion (AML.T"},
		ttps:      []string{"T1613", "T1195", "T1199", "T1059.013", "T1041", "AML.T0007", "AML.T0010.002", "AML.T0051", "AML.T0053", "AML.T0024"}},
	{id: "ai2-mcp-tool-response-injection", op: "MCP tool-RESPONSE injection -> persistent agent-memory contamination (", product: "ai", gpu: false,
		killChain: []string{"recon: map tool-result ingestion + memory archit", "initial-access: control a tool response via back", "execution: inject directives into tool result th", "persistence: write contamination to agent-memory", "priv-esc: contaminated memory drives privileged ", "collection: memory-driven data gathering each se", "exfil: memory-instructed exfil per session (T104", "impact: cross-session durable agent compromise ("},
		ttps:      []string{"T1613", "T1557", "T1565", "T1059.013", "T1041", "AML.T0007", "AML.T0010.002", "AML.T0051", "AML.T0054", "AML.T0024"}},
	{id: "ai2-poisoned-model-registry", op: "Poisoned model registry — malicious model/version pushed to the regist", product: "both", gpu: false,
		killChain: []string{"recon: map registry push access, signing/admissi", "initial-access: obtain push access via stolen CI", "execution: push backdoored version + mutate mani", "persistence: poison in registry; re-push racing ", "priv-esc: backdoor fires across every auto-pulli", "collection: backdoor exfils inference data / har", "exfil: egress harvested data (T1041)", "impact: fleet-wide compromise from one push (AML"},
		ttps:      []string{"T1613", "T1078", "T1199", "T1195", "T1195.002", "T1525", "T1041", "AML.T0010", "AML.T0010.002", "AML.T0003"}},
	{id: "ai2-rag-retrieval-poisoning", op: "RAG corpus poisoning -> persistent indirect-prompt-injection + retriev", product: "ai", gpu: false,
		killChain: []string{"recon: discover corpus, ingestion pipeline, chun", "initial-access: plant malicious doc via ingested", "execution: poisoned doc with indirect injection ", "persistence: poisoned doc in data-plane corpus s", "priv-esc: injection instructs app to call intern", "collection: each retrieval gathers surrounding s", "exfil: context exfiltrated out of band per query", "impact: durable query-triggered manipulation + o"},
		ttps:      []string{"T1613", "T1530", "T1213", "T1078", "T1190", "T1199", "T1565", "T1195", "T1041", "AML.T0007"}},
	{id: "ai2-tampered-inference-base-image", op: "Tampered inference base image — a poisoned serving-image layer as a du", product: "both", gpu: false,
		killChain: []string{"recon: identify serving image, registry/tag, bui", "initial-access: inject malicious layer in CI / m", "execution: serving pods run injected layer at st", "persistence: tamper in image ref; rotation re-pu", "priv-esc: injected layer steals SA token / IMDS ", "lateral: pivot with stolen creds to other namesp", "collection: stage model weights + secrets (AML.T", "exfil: egress staged data (T1041/AML.T0048)"},
		ttps:      []string{"T1613", "T1612", "T1195.002", "T1525", "T1204.003", "T1552.007", "T1078.004", "T1041", "AML.T0010", "AML.T0010.001"}},
}
