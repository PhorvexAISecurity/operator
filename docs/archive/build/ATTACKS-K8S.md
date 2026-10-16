# Kubernetes Attack Scenario Catalog (ATTACKS-K8S)

The 18 attack scenarios exercised by the Phoenix / Phorvex attack-benchmark
harness (`build/test-harness/scenarios/`, one self-registering file each). Each is
scored against a **concrete observable oracle** and carries an **honest,
code-grounded R6-response verdict**.

## R6-response legend (grounded in `build/phoenix-extended/api/v1beta1`)

The Phoenix response is **reactive and exact-match**: in default Exact mode the
matcher compares the 3-string projection `{Type, ThreatLevel, Source}` of a
strategy Rule against an inbound `SecurityEvent` CR, then runs a pod-level action
(delete | disable | quarantine | rotate | warmSwap | regenerate | nodeRotate) on
the AMTD `PodSelector`-matched pods. It **requires** (a) an external emitter
(Falco / KubeArmor / Prometheus) to create a normalized SecurityEvent, and (b) a
matching strategy entry. Phoenix has **no** admission controller, **no** live
image-provenance / registry enforcement, **no** CI/CD hook, and **no** IMDS /
secrets-mount visibility. These facts drive every verdict below.

| Tag | Meaning |
|---|---|
| **R6-COVERS** | a genuine reactive matcher path can disrupt the oracle (typically emitter-dependent, but a real path exists). |
| **R6-PARTIAL** | Phoenix disrupts only **opportunistically** / as a side effect of rotation, not by detection — the marketing claim overshoots the implemented code. |
| **R6-CANNOT-RESPOND** | no matcher path applies; rotation cannot touch the oracle (a genuine Phorvex differentiator). |

---

## Summary table

| # | Scenario | Category | R6 verdict | ATT&CK technique IDs | Oracle (one-line) |
|---|---|---|---|---|---|
| 1 | c1-escape-persist | ClassicChain | **R6-PARTIAL** | T1610, T1611, T1068, T1543.005, T1525, T1059.013 | Backdoor sleeper alive >= N s post-Execute AND marker process seen again after a forced pod restart (true persistence). |
| 2 | c1-lateral | ClassicChain | **R6-PARTIAL** | T1046, T1613, T1550.001, T1609, T1059.013 | A second target pod reached over the network AND a command executed inside it (marker file in target pod). |
| 3 | c1-credtheft-rbac | ClassicChain | **R6-CANNOT-RESPOND** | T1552.007, T1528, T1552.001, T1078.001, T1069, T1550.001 | A mounted SA token is read and used SUCCESSFULLY against the API server from outside the pod (HTTP 200 + data). |
| 4 | c1-c2-exfil | ClassicChain | **R6-PARTIAL** | T1041, T1071, T1567, T1029, T1048 | >= N bytes received and counted by the in-cluster MOCK C2/exfil sink. |
| 5 | c1-stealth-dweller | ClassicChain | **R6-PARTIAL** | T1070, T1036.005, T1685, T1564 | Dweller alive after dwell window W AND **zero** SecurityEvent CRs created (survival purely by stealth). |
| 6 | c2-dwell-rotation | R6Claimed | **R6-COVERS** | T1543.005, T1525, T1133, T1078.003 | Attacker dwell = wall-clock seconds a foothold survives; achieved iff dwell exceeds the rotation interval. |
| 7 | c2-persistence-evict | R6Claimed | **R6-COVERS** | T1543.005, T1611, T1059.013, T1070 | After a SecurityEvent for the pod, malicious process gone within T (old pod UID terminated AND marker absent in replacement). |
| 8 | c2-recon-window | R6Claimed | **R6-PARTIAL** | T1613, T1046, T1069, T1526 | Enumerate target IP+identity at t0, re-validate after one interval; denied iff the mapped IP/identity is no longer valid. |
| 9 | c2-lateral-disrupt | R6Claimed | **R6-PARTIAL** | T1550.001, T1046, T1609, T1021 | Mid-move A->B disrupted iff the in-flight session breaks AND the command in B fails because A or B was rotated. |
| 10 | c2-c2-disrupt | R6Claimed | **R6-PARTIAL** | T1071, T1573, T1008, T1105 | A persistent beacon disrupted iff its session is severed by a rotation before delivering K heartbeats. |
| 11 | c2-supplychain-foothold | R6Claimed | **R6-PARTIAL** | T1525, T1204.003, T1610, T1543.005 | Malicious-image foothold persists iff its marker process survives past the rotation interval. |
| 12 | c3-supplychain | ModernUnsupported | **R6-CANNOT-RESPOND** | T1525, T1204.003, T1610, T1612 | A pod pulls a tampered image from the MOCK registry AND the tampered payload runs (injected-layer marker written). |
| 13 | c3-cicd | ModernUnsupported | **R6-CANNOT-RESPOND** | T1053.007, T1610, T1525, T1204.003 | A MOCK in-ns pipeline runner executes an injected step / tampers a build artifact (injected marker in the output volume). |
| 14 | c3-sidecar-inject | ModernUnsupported | **R6-CANNOT-RESPOND** | T1610, T1543.005, T1525, T1611 | An injected sidecar/init container runs with its granted access (reads shared volume / SA token and writes proof). |
| 15 | c3-admission-bypass | ModernUnsupported | **R6-CANNOT-RESPOND** | T1610, T1611, T1068, T1078.001 | A deliberately policy-violating pod (privileged/hostPath, sandbox ns) is admitted, reaches Running, and exercises the violation. |
| 16 | c3-cryptomining | ModernUnsupported | **R6-PARTIAL** | T1496.001, T1610, T1059.013 | A CPU-bounded miner stand-in accrues >= C CPU-seconds within a window before any rotation. |
| 17 | c3-imds-theft | ModernUnsupported | **R6-CANNOT-RESPOND** | T1552.005, T1528, T1552.007, T1078.004 | The pod retrieves a FAKE cloud cred from the MOCK 169.254.169.254 stand-in AND uses it successfully vs the mock cloud API. |
| 18 | c3-secrets-sprawl | ModernUnsupported | **R6-CANNOT-RESPOND** | T1552.001, T1552.007, T1528, T1078 | A secret value is read from an over-permissive mount/env AND used successfully (authenticates to the mock sink/API). |

---

## Detail

### 1. c1-escape-persist — R6-PARTIAL
- **Category:** ClassicChain.
- **Source:** Task SCENARIO SET Cat1; ADA paper III.C "Container Escape & Privilege Escalation (runc CVE-2019-5736)"; AMTD-AI-infra Case Study SolarWinds.
- **ATT&CK:** T1610, T1611, T1068, T1543.005, T1525, T1059.013.
- **Oracle (observable):** A backdoor process (a sleeper `sh` loop the attacker writes via an emulated runc-overwrite file-clobber against the OWNED target container) is alive >= N seconds post-Execute **AND** a named marker process is observed again after a forced pod restart (true persistence, not just survival).
- **Honest R6 justification:** Phoenix has no escape detector itself; it acts ONLY if an emitter (Falco) raises a SecurityEvent normalized to `{Type:panic}` and a strategy Rule matches it -> rotate/delete the pod, which DOES sever an in-memory backdoor on the next cycle (matcher.go exact path + RotateAction). So if-and-only-if the panic emitter+strategy exist is the persistence oracle broken; with no emitter wired (timer-only `d-r6blindtimer`) the backdoor survives until the next blind rotation. Reactive, exact-match, emitter-dependent.

### 2. c1-lateral — R6-PARTIAL
- **Category:** ClassicChain.
- **Source:** Task SCENARIO SET Cat1; ADA paper II "Lateral Movement: long-lived container identities"; Phoenix-K8s product "Temporal Network Policies / lateral movement prevention".
- **ATT&CK:** T1046, T1613, T1550.001, T1609, T1059.013.
- **Oracle (observable):** From a compromised source pod, a second target pod is reached over the network **AND** a command is executed inside it (observable marker file written in the target pod's filesystem / unique stdout captured via exec).
- **Honest R6 justification:** Phoenix does not inspect traffic; lateral movement is disrupted only as a SIDE EFFECT of rotating the source/target pod (new IP/identity) when a matching SecurityEvent fires, or by the blind timer happening to rotate mid-move. The matcher cannot see "pod A exec'd into pod B"; there is no lateral-movement emitter in the canonical vocabulary. Opportunistic, not detected. *(Note: in the harness the marker write into B is a harness-exec stand-in; pod A does perform a real network dial to B's IP. The disruption measurement remains valid — if B rotates, the marker is gone.)*

### 3. c1-credtheft-rbac — R6-CANNOT-RESPOND
- **Category:** ClassicChain.
- **Source:** Task SCENARIO SET Cat1; ADA paper III.C "Configuration Exploitation: misconfigured RBAC, leaked secrets"; ADA MAESTRO L2/L6.
- **ATT&CK:** T1552.007, T1528, T1552.001, T1078.001, T1069, T1550.001.
- **Oracle (observable):** A ServiceAccount token mounted in the compromised pod is read and then used SUCCESSFULLY against the API server (e.g. list pods / read a secret it is RBAC-permitted to reach) from outside the original pod, returning HTTP 200 / data. *(This oracle mints+replays the REAL stolen SA token against the live apiserver — a 200-with-data is a genuine authz proof.)*
- **Honest R6 justification:** Token theft and its API use leave NO signal in Phoenix's emitter vocabulary (no Type for credential access); the matcher has nothing to match. Even a rotation of the victim pod does NOT revoke an already-exfiltrated, still-valid SA token (the token's secret/projected-volume identity is not invalidated by pod replacement). Phoenix cannot respond.

### 4. c1-c2-exfil — R6-PARTIAL
- **Category:** ClassicChain.
- **Source:** Task SCENARIO SET Cat1; Phoenix-adaptive-containers III "Disrupts C2 Communication"; AMTD-AI-infra "C2 channels dropped with identity rotation".
- **ATT&CK:** T1041, T1071, T1567, T1029, T1048.
- **Oracle (observable):** At least N bytes (fixed payload size) are received and counted by the in-cluster MOCK C2/exfil sink from the compromised pod (sink reports received byte count >= N).
- **Honest R6 justification:** Phoenix claims (product page + adaptive-containers paper) to disrupt C2 by rotating identities. True only opportunistically: a rotation landing DURING the transfer resets the connection, but Phoenix has no exfil detector/emitter, so it cannot target the exfiltrating pod on demand. A short transfer completes between rotations. Rate-dependent partial.

### 5. c1-stealth-dweller — R6-PARTIAL
- **Category:** ClassicChain.
- **Source:** Task SCENARIO SET Cat1; AMTD-AI-infra "Defense Evasion" row; ADA paper "threats that may evade detection".
- **ATT&CK:** T1070, T1036.005, T1685, T1564.
- **Oracle (observable):** Dweller process is alive after a dwell window W **AND** no SecurityEvent CR was created for it (zero detection) — survival achieved purely by stealth; the defense arm only matters if a blind/scheduled rotation evicts it within W.
- **Honest R6 justification:** This is the PHOENIX THESIS test: a dweller that emits NO detection event. Because the matcher is reactive/emitter-dependent, a stealth dweller produces no SecurityEvent, so quarantine never fires; ONLY blind/scheduled rotation (no telemetry) can evict it. Isolates Phoenix's enforcement-without-detection value and its limit. Evicted only by time-based rotation, never by detection.

### 6. c2-dwell-rotation — R6-COVERS
- **Category:** R6Claimed.
- **Source:** EXTRACTED Cat2: Phoenix-K8s "DWELL_TIME 0ms / The Persistence Trap"; AMTD-AI-infra "Dwell Time 150+ days -> <60 mins"; ADA Abstract "regularly destroying/respawning".
- **ATT&CK:** T1543.005, T1525, T1133, T1078.003.
- **Oracle (observable):** Measured attacker dwell = wall-clock seconds a planted foothold process stays alive before forced rotation/replacement; attacker "achieved" iff dwell exceeds the rotation interval; defense disruption = dwell capped at/below the configured interval across trials.
- **Honest R6 justification:** Phoenix's CORE designed-for claim and honest strength: a long-lived foothold is bounded by the rotation period regardless of detection. Even the blind timer (no emitter) caps dwell at the interval; FullPhoenix with a `{timed, TimeBasedTrigger}` strategy + RotateAction does this by design. Covers — but the oracle measures the REAL cap (= the interval), not the marketing 0ms.

### 7. c2-persistence-evict — R6-COVERS
- **Category:** R6Claimed.
- **Source:** EXTRACTED Cat2: Phoenix-K8s "Self-Healing Regeneration / Panic Mutation: Falco detects -> Phoenix triggers immediate workload rotation"; ADA paper 3.3.
- **ATT&CK:** T1543.005, T1611, T1059.013, T1070.
- **Oracle (observable):** After a SecurityEvent is emitted for the compromised pod, the malicious process is gone within time-to-action T because the pod was deleted/quarantined/rotated (observed: old pod UID terminated **AND** backdoor marker absent in the replacement).
- **Honest R6 justification:** Compromised-pod eviction on a detection event is the exact reactive path the matcher implements: a Falco-sourced `{Type:panic|policy-violation, ThreatLevel:high, Source:FalcoIntegrator}` SecurityEvent -> delete/quarantine/rotate on the PodSelector-matched pod. Covers WHEN emitter+strategy are present; the harness wires the emitter (FullPhoenix Setup) to test the genuine path. **This is the one arm/scenario where the genuine matcher.go path fires** — across the full ≥20-trial benchmark FullPhoenix disrupts c2-persistence-evict at **100% [100,100] (n=21)** and **0% on all 17 other scenarios** (panic event matched, "Pod c2pe-target successfully deleted with ACTION: delete").

### 8. c2-recon-window — R6-PARTIAL
- **Category:** R6Claimed.
- **Source:** EXTRACTED Cat2: Phoenix-K8s "Network Obfuscation / Discovery prevention"; Phoenix-adaptive-containers III "dynamic attack surface thwarts reconnaissance"; AMTD-AI-infra "Reconnaissance limited when IPs/names ephemeral".
- **ATT&CK:** T1613, T1046, T1069, T1526.
- **Oracle (observable):** Attacker enumerates target pod IP+identity at t0, then re-validates the SAME endpoint after one interval; recon "denied" iff the previously-mapped IP/identity is no longer valid (connection fails / identity changed) after rotation.
- **Honest R6 justification:** Phoenix rotates pod IPs/labels, so a recon snapshot goes stale at the rotation boundary — denying a STABLE map. But within one interval recon completes fully, and Phoenix emits no recon detection (the claim "changes before they finish a scan" is interval-bounded, not instantaneous). Denies persistence-of-recon, not the recon itself.

### 9. c2-lateral-disrupt — R6-PARTIAL
- **Category:** R6Claimed.
- **Source:** EXTRACTED Cat2: Phoenix-K8s "Temporal Network Policies: disposable network paths / Lateral movement becomes impossible"; ADA 3.3.
- **ATT&CK:** T1550.001, T1046, T1609, T1021.
- **Oracle (observable):** Attacker mid-lateral-move (reaching pod B from compromised pod A) is disrupted iff the in-flight session breaks **AND** the command in B fails to complete because A or B was rotated during the move; success-for-attacker = command runs in B before any rotation.
- **Honest R6 justification:** The product asserts "lateral movement becomes impossible". Reality from the CRD: Phoenix's actuators are pod delete/rotate; the "Temporal Network Policies / ephemeral service-mesh paths" bullet is NOT a wired action in `api/v1beta1` (no NetworkPolicy actuator). Lateral movement is disrupted only by rotating the moving pod, opportunistically. The strong product claim overshoots the implemented capability.

### 10. c2-c2-disrupt — R6-PARTIAL
- **Category:** R6Claimed.
- **Source:** EXTRACTED Cat2: Phoenix-adaptive-containers III "Disrupts C2 Communication"; AMTD-AI-infra "C2 channels get dropped regularly with identity rotation".
- **ATT&CK:** T1071, T1573, T1008, T1105.
- **Oracle (observable):** A persistent beacon from the compromised pod to the mock C2 sink is "disrupted" iff the established session is severed by a rotation before delivering K heartbeats; attacker success = K heartbeats delivered on one stable identity.
- **Honest R6 justification:** Same actuator reality as c1-c2-exfil but framed as the R6 CLAIM. Identity rotation drops a long-lived C2 channel at each cycle (true) but cannot target an active channel on demand (no C2 emitter). A beacon re-establishes after rotation; only sustained/long transfers are reliably disrupted. Equal-rate-comparable partial.

### 11. c2-supplychain-foothold — R6-PARTIAL
- **Category:** R6Claimed.
- **Source:** EXTRACTED Cat2: AMTD-AI-infra Case Study SolarWinds "Compromised image/update flow -> short-lived containers from known-good sources"; ADA MAESTRO L4 "Compromised Container Images -> image signing/short-lived creds".
- **ATT&CK:** T1525, T1204.003, T1610, T1543.005.
- **Oracle (observable):** A foothold established by a malicious-image container persists iff its marker process survives past the rotation interval; disruption = foothold process replaced by a known-good (mock golden) image within the interval. **Prevention of the initial pull is NOT claimed/measured here** (that is c3-supplychain).
- **Honest R6 justification:** R6 claims rotation + "signed verifiable images/immutable baselines" mitigate supply-chain footholds. The CRD's Baseline/Regenerate path exists but is digest-pin REFERENCES + a TYPE-ONLY Regenerate action (no live signature/provenance enforcement wired). Phoenix bounds the FOOTHOLD's lifetime by rotation but does NOT block the malicious image from running. Caps foothold dwell; does not prevent the pull/exec.

### 12. c3-supplychain — R6-CANNOT-RESPOND
- **Category:** ModernUnsupported.
- **Source:** Task SCENARIO SET Cat3 c3-supplychain; ADA MAESTRO L4 "Compromised Container Images".
- **ATT&CK:** T1525, T1204.003, T1610, T1612.
- **Oracle (observable):** A MOCK in-cluster registry serves a tampered image; achieved iff a pod pulls that image **AND** the tampered payload runs (marker written by the injected layer's entrypoint).
- **Honest R6 justification:** Phoenix has no admission/image-provenance enforcement actuator in `api/v1beta1`; the matcher only consumes post-hoc SecurityEvents and rotates pods. It cannot block a tampered image from being pulled+run; **rotation just re-pulls the same poisoned image.** Genuine Phorvex differentiator.

### 13. c3-cicd — R6-CANNOT-RESPOND
- **Category:** ModernUnsupported.
- **Source:** Task SCENARIO SET Cat3 c3-cicd; AMTD-AI-infra SolarWinds "Compromised CI/CD system, static build pipelines".
- **ATT&CK:** T1053.007, T1610, T1525, T1204.003.
- **Oracle (observable):** A MOCK in-namespace pipeline runner executes; achieved iff an injected pipeline step runs / a build artifact is tampered (injected step's marker artifact present in the mock output volume).
- **Honest R6 justification:** CI/CD pipeline compromise occurs at build time, before any workload pod exists for Phoenix to rotate; no emitter in the vocabulary covers pipeline-step injection. Phoenix's pod-rotation actuator is out of band. Cannot respond. Phorvex differentiator.

### 14. c3-sidecar-inject — R6-CANNOT-RESPOND
- **Category:** ModernUnsupported.
- **Source:** Task SCENARIO SET Cat3 c3-sidecar-inject; ADA MAESTRO L3 "Privilege Escalation via CRDs / Tool Misuse".
- **ATT&CK:** T1610, T1543.005, T1525, T1611.
- **Oracle (observable):** Achieved iff an injected sidecar/init container runs with the access it was granted (marker: sidecar reads the shared volume / mounts the SA token and writes proof).
- **Honest R6 justification:** Injecting a malicious sidecar/init container is an admission-time mutation; Phoenix has no mutating/validating webhook actuator and no emitter for "unexpected container added". **A rotation re-creates the pod from its (already-poisoned) spec, re-injecting the sidecar.** Cannot respond. Differentiator.

### 15. c3-admission-bypass — R6-CANNOT-RESPOND
- **Category:** ModernUnsupported.
- **Source:** Task SCENARIO SET Cat3 c3-admission-bypass; ADA MAESTRO L3 "Protect admission controllers".
- **ATT&CK:** T1610, T1611, T1068, T1078.001.
- **Oracle (observable):** Achieved iff a deliberately policy-violating pod (e.g. privileged / hostPath, in the sandbox ns only) is admitted and reaches Running state and its violating capability is exercised (marker written from the privileged context).
- **Honest R6 justification:** Phoenix is not an admission controller and emits/consumes nothing at admission; a policy-violating pod that is admitted simply runs, and **rotation would re-admit it.** No matcher path applies. Cannot respond. Differentiator.

### 16. c3-cryptomining — R6-PARTIAL
- **Category:** ModernUnsupported.
- **Source:** Task SCENARIO SET Cat3 c3-cryptomining; Phoenix-AI "LLM-Jacking: hijack GPU compute"; AMTD-AI-infra "cryptojacking".
- **ATT&CK:** T1496.001, T1610, T1059.013.
- **Oracle (observable):** A CPU-BOUNDED miner stand-in (busy loop under a CPU limit) accrues >= C CPU-seconds within a window before any rotation; disruption = miner pod rotated/killed before reaching C CPU-seconds.
- **Honest R6 justification:** Phoenix can evict a miner IF an emitter (Prometheus integrator) raises a high-CPU/anomaly SecurityEvent that a strategy matches -> rotate; that path exists (Metrics + Scored matcher). But absent that wired emitter + Scored strategy, the CPU-bounded miner runs uninterrupted until a blind rotation. Emitter + Scored-mode dependent; **in default Exact mode the anomalyScore clause is INERT** (`matcher.go MatchStrategyForMode`). *GPU/MIG-specific micro-shuffling variants are **capability-pending** on this CPU-only node.*

### 17. c3-imds-theft — R6-CANNOT-RESPOND
- **Category:** ModernUnsupported.
- **Source:** Task SCENARIO SET Cat3 c3-imds-theft; ADA paper II "Model Extraction / cloud cred"; Phoenix-AI "Model Theft / Zero-Trust Model Access".
- **ATT&CK:** T1552.005, T1528, T1552.007, T1078.004.
- **Oracle (observable):** A MOCK 169.254.169.254 metadata endpoint (in-ns ClusterIP stand-in) issues a fake cloud credential; achieved iff the compromised pod retrieves it **AND** uses it successfully against the mock cloud API (mock returns an authorized response to the stolen cred).
- **Honest R6 justification:** IMDS credential theft hits the cloud metadata endpoint, invisible to Phoenix (no emitter, no network actuator); a stolen cloud credential remains valid after the pod rotates (it is a cloud-side credential, not a pod identity Phoenix can revoke). Cannot respond. Strong Phorvex differentiator. *(Anchor: in the full ≥20-trial benchmark this oracle anchors at **21/21 undefended**. The 2-trial smoke had FAILED to anchor it — the mock IMDS/cloud-API responder emitted literal "\r\n" text instead of CRLF, so every client read 0 bytes ("fetched cred body len=0"). Fixed (CRLF-correct `printf` format + an active in-pod readiness gate), verified serving on busybox:1.36. That was a harness bug, never a Phoenix win.)*

### 18. c3-secrets-sprawl — R6-CANNOT-RESPOND
- **Category:** ModernUnsupported.
- **Source:** Task SCENARIO SET Cat3 c3-secrets-sprawl; ADA MAESTRO L2/L6 "leaked secrets / secure credential management".
- **ATT&CK:** T1552.001, T1552.007, T1528, T1078.
- **Oracle (observable):** Achieved iff a secret value is read from an over-permissive volume mount/env var in the compromised pod **AND** then used successfully (e.g. authenticates to the mock sink / mock API that trusts that secret).
- **Honest R6 justification:** Reading a secret from an over-permissive mount/env is a single in-pod read with no runtime signal Phoenix's emitters classify; **rotation does not un-leak an already-read secret value, and the over-permissive mount is re-created on the rotated pod.** Cannot respond. Differentiator. *(Same mock responder bug as c3-imds-theft affected its smoke anchor; in the full ≥20-trial benchmark it anchors at **21/21 undefended** after the fix.)*

---

## Verdict distribution

| Verdict | Count | Scenarios |
|---|---|---|
| **R6-COVERS** | 2 | c2-dwell-rotation, c2-persistence-evict |
| **R6-PARTIAL** | 9 | c1-escape-persist, c1-lateral, c1-c2-exfil, c1-stealth-dweller, c2-recon-window, c2-lateral-disrupt, c2-c2-disrupt, c2-supplychain-foothold, c3-cryptomining |
| **R6-CANNOT-RESPOND** | 7 | c1-credtheft-rbac, c3-supplychain, c3-cicd, c3-sidecar-inject, c3-admission-bypass, c3-imds-theft, c3-secrets-sprawl |

Total: 2 + 9 + 7 = **18** scenarios.

All numbers cited as measured trace to a raw log + command via
`build/test-harness/out-bench/provenance.json` (full ≥20-trial benchmark;
`masterSeed=1337`). See `build/EFFECTIVENESS-K8S.md` for the per-arm results
(n=21, 95% CI) and `build/ATTACK-COVERAGE-K8S.md` for the ATT&CK coverage matrix.
