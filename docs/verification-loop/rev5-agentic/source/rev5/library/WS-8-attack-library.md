# WS-8 — Phorvex Attack-Coverage Library (complete)

Built from the six sources, keyed to public IDs. Stage 0 of the Rev 5 loop. Every entry is defensive: it records the attacker **end state** Phorvex must remove and the **actuator** that removes it, never attack how-to. Full technique text is fetched from the source DB at runtime by ID.

**700 entries** — bucket 1 covered: 148 · bucket 2 after-effect: 100 · bucket 3 design-stage: 12 · bucket 4 out-of-scope: 440.
**By source:** ATLAS 120 · ATLAS-sub 88 · ATT&CK 172 · ATT&CK-sub 233 · MS-K8s 40 · OWASP-LLM 10 · OWASP-Agentic 10 · OWASP-MCP 10 · NIST-AI-100-2 12 · AVID 5.

**Sources & versions:** MITRE ATLAS 2026.09 (120 + 88 subs, all) · MITRE ATT&CK (all 172 top-level + 233 subs on Containers/IaaS/Linux) · Microsoft Threat Matrix for Kubernetes (all 40 cells) · OWASP LLM01-10 / Agentic ASI01-10 / MCP01-10 (all) · NIST AI 100-2 (full taxonomy, 12) · AVID (5) · CIS + NSA/CISA (preconditions vocabulary).

## Schema
```
framework,id,parent,name,tactics,platforms,bucket,surface,actuator,actuator_status,preconditions,attacker_end_state,confirmation_probe,scope_reason
```
- **bucket**: 1 covered now · 2 after-effect (roll back/evict) · 3 design-stage · 4 out of scope (reason given).
- **actuator_status** (vs Phorvex's real `MutatingActions`): `exists` (rotate/quarantine, shipped) · `partial(...)` (handler exists but label-only M-33, or conditional M-35, or PENDING-GPU / CRD-blocked M-2) · `needs-build` (no actuator today → the design roster synthesises it).
- **preconditions**: CIS/NSA-CISA misconfig tags that must hold on a scanned stack for the entry to APPLY. `|` = any-of.

## Actuator gap (what to build, by priority)

| Actuator | Status | Techniques it would cover |
|---|---|---|
| identity-rotate | partial(label-only M-33) | 43 |
| quarantine | exists | 40 |
| respawn | exists | 28 |
| registry-rollback | needs-build | 25 |
| key-rotate | needs-build | 25 |
| evict | exists | 20 |
| cut the network | exists | 14 |
| node-cordon-drain-replace | needs-build | 10 |
| (pointer) | - | 10 |
| cut reachability | exists | 8 |
| constrain-agent-scope | needs-build | 6 |
| context-reset | needs-build | 6 |
| throttle | needs-build | 5 |
| endpoint-rotate | partial(conditional M-35) | 5 |
| tool-repin | needs-build | 5 |
| route-rotate | partial(label-only M-33) | 4 |
| rag-restore | needs-build | 3 |
| cut egress | exists | 1 |
| network-quarantine | exists | 1 |
| cut the route | exists | 1 |

**Reading it:** `exists` rows work today. `partial` rows are the highest-value fixes (identity-rotate/route-rotate are label-only; the AI moves are PENDING-GPU/CRD). `needs-build` rows are the design-roster backlog — node cordon/drain/replace, registry rollback, RAG/context restore, MCP tool re-pin, key rotation, agent-scope constraint, throttle.


## Bucket 1 — Covered now

| ID | Name | Surface | Actuator | Status | Preconditions | End state removed | Probe |
|---|---|---|---|---|---|---|---|
| AML.T0007 | Discover AI Artifacts | k8s | identity-rotate | partial(label-only M-33) | workload-present | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| AML.T0025 | Exfiltration via Cyber Means | cni | cut egress | exists | no-networkpolicy | attacker exfil channel open | egress edge removed (already-sent data out of scope) |
| AML.T0029 | Denial of AI Service | serving | quarantine | exists | serves-model | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| AML.T0034 | Cost Harvesting | serving | throttle | needs-build | serves-model | attacker driving runaway cost/load | driving path capped; rate at baseline |
| AML.T0035 | AI Artifact Collection | k8s | cut reachability | exists | no-networkpolicy | attacker can reach the target over the pod network | foothold->target edge removed |
| AML.T0044 | Full AI Model Access | serving | network-quarantine | exists | serves-model | attacker has access on the serving pod | serving pod isolated; edge removed |
| AML.T0046 | Spamming AI System with Chaff Data | serving | quarantine | exists | serves-model | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| AML.T0049 | Exploit Public-Facing Application | k8s | quarantine | exists | public-exposure | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| AML.T0050 | Command and Scripting Interpreter | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| AML.T0063 | Discover AI Model Outputs | serving | endpoint-rotate | partial(conditional M-35) | serves-model | attacker learned the model endpoint | endpoint route epoch rotated |
| AML.T0069 | Discover LLM System Information | serving | endpoint-rotate | partial(conditional M-35) | serves-model | attacker learned the model endpoint | endpoint route epoch rotated |
| AML.T0074 | Masquerading | k8s | evict | exists | workload-present | attacker-controlled workload running | workload gone; owner not rescheduling it |
| AML.T0084 | Discover AI Agent Configuration | agent | identity-rotate | partial(label-only M-33) | has-agent | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| AML.T0085 | Data from AI Services | k8s | cut reachability | exists | no-networkpolicy | attacker can reach the target over the pod network | foothold->target edge removed |
| AML.T0096 | AI Service API | cni | cut the network | exists | no-networkpolicy | attacker C2 / DoS channel open | channel edge removed |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | agent | constrain-agent-scope | needs-build | has-agent | over-broad agent identity/tool scope abused | agent scope reduced; identity rotated |
| AML.T0103 | Deploy AI Agent | k8s | evict | exists | has-agent | attacker-controlled workload running | workload gone; owner not rescheduling it |
| AML.T0105 | Escape to Host | node | node-cordon-drain-replace | needs-build | privileged-pod|hostpath-mount|host-namespace | attacker on the host/node | workload off node; node cordoned/replaced |
| AML.T0108 | AI Agent | cni | cut the network | exists | has-agent;no-networkpolicy | attacker C2 / DoS channel open | channel edge removed |
| AML.T0112 | Machine Compromise | node | node-cordon-drain-replace | needs-build | privileged-pod|hostpath-mount|host-namespace | attacker on the host/node | workload off node; node cordoned/replaced |
| AML.T0114 | AI Service Web Interface | cni | cut the route | exists | public-exposure | attacker reaches the service route | route removed |
| AML.T0116 | Autonomous Reconnaissance | k8s | quarantine | exists | has-agent | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| AML.T0117 | Autonomous Attack-Path Adaptation | agent | evict | exists | has-agent | attacker-controlled workload running | workload gone; owner not rescheduling it |
| AML.T0119 | Exploit Automated Artifact Processing Pipeline | k8s | quarantine | exists | automated-pipeline | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| AML.T0121 | AI Agent Environment Reconstruction | k8s | identity-rotate | partial(label-only M-33) | workload-present | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| AML.T0122 | Exploitation of Remote Services | cni | cut reachability | exists | no-networkpolicy | attacker can reach the target over the pod network | foothold->target edge removed |
| AML.T0124 | Autonomous Attack Orchestration | agent | evict | exists | has-agent | attacker-controlled workload running | workload gone; owner not rescheduling it |
| AML.T0132 | Misconfigured or Publicly Exposed AI Services | cni | route-rotate | partial(label-only M-33) | public-exposure | attacker learned/reaches the route | route epoch rotated |
| AML.T0133 | Discover AI Agent Runtime Capabilities | agent | identity-rotate | partial(label-only M-33) | has-agent | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| T1036 | Masquerading | k8s | evict | exists | workload-present | attacker-controlled workload running | workload gone; owner not rescheduling it |
| T1046 | Network Service Discovery | cni | route-rotate | partial(label-only M-33) | no-networkpolicy | attacker learned/reaches the route | route epoch rotated |
| T1059 | Command and Scripting Interpreter | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| T1068 | Exploitation for Privilege Escalation | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| T1069 | Permission Groups Discovery | k8s | identity-rotate | partial(label-only M-33) | overbroad-rbac | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| T1070 | Indicator Removal | k8s | respawn | exists | workload-present | attacker modification persisted in the pod | pod replaced from clean image |
| T1133 | External Remote Services | k8s | quarantine | exists | public-exposure | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| T1190 | Exploit Public-Facing Application | k8s | quarantine | exists | public-exposure | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| T1204 | User Execution | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| T1485 | Data Destruction | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| T1490 | Inhibit System Recovery | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| T1496 | Resource Hijacking | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| T1498 | Network Denial of Service | cni | cut the network | exists | no-networkpolicy | attacker C2 / DoS channel open | channel edge removed |
| T1499 | Endpoint Denial of Service | cni | cut the network | exists | public-exposure | attacker C2 / DoS channel open | channel edge removed |
| T1543 | Create or Modify System Process | k8s | respawn | exists | workload-present | attacker modification persisted in the pod | pod replaced from clean image |
| T1550 | Use Alternate Authentication Material | identity | identity-rotate | partial(label-only M-33) | mounted-sa-token | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| T1609 | Container Administration Command | k8s | quarantine | exists | overbroad-rbac | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| T1610 | Deploy Container | k8s | evict | exists | overbroad-rbac | attacker-controlled workload running | workload gone; owner not rescheduling it |
| T1611 | Escape to Host | node | node-cordon-drain-replace | needs-build | privileged-pod|hostpath-mount|host-namespace | attacker on the host/node | workload off node; node cordoned/replaced |
| T1613 | Container and Resource Discovery | k8s | identity-rotate | partial(label-only M-33) | overbroad-rbac | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| T1685 | Disable or Modify Tools | k8s | respawn | exists | workload-present | attacker modification persisted in the pod | pod replaced from clean image |
| MS-IN-application-vulnerabil | Application vulnerability | k8s | quarantine | exists | public-exposure | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| MS-IN-exposed-sensitive-inte | Exposed sensitive interfaces | cni | route-rotate | partial(label-only M-33) | public-exposure | attacker learned/reaches the route | route epoch rotated |
| MS-EX-exec-into-container | Exec into container | k8s | quarantine | exists | overbroad-rbac | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| MS-EX-bashcmd-inside-contain | Bash/cmd inside container | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| MS-EX-new-container | New container | k8s | evict | exists | overbroad-rbac | attacker-controlled workload running | workload gone; owner not rescheduling it |
| MS-EX-application-exploit-(r | Application exploit (RCE) | k8s | quarantine | exists | public-exposure | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| MS-EX-ssh-server-running-ins | SSH server running inside container | k8s | respawn | exists | workload-present | attacker modification persisted in the pod | pod replaced from clean image |
| MS-EX-sidecar-injection | Sidecar injection | k8s | respawn | exists | overbroad-rbac | attacker modification persisted in the pod | pod replaced from clean image |
| MS-PE-backdoor-container | Backdoor container | k8s | respawn | exists | workload-present | attacker modification persisted in the pod | pod replaced from clean image |
| MS-PE-writable-hostpath-moun | Writable hostPath mount | node | node-cordon-drain-replace | needs-build | hostpath-mount | attacker on the host/node | workload off node; node cordoned/replaced |
| MS-PE-static-pods | Static pods | node | node-cordon-drain-replace | needs-build | host-namespace | attacker on the host/node | workload off node; node cordoned/replaced |
| MS-PR-privileged-container | Privileged container | node | node-cordon-drain-replace | needs-build | privileged-pod | attacker on the host/node | workload off node; node cordoned/replaced |
| MS-DE-clear-container-logs | Clear container logs | k8s | respawn | exists | workload-present | attacker modification persisted in the pod | pod replaced from clean image |
| MS-DE-delete-kubernetes-even | Delete Kubernetes events | k8s | respawn | exists | overbroad-rbac | attacker modification persisted in the pod | pod replaced from clean image |
| MS-DE-pod-or-container-name- | Pod or container name similarity | k8s | evict | exists | workload-present | attacker-controlled workload running | workload gone; owner not rescheduling it |
| MS-DI-access-kubernetes-api- | Access Kubernetes API server | k8s | identity-rotate | partial(label-only M-33) | overbroad-rbac | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| MS-DI-access-kubelet-api | Access Kubelet API | node | node-cordon-drain-replace | needs-build | host-namespace | attacker on the host/node | workload off node; node cordoned/replaced |
| MS-DI-network-mapping | Network mapping | cni | route-rotate | partial(label-only M-33) | no-networkpolicy | attacker learned/reaches the route | route epoch rotated |
| MS-LA-cluster-internal-netwo | Cluster internal networking | cni | cut reachability | exists | no-networkpolicy | attacker can reach the target over the pod network | foothold->target edge removed |
| MS-LA-coredns-poisoning | CoreDNS poisoning | cni | cut the network | exists | no-networkpolicy | attacker C2 / DoS channel open | channel edge removed |
| MS-LA-arp-poisoning-and-ip-s | ARP poisoning and IP spoofing | cni | cut the network | exists | no-networkpolicy | attacker C2 / DoS channel open | channel edge removed |
| MS-CO-images-from-a-private- | Images from a private registry | k8s | cut reachability | exists | no-networkpolicy | attacker can reach the target over the pod network | foothold->target edge removed |
| MS-CO-collecting-data-from-p | Collecting data from pod | k8s | cut reachability | exists | no-networkpolicy | attacker can reach the target over the pod network | foothold->target edge removed |
| MS-IM-data-destruction | Data destruction | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| MS-IM-resource-hijacking | Resource hijacking | k8s | quarantine | exists | workload-present | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| MS-IM-denial-of-service | Denial of service | cni | cut the network | exists | no-networkpolicy | attacker C2 / DoS channel open | channel edge removed |
| LLM10:2025 | Unbounded Consumption | serving | throttle | needs-build | serves-model | attacker driving runaway cost/load | driving path capped; rate at baseline |
| ASI05:2026 | Unexpected Code Execution | k8s | quarantine | exists | has-agent | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| ASI07:2026 | Insecure Inter-Agent Communication | cni | cut the network | exists | has-agent;no-networkpolicy | attacker C2 / DoS channel open | channel edge removed |
| ASI08:2026 | Cascading Failures | k8s | quarantine | exists | has-agent | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| ASI10:2026 | Rogue Agents | k8s | evict | exists | has-agent | attacker-controlled workload running | workload gone; owner not rescheduling it |
| MCP05:2025 | Command Injection & Execution | k8s | quarantine | exists | has-mcp-tools | attacker foothold active on the workload | foothold path cut; workload Ready on clean placement |
| MCP09:2025 | Shadow MCP Servers | k8s | evict | exists | has-mcp-tools | attacker-controlled workload running | workload gone; owner not rescheduling it |
| AVID-SEC-availability | Security — availability/DoS | - | (pointer) | - |  | (see referenced entry) |  |

*(+64 ATLAS sub-techniques inherit their parent's mapping — in the CSV/YAML.)*

## Bucket 2 — After-effect (roll back / evict the persisted state)

| ID | Name | Surface | Actuator | Status | Preconditions | End state removed | Probe |
|---|---|---|---|---|---|---|---|
| AML.T0010 | AI Supply Chain Compromise | artifact | registry-rollback | needs-build | no-image-signing|mutable-tag | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| AML.T0012 | Valid Accounts | identity | identity-rotate | partial(label-only M-33) | mounted-sa-token|plaintext-secret | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| AML.T0018 | Manipulate AI Model | serving | registry-rollback | needs-build | serves-model | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| AML.T0031 | Erode AI Model Integrity | serving | registry-rollback | needs-build | serves-model | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| AML.T0055 | Unsecured Credentials | identity | key-rotate | needs-build | plaintext-secret | credential exposed/harvested on infra | credential rotated; old value rejected |
| AML.T0070 | RAG Poisoning | serving | rag-restore | needs-build | uses-rag | poisoned index/model/tool-data persisted | store hash == trusted snapshot |
| AML.T0073 | Impersonation | identity | identity-rotate | partial(label-only M-33) | workload-present | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| AML.T0076 | Corrupt AI Model | serving | registry-rollback | needs-build | serves-model | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| AML.T0080 | AI Agent Context Poisoning | serving | context-reset | needs-build | has-agent | poisoned agent memory/context/config persisted | context/config == trusted snapshot |
| AML.T0081 | Modify AI Agent Configuration | agent | context-reset | needs-build | has-agent | poisoned agent memory/context/config persisted | context/config == trusted snapshot |
| AML.T0082 | RAG Credential Harvesting | identity | key-rotate | needs-build | uses-rag | credential exposed/harvested on infra | credential rotated; old value rejected |
| AML.T0083 | Credentials from AI Agent Configuration | identity | key-rotate | needs-build | has-agent | credential exposed/harvested on infra | credential rotated; old value rejected |
| AML.T0098 | AI Agent Tool Credential Harvesting | identity | key-rotate | needs-build | has-mcp-tools | credential exposed/harvested on infra | credential rotated; old value rejected |
| AML.T0099 | AI Agent Tool Data Poisoning | serving | rag-restore | needs-build | has-mcp-tools | poisoned index/model/tool-data persisted | store hash == trusted snapshot |
| AML.T0109 | AI Supply Chain Rug Pull | artifact | registry-rollback | needs-build | no-image-signing|mutable-tag | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| AML.T0110 | AI Agent Tool Poisoning | serving | tool-repin | needs-build | has-mcp-tools | poisoned MCP tool descriptor loaded | descriptor hash == trusted |
| AML.T0113 | Steal Web Session Cookie | identity | identity-rotate | partial(label-only M-33) | workload-present | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| AML.T0115 | Publish Poisoned AI Artifacts | artifact | registry-rollback | needs-build | no-image-signing|mutable-tag | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| T1053 | Scheduled Task/Job | k8s | respawn | exists | overbroad-rbac | attacker modification persisted in the pod | pod replaced from clean image |
| T1078 | Valid Accounts | identity | identity-rotate | partial(label-only M-33) | mounted-sa-token | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| T1098 | Account Manipulation | identity | identity-rotate | partial(label-only M-33) | overbroad-rbac | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| T1110 | Brute Force | identity | key-rotate | needs-build | public-exposure | credential exposed/harvested on infra | credential rotated; old value rejected |
| T1136 | Create Account | identity | identity-rotate | partial(label-only M-33) | overbroad-rbac | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| T1525 | Implant Internal Image | artifact | registry-rollback | needs-build | no-image-signing|mutable-tag | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| T1528 | Steal Application Access Token | identity | key-rotate | needs-build | mounted-sa-token | credential exposed/harvested on infra | credential rotated; old value rejected |
| T1552 | Unsecured Credentials | identity | key-rotate | needs-build | plaintext-secret | credential exposed/harvested on infra | credential rotated; old value rejected |
| T1612 | Build Image on Host | node | node-cordon-drain-replace | needs-build | privileged-pod | attacker on the host/node | workload off node; node cordoned/replaced |
| MS-IN-using-cloud-credential | Using cloud credentials | identity | identity-rotate | partial(label-only M-33) | mounted-sa-token | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| MS-IN-compromised-image-in-r | Compromised image in registry | artifact | registry-rollback | needs-build | no-image-signing|mutable-tag | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| MS-IN-kubeconfig-file | Kubeconfig file | identity | key-rotate | needs-build | plaintext-secret | credential exposed/harvested on infra | credential rotated; old value rejected |
| MS-PE-kubernetes-cronjob | Kubernetes CronJob | k8s | respawn | exists | overbroad-rbac | attacker modification persisted in the pod | pod replaced from clean image |
| MS-PE-malicious-admission-co | Malicious admission controller | k8s | respawn | exists | overbroad-rbac | attacker modification persisted in the pod | pod replaced from clean image |
| MS-PE-container-service-acco | Container service account | identity | identity-rotate | partial(label-only M-33) | mounted-sa-token | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| MS-PR-cluster-admin-binding | Cluster-admin binding | identity | identity-rotate | partial(label-only M-33) | cluster-admin-binding | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| MS-PR-access-cloud-resources | Access cloud resources | identity | identity-rotate | partial(label-only M-33) | mounted-sa-token | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| MS-CR-list-kubernetes-secret | List Kubernetes secrets | identity | key-rotate | needs-build | overbroad-rbac | credential exposed/harvested on infra | credential rotated; old value rejected |
| MS-CR-mount-service-principa | Mount service principal | identity | key-rotate | needs-build | mounted-sa-token | credential exposed/harvested on infra | credential rotated; old value rejected |
| MS-CR-application-credential | Application credentials in configuration files | identity | key-rotate | needs-build | plaintext-secret | credential exposed/harvested on infra | credential rotated; old value rejected |
| MS-CR-access-managed-identit | Access Managed Identity credentials | identity | identity-rotate | partial(label-only M-33) | mounted-sa-token | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| MS-DI-instance-metadata-api | Instance Metadata API | identity | identity-rotate | partial(label-only M-33) | mounted-sa-token | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| LLM03:2025 | Supply Chain | artifact | registry-rollback | needs-build | no-image-signing|mutable-tag | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| LLM04:2025 | Data and Model Poisoning | serving | registry-rollback | needs-build | serves-model | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| LLM08:2025 | Vector and Embedding Weaknesses | serving | rag-restore | needs-build | uses-rag | poisoned index/model/tool-data persisted | store hash == trusted snapshot |
| ASI03:2026 | Identity & Privilege Abuse | identity | identity-rotate | partial(label-only M-33) | has-agent | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| ASI04:2026 | Agentic Supply Chain Vulnerabilities | artifact | registry-rollback | needs-build | no-image-signing|mutable-tag | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| ASI06:2026 | Memory & Context Poisoning | serving | context-reset | needs-build | has-agent | poisoned agent memory/context/config persisted | context/config == trusted snapshot |
| MCP01:2025 | Token Mismanagement & Secret Exposure | identity | key-rotate | needs-build | has-mcp-tools | credential exposed/harvested on infra | credential rotated; old value rejected |
| MCP03:2025 | Tool Poisoning | serving | tool-repin | needs-build | has-mcp-tools | poisoned MCP tool descriptor loaded | descriptor hash == trusted |
| MCP04:2025 | Software Supply Chain Attacks & Dependency Tampering | artifact | registry-rollback | needs-build | no-image-signing|mutable-tag | poisoned artifact/image/model in supply chain | running digest == trusted-pin |
| MCP07:2025 | Insufficient Authentication & Authorization | identity | identity-rotate | partial(label-only M-33) | has-mcp-tools | attacker holds/learned a workload identity or recon map | identity epoch rotated; map stale |
| MCP10:2025 | Context Injection & Over-Sharing | serving | context-reset | needs-build | has-mcp-tools | poisoned agent memory/context/config persisted | context/config == trusted snapshot |
| NIST-PredAI-poison-avail | Poisoning — availability | - | (pointer) | - |  | (see referenced entry) |  |
| NIST-PredAI-poison-target | Poisoning — targeted/backdoor | - | (pointer) | - |  | (see referenced entry) |  |
| NIST-GenAI-supply | GenAI — supply chain | - | (pointer) | - |  | (see referenced entry) |  |
| NIST-GenAI-indirect-inject | GenAI — indirect prompt injection | - | (pointer) | - |  | (see referenced entry) |  |
| NIST-GenAI-poison | GenAI — poisoning | - | (pointer) | - |  | (see referenced entry) |  |
| AVID-SEC-poison | Security — poisoning | - | (pointer) | - |  | (see referenced entry) |  |

*(+43 ATLAS sub-techniques inherit their parent's mapping — in the CSV/YAML.)*

## Bucket 3 — Design-stage (design roster synthesises the actuator)

| ID | Name | Surface | Actuator | Status | Preconditions | End state removed | Probe |
|---|---|---|---|---|---|---|---|
| AML.T0024 | Exfiltration via AI Inference API | serving | key-rotate | needs-build | serves-model | credential exposed/harvested on infra | credential rotated; old value rejected |
| AML.T0053 | AI Agent Tool Invocation | agent | constrain-agent-scope | needs-build | has-agent | over-broad agent identity/tool scope abused | agent scope reduced; identity rotated |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | agent | constrain-agent-scope | needs-build | has-agent | over-broad agent identity/tool scope abused | agent scope reduced; identity rotated |
| LLM06:2025 | Excessive Agency | agent | constrain-agent-scope | needs-build | has-agent | over-broad agent identity/tool scope abused | agent scope reduced; identity rotated |
| ASI02:2026 | Tool Misuse | agent | constrain-agent-scope | needs-build | has-agent | over-broad agent identity/tool scope abused | agent scope reduced; identity rotated |
| MCP02:2025 | Privilege Escalation via Scope Creep | agent | constrain-agent-scope | needs-build | has-mcp-tools | over-broad agent identity/tool scope abused | agent scope reduced; identity rotated |
| NIST-PredAI-priv-reconstruct | Privacy — data reconstruction | - | (pointer) | - |  | (see referenced entry) |  |
| NIST-PredAI-priv-extraction | Privacy — model extraction | - | (pointer) | - |  | (see referenced entry) |  |
| AVID-SEC-theft | Security — model/IP theft | - | (pointer) | - |  | (see referenced entry) |  |

*(+3 ATLAS sub-techniques inherit their parent's mapping — in the CSV/YAML.)*

## Bucket 4 — Out of scope for MTD (honest edge)

| ID | Name | Why |
|---|---|---|
| AML.T0000 | Search Open Technical Databases | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0001 | Search Open AI Vulnerability Analysis | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0002 | Acquire Public AI Artifacts | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0003 | Search Victim-Owned Websites | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0004 | Search Application Repositories | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0005 | Create Proxy AI Model | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0006 | Active Scanning | infra effect covered by another entry |
| AML.T0008 | Acquire Infrastructure | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0011 | User Execution | social/lure; foothold (if any) covered by initial-access entries |
| AML.T0013 | Discover AI Model Ontology | attacker knowledge, not movable infra |
| AML.T0014 | Discover AI Model Family | attacker knowledge, not movable infra |
| AML.T0015 | Evade AI Model | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0016 | Obtain Capabilities | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0017 | Develop Capabilities | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0020 | Training Data Poisoning | training-time; resulting model covered by the model-rollback entries |
| AML.T0021 | Establish Accounts | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0036 | Data from Information Repositories | host-level data; see the node entries |
| AML.T0037 | Data from Local System | host-level data; see the node entries |
| AML.T0040 | AI Model Inference API Access | infra effect covered by another entry |
| AML.T0041 | Physical Environment Access | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0042 | Verify Attack | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0043 | Craft Adversarial Data | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0047 | AI-Enabled Product or Service | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0048 | External Harms | infra effect covered by another entry |
| AML.T0051 | LLM Prompt Injection | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0052 | Phishing | social/lure; foothold (if any) covered by initial-access entries |
| AML.T0054 | LLM Jailbreak | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0056 | Extract LLM System Prompt | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0057 | LLM Data Leakage | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0059 | Erode Dataset Integrity | training-time; resulting model covered by the model-rollback entries |
| AML.T0060 | Publish Hallucinated Entities | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0061 | LLM Prompt Self-Replication | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0062 | Discover LLM Hallucinations | attacker knowledge, not movable infra |
| AML.T0064 | Gather RAG-Indexed Targets | attacker knowledge, not movable infra |
| AML.T0065 | LLM Prompt Crafting | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0066 | Retrieval Content Crafting | infra effect covered by another entry |
| AML.T0067 | LLM Trusted Output Components Manipulation | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0068 | LLM Prompt Obfuscation | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0071 | False RAG Entry Injection | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0072 | Cyber Communication Channel | infra effect covered by another entry |
| AML.T0075 | Enterprise Resource Discovery | attacker knowledge, not movable infra |
| AML.T0077 | LLM Response Rendering | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0078 | Drive-by Compromise | social/lure; foothold (if any) covered by initial-access entries |
| AML.T0079 | Stage Capabilities | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0087 | Gather Victim Identity Information | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0088 | Generate Deepfakes | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0089 | Enterprise Environment Discovery | attacker knowledge, not movable infra |
| AML.T0090 | OS Credential Dumping | host-level data; see the node entries |
| AML.T0091 | Use Alternate Authentication Material | infra effect covered by another entry |
| AML.T0092 | Manipulate User LLM Chat History | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0093 | Prompt Infiltration via Public-Facing Application | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0094 | Delay Execution of LLM Instructions | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0095 | Search Open Websites/Domains | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0097 | Virtualization/Sandbox Evasion | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0100 | AI Agent Clickbait | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0102 | Generate Malicious Commands | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0106 | Exploitation for Credential Access | infra effect covered by another entry |
| AML.T0107 | Exploitation for Defense Evasion | infra effect covered by another entry |
| AML.T0111 | AI Supply Chain Reputation Inflation | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0118 | Autonomous AI Agent Communication | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0120 | AI Artifact Repository | infra effect covered by another entry |
| AML.T0123 | Obfuscated Files or Information | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0125 | Create Account | infra effect covered by another entry |
| AML.T0126 | Automated Collection | host-level data; see the node entries |
| AML.T0127 | Data Staged | host-level data; see the node entries |
| AML.T0128 | Compromise Infrastructure | off-system OSINT / attacker-side (not on customer infra) |
| AML.T0129 | Triggers in Multimodal Inputs | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0130 | AI Agent Response Biasing | in-request attack; no persisted infra state -> inline filter / partner |
| AML.T0131 | Crafted AI Assistant Links | social/lure; foothold (if any) covered by initial-access entries |
| AML.T0134 | AI Targeted Cloaking | in-request attack; no persisted infra state -> inline filter / partner |
| T1001 | Data Obfuscation | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1003 | OS Credential Dumping | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1005 | Data from Local System | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1007 | System Service Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1008 | Fallback Channels | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1010 | Application Window Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1011 | Exfiltration Over Other Network Medium | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1014 | Rootkit | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1016 | System Network Configuration Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1018 | Remote System Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1020 | Automated Exfiltration | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1021 | Remote Services | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1025 | Data from Removable Media | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1027 | Obfuscated Files or Information | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1029 | Scheduled Transfer | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1030 | Data Transfer Size Limits | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1033 | System Owner/User Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1037 | Boot or Logon Initialization Scripts | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1039 | Data from Network Shared Drive | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1040 | Network Sniffing | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1041 | Exfiltration Over C2 Channel | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1048 | Exfiltration Over Alternative Protocol | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1049 | System Network Connections Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1052 | Exfiltration Over Physical Medium | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1055 | Process Injection | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1056 | Input Capture | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1057 | Process Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1071 | Application Layer Protocol | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1072 | Software Deployment Tools | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1074 | Data Staged | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1080 | Taint Shared Content | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1082 | System Information Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1083 | File and Directory Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1087 | Account Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1090 | Proxy | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1092 | Communication Through Removable Media | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1095 | Non-Application Layer Protocol | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1102 | Web Service | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1104 | Multi-Stage Channels | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1105 | Ingress Tool Transfer | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1106 | Native API | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1111 | Multi-Factor Authentication Interception | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1113 | Screen Capture | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1114 | Email Collection | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1115 | Clipboard Data | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1119 | Automated Collection | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1120 | Peripheral Device Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1123 | Audio Capture | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1124 | System Time Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1125 | Video Capture | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1129 | Shared Modules | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1132 | Data Encoding | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1135 | Network Share Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1140 | Deobfuscate/Decode Files or Information | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1176 | Software Extensions | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1189 | Drive-by Compromise | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1195 | Supply Chain Compromise | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1199 | Trusted Relationship | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1200 | Hardware Additions | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1201 | Password Policy Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1203 | Exploitation for Client Execution | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1205 | Traffic Signaling | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1210 | Exploitation of Remote Services | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1211 | Exploitation for Stealth | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1212 | Exploitation for Credential Access | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1213 | Data from Information Repositories | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1217 | Browser Information Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1218 | System Binary Proxy Execution | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1219 | Remote Access Tools | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1222 | File and Directory Permissions Modification | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1480 | Execution Guardrails | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1486 | Data Encrypted for Impact | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1489 | Service Stop | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1491 | Defacement | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1495 | Firmware Corruption | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1497 | Virtualization/Sandbox Evasion | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1505 | Server Software Component | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1518 | Software Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1526 | Cloud Service Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1529 | System Shutdown/Reboot | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1530 | Data from Cloud Storage | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1531 | Account Access Removal | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1534 | Internal Spearphishing | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1535 | Unused/Unsupported Cloud Regions | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1537 | Transfer Data to Cloud Account | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1538 | Cloud Service Dashboard | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1539 | Steal Web Session Cookie | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1542 | Pre-OS Boot | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1546 | Event Triggered Execution | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1547 | Boot or Logon Autostart Execution | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1548 | Abuse Elevation Control Mechanism | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1553 | Subvert Trust Controls | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1554 | Compromise Host Software Binary | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1555 | Credentials from Password Stores | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1556 | Modify Authentication Process | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1557 | Adversary-in-the-Middle | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1558 | Steal or Forge Kerberos Tickets | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1559 | Inter-Process Communication | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1560 | Archive Collected Data | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1561 | Disk Wipe | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1563 | Remote Service Session Hijacking | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1564 | Hide Artifacts | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1565 | Data Manipulation | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1566 | Phishing | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1567 | Exfiltration Over Web Service | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1568 | Dynamic Resolution | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1569 | System Services | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1570 | Lateral Tool Transfer | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1571 | Non-Standard Port | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1572 | Protocol Tunneling | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1573 | Encrypted Channel | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1574 | Hijack Execution Flow | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1578 | Modify Cloud Compute Infrastructure | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1580 | Cloud Infrastructure Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1606 | Forge Web Credentials | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1614 | System Location Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1619 | Cloud Storage Object Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1620 | Reflective Code Loading | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1621 | Multi-Factor Authentication Request Generation | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1622 | Debugger Evasion | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1648 | Serverless Execution | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1649 | Steal or Forge Authentication Certificates | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1651 | Cloud Administration Command | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1652 | Device Driver Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1653 | Power Settings | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1654 | Log Enumeration | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1657 | Financial Theft | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1659 | Content Injection | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1665 | Hide Infrastructure | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1666 | Modify Cloud Resource Hierarchy | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1667 | Email Bombing | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1668 | Exclusive Control | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1669 | Wi-Fi Networks | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1673 | Virtual Machine Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1674 | Input Injection | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1678 | Delay Execution | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1680 | Local Storage Discovery | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1684 | Social Engineering | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1686 | Disable or Modify System Firewall | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1687 | Exploitation for Defense Impairment | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1689 | Downgrade Attack | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| T1690 | Prevent Command History Logging | ATT&CK on IaaS/Linux but no K8s-control-plane end-state (host/cloud-level; see node/identity entries) |
| MS-DE-connect-from-proxy-ser | Connect from proxy server | host/proxy-level; no K8s-control-plane end-state |
| LLM01:2025 | Prompt Injection | in-request / governance; no movable infra state |
| LLM02:2025 | Sensitive Information Disclosure | in-request / governance; no movable infra state |
| LLM05:2025 | Improper Output Handling | in-request / governance; no movable infra state |
| LLM07:2025 | System Prompt Leakage | in-request / governance; no movable infra state |
| LLM09:2025 | Misinformation | in-request / governance; no movable infra state |
| ASI01:2026 | Agent Goal Hijack | in-request / governance; no movable infra state |
| ASI09:2026 | Human-Agent Trust Exploitation | in-request / governance; no movable infra state |
| MCP06:2025 | Prompt Injection via Contextual Payloads | in-request / governance; no movable infra state |
| MCP08:2025 | Lack of Audit and Telemetry | in-request / governance; no movable infra state |
| NIST-PredAI-evasion | Evasion (adversarial examples) | in-request; see ATLAS AML.T0015 |
| NIST-PredAI-priv-membership | Privacy — membership inference | in-request inference; no infra end-state |
| NIST-PredAI-priv-property | Privacy — property inference | in-request inference; no infra end-state |
| NIST-GenAI-direct-inject | GenAI — direct prompt injection | in-request; inline filter / partner |
| NIST-GenAI-abuse | GenAI — abuse/misuse | governance; no movable infra state |
| AVID-SEC-leak | Security — information leak | in-request/privacy; see NIST privacy pointers |
| AVID-SEC-evasion | Security — evasion | in-request; see ATLAS AML.T0015 |

*(+211 out-of-scope ATLAS sub-techniques in the CSV/YAML.)*

## Preconditions vocabulary (CIS / NSA-CISA)

`public-exposure` · `privileged-pod` · `hostpath-mount` · `host-namespace` · `overbroad-rbac` · `cluster-admin-binding` · `mounted-sa-token` · `plaintext-secret` · `no-networkpolicy` · `no-image-signing` · `mutable-tag` · `serves-model` · `has-agent` · `has-mcp-tools` · `uses-rag` · `workload-present` · `automated-pipeline`. The scan (WS-1) sets these per workload; an entry applies when its preconditions hold.

## Caveats for review (hand to Zeinab + AI engineer)

- `actuator_status` and `preconditions` are a first pass from the code and the CIS/NSA categories — confirm per entry.
- NIST AI 100-2 rows are taxonomy pointers to the ATLAS entries that carry the infra end-state, not duplicates.
- OWASP Agentic/MCP IDs are pinned to the published lists; re-check against the OWASP GenAI repo at build time.
