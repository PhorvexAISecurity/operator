# MITRE ATT&CK for Containers — Coverage Matrix (ATTACK-COVERAGE-K8S)

Coverage of the **MITRE ATT&CK for Containers** matrix by the 18 harness
scenarios, organized **tactic x technique** so coverage gaps are visible. Each
technique is marked **TESTED** (exercised by >= 1 scenario) or **NOT TESTED**, with
the exact scenario -> technique mapping.

**Generated from the full ≥20-trial benchmark:**
`build/test-harness/out-bench/mitre_matrix.md` reports **38 techniques exercised
across 18 scenarios** (the technique→scenario mapping is independent of trial count;
it is fixed by each scenario's `AttackTechniqueIDs` metadata). The per-technique
scenario lists below are the harness's own emitted mapping; the per-tactic framing
and the gap list come from the locked ATT&CK matrix + the harness coverage report.

Legend: ✅ TESTED — at least one scenario exercises the technique · ⬜ NOT TESTED.

---

## Coverage by tactic

### Initial Access

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | ⬜ NOT TESTED | — |
| T1133 | External Remote Services | ✅ TESTED | c2-dwell-rotation |
| T1078 | Valid Accounts | ✅ TESTED | c3-secrets-sprawl |
| T1078.001 | Valid Accounts: Default Accounts | ✅ TESTED | c1-credtheft-rbac, c3-admission-bypass |
| T1078.003 | Valid Accounts: Local Accounts | ✅ TESTED | c2-dwell-rotation |

### Execution

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1059 | Command and Scripting Interpreter | ✅ TESTED (via .013) | see T1059.013 |
| T1059.013 | Command/Scripting: Container CLI/API | ✅ TESTED | c1-escape-persist, c1-lateral, c2-persistence-evict, c3-cryptomining |
| T1609 | Container Administration Command | ✅ TESTED | c1-lateral, c2-lateral-disrupt |
| T1610 | Deploy Container | ✅ TESTED | c1-escape-persist, c2-supplychain-foothold, c3-admission-bypass, c3-cicd, c3-cryptomining, c3-sidecar-inject, c3-supplychain |
| T1053 | Scheduled Task/Job | ✅ TESTED (via .007) | see T1053.007 |
| T1053.007 | Scheduled Task/Job: Container Orchestration Job | ✅ TESTED | c3-cicd |
| T1204 | User Execution | ✅ TESTED (via .003) | see T1204.003 |
| T1204.003 | User Execution: Malicious Image | ✅ TESTED | c2-supplychain-foothold, c3-cicd, c3-supplychain |

### Persistence

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1098 | Account Manipulation | ⬜ NOT TESTED | — |
| T1098.006 | Account Manipulation: Additional Container Cluster Roles | ⬜ NOT TESTED | — |
| T1136 | Create Account | ⬜ NOT TESTED | — |
| T1136.001 | Create Account: Local Account | ⬜ NOT TESTED | — |
| T1543 | Create or Modify System Process | ✅ TESTED (via .005) | see T1543.005 |
| T1543.005 | Create/Modify System Process: Container Service | ✅ TESTED | c1-escape-persist, c2-dwell-rotation, c2-persistence-evict, c2-supplychain-foothold, c3-sidecar-inject |
| T1133 | External Remote Services | ✅ TESTED | c2-dwell-rotation |
| T1525 | Implant Internal Image | ✅ TESTED | c1-escape-persist, c2-dwell-rotation, c2-supplychain-foothold, c3-cicd, c3-sidecar-inject, c3-supplychain |
| T1053.007 | Scheduled Task/Job: Container Orchestration Job | ✅ TESTED | c3-cicd |
| T1078.001 | Valid Accounts: Default Accounts | ✅ TESTED | c1-credtheft-rbac, c3-admission-bypass |
| T1078.003 | Valid Accounts: Local Accounts | ✅ TESTED | c2-dwell-rotation |

### Privilege Escalation

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1098.006 | Account Manipulation: Additional Container Cluster Roles | ⬜ NOT TESTED | — |
| T1543.005 | Create/Modify System Process: Container Service | ✅ TESTED | c1-escape-persist, c2-dwell-rotation, c2-persistence-evict, c2-supplychain-foothold, c3-sidecar-inject |
| T1611 | Escape to Host | ✅ TESTED | c1-escape-persist, c2-persistence-evict, c3-admission-bypass, c3-sidecar-inject |
| T1068 | Exploitation for Privilege Escalation | ✅ TESTED | c1-escape-persist, c3-admission-bypass |
| T1053.007 | Scheduled Task/Job: Container Orchestration Job | ✅ TESTED | c3-cicd |
| T1078.001 | Valid Accounts: Default Accounts | ✅ TESTED | c1-credtheft-rbac, c3-admission-bypass |
| T1612 | Build Image on Host | ✅ TESTED | c3-supplychain |

### Defense Evasion

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1070 | Indicator Removal | ✅ TESTED | c1-stealth-dweller, c2-persistence-evict |
| T1036 | Masquerading | ✅ TESTED (via .005) | see T1036.005 |
| T1036.005 | Masquerading: Match Legitimate Name/Location | ✅ TESTED | c1-stealth-dweller |
| T1036.010 | Masquerading: Masquerade Account Name | ⬜ NOT TESTED | — |
| T1685 | Disable or Modify Tools | ✅ TESTED | c1-stealth-dweller |
| T1564 | Hide Artifacts | ✅ TESTED | c1-stealth-dweller |
| T1078.001 | Valid Accounts: Default Accounts | ✅ TESTED | c1-credtheft-rbac, c3-admission-bypass |

### Credential Access

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1110 | Brute Force | ⬜ NOT TESTED | — |
| T1110.001 | Brute Force: Password Guessing | ⬜ NOT TESTED | — |
| T1110.003 | Brute Force: Password Spraying | ⬜ NOT TESTED | — |
| T1110.004 | Brute Force: Credential Stuffing | ⬜ NOT TESTED | — |
| T1528 | Steal Application Access Token | ✅ TESTED | c1-credtheft-rbac, c3-imds-theft, c3-secrets-sprawl |
| T1552 | Unsecured Credentials | ✅ TESTED (via .001/.005/.007) | see subtechniques |
| T1552.001 | Unsecured Credentials: Credentials In Files | ✅ TESTED | c1-credtheft-rbac, c3-secrets-sprawl |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | ✅ TESTED | c3-imds-theft |
| T1552.007 | Unsecured Credentials: Container API | ✅ TESTED | c1-credtheft-rbac, c3-imds-theft, c3-secrets-sprawl |

### Discovery

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1613 | Container and Resource Discovery | ✅ TESTED | c1-lateral, c2-recon-window |
| T1046 | Network Service Discovery | ✅ TESTED | c1-lateral, c2-lateral-disrupt, c2-recon-window |
| T1069 | Permission Groups Discovery | ✅ TESTED | c1-credtheft-rbac, c2-recon-window |
| T1526 | Cloud Service Discovery | ✅ TESTED | c2-recon-window |

### Lateral Movement

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1550 | Use Alternate Authentication Material | ✅ TESTED (via .001) | see T1550.001 |
| T1550.001 | Use Alt Auth Material: Application Access Token | ✅ TESTED | c1-credtheft-rbac, c1-lateral, c2-lateral-disrupt |
| T1021 | Remote Services | ✅ TESTED | c2-lateral-disrupt |

### Collection / Command & Control / Exfiltration (container-relevant)

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1071 | Application Layer Protocol | ✅ TESTED | c1-c2-exfil, c2-c2-disrupt |
| T1573 | Encrypted Channel | ✅ TESTED | c2-c2-disrupt |
| T1008 | Fallback Channels | ✅ TESTED | c2-c2-disrupt |
| T1105 | Ingress Tool Transfer | ✅ TESTED | c2-c2-disrupt |
| T1041 | Exfiltration Over C2 Channel | ✅ TESTED | c1-c2-exfil |
| T1048 | Exfiltration Over Alternative Protocol | ✅ TESTED | c1-c2-exfil |
| T1567 | Exfiltration Over Web Service | ✅ TESTED | c1-c2-exfil |
| T1029 | Scheduled Transfer | ✅ TESTED | c1-c2-exfil |

### Impact

| Technique | Name | Status | Scenarios |
|---|---|---|---|
| T1485 | Data Destruction | ⬜ NOT TESTED | — |
| T1499 | Endpoint Denial of Service | ⬜ NOT TESTED | — |
| T1490 | Inhibit System Recovery | ⬜ NOT TESTED | — |
| T1498 | Network Denial of Service | ⬜ NOT TESTED | — |
| T1496 | Resource Hijacking | ✅ TESTED (via .001) | see T1496.001 |
| T1496.001 | Resource Hijacking: Compute Hijacking | ✅ TESTED | c3-cryptomining |
| T1496.002 | Resource Hijacking: Bandwidth Hijacking | ⬜ NOT TESTED | — |

---

## Coverage gaps (NOT TESTED — intentional or environment-limited)

From the harness coverage report (`coverageNotTested`):

- **T1190** Exploit Public-Facing Application — no public-facing-exploit scenario in this set.
- **T1110 / .001 / .003 / .004** Brute Force family — out of scope for the rotation-vs-oracle question.
- **T1098 / .006** Account Manipulation, **T1136 / .001** Create Account, **T1036.010** Masquerade Account Name — persistence/evasion variants not in the current 18.
- **T1485** Data Destruction, **T1490** Inhibit System Recovery, **T1498** Network DoS, **T1499** Endpoint DoS, **T1496.002** Bandwidth Hijacking — Impact-tactic variants not exercised.
- **GPU/MIG-specific techniques** — **capability-pending** environment gap: the
  single-node CPU-only kind cluster reports GPU=false, MIG=false, MultiNode=false
  (`NodeCount=1`). GPU micro-shuffling / MIG-slice reassignment / NIM GPU-hardening
  variants are reported capability-pending, **not fabricated**. The CPU-bounded
  miner (c3-cryptomining, T1496.001) WAS run as the resource-hijacking proxy.

---

## Coverage summary

- **38 techniques exercised** across the 18 scenarios (parent techniques counted
  when any sub-technique is exercised).
- **Tactic breadth:** Initial Access, Execution, Persistence, Privilege Escalation,
  Defense Evasion, Credential Access, Discovery, Lateral Movement,
  Command & Control, Exfiltration, and Impact (Compute Hijacking) all have at least
  one tested technique.
- **Known untested areas:** Brute Force, Account Manipulation / Create Account,
  most Impact variants (Data Destruction, DoS, Bandwidth Hijacking), Exploit
  Public-Facing Application, and all GPU/MIG-specific techniques (capability-pending
  on this cluster).

Every per-technique mapping above is the harness's own emitted matrix
(`build/test-harness/out-bench/mitre_matrix.md`), reproducible from
`masterSeed=1337` and traceable via `build/test-harness/out-bench/provenance.json`.
