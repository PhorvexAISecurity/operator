# MITRE ATT&CK for Containers — Coverage Matrix

53 techniques exercised across 52 scenarios.

| Technique | Name | Scenarios |
|---|---|---|
| T1008 | Fallback Channels | c2-c2-disrupt |
| T1021 | Remote Services | c2-lateral-disrupt |
| T1029 | Scheduled Transfer | c1-c2-exfil |
| T1036.005 | Masquerading: Match Legitimate Name/Location | c1-stealth-dweller |
| T1041 | Exfiltration Over C2 Channel | ai1-model-theft, ai2-query-extraction, c1-c2-exfil, c1-fast-attacker |
| T1046 | Network Service Discovery | c1-lateral, c2-lateral-disrupt, c2-recon-window |
| T1048 | Exfiltration Over Alternative Protocol | c1-c2-exfil |
| T1053.007 | Scheduled Task/Job: Container Orchestration Job | c3-cicd |
| T1059.013 | Command/Scripting: Container CLI/API | ai1-llm-jacking, ai1-pillar03-panic-mutation, ai1-prompt-injection, ai2-agent-excessive-agency, ai2-agent-injection-to-persistence, ai2-agent-memory-contamination, ai2-agent-rogue-tool-persistence, ai2-excessive-agency, ai2-mcp-rogue-server, ai2-mcp-tool-poisoning, ai2-mcp-tool-response-injection, c1-escape-persist, c1-lateral, c2-persistence-evict, c3-cryptomining |
| T1068 | Exploitation for Privilege Escalation | c1-escape-persist, c1-heldout-cve, c3-admission-bypass |
| T1069 | Permission Groups Discovery | c1-credtheft-rbac, c2-recon-window |
| T1070 | Indicator Removal | c1-stealth-dweller, c2-persistence-evict |
| T1070.004 |  | c1-llm-adaptive |
| T1071 | Application Layer Protocol | c1-c2-exfil, c2-c2-disrupt |
| T1078 | Valid Accounts | ai2-agent-excessive-agency, ai2-excessive-agency, b-recon-lifetime, c3-secrets-sprawl, e-dilution-n9 |
| T1078.001 | Valid Accounts: Default Accounts | c1-credtheft-rbac, c3-admission-bypass |
| T1078.003 | Valid Accounts: Local Accounts | c2-dwell-rotation |
| T1078.004 | Valid Accounts: Cloud Accounts | b-recon-lifetime-ai, c3-imds-theft |
| T1105 | Ingress Tool Transfer | c2-c2-disrupt |
| T1133 | External Remote Services | c2-dwell-rotation |
| T1190 | Exploit Public-Facing Application | c1-fast-attacker, c1-heldout-cve |
| T1195 |  | ai2-agent-rogue-tool-persistence, ai2-data-model-poisoning, ai2-mcp-tool-poisoning, ai2-poisoned-model-registry, ai2-rag-retrieval-poisoning |
| T1204.003 | User Execution: Malicious Image | ai2-malicious-model-artifact, ai2-tampered-inference-base-image, c2-supplychain-foothold, c3-cicd, c3-supplychain |
| T1486 |  | c1-fast-attacker, c2-stateful-training |
| T1496 | Resource Hijacking | c2-stateful-training |
| T1496.001 | Resource Hijacking: Compute Hijacking | ai1-llm-jacking, ai2-unbounded-consumption, c3-cryptomining |
| T1499 | Endpoint Denial of Service | ai2-unbounded-consumption |
| T1525 | Implant Internal Image | ai2-malicious-model-artifact, ai2-poisoned-model-registry, ai2-tampered-inference-base-image, c1-escape-persist, c2-dwell-rotation, c2-supplychain-foothold, c3-cicd, c3-sidecar-inject, c3-supplychain |
| T1526 | Cloud Service Discovery | c2-recon-window |
| T1528 | Steal Application Access Token | c1-credtheft-rbac, c3-imds-theft, c3-secrets-sprawl |
| T1530 |  | ai1-model-theft, ai2-co-location-cross-tenant, ai2-embedding-store-tampering, ai2-embedding-vector-weakness, ai2-gpu-side-channel, ai2-kvcache-poisoning-cross-session-leak, ai2-query-extraction, ai2-sensitive-info-disclosure, ai2-system-prompt-leakage, b-recon-lifetime-ai |
| T1543.005 | Create/Modify System Process: Container Service | ai2-agent-injection-to-persistence, c1-escape-persist, c1-heldout-cve, c1-llm-adaptive, c2-dwell-rotation, c2-persistence-evict, c2-stateful-training, c2-supplychain-foothold, c3-sidecar-inject |
| T1550.001 | Use Alt Auth Material: Application Access Token | c1-credtheft-rbac, c1-lateral, c2-lateral-disrupt |
| T1552 | Unsecured Credentials | ai2-sensitive-info-disclosure, ai2-system-prompt-leakage |
| T1552.001 | Unsecured Credentials: Credentials In Files | c1-credtheft-rbac, c3-secrets-sprawl |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | c3-imds-theft |
| T1552.007 | Unsecured Credentials: Container API | c1-credtheft-rbac, c3-imds-theft, c3-secrets-sprawl |
| T1557 |  | ai1-inference-manipulation, ai2-mcp-rogue-server |
| T1564 | Hide Artifacts | c1-stealth-dweller |
| T1565 |  | ai1-pillar03-panic-mutation, ai1-prompt-injection, ai2-agent-memory-contamination, ai2-embedding-store-tampering, ai2-embedding-vector-weakness, ai2-kvcache-poisoning-cross-session-leak, ai2-mcp-tool-response-injection, ai2-rag-retrieval-poisoning |
| T1565.001 |  | ai2-data-model-poisoning |
| T1565.002 |  | ai1-inference-manipulation |
| T1567 | Exfiltration Over Web Service | ai1-model-theft, c1-c2-exfil |
| T1573 | Encrypted Channel | c2-c2-disrupt |
| T1590 |  | b-recon-lifetime, b-recon-lifetime-ai, e-dilution-n9 |
| T1592 |  | b-recon-lifetime |
| T1595 |  | c1-llm-adaptive |
| T1609 | Container Administration Command | c1-lateral, c2-lateral-disrupt |
| T1610 | Deploy Container | ai1-llm-jacking, ai1-pillar03-panic-mutation, ai2-co-location-cross-tenant, c1-escape-persist, c2-supplychain-foothold, c3-admission-bypass, c3-cicd, c3-cryptomining, c3-sidecar-inject, c3-supplychain |
| T1611 | Escape to Host | c1-escape-persist, c2-persistence-evict, c3-admission-bypass, c3-sidecar-inject |
| T1612 | Build Image on Host | c3-supplychain |
| T1613 | Container and Resource Discovery | c1-lateral, c2-recon-window |
| T1685 | Disable or Modify Tools | c1-stealth-dweller |
