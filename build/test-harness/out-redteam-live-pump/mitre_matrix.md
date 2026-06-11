# MITRE ATT&CK for Containers — Coverage Matrix

136 techniques exercised across 106 scenarios.

| Technique | Name | Scenarios |
|---|---|---|
| AML.T0002 |  | ai2-embedding-vector-weakness-apt |
| AML.T0003 |  | ai2-data-model-poisoning-apt, ai2-poisoned-model-registry-apt |
| AML.T0006 |  | b-recon-lifetime-ai-apt |
| AML.T0007 |  | ai2-co-location-cross-tenant-apt, ai2-embedding-store-tampering-apt, ai2-embedding-vector-weakness-apt, ai2-gpu-side-channel-apt, ai2-kvcache-poisoning-cross-session-leak-apt, ai2-mcp-rogue-server-apt, ai2-mcp-tool-poisoning-apt, ai2-mcp-tool-response-injection-apt, ai2-rag-retrieval-poisoning-apt, b-recon-lifetime-ai-apt |
| AML.T0010 |  | ai2-poisoned-model-registry-apt, ai2-tampered-inference-base-image-apt |
| AML.T0010.001 |  | ai2-tampered-inference-base-image-apt |
| AML.T0010.002 |  | ai2-mcp-rogue-server-apt, ai2-mcp-tool-poisoning-apt, ai2-mcp-tool-response-injection-apt, ai2-poisoned-model-registry-apt |
| AML.T0011 |  | ai1-llm-jacking-apt |
| AML.T0015 |  | ai1-inference-manipulation-apt |
| AML.T0018 |  | ai2-data-model-poisoning-apt |
| AML.T0019 |  | ai2-data-model-poisoning-apt |
| AML.T0020 |  | ai1-pillar03-panic-mutation-apt, ai2-agent-rogue-tool-persistence-apt, ai2-data-model-poisoning-apt, ai2-embedding-store-tampering-apt |
| AML.T0024 |  | ai1-inference-manipulation-apt, ai2-embedding-store-tampering-apt, ai2-embedding-vector-weakness-apt, ai2-gpu-side-channel-apt, ai2-kvcache-poisoning-cross-session-leak-apt, ai2-mcp-tool-poisoning-apt, ai2-mcp-tool-response-injection-apt |
| AML.T0024.000 |  | ai2-query-extraction-apt, ai2-sensitive-info-disclosure-apt |
| AML.T0024.001 |  | ai1-llm-jacking-apt, ai2-co-location-cross-tenant-apt, ai2-embedding-store-tampering-apt, ai2-gpu-side-channel-apt, ai2-kvcache-poisoning-cross-session-leak-apt |
| AML.T0024.002 |  | ai1-model-theft-apt, ai2-co-location-cross-tenant-apt, ai2-query-extraction-apt, ai2-unbounded-consumption-apt, b-recon-lifetime-ai-apt |
| AML.T0029 |  | ai2-unbounded-consumption-apt, c3-cryptomining-apt |
| AML.T0031 |  | ai1-pillar03-panic-mutation-apt |
| AML.T0034 |  | ai1-llm-jacking-apt, ai2-unbounded-consumption-apt, c3-cryptomining-apt |
| AML.T0035 |  | ai1-model-theft-apt, ai2-gpu-side-channel-apt, ai2-kvcache-poisoning-cross-session-leak-apt, ai2-query-extraction-apt, b-recon-lifetime-ai-apt |
| AML.T0037 |  | ai1-model-theft-apt |
| AML.T0040 |  | ai1-inference-manipulation-apt, ai1-model-theft-apt, ai2-gpu-side-channel-apt, ai2-query-extraction-apt, b-recon-lifetime-ai-apt |
| AML.T0044 |  | ai2-embedding-vector-weakness-apt, ai2-gpu-side-channel-apt |
| AML.T0047 |  | ai1-inference-manipulation-apt |
| AML.T0048 |  | ai2-agent-excessive-agency-apt, ai2-agent-rogue-tool-persistence-apt, ai2-excessive-agency-apt |
| AML.T0051 |  | ai1-pillar03-panic-mutation-apt, ai1-prompt-injection-apt, ai2-agent-injection-to-persistence-apt, ai2-agent-memory-contamination-apt, ai2-kvcache-poisoning-cross-session-leak-apt, ai2-mcp-rogue-server-apt, ai2-mcp-tool-poisoning-apt, ai2-mcp-tool-response-injection-apt, ai2-system-prompt-leakage-apt |
| AML.T0051.000 |  | ai1-prompt-injection-apt |
| AML.T0051.001 |  | ai1-prompt-injection-apt |
| AML.T0053 |  | ai2-agent-excessive-agency-apt, ai2-agent-rogue-tool-persistence-apt, ai2-excessive-agency-apt, ai2-mcp-tool-poisoning-apt |
| AML.T0054 |  | ai1-prompt-injection-apt, ai2-agent-excessive-agency-apt, ai2-agent-injection-to-persistence-apt, ai2-agent-memory-contamination-apt, ai2-excessive-agency-apt, ai2-mcp-tool-response-injection-apt |
| AML.T0055 |  | c3-secrets-sprawl-apt |
| AML.T0056 |  | ai2-system-prompt-leakage-apt |
| AML.T0057 |  | ai2-sensitive-info-disclosure-apt |
| AML.T0061 |  | ai1-prompt-injection-apt, ai2-agent-injection-to-persistence-apt, ai2-agent-memory-contamination-apt |
| AML.T0070 |  | ai2-agent-memory-contamination-apt |
| T1005 |  | c2-stateful-training-apt |
| T1008 | Fallback Channels | c2-c2-disrupt, c2-c2-disrupt-apt |
| T1018 |  | b-recon-lifetime-apt, c1-lateral-apt, c2-recon-window-apt |
| T1021 | Remote Services | ai2-malicious-model-artifact-apt, ai2-mcp-rogue-server-apt, c1-heldout-cve-apt, c1-lateral-apt, c2-lateral-disrupt, c2-lateral-disrupt-apt |
| T1027 |  | c1-llm-adaptive-apt, c2-dwell-rotation-apt |
| T1027.001 |  | c2-supplychain-foothold-apt |
| T1029 | Scheduled Transfer | c1-c2-exfil, c1-c2-exfil-apt |
| T1030 |  | ai1-model-theft-apt, c1-c2-exfil-apt, c2-c2-disrupt-apt |
| T1036 | Masquerading | c1-llm-adaptive-apt |
| T1036.005 | Masquerading: Match Legitimate Name/Location | apt-dispersion-steer-live, c1-stealth-dweller, c1-stealth-dweller-apt |
| T1041 | Exfiltration Over C2 Channel | ai1-inference-manipulation-apt, ai1-model-theft, ai1-model-theft-apt, ai2-co-location-cross-tenant-apt, ai2-embedding-vector-weakness-apt, ai2-gpu-side-channel-apt, ai2-kvcache-poisoning-cross-session-leak-apt, ai2-malicious-model-artifact-apt, ai2-mcp-rogue-server-apt, ai2-mcp-tool-poisoning-apt, ai2-mcp-tool-response-injection-apt, ai2-poisoned-model-registry-apt, ai2-query-extraction, ai2-query-extraction-apt, ai2-rag-retrieval-poisoning-apt, ai2-sensitive-info-disclosure-apt, ai2-system-prompt-leakage-apt, ai2-tampered-inference-base-image-apt, c1-c2-exfil, c1-c2-exfil-apt, c1-fast-attacker, c1-fast-attacker-apt, c1-heldout-cve-apt, c1-stealth-dweller-apt, c2-c2-disrupt-apt, c3-cicd-apt, c3-imds-theft-apt, c3-secrets-sprawl-apt, c3-sidecar-inject-apt, c3-supplychain-apt |
| T1046 | Network Service Discovery | c1-lateral, c1-lateral-apt, c2-lateral-disrupt, c2-lateral-disrupt-apt, c2-recon-window, c2-recon-window-apt |
| T1048 | Exfiltration Over Alternative Protocol | c1-c2-exfil, c1-c2-exfil-apt |
| T1053.003 |  | c1-escape-persist-apt, c3-cryptomining-apt |
| T1053.005 |  | c2-dwell-rotation-apt |
| T1053.007 | Scheduled Task/Job: Container Orchestration Job | c3-cicd, c3-cicd-apt |
| T1059 | Command and Scripting Interpreter | ai2-malicious-model-artifact-apt |
| T1059.013 | Command/Scripting: Container CLI/API | ai1-llm-jacking, ai1-llm-jacking-apt, ai1-pillar03-panic-mutation, ai1-pillar03-panic-mutation-apt, ai1-prompt-injection, ai1-prompt-injection-apt, ai2-agent-excessive-agency, ai2-agent-excessive-agency-apt, ai2-agent-injection-to-persistence, ai2-agent-injection-to-persistence-apt, ai2-agent-memory-contamination, ai2-agent-memory-contamination-apt, ai2-agent-rogue-tool-persistence, ai2-agent-rogue-tool-persistence-apt, ai2-excessive-agency, ai2-excessive-agency-apt, ai2-mcp-rogue-server, ai2-mcp-rogue-server-apt, ai2-mcp-tool-poisoning, ai2-mcp-tool-poisoning-apt, ai2-mcp-tool-response-injection, ai2-mcp-tool-response-injection-apt, c1-escape-persist, c1-escape-persist-apt, c1-heldout-cve-apt, c1-lateral, c2-persistence-evict, c2-persistence-evict-apt, c3-cryptomining, c3-cryptomining-apt |
| T1068 | Exploitation for Privilege Escalation | c1-escape-persist, c1-escape-persist-apt, c1-heldout-cve, c1-heldout-cve-apt, c3-admission-bypass, c3-admission-bypass-apt |
| T1069 | Permission Groups Discovery | c1-credtheft-rbac, c2-recon-window, c2-recon-window-apt |
| T1069.002 |  | c3-admission-bypass-apt |
| T1069.003 |  | c1-credtheft-rbac-apt |
| T1070 | Indicator Removal | c1-stealth-dweller, c1-stealth-dweller-apt, c2-persistence-evict |
| T1070.004 |  | c1-llm-adaptive, c1-llm-adaptive-apt, c2-persistence-evict-apt |
| T1070.006 |  | c1-stealth-dweller-apt |
| T1071 | Application Layer Protocol | c1-c2-exfil, c1-c2-exfil-apt, c2-c2-disrupt |
| T1071.001 |  | ai1-inference-manipulation-apt, ai1-model-theft-apt, c1-c2-exfil-apt, c2-c2-disrupt-apt, c3-sidecar-inject-apt, c3-supplychain-apt |
| T1074 |  | c1-c2-exfil-apt, c1-heldout-cve-apt, c1-lateral-apt |
| T1078 | Valid Accounts | ai1-prompt-injection-apt, ai2-agent-excessive-agency, ai2-agent-excessive-agency-apt, ai2-data-model-poisoning-apt, ai2-embedding-store-tampering-apt, ai2-embedding-vector-weakness-apt, ai2-excessive-agency, ai2-excessive-agency-apt, ai2-kvcache-poisoning-cross-session-leak-apt, ai2-poisoned-model-registry-apt, ai2-rag-retrieval-poisoning-apt, ai2-sensitive-info-disclosure-apt, ai2-system-prompt-leakage-apt, b-recon-lifetime, b-recon-lifetime-apt, c3-secrets-sprawl, c3-secrets-sprawl-apt, e-dilution-fleet-apt, e-dilution-n9 |
| T1078.001 | Valid Accounts: Default Accounts | c1-credtheft-rbac, c1-credtheft-rbac-apt, c3-admission-bypass, c3-admission-bypass-apt |
| T1078.003 | Valid Accounts: Local Accounts | c2-dwell-rotation, c2-dwell-rotation-apt, c2-lateral-disrupt-apt, c2-persistence-evict-apt, c2-recon-window-apt |
| T1078.004 | Valid Accounts: Cloud Accounts | ai1-llm-jacking-apt, ai2-co-location-cross-tenant-apt, ai2-malicious-model-artifact-apt, ai2-tampered-inference-base-image-apt, ai2-unbounded-consumption-apt, apt-dispersion-steer-live, apt-lambda-pump-live, b-recon-lifetime-ai, b-recon-lifetime-ai-apt, c1-credtheft-rbac-apt, c3-cicd-apt, c3-imds-theft, c3-imds-theft-apt |
| T1082 |  | c1-escape-persist-apt, c1-stealth-dweller-apt |
| T1098 | Account Manipulation | ai2-agent-excessive-agency-apt, ai2-excessive-agency-apt |
| T1098.001 |  | c1-credtheft-rbac-apt, c3-imds-theft-apt, c3-sidecar-inject-apt |
| T1098.003 |  | c3-imds-theft-apt |
| T1102 |  | c2-c2-disrupt-apt |
| T1105 | Ingress Tool Transfer | c2-c2-disrupt, c2-c2-disrupt-apt |
| T1110.003 |  | c3-secrets-sprawl-apt |
| T1133 | External Remote Services | c2-dwell-rotation, c2-dwell-rotation-apt |
| T1136.003 |  | c1-credtheft-rbac-apt |
| T1190 | Exploit Public-Facing Application | ai2-embedding-store-tampering-apt, ai2-rag-retrieval-poisoning-apt, c1-fast-attacker, c1-fast-attacker-apt, c1-heldout-cve, c1-heldout-cve-apt |
| T1195 |  | ai2-agent-rogue-tool-persistence, ai2-agent-rogue-tool-persistence-apt, ai2-data-model-poisoning, ai2-mcp-tool-poisoning, ai2-mcp-tool-poisoning-apt, ai2-poisoned-model-registry, ai2-poisoned-model-registry-apt, ai2-rag-retrieval-poisoning, ai2-rag-retrieval-poisoning-apt |
| T1195.001 |  | ai2-data-model-poisoning-apt |
| T1195.002 |  | ai2-malicious-model-artifact-apt, ai2-poisoned-model-registry-apt, ai2-tampered-inference-base-image-apt, c2-supplychain-foothold-apt, c3-cicd-apt, c3-sidecar-inject-apt, c3-supplychain-apt |
| T1199 |  | ai2-data-model-poisoning-apt, ai2-mcp-rogue-server-apt, ai2-mcp-tool-poisoning-apt, ai2-poisoned-model-registry-apt, ai2-rag-retrieval-poisoning-apt |
| T1204.003 | User Execution: Malicious Image | ai2-malicious-model-artifact, ai2-malicious-model-artifact-apt, ai2-tampered-inference-base-image, ai2-tampered-inference-base-image-apt, c2-supplychain-foothold, c2-supplychain-foothold-apt, c3-cicd, c3-supplychain, c3-supplychain-apt |
| T1213 |  | ai2-data-model-poisoning-apt, ai2-embedding-vector-weakness-apt, ai2-rag-retrieval-poisoning-apt, c3-secrets-sprawl-apt |
| T1213.003 |  | c3-cicd-apt |
| T1480 |  | c2-persistence-evict-apt |
| T1485 | Data Destruction | c1-fast-attacker-apt, c2-stateful-training-apt |
| T1486 |  | c1-fast-attacker, c1-fast-attacker-apt, c2-stateful-training, c2-stateful-training-apt |
| T1496 | Resource Hijacking | ai1-llm-jacking-apt, apt-lambda-pump-live, c1-fast-attacker-apt, c2-stateful-training, c2-stateful-training-apt, e-dilution-fleet-apt |
| T1496.001 | Resource Hijacking: Compute Hijacking | ai1-llm-jacking, ai1-llm-jacking-apt, ai2-unbounded-consumption, ai2-unbounded-consumption-apt, c3-cryptomining, c3-cryptomining-apt |
| T1497 |  | c1-llm-adaptive-apt |
| T1498.001 |  | apt-dispersion-steer-live |
| T1499 | Endpoint Denial of Service | ai2-unbounded-consumption, ai2-unbounded-consumption-apt |
| T1499.003 |  | e-dilution-fleet-apt |
| T1499.004 |  | ai2-unbounded-consumption-apt, apt-lambda-pump-live |
| T1525 | Implant Internal Image | ai1-inference-manipulation-apt, ai2-co-location-cross-tenant-apt, ai2-data-model-poisoning-apt, ai2-malicious-model-artifact, ai2-malicious-model-artifact-apt, ai2-poisoned-model-registry, ai2-poisoned-model-registry-apt, ai2-tampered-inference-base-image, ai2-tampered-inference-base-image-apt, c1-escape-persist, c1-escape-persist-apt, c2-dwell-rotation, c2-dwell-rotation-apt, c2-supplychain-foothold, c2-supplychain-foothold-apt, c3-cicd, c3-cicd-apt, c3-cryptomining-apt, c3-sidecar-inject, c3-sidecar-inject-apt, c3-supplychain, c3-supplychain-apt |
| T1526 | Cloud Service Discovery | c2-recon-window, c2-recon-window-apt |
| T1528 | Steal Application Access Token | ai1-llm-jacking-apt, c1-credtheft-rbac, c1-credtheft-rbac-apt, c3-imds-theft, c3-imds-theft-apt, c3-secrets-sprawl, c3-secrets-sprawl-apt |
| T1530 |  | ai1-model-theft, ai1-model-theft-apt, ai2-co-location-cross-tenant, ai2-embedding-store-tampering, ai2-embedding-store-tampering-apt, ai2-embedding-vector-weakness, ai2-embedding-vector-weakness-apt, ai2-gpu-side-channel, ai2-gpu-side-channel-apt, ai2-kvcache-poisoning-cross-session-leak, ai2-kvcache-poisoning-cross-session-leak-apt, ai2-query-extraction, ai2-query-extraction-apt, ai2-rag-retrieval-poisoning-apt, ai2-sensitive-info-disclosure, ai2-sensitive-info-disclosure-apt, ai2-system-prompt-leakage, ai2-system-prompt-leakage-apt, b-recon-lifetime-ai, b-recon-lifetime-ai-apt, c2-stateful-training-apt, c3-imds-theft-apt, c3-secrets-sprawl-apt |
| T1537 |  | c3-imds-theft-apt |
| T1543.005 | Create/Modify System Process: Container Service | ai2-agent-excessive-agency-apt, ai2-agent-injection-to-persistence, ai2-agent-injection-to-persistence-apt, ai2-agent-rogue-tool-persistence-apt, ai2-malicious-model-artifact-apt, c1-escape-persist, c1-escape-persist-apt, c1-heldout-cve, c1-heldout-cve-apt, c1-lateral-apt, c1-llm-adaptive, c1-llm-adaptive-apt, c1-stealth-dweller-apt, c2-dwell-rotation, c2-dwell-rotation-apt, c2-persistence-evict, c2-persistence-evict-apt, c2-stateful-training, c2-stateful-training-apt, c2-supplychain-foothold, c3-admission-bypass-apt, c3-cryptomining-apt, c3-sidecar-inject, c3-sidecar-inject-apt |
| T1546 |  | ai2-agent-injection-to-persistence-apt |
| T1550.001 | Use Alt Auth Material: Application Access Token | c1-credtheft-rbac, c1-credtheft-rbac-apt, c1-lateral, c1-lateral-apt, c2-lateral-disrupt, c2-lateral-disrupt-apt |
| T1552 | Unsecured Credentials | ai1-inference-manipulation-apt, ai2-sensitive-info-disclosure, ai2-sensitive-info-disclosure-apt, ai2-system-prompt-leakage, ai2-system-prompt-leakage-apt |
| T1552.001 | Unsecured Credentials: Credentials In Files | ai2-embedding-store-tampering-apt, c1-credtheft-rbac, c1-credtheft-rbac-apt, c2-dwell-rotation-apt, c2-lateral-disrupt-apt, c2-persistence-evict-apt, c2-stateful-training-apt, c2-supplychain-foothold-apt, c3-admission-bypass-apt, c3-cicd-apt, c3-secrets-sprawl, c3-secrets-sprawl-apt, c3-sidecar-inject-apt |
| T1552.004 |  | c3-admission-bypass-apt, c3-cicd-apt, c3-secrets-sprawl-apt, c3-sidecar-inject-apt |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | ai1-llm-jacking-apt, ai1-model-theft-apt, ai2-excessive-agency-apt, c1-credtheft-rbac-apt, c1-escape-persist-apt, c3-imds-theft, c3-imds-theft-apt, c3-supplychain-apt |
| T1552.007 | Unsecured Credentials: Container API | ai2-co-location-cross-tenant-apt, ai2-malicious-model-artifact-apt, ai2-tampered-inference-base-image-apt, c1-credtheft-rbac, c1-credtheft-rbac-apt, c1-lateral-apt, c3-imds-theft, c3-imds-theft-apt, c3-secrets-sprawl, c3-secrets-sprawl-apt |
| T1554 |  | ai2-agent-rogue-tool-persistence-apt, c3-cicd-apt, c3-supplychain-apt |
| T1557 |  | ai1-inference-manipulation, ai1-inference-manipulation-apt, ai2-mcp-rogue-server, ai2-mcp-rogue-server-apt, ai2-mcp-tool-response-injection-apt |
| T1560.001 |  | c1-c2-exfil-apt |
| T1564 | Hide Artifacts | c1-stealth-dweller, c1-stealth-dweller-apt |
| T1565 |  | ai1-pillar03-panic-mutation, ai1-pillar03-panic-mutation-apt, ai1-prompt-injection, ai1-prompt-injection-apt, ai2-agent-memory-contamination, ai2-agent-memory-contamination-apt, ai2-embedding-store-tampering, ai2-embedding-store-tampering-apt, ai2-embedding-vector-weakness, ai2-embedding-vector-weakness-apt, ai2-kvcache-poisoning-cross-session-leak, ai2-kvcache-poisoning-cross-session-leak-apt, ai2-mcp-tool-response-injection, ai2-mcp-tool-response-injection-apt, ai2-rag-retrieval-poisoning, ai2-rag-retrieval-poisoning-apt |
| T1565.001 |  | ai2-data-model-poisoning, ai2-data-model-poisoning-apt |
| T1565.002 |  | ai1-inference-manipulation, ai1-inference-manipulation-apt |
| T1567 | Exfiltration Over Web Service | ai1-model-theft, ai1-model-theft-apt, ai2-query-extraction-apt, c1-c2-exfil, c1-c2-exfil-apt |
| T1567.002 |  | c1-c2-exfil-apt |
| T1570 |  | c2-lateral-disrupt-apt |
| T1571 |  | c2-c2-disrupt-apt |
| T1573 | Encrypted Channel | c2-c2-disrupt |
| T1573.001 |  | c2-c2-disrupt-apt |
| T1580 |  | ai2-co-location-cross-tenant-apt, c2-recon-window-apt, c3-imds-theft-apt |
| T1590 |  | ai2-mcp-rogue-server-apt, b-recon-lifetime, b-recon-lifetime-ai, b-recon-lifetime-ai-apt, b-recon-lifetime-apt, e-dilution-fleet-apt, e-dilution-n9 |
| T1591 |  | b-recon-lifetime-apt |
| T1592 |  | b-recon-lifetime, b-recon-lifetime-apt, c1-heldout-cve-apt, c1-stealth-dweller-apt |
| T1595 |  | c1-fast-attacker-apt, c1-llm-adaptive, c1-llm-adaptive-apt |
| T1595.002 |  | c1-heldout-cve-apt |
| T1606 |  | ai2-agent-memory-contamination-apt |
| T1606.002 |  | c3-cicd-apt, c3-supplychain-apt |
| T1609 | Container Administration Command | c1-lateral, c1-lateral-apt, c2-lateral-disrupt, c2-lateral-disrupt-apt |
| T1610 | Deploy Container | ai1-llm-jacking, ai1-llm-jacking-apt, ai1-pillar03-panic-mutation, ai1-pillar03-panic-mutation-apt, ai2-co-location-cross-tenant, ai2-co-location-cross-tenant-apt, ai2-gpu-side-channel-apt, c1-escape-persist, c1-escape-persist-apt, c1-lateral-apt, c2-supplychain-foothold, c2-supplychain-foothold-apt, c3-admission-bypass, c3-admission-bypass-apt, c3-cicd, c3-cryptomining, c3-cryptomining-apt, c3-sidecar-inject, c3-sidecar-inject-apt, c3-supplychain, c3-supplychain-apt, e-dilution-fleet-apt |
| T1610.000 |  | c3-admission-bypass-apt |
| T1611 | Escape to Host | ai1-pillar03-panic-mutation-apt, apt-dispersion-steer-live, apt-lambda-pump-live, c1-escape-persist, c1-escape-persist-apt, c2-persistence-evict, c2-persistence-evict-apt, c3-admission-bypass, c3-admission-bypass-apt, c3-sidecar-inject, c3-sidecar-inject-apt |
| T1612 | Build Image on Host | ai1-pillar03-panic-mutation-apt, ai2-tampered-inference-base-image-apt, c2-supplychain-foothold-apt, c3-supplychain, c3-supplychain-apt |
| T1613 | Container and Resource Discovery | ai2-co-location-cross-tenant-apt, ai2-embedding-store-tampering-apt, ai2-embedding-vector-weakness-apt, ai2-gpu-side-channel-apt, ai2-kvcache-poisoning-cross-session-leak-apt, ai2-malicious-model-artifact-apt, ai2-mcp-rogue-server-apt, ai2-mcp-tool-poisoning-apt, ai2-mcp-tool-response-injection-apt, ai2-poisoned-model-registry-apt, ai2-rag-retrieval-poisoning-apt, ai2-tampered-inference-base-image-apt, b-recon-lifetime-apt, c1-escape-persist-apt, c1-lateral, c1-lateral-apt, c2-lateral-disrupt-apt, c2-recon-window, c2-recon-window-apt, c3-admission-bypass-apt, c3-cryptomining-apt, e-dilution-fleet-apt |
| T1685 | Disable or Modify Tools | c1-stealth-dweller, c1-stealth-dweller-apt |
| T1induce-not-real-removed |  | c3-cryptomining-apt |
