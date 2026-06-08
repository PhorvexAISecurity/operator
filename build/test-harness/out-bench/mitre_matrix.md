# MITRE ATT&CK for Containers — Coverage Matrix

38 techniques exercised across 18 scenarios.

| Technique | Name | Scenarios |
|---|---|---|
| T1008 | Fallback Channels | c2-c2-disrupt |
| T1021 | Remote Services | c2-lateral-disrupt |
| T1029 | Scheduled Transfer | c1-c2-exfil |
| T1036.005 | Masquerading: Match Legitimate Name/Location | c1-stealth-dweller |
| T1041 | Exfiltration Over C2 Channel | c1-c2-exfil |
| T1046 | Network Service Discovery | c1-lateral, c2-lateral-disrupt, c2-recon-window |
| T1048 | Exfiltration Over Alternative Protocol | c1-c2-exfil |
| T1053.007 | Scheduled Task/Job: Container Orchestration Job | c3-cicd |
| T1059.013 | Command/Scripting: Container CLI/API | c1-escape-persist, c1-lateral, c2-persistence-evict, c3-cryptomining |
| T1068 | Exploitation for Privilege Escalation | c1-escape-persist, c3-admission-bypass |
| T1069 | Permission Groups Discovery | c1-credtheft-rbac, c2-recon-window |
| T1070 | Indicator Removal | c1-stealth-dweller, c2-persistence-evict |
| T1071 | Application Layer Protocol | c1-c2-exfil, c2-c2-disrupt |
| T1078 | Valid Accounts | c3-secrets-sprawl |
| T1078.001 | Valid Accounts: Default Accounts | c1-credtheft-rbac, c3-admission-bypass |
| T1078.003 | Valid Accounts: Local Accounts | c2-dwell-rotation |
| T1078.004 | Valid Accounts: Cloud Accounts | c3-imds-theft |
| T1105 | Ingress Tool Transfer | c2-c2-disrupt |
| T1133 | External Remote Services | c2-dwell-rotation |
| T1204.003 | User Execution: Malicious Image | c2-supplychain-foothold, c3-cicd, c3-supplychain |
| T1496.001 | Resource Hijacking: Compute Hijacking | c3-cryptomining |
| T1525 | Implant Internal Image | c1-escape-persist, c2-dwell-rotation, c2-supplychain-foothold, c3-cicd, c3-sidecar-inject, c3-supplychain |
| T1526 | Cloud Service Discovery | c2-recon-window |
| T1528 | Steal Application Access Token | c1-credtheft-rbac, c3-imds-theft, c3-secrets-sprawl |
| T1543.005 | Create/Modify System Process: Container Service | c1-escape-persist, c2-dwell-rotation, c2-persistence-evict, c2-supplychain-foothold, c3-sidecar-inject |
| T1550.001 | Use Alt Auth Material: Application Access Token | c1-credtheft-rbac, c1-lateral, c2-lateral-disrupt |
| T1552.001 | Unsecured Credentials: Credentials In Files | c1-credtheft-rbac, c3-secrets-sprawl |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | c3-imds-theft |
| T1552.007 | Unsecured Credentials: Container API | c1-credtheft-rbac, c3-imds-theft, c3-secrets-sprawl |
| T1564 | Hide Artifacts | c1-stealth-dweller |
| T1567 | Exfiltration Over Web Service | c1-c2-exfil |
| T1573 | Encrypted Channel | c2-c2-disrupt |
| T1609 | Container Administration Command | c1-lateral, c2-lateral-disrupt |
| T1610 | Deploy Container | c1-escape-persist, c2-supplychain-foothold, c3-admission-bypass, c3-cicd, c3-cryptomining, c3-sidecar-inject, c3-supplychain |
| T1611 | Escape to Host | c1-escape-persist, c2-persistence-evict, c3-admission-bypass, c3-sidecar-inject |
| T1612 | Build Image on Host | c3-supplychain |
| T1613 | Container and Resource Discovery | c1-lateral, c2-recon-window |
| T1685 | Disable or Modify Tools | c1-stealth-dweller |
