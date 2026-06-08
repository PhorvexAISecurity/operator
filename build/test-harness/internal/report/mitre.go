package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// MitreTechnique is one ATT&CK for Containers technique.
type MitreTechnique struct {
	ID   string
	Name string
}

// mitreNames is the ATT&CK for Containers technique-id -> name lookup the matrix
// renderer uses. It covers every technique referenced by the scenario set. New
// techniques referenced by a future scenario just need one line added here (or
// they render with a blank name, which is harmless).
var mitreNames = map[string]string{
	"T1190": "Exploit Public-Facing Application", "T1133": "External Remote Services",
	"T1078": "Valid Accounts", "T1078.001": "Valid Accounts: Default Accounts",
	"T1078.003": "Valid Accounts: Local Accounts", "T1078.004": "Valid Accounts: Cloud Accounts",
	"T1059": "Command and Scripting Interpreter", "T1059.013": "Command/Scripting: Container CLI/API",
	"T1609": "Container Administration Command", "T1610": "Deploy Container",
	"T1053": "Scheduled Task/Job", "T1053.007": "Scheduled Task/Job: Container Orchestration Job",
	"T1204": "User Execution", "T1204.003": "User Execution: Malicious Image",
	"T1098": "Account Manipulation", "T1098.006": "Account Manip: Additional Container Cluster Roles",
	"T1136": "Create Account", "T1136.001": "Create Account: Local Account",
	"T1543": "Create or Modify System Process", "T1543.005": "Create/Modify System Process: Container Service",
	"T1525": "Implant Internal Image", "T1611": "Escape to Host",
	"T1068": "Exploitation for Privilege Escalation", "T1612": "Build Image on Host",
	"T1070": "Indicator Removal", "T1036": "Masquerading",
	"T1036.005": "Masquerading: Match Legitimate Name/Location", "T1036.010": "Masquerading: Masquerade Account Name",
	"T1685": "Disable or Modify Tools", "T1564": "Hide Artifacts",
	"T1110": "Brute Force", "T1528": "Steal Application Access Token",
	"T1552": "Unsecured Credentials", "T1552.001": "Unsecured Credentials: Credentials In Files",
	"T1552.005": "Unsecured Credentials: Cloud Instance Metadata API", "T1552.007": "Unsecured Credentials: Container API",
	"T1613": "Container and Resource Discovery", "T1046": "Network Service Discovery",
	"T1069": "Permission Groups Discovery", "T1526": "Cloud Service Discovery",
	"T1550": "Use Alternate Authentication Material", "T1550.001": "Use Alt Auth Material: Application Access Token",
	"T1021": "Remote Services", "T1041": "Exfiltration Over C2 Channel",
	"T1071": "Application Layer Protocol", "T1567": "Exfiltration Over Web Service",
	"T1029": "Scheduled Transfer", "T1048": "Exfiltration Over Alternative Protocol",
	"T1573": "Encrypted Channel", "T1008": "Fallback Channels", "T1105": "Ingress Tool Transfer",
	"T1496": "Resource Hijacking", "T1496.001": "Resource Hijacking: Compute Hijacking",
	"T1496.002": "Resource Hijacking: Bandwidth Hijacking",
	"T1485": "Data Destruction", "T1499": "Endpoint Denial of Service",
	"T1490": "Inhibit System Recovery", "T1498": "Network Denial of Service",
}

// RenderMitreMatrix builds a coverage matrix of which scenarios exercise which
// ATT&CK techniques. It is GENERIC: it reads each registered scenario's
// AttackTechniqueIDs, so a new scenario's techniques appear with no edit here.
func RenderMitreMatrix(scenarios []core.Scenario) string {
	// Collect technique -> scenarios.
	tech := map[string][]string{}
	for _, s := range scenarios {
		m := s.Metadata()
		for _, id := range m.AttackTechniqueIDs {
			tech[id] = append(tech[id], m.Name)
		}
	}
	ids := make([]string, 0, len(tech))
	for id := range tech {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var b strings.Builder
	b.WriteString("# MITRE ATT&CK for Containers — Coverage Matrix\n\n")
	b.WriteString(fmt.Sprintf("%d techniques exercised across %d scenarios.\n\n", len(ids), len(scenarios)))
	b.WriteString("| Technique | Name | Scenarios |\n|---|---|---|\n")
	for _, id := range ids {
		name := mitreNames[id]
		scs := tech[id]
		sort.Strings(scs)
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", id, name, strings.Join(dedupe(scs), ", ")))
	}
	return b.String()
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
