package console

import (
	"errors"
	"fmt"

	"github.com/phorvex/phorvex/internal/agentdeny"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	credentialCatalogueNamespace  = "p4-demo"
	credentialCatalogueDeployment = "demo-api"
	credentialCataloguePolicy     = "demo-api-defense"
	credentialCatalogueSelector   = "app.kubernetes.io/name"
	credentialCatalogueLabel      = "demo-api"
	credentialCataloguePodPrefix  = "demo-api-"
	credentialObservationKey      = "phorvex.ai/credential-revoke-observation-v1"
)

// identityCredentialServerProfile is compiled server authority. API callers
// can select a catalogue ID, but cannot choose any namespace, workload,
// ServiceAccount, token Secret, grant, policy, or oracle identity.
type identityCredentialServerProfile struct {
	CatalogueID    string
	Namespace      string
	Deployment     string
	PolicyName     string
	SelectorKey    string
	SelectorValue  string
	PodPrefix      string
	ServiceAccount string
	TokenSecret    string
	ObservationKey string
	GrantResource  string
	GrantVerbs     [2]string
}

func credentialProfile(id, serviceAccount string) identityCredentialServerProfile {
	return identityCredentialServerProfile{
		CatalogueID: id, Namespace: credentialCatalogueNamespace, Deployment: credentialCatalogueDeployment,
		PolicyName: credentialCataloguePolicy, SelectorKey: credentialCatalogueSelector,
		SelectorValue: credentialCatalogueLabel, PodPrefix: credentialCataloguePodPrefix,
		ServiceAccount: serviceAccount, TokenSecret: serviceAccount + "-token",
		ObservationKey: credentialObservationKey, GrantResource: "pods", GrantVerbs: [2]string{"get", "list"},
	}
}

var credentialCatalogueServerProfiles = map[string]identityCredentialServerProfile{
	"AML.T0035":                    credentialProfile("AML.T0035", "cred-aml-t0035"),
	"AML.T0055":                    credentialProfile("AML.T0055", "cred-aml-t0055"),
	"AML.T0082":                    credentialProfile("AML.T0082", "cred-aml-t0082"),
	"AML.T0083":                    credentialProfile("AML.T0083", "cred-aml-t0083"),
	"AML.T0098":                    credentialProfile("AML.T0098", "cred-aml-t0098"),
	"MCP01:2025":                   credentialProfile("MCP01:2025", "cred-mcp01-2025"),
	"MS-CO-images-from-a-private-": credentialProfile("MS-CO-images-from-a-private-", "cred-ms-co-images-from-a-private-registry"),
	"MS-CR-access-managed-identit": credentialProfile("MS-CR-access-managed-identit", "cred-ms-cr-access-managed-identity"),
	"MS-CR-application-credential": credentialProfile("MS-CR-application-credential", "cred-ms-cr-application-credential"),
	"MS-CR-list-kubernetes-secret": credentialProfile("MS-CR-list-kubernetes-secret", "cred-ms-cr-list-kubernetes-secret"),
	"MS-CR-mount-service-principa": credentialProfile("MS-CR-mount-service-principa", "cred-ms-cr-mount-service-principal"),
	"MS-IN-kubeconfig-file":        credentialProfile("MS-IN-kubeconfig-file", "cred-ms-in-kubeconfig-file"),
	"MS-IN-using-cloud-credential": credentialProfile("MS-IN-using-cloud-credential", "cred-ms-in-using-cloud-credential"),
	"MS-PR-access-cloud-resources": credentialProfile("MS-PR-access-cloud-resources", "cred-ms-pr-access-cloud-resources"),
	"T1059.009":                    credentialProfile("T1059.009", "cred-t1059-009"),
	"T1078.004":                    credentialProfile("T1078.004", "cred-t1078-004"),
	"T1098.001":                    credentialProfile("T1098.001", "cred-t1098-001"),
	"T1098.003":                    credentialProfile("T1098.003", "cred-t1098-003"),
	"T1136.003":                    credentialProfile("T1136.003", "cred-t1136-003"),
	"T1552":                        credentialProfile("T1552", "cred-t1552"),
	"T1552.001":                    credentialProfile("T1552.001", "cred-t1552-001"),
	"T1552.003":                    credentialProfile("T1552.003", "cred-t1552-003"),
	"T1552.004":                    credentialProfile("T1552.004", "cred-t1552-004"),
	"T1552.007":                    credentialProfile("T1552.007", "cred-t1552-007"),
}

func validateCredentialCatalogueServerProfile(id string) error {
	p, ok := credentialCatalogueServerProfiles[id]
	if !ok || p.CatalogueID != id || p.Namespace != credentialCatalogueNamespace ||
		p.Deployment != credentialCatalogueDeployment || p.PolicyName != credentialCataloguePolicy ||
		p.SelectorKey != credentialCatalogueSelector || p.SelectorValue != credentialCatalogueLabel ||
		p.PodPrefix != credentialCataloguePodPrefix || p.ObservationKey != credentialObservationKey ||
		p.GrantResource != "pods" || p.GrantVerbs != [2]string{"get", "list"} ||
		p.TokenSecret != p.ServiceAccount+"-token" {
		return fmt.Errorf("credential catalogue profile %q has no exact server-owned definition", id)
	}
	for _, name := range []string{p.Namespace, p.Deployment, p.PolicyName, p.ServiceAccount, p.TokenSecret} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return errors.New("credential catalogue server profile contains an invalid Kubernetes identity")
		}
	}
	return nil
}

type identityAgentServerProfile struct {
	CatalogueID    string
	Namespace      string
	SelectorKey    string
	SelectorVal    string
	Service        string
	PolicyName     string
	AgentName      string
	GuardConfigMap string
	CallerID       string
	ActionID       string
	ObservationKey string
	Objective      string
	GuardKey       string
	ReadbackPath   string
}

func agentProfile(id, caller, action string) identityAgentServerProfile {
	return identityAgentServerProfile{CatalogueID: id, Namespace: "p6-demo", SelectorKey: agentdeny.AppLabel,
		SelectorVal: agentdeny.AppLabelValue, Service: agentdeny.ServiceName, PolicyName: "agent-defense",
		AgentName: agentdeny.ServiceName, GuardConfigMap: agentdeny.GuardConfigMapName,
		CallerID: caller, ActionID: action, ObservationKey: agentdeny.ObservationAnnotation,
		Objective: agentdeny.Objective, GuardKey: agentdeny.GuardKey, ReadbackPath: agentdeny.ReadbackPath}
}

// These six definitions pin the reviewed semantics even though packaging does
// not yet provide an immutable fixture that can safely make them runnable.
var agentCatalogueServerProfiles = map[string]identityAgentServerProfile{
	"AML.T0053":  agentProfile("AML.T0053", "caller-t0053", "invoke-tool"),
	"AML.T0086":  agentProfile("AML.T0086", "caller-t0086", "exfil-data"),
	"AML.T0101":  agentProfile("AML.T0101", "caller-t0101", "destroy-data"),
	"ASI02:2026": agentProfile("ASI02:2026", "caller-asi02", "misuse-tool"),
	"LLM06:2025": agentProfile("LLM06:2025", "caller-llm06", "excessive-action"),
	"MCP02:2025": agentProfile("MCP02:2025", "caller-mcp02", "escalate-scope"),
}

func validateAgentCatalogueServerProfile(id string) error {
	p, ok := agentCatalogueServerProfiles[id]
	if !ok || p.CatalogueID != id || p.Namespace != "p6-demo" || p.SelectorKey != agentdeny.AppLabel ||
		p.SelectorVal != agentdeny.AppLabelValue || p.Service != agentdeny.ServiceName || p.PolicyName != "agent-defense" ||
		p.AgentName != agentdeny.ServiceName || p.GuardConfigMap != agentdeny.GuardConfigMapName ||
		p.CallerID == "" || p.ActionID == "" || p.ObservationKey != agentdeny.ObservationAnnotation ||
		p.Objective != agentdeny.Objective || p.GuardKey != agentdeny.GuardKey || p.ReadbackPath != agentdeny.ReadbackPath {
		return fmt.Errorf("agent-action catalogue profile %q has no exact server-owned definition", id)
	}
	for _, name := range []string{p.Namespace, p.Service, p.PolicyName, p.AgentName, p.GuardConfigMap, p.CallerID, p.ActionID} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return errors.New("agent-action catalogue server profile contains an invalid Kubernetes identity")
		}
	}
	return nil
}
