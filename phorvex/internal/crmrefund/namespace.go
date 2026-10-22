package crmrefund

import "os"

const (
	StagingNamespace    = "phorvex-staging"
	NamespaceEnv        = "PHORVEX_CRM_REFUND_NAMESPACE"
	StagingFixtureLabel = "phorvex.ai/newstack-fixture"
	StagingFixtureValue = "crm-refund"
)

// NamespaceAllowed preserves the CRM boundary and admits the disposable staging
// fixture only through an exact, explicit process configuration. Arbitrary
// namespaces and configuration values never extend this actuator's authority.
func NamespaceAllowed(namespace string) bool {
	return namespace == Namespace ||
		(namespace == StagingNamespace && os.Getenv(NamespaceEnv) == StagingNamespace)
}

func stagingFixtureMatches(namespace string, labels map[string]string) bool {
	return namespace != StagingNamespace || labels[StagingFixtureLabel] == StagingFixtureValue
}
