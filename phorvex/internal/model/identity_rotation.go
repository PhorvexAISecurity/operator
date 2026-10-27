package model

// IdentityRotationObservation is a nonsecret, validated snapshot prerequisite for
// LIGHT ServiceAccount credential revocation. It establishes a dedicated account and the
// exact projected credential, not process compromise or an observed revocation outcome.
// Trusted producers (the authoritative identityfixture.Observe, bound to a trusted
// pod-bound-api-auth detector event) supply this snapshot; it is never inferred from
// tenant labels. The native identity-rotate handler consumes it to delete+recreate the
// ServiceAccount (new UID) and remove legacy token Secrets, genuinely invalidating a
// stolen pod-bound bearer while the Pod is retained.
type IdentityRotationObservation struct {
	Namespace, NamespaceUID                                              string
	PodName, PodUID, PodResourceVersion                                  string
	ServiceAccountName, ServiceAccountUID, ServiceAccountResourceVersion string
	PodInventoryVersion                                                  string
	PolicyName, PolicyUID                                                string
	PolicyGeneration                                                     int64
	DedicatedServiceAccount                                              bool
	ExternalTokenTheftOnly                                               bool
	// Complete trusted inventory includes unreferenced, manually created legacy tokens.
	// The actuator has get/delete only, never Secret list or token issuance.
	// Trusted admission must also rule out external EKS Pod Identity associations.
	FederatedIdentityAbsent      bool
	LegacyTokenInventoryComplete bool
	LegacyTokenSecrets           []IdentityRotationSecret
	EvidenceSource               string
}

// HasIdentityRotationObservation rejects partial and stale object bindings. A
// projection alone grants no light-rotation capability; dedicated-consumer and
// external-theft admission must also have been validated by the producer.
func (p Pod) HasIdentityRotationObservation() bool {
	o := p.IdentityRotationObservation
	return p.HasPodBoundKubeAPIAuth() && o != nil &&
		o.Namespace == p.Namespace && o.NamespaceUID != "" &&
		o.PodName == p.Name && o.PodUID == p.UID && o.PodResourceVersion == p.PodResourceVersion &&
		p.ServiceAccount != "default" && o.ServiceAccountName == p.ServiceAccount &&
		o.ServiceAccountUID == p.PodBoundKubeAPIAuth.ServiceAccountUID &&
		o.ServiceAccountResourceVersion != "" && o.PodInventoryVersion != "" &&
		o.PolicyName != "" && o.PolicyUID != "" && o.PolicyGeneration > 0 &&
		o.DedicatedServiceAccount && o.ExternalTokenTheftOnly &&
		o.EvidenceSource == "validated-dedicated-sa-credential"
}

// IdentityRotationEligible is the shared boundary for native selection support,
// candidate generation and the capability Witness. An unknown policy epoch is
// unsupported, including callers that only provide a policy name/UID.
func (p Pod) IdentityRotationEligible(name, uid string, generation int64) bool {
	if !p.HasIdentityRotationObservation() || name == "" || uid == "" || generation <= 0 {
		return false
	}
	o := p.IdentityRotationObservation
	return o.PolicyName == name && o.PolicyUID == uid && o.PolicyGeneration == generation
}

// IdentityRotationSecret binds a legacy token Secret without retaining credential bytes.
type IdentityRotationSecret struct{ Name, UID, ResourceVersion string }
