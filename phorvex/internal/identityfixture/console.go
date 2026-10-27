package identityfixture

import "time"

// Shared CONSOLE/TEST producer contract.
//
// The operator's recon admits an IdentityRotationObservation for this fixture only
// after Observe(active=true) sees the short-lived positive-control marker ConfigMap
// below. The Console live-attack (internal/console) is the producer that writes that
// marker — only after it has proven a stolen bearer actually authenticated. These
// constants are the single source of truth for BOTH sides, so the producer and this
// observer can never drift. Every value here is byte-identical to the literals the
// observer previously inlined; Observe/Validate now reference these names.
const (
	// NamespacePrefix is the required owned test-namespace name prefix.
	NamespacePrefix = "console-identity-"
	// NamespaceOwnedLabelValue is the value Label must carry on the owned namespace.
	NamespaceOwnedLabelValue = "owned"
	// RunPrefix prefixes the per-run dedicated ServiceAccount / Deployment / marker name.
	RunPrefix = "console-id-"
	// TokenExpirationSeconds pins the short-lived projected token (10 minutes), the
	// property that makes kubelet mounted-token renewal observable inside the window.
	TokenExpirationSeconds int64 = 600
	// MarkerProducer labels the positive-control receipt as the Console/TEST producer.
	// It is the clearly-labelled producer identity the acceptance contract requires.
	MarkerProducer = "CONSOLE/TEST external-token-theft-only"
	// Marker ConfigMap data keys.
	MarkerKeyPodUID   = "podUID"
	MarkerKeySAUID    = "saUID"
	MarkerKeyProducer = "producer"
	MarkerKeyLandedAt = "landedAt"
)

// MarkerMaxAge bounds how long after the stolen bearer landed the positive-control
// receipt remains admissible; a stale marker is never credited.
const MarkerMaxAge = 12 * time.Minute
