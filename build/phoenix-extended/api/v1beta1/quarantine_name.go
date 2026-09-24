package v1beta1

import (
	"crypto/sha256"
	"encoding/hex"

	"k8s.io/apimachinery/pkg/util/validation"
)

// QuarantineNetworkPolicyName is used both as a NetworkPolicy name and as the
// Pod selector label value. Preserve the original name whenever it fits the
// Kubernetes label-value contract. Long, otherwise valid Pod names use one
// deterministic, domain-separated 192-bit identity within that 63-byte bound.
func QuarantineNetworkPolicyName(namespace, pod string) string {
	legacy := namespace + "-" + pod + "-policy"
	if len(legacy) <= 63 && len(validation.IsValidLabelValue(legacy)) == 0 {
		return legacy
	}
	h := sha256.Sum256([]byte("phoenix-quarantine-policy-v1\x00" + namespace + "\x00" + pod))
	return "amtd-q-" + hex.EncodeToString(h[:24])
}
