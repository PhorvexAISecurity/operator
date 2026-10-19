package actuatorapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ContractVersion is the dispatcher-actuator contract a build speaks. An actuator
// refuses a client built against another version.
const ContractVersion = 1

// Config is the configuration the dispatcher and a separate actuator must share:
// the operator namespace that holds the protected-operation journals, the kill
// switch and the operator-scoped access the dispatcher checks; the detector
// identities whose adapter evidence the actuator re-checks before a reload; and
// the reviewed endpoint lease authority the dispatcher fences on and the actuator
// enforces.
type Config struct {
	OperatorNamespace                string
	TrustedDetectors                 []string
	EndpointLeaseApprovedSource      string
	EndpointLeaseApprovedProxyImage  string
	EndpointLeaseApprovedEngineImage string
}

// SHA256 identifies the configuration. The detector identities compare as a set.
func (c Config) SHA256() string {
	c.TrustedDetectors = append([]string{}, c.TrustedDetectors...)
	sort.Strings(c.TrustedDetectors)
	raw, err := json.Marshal(c)
	if err != nil {
		panic(err) // the struct holds only strings
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
