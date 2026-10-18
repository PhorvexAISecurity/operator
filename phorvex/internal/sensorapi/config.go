package sensorapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ContractVersion is the dispatcher-sensor contract a build speaks. A sensor
// refuses a client built against another version.
const ContractVersion = 1

// Config is the configuration the dispatcher and a separate sensor must share:
// which identities' evidence the projection trusts, and the reviewed endpoint
// lease authority the bindings are checked against. The dispatcher reads the same
// trust when it scopes claims and admits evidence, so a difference would make the
// two disagree about what the cluster shows.
type Config struct {
	TrustedDetectors                 []string
	TrustedLossObservers             []string
	TrustedCurrentInventoryObservers []string
	EndpointLeaseApprovedSource      string
	EndpointLeaseApprovedProxyImage  string
	EndpointLeaseApprovedEngineImage string
}

// SHA256 identifies the configuration. The identity lists compare as sets.
func (c Config) SHA256() string {
	for _, list := range []*[]string{&c.TrustedDetectors, &c.TrustedLossObservers, &c.TrustedCurrentInventoryObservers} {
		sorted := append([]string{}, *list...)
		sort.Strings(sorted)
		*list = sorted
	}
	raw, err := json.Marshal(c)
	if err != nil {
		panic(err) // the struct holds only strings
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
