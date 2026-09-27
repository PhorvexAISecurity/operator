package console

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
)

type endpointLeaseState struct {
	Version            int      `json:"version"`
	Revision           uint64   `json:"revision"`
	ServiceUID         string   `json:"serviceUID"`
	ProxySourceSHA256  string   `json:"proxySourceSHA256"`
	SecretUID          string   `json:"secretUID"`
	SeedSHA256         string   `json:"seedSHA256"`
	AllowedClientHMACs []string `json:"allowedClientHMACs"`
	RevokedClientHMACs []string `json:"revokedClientHMACs"`
	LastOperationID    string   `json:"lastOperationID"`
}

func endpointLeaseSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func endpointLeaseHMAC(seed, bearer []byte) string {
	mac := hmac.New(sha256.New, seed)
	_, _ = mac.Write(bearer)
	return hex.EncodeToString(mac.Sum(nil))
}

func endpointLeaseStrictJSON(raw []byte, out any, max int) error {
	if len(raw) == 0 || len(raw) > max || rejectNATSNestedDuplicates(raw) != nil {
		return errors.New("endpoint lease JSON invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("endpoint lease JSON schema invalid")
	}
	var canonical any
	if json.Unmarshal(raw, &canonical) != nil {
		return errors.New("endpoint lease JSON invalid")
	}
	b, _ := json.Marshal(canonical)
	if !bytes.Equal(raw, b) {
		return errors.New("endpoint lease JSON noncanonical")
	}
	return nil
}

func endpointLeaseSortedIDs(ids []string) bool {
	for i, id := range ids {
		if !staticSHA256.MatchString(id) || i > 0 && ids[i-1] >= id {
			return false
		}
	}
	return true
}

func parseEndpointLeaseState(raw []byte, p endpointLeaseProfile) (endpointLeaseState, error) {
	var state endpointLeaseState
	if err := endpointLeaseStrictJSON(raw, &state, 16<<10); err != nil {
		return state, err
	}
	if state.Version != 1 || state.Revision > 1<<53-1 || state.ServiceUID != p.ServiceUID ||
		state.ProxySourceSHA256 != p.ProxySourceSHA256 || state.SecretUID != p.TenantSecretUID ||
		state.SeedSHA256 != p.SeedSHA256 || len(state.AllowedClientHMACs) == 0 ||
		len(state.AllowedClientHMACs) > 256 || len(state.RevokedClientHMACs) > 256 ||
		!endpointLeaseSortedIDs(state.AllowedClientHMACs) || !endpointLeaseSortedIDs(state.RevokedClientHMACs) ||
		(state.Revision == 0 && state.LastOperationID != "") ||
		(state.Revision > 0 && !staticSHA256.MatchString(state.LastOperationID)) {
		return state, errors.New("endpoint lease state authority invalid")
	}
	for _, id := range state.AllowedClientHMACs {
		if sort.SearchStrings(state.RevokedClientHMACs, id) < len(state.RevokedClientHMACs) &&
			state.RevokedClientHMACs[sort.SearchStrings(state.RevokedClientHMACs, id)] == id {
			return state, errors.New("endpoint lease roster collision")
		}
	}
	return state, nil
}

func endpointLeaseBefore(state endpointLeaseState, p endpointLeaseProfile) bool {
	return state.Revision == 0 && len(state.AllowedClientHMACs) == 2 && len(state.RevokedClientHMACs) == 0 &&
		state.AllowedClientHMACs[0] != state.AllowedClientHMACs[1] &&
		sort.SearchStrings(state.AllowedClientHMACs, p.ClientAHMAC) < 2 &&
		sort.SearchStrings(state.AllowedClientHMACs, p.ClientBHMAC) < 2 &&
		state.AllowedClientHMACs[sort.SearchStrings(state.AllowedClientHMACs, p.ClientAHMAC)] == p.ClientAHMAC &&
		state.AllowedClientHMACs[sort.SearchStrings(state.AllowedClientHMACs, p.ClientBHMAC)] == p.ClientBHMAC
}

func endpointLeaseDesired(prior endpointLeaseState, p endpointLeaseProfile, operationID string) (endpointLeaseState, error) {
	if !endpointLeaseBefore(prior, p) || !staticSHA256.MatchString(operationID) {
		return endpointLeaseState{}, errors.New("endpoint lease cutover prerequisites differ")
	}
	after := prior
	after.Revision = prior.Revision + 1
	after.AllowedClientHMACs = []string{p.ClientBHMAC}
	after.RevokedClientHMACs = []string{p.ClientAHMAC}
	after.LastOperationID = operationID
	return after, nil
}

func endpointLeaseStateBytes(state endpointLeaseState) []byte {
	b, _ := json.Marshal(state)
	var canonical any
	_ = json.Unmarshal(b, &canonical)
	b, _ = json.Marshal(canonical)
	return b
}

type endpointLeaseTokens struct{ A, B []byte }

func endpointLeaseTokenValid(raw []byte) bool {
	if len(raw) < 32 || len(raw) > 256 {
		return false
	}
	for _, b := range raw {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func endpointLeaseMountedTokens(p endpointLeaseProfile) (endpointLeaseTokens, error) {
	var tokens endpointLeaseTokens
	a, errA := os.ReadFile("/etc/phorvex-endpoint-lease-callers/client-a")
	b, errB := os.ReadFile("/etc/phorvex-endpoint-lease-callers/client-b")
	if errA != nil || errB != nil || !endpointLeaseTokenValid(a) || !endpointLeaseTokenValid(b) ||
		bytes.Equal(a, b) || endpointLeaseSHA(a) != p.ClientASHA256 || endpointLeaseSHA(b) != p.ClientBSHA256 {
		return tokens, errors.New("reviewed caller Secret copy unavailable")
	}
	tokens.A, tokens.B = a, b
	return tokens, nil
}
