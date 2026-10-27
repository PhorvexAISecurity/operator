// Package datastore defines the narrow datastore-restore contract that the
// datastore-restore actuator enacts and a datastore (RAG index / agent persistent memory /
// tool-data store) workload reflects. It is NAMESPACE-PARAMETRIC: the namespace is carried
// by the trusted observation and the live pod rather than pinned to any app namespace.
//
// The persistent store content lives in an app-facing ConfigMap (StoreConfigMapName); the
// known-good baseline lives in a SEPARATE, operator-owned ConfigMap (TrustedSnapshotConfigMapName)
// that the attack never touches. The actuator restores the store content from the operator
// snapshot — never from anything carried by the event — and the restored content's canonical
// sha256 must equal the operator snapshot's recomputed canonical sha256 ("store hash == trusted
// snapshot"). The store workload re-reads the store ConfigMap live per request, so a restore is
// reflected without a pod restart; the poison is persisted (survives a rotate) precisely because
// it lives in this ConfigMap, which is why only a restore — not rotate/quarantine — remediates it.
package datastore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
)

// Identity surface. There is NO package-level Namespace constant: the namespace is a
// parameter threaded from the observation/pod so any lane's datastore workload (e.g. p3-demo)
// is defended without a hard-coded app namespace. The names below are a fixed convention for
// the generic "datastore" workload type.
const (
	ServiceName                  = "rag-store"
	AppLabel                     = "app"
	AppLabelValue                = "rag-store"
	StoreConfigMapName           = "datastore-content"          // app-facing persistent store (poisoned, then restored)
	StoreKey                     = "store.json"                 // the datastore records the app serves
	TrustedSnapshotConfigMapName = "datastore-trusted-snapshot" // operator-owned baseline; attacker never writes it
	TrustedContentKey            = "store.json"                 // the trusted known-good records
	TrustedSHAKey                = "store.sha256"               // the trusted canonical sha256 (recomputed, never trusted blindly)
	StoreMountPath               = "/etc/phorvex-datastore"
	ReadbackPath                 = "/phorvex-store/hash"
	GetPath                      = "/phorvex-store/get"
	DumpPath                     = "/phorvex-store/dump"
	Objective                    = "ai2-datastore-poisoning"
	RuleType                     = "phorvex.attack.datastore"
	ServingPort                  = 8080
	ObservationAnnotation        = "phorvex.ai/datastore-observation-v1"
	maxStoreBytes                = 262144 // 256 KiB — bounds parse cost; well under the ConfigMap 1 MiB limit
)

var (
	shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idPattern  = regexp.MustCompile(`^[A-Za-z0-9:_.\-/]{1,128}$`)
	nsPattern  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

func ValidSHA(s string) bool       { return shaPattern.MatchString(s) }
func ValidID(s string) bool        { return idPattern.MatchString(s) }
func ValidNamespace(s string) bool { return nsPattern.MatchString(s) }

func sha256Hex(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// Record is one datastore element: a RAG document / memory note / tool-data row.
type Record struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

// Store is the datastore content document. The canonical form sorts records by ID and
// marshals compactly, so the content sha256 is independent of formatting or record order —
// a poisoning that only reorders records cannot pretend to be clean, and a hand-installed
// YAML baseline with incidental whitespace still matches its recomputed sha.
type Store struct {
	Records []Record `json:"records"`
}

// ParseStore decodes store bytes strictly: bounded size, no unknown fields, no trailing data,
// unique non-empty record IDs.
func ParseStore(raw []byte) (Store, error) {
	if len(raw) == 0 || len(raw) > maxStoreBytes {
		return Store{}, errors.New("datastore content size out of bounds")
	}
	var s Store
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Store{}, err
	}
	if _, err := d.Token(); err != io.EOF {
		return Store{}, errors.New("datastore content has trailing data")
	}
	if s.Records == nil {
		return Store{}, errors.New("datastore content has no records field")
	}
	seen := map[string]bool{}
	for _, r := range s.Records {
		if !ValidID(r.ID) || seen[r.ID] {
			return Store{}, errors.New("datastore record id invalid or duplicated")
		}
		if len(r.Content) > maxStoreBytes {
			return Store{}, errors.New("datastore record content too large")
		}
		seen[r.ID] = true
	}
	return s, nil
}

// Canonical returns the canonical bytes: records sorted by ID, compact JSON.
func (s Store) Canonical() []byte {
	rs := append([]Record(nil), s.Records...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	raw, _ := json.Marshal(Store{Records: rs})
	return raw
}

func (s Store) IDs() []string {
	ids := make([]string, 0, len(s.Records))
	for _, r := range s.Records {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}

// CanonicalSHA parses store bytes and returns the sha256 of their canonical form. This is the
// authoritative "store hash" compared against the trusted snapshot.
func CanonicalSHA(raw []byte) (string, error) {
	s, err := ParseStore(raw)
	if err != nil {
		return "", err
	}
	return sha256Hex(s.Canonical()), nil
}

// Observation is the trusted, admission-stamped evidence that the persistent store was
// poisoned. It carries only public identities and content digests — never the poisoned bytes
// and never any replacement content. The actuator restores Namespace's store from the
// operator snapshot (parametric — no hard-coded app namespace).
type Observation struct {
	Version                     int    `json:"version"`
	Namespace                   string `json:"namespace"`
	StoreName                   string `json:"storeName"`
	StoreConfigMapUID           string `json:"storeConfigMapUID"`
	TrustedSnapshotConfigMapUID string `json:"trustedSnapshotConfigMapUID"`
	ServiceUID                  string `json:"serviceUID"`
	TargetPodUID                string `json:"targetPodUID"`
	PoisonedSHA256              string `json:"poisonedSHA256"`
	TrustedSHA256               string `json:"trustedSHA256"`
	Objective                   string `json:"objective"`
	ObservedAt                  string `json:"observedAt"`
	PolicyName                  string `json:"policyName"`
	PolicyUID                   string `json:"policyUID"`
	PolicyGeneration            int64  `json:"policyGeneration"`
}

// ParseObservation decodes the event annotation strictly and validates every field's shape.
func ParseObservation(raw string) (Observation, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return Observation{}, errors.New("datastore observation size")
	}
	var o Observation
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return Observation{}, err
	}
	if _, err := d.Token(); err != io.EOF {
		return Observation{}, errors.New("datastore observation trailing data")
	}
	if o.Version != 1 || !ValidNamespace(o.Namespace) || o.StoreName == "" ||
		o.StoreConfigMapUID == "" || o.TrustedSnapshotConfigMapUID == "" || o.ServiceUID == "" ||
		o.TargetPodUID == "" || !ValidSHA(o.PoisonedSHA256) || !ValidSHA(o.TrustedSHA256) ||
		o.PoisonedSHA256 == o.TrustedSHA256 || o.Objective != Objective || o.ObservedAt == "" ||
		o.PolicyName == "" || o.PolicyUID == "" || o.PolicyGeneration < 1 {
		return Observation{}, errors.New("datastore observation invalid")
	}
	return o, nil
}
