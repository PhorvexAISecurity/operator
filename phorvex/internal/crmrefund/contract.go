// Package crmrefund defines the narrow CRM refund deny-guard contract that the
// crm-refund-revoke actuator writes and the mini-CRM app enforces. It has authority
// only over the operator-owned refund deny-list; it never authenticates callers and
// never touches accounts, orders or any other CRM state. The mini-CRM is
// deliberately unauthenticated (confused-deputy); this guard lets the brain revoke
// refunds for a specific abused order across every serving Pod without inventing a
// caller identity. An empty or absent guard preserves the original behaviour.
package crmrefund

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"time"
)

const (
	Namespace             = "crm"
	ServiceName           = "crm"
	AppLabelSelector      = "app=crm"
	GuardConfigMapName    = "crm-refund-guard"
	GuardKey              = "denied.json"
	GuardMountPath        = "/etc/phorvex-crm-guard"
	JournalName           = "phorvex-crm-refund-revoke-journal"
	JournalKey            = "receipts.json"
	JournalLabel          = "phorvex.ai/crm-refund-revoke-journal"
	GuardUIDAnnotation    = "phorvex.ai/crm-refund-guard-configmap-uid"
	ServiceUIDAnnotation  = "phorvex.ai/crm-live-service-uid"
	ObservationAnnotation = "phorvex.ai/crm-refund-observation-v1"
	RuleType              = "phorvex.attack.crm-refund-abuse"
)

var (
	shaPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	orderPattern = regexp.MustCompile(`^OR-[A-Za-z0-9]{1,32}$`)
)

func SHA256(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func ValidSHA(s string) bool   { return shaPattern.MatchString(s) }
func ValidOrderID(s string) bool { return orderPattern.MatchString(s) }

// Guard is the operator-owned deny-list the mini-CRM re-reads per request. The app
// keeps only denied_order_ids; this type adds a revision/operation ledger so the
// actuator's writes are idempotent and auditable. The app-facing bytes are produced
// by EncodeAppGuard (just {"denied_order_ids":[...]}), while EncodeState carries the
// full ledger for the actuator's own ConfigMap-state key.
type Guard struct {
	Version  int     `json:"version"`
	Revision uint64  `json:"revision"`
	Entries  []Entry `json:"entries"`
}

type Entry struct {
	Active      bool   `json:"active"`
	OrderID     string `json:"orderId"`
	OperationID string `json:"operationId"`
}

// EncodeAppGuard returns exactly what app.py reads: {"denied_order_ids":[sorted ids]}.
func (g Guard) EncodeAppGuard() string {
	ids := make([]string, 0, len(g.Entries))
	for _, e := range g.Entries {
		if e.Active {
			ids = append(ids, e.OrderID)
		}
	}
	sort.Strings(ids)
	raw, _ := json.Marshal(map[string]any{"denied_order_ids": ids})
	return string(raw)
}

func (g Guard) Entry(orderID string) (Entry, bool) {
	for _, e := range g.Entries {
		if e.OrderID == orderID {
			return e, true
		}
	}
	return Entry{}, false
}

// Append revokes one order's refunds under a unique operation id. It refuses a
// repeated order, a reused operation id, a malformed order id, or capacity overflow.
func (g Guard) Append(orderID, operationID string) (Guard, error) {
	if !ValidOrderID(orderID) || operationID == "" || len(operationID) > 128 || len(g.Entries) >= 256 {
		return Guard{}, errors.New("crm refund guard capacity or proposed entry invalid")
	}
	if _, exists := g.Entry(orderID); exists {
		return Guard{}, errors.New("crm refund already revoked for this order")
	}
	for _, e := range g.Entries {
		if e.OperationID == operationID {
			return Guard{}, errors.New("crm refund decision already used")
		}
	}
	next := Guard{Version: 2, Revision: g.Revision + 1, Entries: append([]Entry(nil), g.Entries...)}
	next.Entries = append(next.Entries, Entry{Active: true, OrderID: orderID, OperationID: operationID})
	sort.Slice(next.Entries, func(i, j int) bool { return next.Entries[i].OrderID < next.Entries[j].OrderID })
	return next, nil
}

func EncodeState(g Guard) (string, error) {
	raw, e := json.Marshal(map[string]any{"version": g.Version, "revision": g.Revision, "entries": g.Entries})
	if e != nil {
		return "", e
	}
	if _, e = ParseState(string(raw)); e != nil {
		return "", e
	}
	return string(raw), nil
}

func ParseState(raw string) (Guard, error) {
	var g Guard
	if e := decodeExactBound(raw, map[string]bool{"version": true, "revision": true, "entries": true}, &g, 65536); e != nil {
		return Guard{}, e
	}
	if g.Version != 2 || g.Entries == nil || len(g.Entries) > 256 || g.Revision != uint64(len(g.Entries)) {
		return Guard{}, errors.New("crm refund guard state invalid")
	}
	prev := ""
	seenOps := map[string]bool{}
	for _, e := range g.Entries {
		if !e.Active || !ValidOrderID(e.OrderID) || e.OrderID <= prev ||
			e.OperationID == "" || len(e.OperationID) > 128 || seenOps[e.OperationID] {
			return Guard{}, errors.New("crm refund guard entry invalid or repeated")
		}
		prev = e.OrderID
		seenOps[e.OperationID] = true
	}
	canonical, _ := json.Marshal(map[string]any{"version": g.Version, "revision": g.Revision, "entries": g.Entries})
	if raw != string(canonical) {
		return Guard{}, errors.New("crm refund guard state not canonical")
	}
	return g, nil
}

// Observation is the trusted, admission-stamped evidence that a cross-record refund
// abuse landed. The actuator revokes exactly Observation.OrderID.
type Observation struct {
	Version          int       `json:"version"`
	OrderID          string    `json:"orderId"`
	OrderAccountID   string    `json:"orderAccountId"`
	CallerAccountID  string    `json:"callerAccountId"`
	GuardConfigMapUID string   `json:"guardConfigMapUID"`
	ServiceUID       string    `json:"serviceUID"`
	TargetPodUID     string    `json:"targetPodUID"`
	PeerPodUID       string    `json:"peerPodUID"`
	Objective        string    `json:"objective"`
	ObservedAt       time.Time `json:"observedAt"`
	PolicyName       string    `json:"policyName"`
	PolicyUID        string    `json:"policyUID"`
	PolicyGeneration int64     `json:"policyGeneration"`
}

func ParseObservation(raw string) (Observation, error) {
	var o Observation
	e := decodeExactBound(raw, map[string]bool{"version": true, "orderId": true, "orderAccountId": true,
		"callerAccountId": true, "guardConfigMapUID": true, "serviceUID": true, "targetPodUID": true,
		"peerPodUID": true, "objective": true, "observedAt": true, "policyName": true, "policyUID": true,
		"policyGeneration": true}, &o, 2048)
	if e != nil {
		return Observation{}, e
	}
	if o.Version != 1 || !ValidOrderID(o.OrderID) || o.OrderAccountID == "" || o.CallerAccountID == "" ||
		o.OrderAccountID == o.CallerAccountID || o.GuardConfigMapUID == "" || o.ServiceUID == "" ||
		o.TargetPodUID == "" || o.PeerPodUID == "" || o.TargetPodUID == o.PeerPodUID ||
		o.Objective != "ai2-cross-record-refund" || o.ObservedAt.IsZero() ||
		o.PolicyName == "" || o.PolicyUID == "" || o.PolicyGeneration < 1 {
		return Observation{}, errors.New("crm refund observation invalid")
	}
	return o, nil
}

func decodeExactBound(raw string, keys map[string]bool, into any, maxBytes int) error {
	if len(raw) == 0 || len(raw) > maxBytes {
		return errors.New("crm refund JSON size")
	}
	d := json.NewDecoder(bytes.NewReader([]byte(raw)))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return errors.New("crm refund JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		v, e := d.Token()
		if e != nil {
			return errors.New("crm refund JSON key")
		}
		k, ok := v.(string)
		if !ok || !keys[k] || seen[k] {
			return errors.New("crm refund JSON key")
		}
		seen[k] = true
		var value json.RawMessage
		if e = d.Decode(&value); e != nil {
			return e
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || len(seen) != len(keys) {
		return errors.New("crm refund JSON keyset")
	}
	if _, e = d.Token(); e != io.EOF {
		return errors.New("crm refund JSON trailing value")
	}
	typed := json.NewDecoder(bytes.NewReader([]byte(raw)))
	typed.DisallowUnknownFields()
	return typed.Decode(into)
}
