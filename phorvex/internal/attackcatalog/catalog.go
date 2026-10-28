// Package attackcatalog exposes the production-embedded, review-pinned attack catalogue.
// It contains metadata only; launch authority is an explicit server-side allowlist elsewhere.
package attackcatalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
)

const (
	Schema       = "phorvex.attack-catalogue.v1"
	ExpectedSize = 192
	FirstID      = "AML.T0012"
)

type Entry struct {
	ID                 string `json:"id"`
	Order              int    `json:"order"`
	Description        string `json:"description"`
	Family             string `json:"family"`
	ExpectedAction     string `json:"expectedAction"`
	EventType          string `json:"eventType"`
	Mode               string `json:"mode"`
	Lane               string `json:"lane"`
	Expected           string `json:"expected"`
	ReactiveCompatible bool   `json:"reactiveCompatible"`
}

type document struct {
	Schema  string  `json:"schema"`
	Count   int     `json:"count"`
	Entries []Entry `json:"entries"`
}

//go:embed catalog.json
var raw []byte

var (
	once    sync.Once
	entries []Entry
	byID    map[string]Entry
	loadErr error
)

func load() {
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		loadErr = fmt.Errorf("decode embedded attack catalogue: %w", err)
		return
	}
	if doc.Schema != Schema || doc.Count != ExpectedSize || len(doc.Entries) != ExpectedSize {
		loadErr = fmt.Errorf("embedded attack catalogue identity changed")
		return
	}
	seen := make(map[string]Entry, ExpectedSize)
	for i, entry := range doc.Entries {
		if entry.Order != i+1 || strings.TrimSpace(entry.ID) == "" || strings.TrimSpace(entry.Description) == "" ||
			strings.TrimSpace(entry.Family) == "" || strings.TrimSpace(entry.ExpectedAction) == "" ||
			strings.TrimSpace(entry.EventType) == "" || entry.Mode != "lane" || strings.TrimSpace(entry.Lane) == "" ||
			entry.Expected != "DEFENDED" || !entry.ReactiveCompatible {
			loadErr = fmt.Errorf("embedded attack catalogue entry %d is invalid", i+1)
			return
		}
		if _, exists := seen[entry.ID]; exists {
			loadErr = fmt.Errorf("embedded attack catalogue ID %q is duplicated", entry.ID)
			return
		}
		seen[entry.ID] = entry
	}
	if doc.Entries[0].ID != FirstID {
		loadErr = fmt.Errorf("embedded attack catalogue first ID changed")
		return
	}
	entries, byID = slices.Clone(doc.Entries), seen
}

func Entries() ([]Entry, error) {
	once.Do(load)
	if loadErr != nil {
		return nil, loadErr
	}
	return slices.Clone(entries), nil
}

func Lookup(id string) (Entry, bool) {
	once.Do(load)
	if loadErr != nil {
		return Entry{}, false
	}
	entry, ok := byID[id]
	return entry, ok
}

func Validate() error {
	once.Do(load)
	return loadErr
}
