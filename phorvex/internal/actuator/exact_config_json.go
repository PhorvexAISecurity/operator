package actuator

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// validateExactObjectArrayJSONKeys rejects encoding/json's case-insensitive
// struct-field aliases for the small versioned configuration documents that
// consist of a root object and an optional array of entry objects. Duplicate
// member names must be rejected separately before calling this helper.
func validateExactObjectArrayJSONKeys(data []byte, arrayField, entryLabel string, rootKeys, entryKeys map[string]struct{}) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil || root == nil {
		return fmt.Errorf("document must be a JSON object")
	}
	for key := range root {
		if _, ok := rootKeys[key]; !ok {
			return fmt.Errorf("field %q does not use an exact published key", key)
		}
	}

	entriesJSON, ok := root[arrayField]
	if !ok || bytes.Equal(bytes.TrimSpace(entriesJSON), []byte("null")) {
		return nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(entriesJSON, &entries); err != nil {
		return fmt.Errorf("field %q must be an array", arrayField)
	}
	for i, raw := range entries {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil || entry == nil {
			return fmt.Errorf("%s %d must be a JSON object", entryLabel, i)
		}
		for key := range entry {
			if _, ok := entryKeys[key]; !ok {
				return fmt.Errorf("%s %d field %q does not use an exact published key", entryLabel, i, key)
			}
		}
	}
	return nil
}
