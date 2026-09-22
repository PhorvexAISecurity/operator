package installedauditobserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func DecodeCursor(raw []byte) (Cursor, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return Cursor{}, errors.New("cursor is empty or oversized")
	}
	if err := rejectDuplicateFields(raw); err != nil {
		return Cursor{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cursor Cursor
	if err := dec.Decode(&cursor); err != nil {
		return Cursor{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Cursor{}, errors.New("cursor has trailing content")
	}
	return cursor, nil
}
