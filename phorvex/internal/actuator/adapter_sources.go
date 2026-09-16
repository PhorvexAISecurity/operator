package actuator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	validation "k8s.io/apimachinery/pkg/util/validation"
)

const maxAdapterSourcesBytes = 1 << 20
const maxAdapterSourcePathBytes = 4096

type AdapterSources map[string]string

type adapterSourcesDocument struct {
	Version int                  `json:"version"`
	Sources []adapterSourceEntry `json:"sources"`
}
type adapterSourceEntry struct {
	Namespace string `json:"namespace"`
	Adapter   string `json:"adapter"`
	Source    string `json:"source"`
}

var adapterIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func adapterSourceKey(namespace, adapter string) string { return namespace + "\x00" + adapter }

func (s AdapterSources) source(namespace, adapter string) (string, bool) {
	v, ok := s[adapterSourceKey(namespace, adapter)]
	return v, ok
}

func LoadAdapterSourcesFile(path string) (AdapterSources, error) {
	if path == "" {
		return AdapterSources{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("adapter clean sources: %w", err)
	}
	defer f.Close()
	limited := &bytes.Buffer{}
	if _, err := limited.ReadFrom(io.LimitReader(f, maxAdapterSourcesBytes+1)); err != nil {
		return nil, err
	}
	if limited.Len() > maxAdapterSourcesBytes {
		return nil, fmt.Errorf("adapter clean sources exceeds %d bytes", maxAdapterSourcesBytes)
	}
	if err := adapterRejectDuplicateJSONFields(limited.Bytes()); err != nil {
		return nil, fmt.Errorf("adapter clean sources: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(limited.Bytes()))
	dec.DisallowUnknownFields()
	var doc adapterSourcesDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("adapter clean sources: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("adapter clean sources: trailing content")
	}
	if doc.Version != 1 || len(doc.Sources) > 1024 {
		return nil, fmt.Errorf("adapter clean sources: unsupported version or too many entries")
	}
	out := AdapterSources{}
	for _, e := range doc.Sources {
		if len(validation.IsDNS1123Label(e.Namespace)) != 0 || !adapterIDPattern.MatchString(e.Adapter) {
			return nil, fmt.Errorf("adapter clean sources: invalid namespace or adapter identity")
		}
		if e.Source == "" || len(e.Source) > maxAdapterSourcePathBytes || e.Source == "/" || strings.ContainsAny(e.Source, "*?[]{}") || strings.IndexFunc(e.Source, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 || !filepath.IsAbs(e.Source) || filepath.Clean(e.Source) != e.Source {
			return nil, fmt.Errorf("adapter clean sources: source must be a clean absolute serving-local path")
		}
		k := adapterSourceKey(e.Namespace, e.Adapter)
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("adapter clean sources: duplicate namespace and adapter")
		}
		out[k] = e.Source
	}
	return out, nil
}

// adapterRejectDuplicateJSONFields rejects ambiguity before typed decoding.
// encoding/json otherwise silently lets the last duplicate field win.
func adapterRejectDuplicateJSONFields(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var value func() error
	value = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = struct{}{}
				if err := value(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return fmt.Errorf("invalid object ending")
			}
		case '[':
			for dec.More() {
				if err := value(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return fmt.Errorf("invalid array ending")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

func copyAdapterSources(in AdapterSources) AdapterSources {
	out := AdapterSources{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
