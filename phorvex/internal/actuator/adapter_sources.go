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
		if e.Source == "" || e.Source == "/" || strings.IndexFunc(e.Source, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 || !filepath.IsAbs(e.Source) || filepath.Clean(e.Source) != e.Source {
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

func copyAdapterSources(in AdapterSources) AdapterSources {
	out := AdapterSources{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
