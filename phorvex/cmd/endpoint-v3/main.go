package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	study "github.com/phorvex/phorvex/internal/cost/endpoint"
)

func main() {
	var in, out, states, config string
	flag.StringVar(&in, "trace", "", "normalized endpoint trace JSON")
	flag.StringVar(&out, "out", "", "result JSON path")
	flag.StringVar(&states, "state-dir", "", "isolated durable V3 state directory")
	flag.StringVar(&config, "config", "", "optional bounded study constants JSON")
	flag.Parse()
	if err := run(in, out, states, config); err != nil {
		fmt.Fprintln(os.Stderr, "endpoint-v3:", err)
		os.Exit(2)
	}
}
func decode(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) > 64<<20 {
		return fmt.Errorf("input exceeds 64 MiB")
	}
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(raw)), 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected a single JSON value")
	}
	return nil
}

// encoding/json otherwise accepts duplicate object keys with last-value wins,
// which would make a reviewed trace differ from what another reader sees.
func uniqueKeys(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds 64")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate or invalid JSON object key")
			}
			seen[key] = true
			if err := uniqueKeys(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for d.More() {
			if err := uniqueKeys(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}
func run(in, out, states, config string) error {
	if in == "" || out == "" || states == "" {
		return fmt.Errorf("-trace, -out, -state-dir are required")
	}
	var trace study.Trace
	if err := decode(in, &trace); err != nil {
		return err
	}
	cfg := study.Defaults()
	if config != "" {
		if err := decode(config, &cfg); err != nil {
			return err
		}
	}
	res, err := study.Run(trace, cfg, study.FileStore{Dir: states})
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(out, append(raw, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("%s: %d/%d comparable ticks; evidence=%s; mode=%s\n", res.State, res.Comparable, len(res.Ticks), res.Evidence, res.Mode)
	return nil
}
