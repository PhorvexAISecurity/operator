// Command parameter-manifest exports the exact versioned decision parameter
// registry. It performs no cluster reads and does not run a decision.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
)

func main() {
	gpuEnvelope := flag.Float64("gpu-envelope-max", cost.GPUEnvelopeMax(), "configured normalized GPU warm-up envelope [0,1]")
	flag.Parse()
	if err := cost.ConfigureGPUEnvelopeMax(*gpuEnvelope); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	manifest := decision.ProductionParameterManifest().Canonical()
	hash, err := manifest.CanonicalHash()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out := struct {
		Manifest any    `json:"manifest"`
		Hash     string `json:"hash"`
	}{Manifest: manifest, Hash: hash}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
