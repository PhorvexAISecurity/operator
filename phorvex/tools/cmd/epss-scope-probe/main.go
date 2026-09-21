// epss-scope-probe is a source-bound offline check for the exact production
// loader, repository fallback and multiplier. It does not add a manager mode or
// write Kubernetes objects.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/recon"
)

func main() {
	var cachePath, imageID string
	flag.StringVar(&cachePath, "cache", "", "exact bare EPSS cache JSON path")
	flag.StringVar(&imageID, "image", "", "running image identity to evaluate")
	flag.Parse()
	if cachePath == "" || imageID == "" {
		fmt.Fprintln(os.Stderr, "--cache and --image are required")
		os.Exit(2)
	}
	if err := platform.LoadEPSSFromFile(cachePath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	lk := platform.EPSSLookupForVerification(imageID)
	multiplier, present, reason := recon.EPSSMultiplier(lk.EPSS, lk.CVSS, lk.Present)
	out := struct {
		Lookup     platform.EPSSLookup `json:"lookup"`
		Multiplier float64             `json:"multiplier"`
		Present    bool                `json:"present"`
		Reason     string              `json:"reason,omitempty"`
	}{lk, multiplier, present, reason}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
