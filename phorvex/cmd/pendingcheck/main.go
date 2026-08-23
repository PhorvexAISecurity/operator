// pendingcheck is the repository gate for PHORVEXSEC-83.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/phorvex/phorvex/internal/pendinggate"
)

func main() {
	root := flag.String("root", ".", "phorvex module root")
	inventory := flag.String("inventory", "PENDING-INVENTORY.md", "committed inventory path")
	write := flag.Bool("write", false, "regenerate the inventory instead of checking it")
	flag.Parse()

	invPath := *inventory
	if !filepath.IsAbs(invPath) {
		invPath = filepath.Join(*root, invPath)
	}
	if *write {
		hits, err := pendinggate.Scan(*root)
		if err != nil {
			fatal(err)
		}
		for _, hit := range hits {
			if hit.Owner == "" {
				fatal(fmt.Errorf("orphan marker %s:%d (%s)", hit.Path, hit.Line, hit.Marker))
			}
			if hit.Production {
				fatal(fmt.Errorf("production marker %s:%d (%s)", hit.Path, hit.Line, hit.Marker))
			}
		}
		if err := os.WriteFile(invPath, pendinggate.RenderInventory(hits), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s (%d owned markers, zero production markers)\n", invPath, len(hits))
		return
	}
	if err := pendinggate.Check(*root, invPath); err != nil {
		fatal(err)
	}
	fmt.Println("pending-marker gate passed: inventory current, all markers owned, production clean")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
