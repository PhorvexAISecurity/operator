// Package pendinggate inventories unfinished-work markers and keeps them out of
// production-tagged paths. PHORVEXSEC-83 owns the gate itself; each inventory row
// names the task that owns the underlying work.
package pendinggate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The fragments keep the gate from matching its own source.
var markerTokens = []string{
	"SP-0-" + "PENDING",
	"PENDING" + "-P4",
	"UN" + "RUN",
	"TO" + "DO",
	"FIX" + "ME",
	"nil" + "Source",
}

var textExtensions = map[string]bool{
	".go": true, ".md": true, ".yaml": true, ".yml": true, ".json": true,
	".sh": true, ".txt": true, ".tmpl": true, ".html": true, ".ts": true,
	".tsx": true, ".js": true,
}

// Hit is one inventory row.
type Hit struct {
	Path       string
	Line       int
	Text       string
	Marker     string
	Owner      string
	Production bool
}

// Scan returns every marker under root. The generated inventory is excluded so
// the output does not recursively inventory itself.
func Scan(root string) ([]Hit, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var hits []Hit
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "PENDING-INVENTORY.md" || !textExtensions[strings.ToLower(filepath.Ext(rel))] {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		// Reports can carry long JSON/HTML lines; inventorying must not silently skip them.
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for lineNo := 1; scanner.Scan(); lineNo++ {
			line := scanner.Text()
			marker := firstMarker(line)
			if marker == "" {
				continue
			}
			hits = append(hits, Hit{
				Path: rel, Line: lineNo, Text: strings.TrimSpace(line), Marker: marker,
				Owner: ownerFor(rel, line), Production: productionTagged(rel),
			})
		}
		return scanner.Err()
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Path != hits[j].Path {
			return hits[i].Path < hits[j].Path
		}
		return hits[i].Line < hits[j].Line
	})
	return hits, nil
}

func firstMarker(line string) string {
	for _, marker := range markerTokens {
		if strings.Contains(line, marker) {
			return marker
		}
	}
	return ""
}

func productionTagged(rel string) bool {
	ext := strings.ToLower(filepath.Ext(rel))
	if ext == ".go" {
		return !strings.HasSuffix(rel, "_test.go")
	}
	if (strings.HasPrefix(rel, "config/") || strings.HasPrefix(rel, "charts/")) &&
		(ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".tmpl") {
		return true
	}
	if strings.HasPrefix(rel, "hack/") && ext == ".sh" {
		return true
	}
	return strings.HasPrefix(rel, "grafana/") && ext == ".json"
}

// ownerFor maps historical and active marker families to their Plane owner. A new
// family deliberately returns empty and fails the gate until it receives a ticket.
func ownerFor(rel, line string) string {
	text := strings.ToLower(rel + " " + line)
	switch {
	case strings.Contains(text, "authn") || strings.Contains(text, "vcluster"):
		return "PHORVEXSEC-152"
	case strings.Contains(text, "epss"):
		return "PHORVEXSEC-104"
	case strings.Contains(text, "observerotation") || strings.Contains(text, "rls"):
		return "PHORVEXSEC-98"
	case strings.Contains(text, "c_flow") || strings.Contains(text, "flow-cost"):
		return "PHORVEXSEC-92"
	case strings.Contains(text, "rl red") || strings.Contains(text, "redteam"):
		return "PHORVEXSEC-23"
	case strings.Contains(text, "gpu") || strings.Contains(text, "dcgm") ||
		strings.Contains(text, "mig") || strings.Contains(text, "vram") ||
		strings.Contains(text, "coldload") || strings.Contains(text, "ai/") ||
		strings.Contains(text, "ai ") || strings.Contains(text, "ai-"):
		return "PHORVEXSEC-87"
	case strings.Contains(text, "real-cluster") || strings.Contains(text, "kubeconfig") ||
		strings.Contains(text, "live telemetry") || strings.Contains(text, "p4a"):
		return "PHORVEXSEC-151"
	case strings.Contains(rel, "P-DASHBOARD"):
		return "PHORVEXSEC-12"
	case strings.Contains(rel, "P-CONTEXT") || strings.Contains(rel, "P-PHYSICS"):
		return "PHORVEXSEC-115"
	case strings.Contains(rel, "METHOD") || strings.Contains(rel, "P1-REPORT"):
		return "PHORVEXSEC-91"
	case strings.Contains(rel, "BENCHMARK-RUNBOOK") || strings.Contains(rel, "P-ACTUATOR") ||
		strings.Contains(rel, "P3-DEEP") || strings.Contains(rel, "P4b") ||
		strings.Contains(rel, "P5-FINAL") || strings.Contains(rel, "EFFECTIVENESS") ||
		strings.Contains(rel, "P-AUDIT"):
		return "PHORVEXSEC-87"
	case strings.Contains(rel, "P4c"):
		return "PHORVEXSEC-151"
	}
	return ""
}

// RenderInventory creates the stable, reviewable source inventory. Rows carry no
// line number on purpose: a marker that merely shifts because an unrelated line
// landed above it is not a change worth failing a build over, and line-keyed rows
// made every such merge stale the inventory and break main. Hit.Line survives for
// the failure messages, which still point at an exact file:line.
func RenderInventory(hits []Hit) []byte {
	var b bytes.Buffer
	fmt.Fprintln(&b, "# Pending-marker inventory")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Generated by `go run ./cmd/pendingcheck -write` (PHORVEXSEC-83).")
	fmt.Fprintln(&b, "Production paths must contain zero rows; historical/design documents may retain a marker only with a Plane owner.")
	fmt.Fprintln(&b, "Rows omit line numbers so edits above a marker cannot stale the inventory; gate failures still report `file:line`.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Total markers: **%d**.\n\n", len(hits))
	fmt.Fprintln(&b, "| File | Production | Owner | Marker | Text |")
	fmt.Fprintln(&b, "|---|---:|---|---|---|")
	for _, hit := range hits {
		owner := hit.Owner
		if owner == "" {
			owner = "**ORPHAN**"
		}
		text := strings.ReplaceAll(hit.Text, "|", "\\|")
		if len(text) > 240 {
			text = text[:237] + "..."
		}
		fmt.Fprintf(&b, "| `%s` | %t | %s | `%s` | %s |\n",
			hit.Path, hit.Production, owner, hit.Marker, text)
	}
	return b.Bytes()
}

// Check enforces all three invariants: every hit has an owner, production has
// no marker, and the committed inventory exactly matches the source tree.
func Check(root, inventoryPath string) error {
	hits, err := Scan(root)
	if err != nil {
		return err
	}
	var problems []string
	for _, hit := range hits {
		if hit.Owner == "" {
			problems = append(problems, fmt.Sprintf("orphan marker %s:%d (%s)", hit.Path, hit.Line, hit.Marker))
		}
		if hit.Production {
			problems = append(problems, fmt.Sprintf("production marker %s:%d (%s, owner %s)", hit.Path, hit.Line, hit.Marker, hit.Owner))
		}
	}
	expected := RenderInventory(hits)
	actual, err := os.ReadFile(inventoryPath)
	if err != nil {
		problems = append(problems, fmt.Sprintf("read inventory: %v", err))
	} else if !bytes.Equal(actual, expected) {
		problems = append(problems, "PENDING-INVENTORY.md is stale; run go run ./cmd/pendingcheck -write")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}
