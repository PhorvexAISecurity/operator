package pendinggate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testMarker() string { return "TO" + "DO" }

func TestScanClassifiesProductionAndDocumentation(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "internal", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal", "x", "x.go"),
		[]byte("package x // "+testMarker()+" GPU validation\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "P-DASHBOARD-REPORT.md"),
		[]byte(testMarker()+" endpoint\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	hits, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2: %#v", len(hits), hits)
	}
	if !hits[1].Production && !hits[0].Production {
		t.Fatalf("expected one production hit: %#v", hits)
	}
	for _, hit := range hits {
		if hit.Owner == "" {
			t.Fatalf("expected mapped owner: %#v", hit)
		}
	}
}

func TestUnknownFamilyIsOrphaned(t *testing.T) {
	if owner := ownerFor("README.md", testMarker()+" unexplained"); owner != "" {
		t.Fatalf("unexpected owner %q", owner)
	}
}

func TestRepositoryInventoryAndProductionGate(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	err := Check(root, filepath.Join(root, "PENDING-INVENTORY.md"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestRenderMarksOrphan(t *testing.T) {
	b := RenderInventory([]Hit{{Path: "README.md", Line: 1, Marker: testMarker(), Text: "x"}})
	if !strings.Contains(string(b), "ORPHAN") {
		t.Fatalf("inventory did not expose orphan: %s", b)
	}
}

func TestCheckRejectsProductionMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "internal", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal", "x", "x.go"),
		[]byte("package x // "+testMarker()+" GPU validation\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hits, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(root, "PENDING-INVENTORY.md")
	if err := os.WriteFile(inv, RenderInventory(hits), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Check(root, inv); err == nil || !strings.Contains(err.Error(), "production marker") {
		t.Fatalf("expected production rejection, got %v", err)
	}
}

func TestCheckRejectsStaleInventory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "P-DASHBOARD-REPORT.md"),
		[]byte(testMarker()+" endpoint\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(root, "PENDING-INVENTORY.md")
	if err := os.WriteFile(inv, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Check(root, inv); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("expected stale inventory rejection, got %v", err)
	}
}
