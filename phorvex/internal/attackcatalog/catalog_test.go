package attackcatalog

import "testing"

func TestEmbeddedCatalogueExactOrderCountAndUniqueness(t *testing.T) {
	got, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != ExpectedSize || got[0].ID != FirstID {
		t.Fatalf("catalogue identity: count=%d first=%q", len(got), got[0].ID)
	}
	seen := map[string]bool{}
	for i, entry := range got {
		if entry.Order != i+1 || seen[entry.ID] {
			t.Fatalf("entry %d: order=%d duplicate=%v id=%q", i, entry.Order, seen[entry.ID], entry.ID)
		}
		seen[entry.ID] = true
		if looked, ok := Lookup(entry.ID); !ok || looked != entry {
			t.Fatalf("lookup %q did not preserve the embedded entry", entry.ID)
		}
	}
}

func TestUnknownIDIsNotAllowlisted(t *testing.T) {
	if _, ok := Lookup("AML.T0012; arbitrary"); ok {
		t.Fatal("unknown input entered the catalogue allowlist")
	}
}
