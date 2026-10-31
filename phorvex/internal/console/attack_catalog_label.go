package console

import (
	"crypto/sha256"
	"encoding/hex"
)

// catalogueIDAnnotationKey is the metadata key under which the exact canonical
// catalogue ID is preserved losslessly. Kubernetes annotations permit ':' (and
// every other character that label values forbid), so the raw ID such as
// "LLM06:2025" or "ASI02:2026" is stored here verbatim. The homonymous label
// phorvex.ai/catalogue-id instead carries catalogueIDLabelValue(id), a
// sanitised, admission-safe projection of the same ID.
const catalogueIDAnnotationKey = "phorvex.ai/catalogue-id"

// catalogueIDLabelValue derives a Kubernetes-valid label value from a canonical
// catalogue ID. Kubernetes rejects ':' (and other characters) in label values,
// so IDs such as "LLM06:2025" cannot be used verbatim as the value of the
// phorvex.ai/catalogue-id label -- admission would fail and the run would error.
//
// The projection is the lowercase alphanumeric slug of the ID followed by an
// 8-hex sha256-derived suffix. The suffix makes the mapping injective in
// practice: two distinct IDs (e.g. "ASI02:2026" and "ASI02-2026") that slugify
// identically still receive different label values. The result is
// deterministic, begins and ends with an alphanumeric character, and is at most
// 63 characters (<=54 slug + '-' + 8 hex), satisfying RFC 1123 label-value
// constraints.
func catalogueIDLabelValue(id string) string {
	sum := sha256.Sum256([]byte(id))
	suffix := hex.EncodeToString(sum[:4])
	slug := k8sCatalogueSlug(id, 54)
	if slug == "" {
		return "id-" + suffix
	}
	return slug + "-" + suffix
}
