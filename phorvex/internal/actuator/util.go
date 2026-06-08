/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package actuator

import (
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// apiNotFound reports whether err is a Kubernetes "not found" error.
func apiNotFound(err error) bool { return apierrors.IsNotFound(err) }

// sanitize makes a string safe for use in a Kubernetes resource name / label value:
// lowercased, non-alphanumerics collapsed to '-', trimmed, and bounded. An empty or
// fully-stripped input yields "default".
func sanitize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "default"
	}
	if len(out) > 200 {
		out = strings.Trim(out[:200], "-")
	}
	return out
}
