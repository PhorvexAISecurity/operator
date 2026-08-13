/*
 * Phorvex Console — VERSION readout.
 *
 * GET /api/version reports the live component versions so the dashboard footer can show, at a
 * glance, WHICH build is deployed and whether a roll actually landed. Honest + best-effort: the
 * operator image is read from the LIVE cluster (never cached/faked); a field is OMITTED rather
 * than guessed when it can't be resolved.
 */

package console

import (
	"context"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BuildStamp identifies the SOURCE BUILD of this console binary. Injected at build time via
//   -ldflags "-X github.com/phorvex/phorvex/internal/console.BuildStamp=<stamp>"
// "dev" when unset.
//
// It is deliberately NOT what the "console" field reports. The release job retags an image ECR
// already holds rather than rebuilding it (ci.yml "Tag the built images with the version"), so
// the binary is compiled before the semver it will ship under even exists — it can only ever
// carry the main-branch tag. Reporting that made /api/version answer {"console":"latest",
// "operator":"0.4.19"} and kept the End-to-End version-match check (P02) permanently yellow.
var BuildStamp = "dev"

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	// "console" and "operator" are both read from the live Deployment so the two are the same
	// KIND of fact and can honestly be compared. consoleBuild keeps the compile-time stamp
	// visible — a mismatch against "console" means the running image was retagged, which is
	// normal here, and is worth being able to see rather than hiding.
	out := map[string]string{"console": BuildStamp, "consoleBuild": BuildStamp}
	conts := deployedContainers()
	// The operator keeps the legacy single-container fallback: it was read as Containers[0]
	// long before the console became a sidecar. The console does NOT get that fallback — in a
	// one-container Deployment the single container IS the operator, and falling back there
	// would report the operator's tag as the console's own version.
	if tag, full := imageOf(conts, "console", false); tag != "" {
		out["console"] = tag
		out["consoleImage"] = full
	}
	if tag, full := imageOf(conts, "manager", true); tag != "" {
		out["operator"] = tag       // short ECR tag the operator deployment runs (e.g. sha-a4c6c82)
		out["operatorImage"] = full // full ref (for the tooltip)
	}
	writeJSON(w, 200, out)
}

// deployedContainers returns the container list of the IN-CLUSTER phorvex-phorvex Deployment —
// the artifact ArgoCD actually rolled. The default kubeconfig context is the EKS host where
// phorvex-system/phorvex-phorvex runs. nil on any error, which callers report as an absent field
// rather than a guess. Fetched once so a single /api/version costs one API call, not one per
// container looked up.
func deployedContainers() []corev1.Container {
	cs, err := clientForContext("")
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	d, err := cs.AppsV1().Deployments("phorvex-system").Get(ctx, "phorvex-phorvex", metav1.GetOptions{})
	if err != nil {
		return nil
	}
	return d.Spec.Template.Spec.Containers
}

// imageOf picks one container's image by NAME and splits it into the tag (after the last ':')
// and the full ref. With allowSingle, a Deployment holding exactly one container matches
// regardless of its name — there is nothing to confuse it with. Otherwise an unmatched name
// returns "" rather than guessing.
func imageOf(conts []corev1.Container, name string, allowSingle bool) (tag, full string) {
	if len(conts) == 0 {
		return "", ""
	}
	if allowSingle && len(conts) == 1 {
		full = conts[0].Image
	} else {
		for _, c := range conts {
			if c.Name == name {
				full = c.Image
				break
			}
		}
	}
	if full == "" {
		return "", ""
	}
	tag = full
	if i := strings.LastIndexByte(full, ':'); i >= 0 {
		tag = full[i+1:]
	}
	return tag, full
}
