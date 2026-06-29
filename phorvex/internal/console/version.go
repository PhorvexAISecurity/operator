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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BuildStamp identifies THIS console build. Injected at build time via
//   -ldflags "-X github.com/phorvex/phorvex/internal/console.BuildStamp=<stamp>"
// so the dashboard can show whether it is serving the latest build. "dev" when unset.
var BuildStamp = "dev"

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	out := map[string]string{"console": BuildStamp}
	if tag, full := operatorImageTag(); tag != "" {
		out["operator"] = tag      // short ECR tag the operator deployment runs (e.g. sha-a4c6c82)
		out["operatorImage"] = full // full ref (for the tooltip)
	}
	writeJSON(w, 200, out)
}

// operatorImageTag reads the IN-CLUSTER Phorvex operator's deployed image from the live cluster
// (the artifact rolled in ECR), returning the tag (after the last ':') + the full ref. The default
// kubeconfig context is the EKS host where phorvex-system/phorvex-phorvex runs. "" on any error.
func operatorImageTag() (tag, full string) {
	cs, err := clientForContext("")
	if err != nil {
		return "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	d, err := cs.AppsV1().Deployments("phorvex-system").Get(ctx, "phorvex-phorvex", metav1.GetOptions{})
	if err != nil || len(d.Spec.Template.Spec.Containers) == 0 {
		return "", ""
	}
	full = d.Spec.Template.Spec.Containers[0].Image
	tag = full
	if i := strings.LastIndexByte(full, ':'); i >= 0 {
		tag = full[i+1:]
	}
	return tag, full
}
