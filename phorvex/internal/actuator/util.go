/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package actuator

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiValidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	identityVersionAnnotation   = "phorvex.ai/identity-version"
	rawTenantAnnotation         = "phorvex.ai/tenant-raw"
	rawNamespaceAnnotation      = "phorvex.ai/namespace-raw"
	metadataIdentityVersion     = "v1"
	metadataIdentityDigestBytes = 16
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

// tenantLabel preserves the legacy value whenever it is already a valid label.
// Invalid legacy values receive a readable prefix and a digest of the full raw input.
func tenantLabel(raw string) string {
	legacy := sanitize(raw)
	if len(validation.IsValidLabelValue(legacy)) == 0 {
		return legacy
	}
	return boundedIdentity("tenant-label-v1", []string{raw}, legacy, validation.LabelValueMaxLength)
}

// boundedAMTDName preserves every valid legacy name byte-for-byte. Only invalid legacy
// names move to the versioned, collision-resistant representation.
func boundedAMTDName(namespace, tenant string) string {
	legacy := "phorvex-" + sanitize(namespace) + "-" + sanitize(tenant)
	if len(validation.IsDNS1123Subdomain(legacy)) == 0 {
		return legacy
	}
	return boundedIdentity("amtd-name-v1", []string{namespace, tenant}, legacy, validation.DNS1123SubdomainMaxLength)
}

func boundedIdentity(domain string, raw []string, readable string, limit int) string {
	h := sha256.New()
	writeFramed := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	writeFramed(domain)
	for _, value := range raw {
		writeFramed(value)
	}
	digest := hex.EncodeToString(h.Sum(nil)[:metadataIdentityDigestBytes])
	prefixLimit := limit - len(digest) - 1
	readable = strings.Trim(sanitize(readable), "-")
	if len(readable) > prefixLimit {
		readable = strings.TrimRight(readable[:prefixLimit], "-")
	}
	if readable == "" {
		readable = "default"
	}
	return readable + "-" + digest
}

func identityAnnotations(namespace, tenant string) map[string]string {
	return map[string]string{
		identityVersionAnnotation: metadataIdentityVersion,
		rawNamespaceAnnotation:    namespace,
		rawTenantAnnotation:       tenant,
	}
}

func mergeAnnotations(existing, additions map[string]string) map[string]string {
	out := make(map[string]string, len(existing)+len(additions))
	for key, value := range existing {
		out[key] = value
	}
	for key, value := range additions {
		out[key] = value
	}
	return out
}

func validateIdentityMetadata(namespace string, annotations map[string]string) error {
	if errs := validation.IsDNS1123Label(namespace); len(errs) != 0 {
		return fmt.Errorf("invalid namespace %q: %s", namespace, strings.Join(errs, "; "))
	}
	if !utf8.ValidString(namespace) || !utf8.ValidString(annotations[rawTenantAnnotation]) {
		return fmt.Errorf("raw Phoenix identity must be valid UTF-8")
	}
	if errs := apiValidation.ValidateAnnotations(annotations, field.NewPath("metadata", "annotations")); len(errs) != 0 {
		return fmt.Errorf("invalid Phoenix identity annotations: %s", errs.ToAggregate())
	}
	return nil
}

func validateObjectMetadata(meta *metav1.ObjectMeta) error {
	if errs := validation.IsDNS1123Subdomain(meta.Name); meta.Name != "" && len(errs) != 0 {
		return fmt.Errorf("invalid metadata.name %q: %s", meta.Name, strings.Join(errs, "; "))
	}
	for key, value := range meta.Labels {
		if errs := validation.IsValidLabelValue(value); len(errs) != 0 {
			return fmt.Errorf("invalid metadata.labels[%q] value %q: %s", key, value, strings.Join(errs, "; "))
		}
	}
	if errs := apiValidation.ValidateAnnotations(meta.Annotations, field.NewPath("metadata", "annotations")); len(errs) != 0 {
		return fmt.Errorf("invalid metadata.annotations: %s", errs.ToAggregate())
	}
	return nil
}
