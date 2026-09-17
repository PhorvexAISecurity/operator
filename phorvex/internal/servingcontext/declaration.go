/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package servingcontext defines the annotation-only declaration boundary shared by
// ingestion and handlers that start from a raw Kubernetes Pod. A declaration is a
// structural routing/configuration witness; it is not evidence that a protocol
// answered or that a particular model is loaded.
package servingcontext

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	ModelIDAnnotation           = "phorvex.ai/model-id"
	ServingPortAnnotation       = "phorvex.ai/serving-port"
	GuardrailVariantAnnotation  = "phorvex.ai/guardrail-variant"
	GuardrailVariantsAnnotation = "phorvex.ai/guardrail-variants"
	MaxGuardrailVariantBytes    = 1024
)

// Declaration is the normalized serving context declared by Pod annotations.
type Declaration struct {
	ModelID string
	Port    int
}

// FromAnnotations normalizes the supported declarations. A serving port is present
// only when it is an integer in the TCP/UDP port range; malformed, empty and
// whitespace-only values remain absent.
func FromAnnotations(annotations map[string]string) Declaration {
	modelID := strings.TrimSpace(annotations[ModelIDAnnotation])
	rawPort := strings.TrimSpace(annotations[ServingPortAnnotation])
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		port = 0
	}
	return Declaration{ModelID: modelID, Port: port}
}

// Declared reports whether either supported structural declaration is present.
func (d Declaration) Declared() bool { return d.ModelID != "" || d.Port != 0 }

// GuardrailRoster is the normalized complete ordered variant declaration. Names
// are opaque and case-sensitive. The first occurrence determines stable order.
type GuardrailRoster struct {
	Current  string
	Variants []string
	index    int
}

// ParseGuardrailRoster validates a complete ordered roster, including the
// current member. Whitespace around names is configuration syntax rather than
// part of an opaque name; empty members remain malformed instead of vanishing.
func ParseGuardrailRoster(current, raw string) (GuardrailRoster, error) {
	current = strings.TrimSpace(current)
	if current == "" || len(current) > MaxGuardrailVariantBytes {
		return GuardrailRoster{}, fmt.Errorf("guardrail current variant must be nonempty and at most %d bytes", MaxGuardrailVariantBytes)
	}
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	variants := make([]string, 0, len(parts))
	currentIndex := -1
	for i, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" || len(name) > MaxGuardrailVariantBytes {
			return GuardrailRoster{}, fmt.Errorf("guardrail roster member %d must be nonempty and at most %d bytes", i, MaxGuardrailVariantBytes)
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		if name == current {
			currentIndex = len(variants)
		}
		variants = append(variants, name)
	}
	if currentIndex < 0 {
		return GuardrailRoster{}, fmt.Errorf("guardrail current variant is not in the complete ordered roster")
	}
	if len(variants) < 2 {
		return GuardrailRoster{}, fmt.Errorf("guardrail roster must contain at least two distinct variants")
	}
	return GuardrailRoster{Current: current, Variants: variants, index: currentIndex}, nil
}

// Next returns the cyclic successor of Current.
func (r GuardrailRoster) Next() string {
	if len(r.Variants) < 2 || r.index < 0 || r.index >= len(r.Variants) {
		return ""
	}
	return r.Variants[(r.index+1)%len(r.Variants)]
}

// Contains reports exact membership in the normalized roster.
func (r GuardrailRoster) Contains(name string) bool {
	for _, candidate := range r.Variants {
		if candidate == name {
			return true
		}
	}
	return false
}
