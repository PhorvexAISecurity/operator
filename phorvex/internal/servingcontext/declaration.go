/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package servingcontext defines the annotation-only declaration boundary shared by
// ingestion and handlers that start from a raw Kubernetes Pod. A declaration is a
// structural routing/configuration witness; it is not evidence that a protocol
// answered or that a particular model is loaded.
package servingcontext

import (
	"strconv"
	"strings"
)

const (
	ModelIDAnnotation     = "phorvex.ai/model-id"
	ServingPortAnnotation = "phorvex.ai/serving-port"
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
