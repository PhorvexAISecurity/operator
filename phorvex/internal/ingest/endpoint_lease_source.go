package ingest

import (
	"errors"
	"strings"
	"sync"

	"github.com/phorvex/phorvex/internal/endpointlease"
)

// This pin comes from the reviewed manager deployment, never from a
// SecurityEvent. Empty keeps the new action unavailable by default.
var endpointLeaseSource struct {
	sync.RWMutex
	sha         string
	image       string
	engineImage string
}

func ConfigureEndpointLeaseApprovedAuthority(sha, image, engineImage string) error {
	if sha != "" && !endpointlease.ValidSHA(sha) {
		return errors.New("endpoint lease approved source must be a lowercase SHA-256")
	}
	if image != "" {
		repo, digest, ok := strings.Cut(image, "@sha256:")
		if !ok || repo == "" || strings.ContainsAny(repo, " \t\n@") || !endpointlease.ValidSHA(digest) {
			return errors.New("endpoint lease approved proxy image must be an immutable repo@sha256")
		}
	}
	if engineImage != "" {
		repo, digest, ok := strings.Cut(engineImage, "@sha256:")
		if !ok || repo == "" || strings.ContainsAny(repo, " \t\n@") || !endpointlease.ValidSHA(digest) {
			return errors.New("endpoint lease approved engine image must be an immutable repo@sha256")
		}
	}
	if (sha == "") != (image == "") || (sha == "") != (engineImage == "") {
		return errors.New("endpoint lease source, proxy image, and engine image must be configured together")
	}
	endpointLeaseSource.Lock()
	endpointLeaseSource.sha = sha
	endpointLeaseSource.image = image
	endpointLeaseSource.engineImage = engineImage
	endpointLeaseSource.Unlock()
	return nil
}

func endpointLeaseApprovedAuthority() (string, string, string) {
	endpointLeaseSource.RLock()
	defer endpointLeaseSource.RUnlock()
	return endpointLeaseSource.sha, endpointLeaseSource.image, endpointLeaseSource.engineImage
}
