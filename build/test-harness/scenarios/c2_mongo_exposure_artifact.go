package scenarios

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

const mongoExposureArtifactSchema = "mongo-exposure-artifact-v1"
const mongoExposureTerminalSchema = "mongo-exposure-terminal-v1"

var mongoExposureRunID = regexp.MustCompile(`^run-[1-9][0-9]*$`)
var mongoExposureNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)

type mongoExposureArtifact struct {
	Schema               string              `json:"schema"`
	RunID                string              `json:"runId"`
	Nonce                string              `json:"nonce"`
	Namespace            string              `json:"namespace"`
	ClusterUID           types.UID           `json:"clusterUID"`
	Source               mongoExposureSource `json:"source"`
	Node                 mongoExposureNode   `json:"node"`
	Database             string              `json:"database"`
	Collection           string              `json:"collection"`
	CollectionUUID       string              `json:"collectionUUID"`
	ServerVersion        string              `json:"serverVersion"`
	DocumentSHA256       string              `json:"documentSHA256"`
	ClientPodName        string              `json:"clientPodName"`
	ClientPodUID         types.UID           `json:"clientPodUID"`
	ClientContainerID    string              `json:"clientContainerID"`
	ClientImageID        string              `json:"clientImageID"`
	ClientRead           string              `json:"clientRead"`
	ClientDocumentSHA256 string              `json:"clientDocumentSHA256"`
	RawReplySHA256       string              `json:"rawReplySHA256"`
	RawReplyBytes        int                 `json:"rawReplyBytes"`
	LegitimateBefore     string              `json:"legitimateBefore"`
	LegitimateAfter      string              `json:"legitimateAfter"`
	ObservedFinding      string              `json:"observedFinding"`
	Validity             string              `json:"validity"`
	Cleanup              string              `json:"cleanup"`
	SecurityOutcome      string              `json:"securityOutcome"`
	StartedAt            string              `json:"startedAt"`
	ObservationEndedAt   string              `json:"observationEndedAt"`
	FinishedAt           string              `json:"finishedAt"`
}

type mongoExposureTerminal struct {
	Schema             string    `json:"schema"`
	RunID              string    `json:"runId"`
	Nonce              string    `json:"nonce"`
	NamespaceUID       types.UID `json:"namespaceUID"`
	ArtifactSHA256     string    `json:"artifactSHA256"`
	CollectionAbsent   bool      `json:"collectionAbsent"`
	ClientPodAbsent    bool      `json:"clientPodAbsent"`
	NamespacePreserved bool      `json:"namespacePreserved"`
	Cleanup            string    `json:"cleanup"`
	ObservedAt         string    `json:"observedAt"`
}

func mongoExposureRoot(out string) (*os.Root, error) {
	if !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return nil, errors.New("Mongo output must be one exact absolute directory")
	}
	resolved, err := filepath.EvalSymlinks(out)
	if err != nil || resolved != out {
		return nil, errors.New("Mongo output directory unavailable or linked")
	}
	return os.OpenRoot(out)
}

func mongoExposureExclusive(out, name string, raw []byte) error {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return errors.New("Mongo evidence absent or oversized")
	}
	root, err := mongoExposureRoot(out)
	if err != nil {
		return err
	}
	defer root.Close()
	if name == "" || filepath.Base(name) != name {
		return errors.New("Mongo evidence name invalid")
	}
	tmp := name + ".tmp"
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	// Link is exclusive: a second attempt cannot replace a prior ledger.
	if err := os.Link(filepath.Join(out, tmp), filepath.Join(out, name)); err != nil {
		return err
	}
	if err := root.Remove(tmp); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func ClaimMongoExposureRun(out, runID, nonce string) error {
	if !mongoExposureRunID.MatchString(runID) || !mongoExposureNonce.MatchString(nonce) {
		return errors.New("Mongo claim identity invalid")
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		return err
	}
	raw, _ := json.Marshal(map[string]string{"schema": "mongo-exposure-claim-v1", "runId": runID, "nonce": nonce, "at": time.Now().UTC().Format(time.RFC3339Nano)})
	return mongoExposureExclusive(out, "mongo-exposure-claim.json", raw)
}

func mongoExposurePhase(out, runID, nonce, phase, resource, name, identity string) error {
	if !mongoExposureRunID.MatchString(runID) || !mongoExposureNonce.MatchString(nonce) || phase == "" || resource == "" || name == "" {
		return errors.New("Mongo phase authority incomplete")
	}
	raw, err := json.Marshal(map[string]string{"schema": "mongo-exposure-phase-v1", "runId": runID, "nonce": nonce, "phase": phase, "resource": resource, "name": name, "identity": identity, "at": time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil || len(raw) > 1024 {
		return errors.New("Mongo phase too large")
	}
	path := filepath.Join(out, "mongo-exposure-phases.jsonl")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_APPEND|syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 {
		return errors.New("Mongo phase journal invalid or oversized")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("Mongo phase journal linked")
	}
	if _, err = f.Write(append(raw, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(out)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeMongoExposureArtifact(out string, a mongoExposureArtifact, t mongoExposureTerminal) error {
	if a.Schema != mongoExposureArtifactSchema || a.SecurityOutcome != "NOT_EVALUATED" || a.RunID == "" || a.Nonce == "" || a.Source.NamespaceUID == "" ||
		a.ClientRead != "UNAUTHENTICATED_EXACT_READ" && a.ClientRead != "MONGO_AUTH_DENIED" && a.ClientRead != "UNKNOWN" && a.ClientRead != "UNKNOWN_SERVER_REFUSAL" && a.ClientRead != "UNKNOWN_DOCUMENT_ABSENT" ||
		a.Validity != "MEASUREMENT_COMPLETE" && a.Validity != "INCONCLUSIVE" || a.Cleanup != "CONFIRMED_ABSENT" && a.Cleanup != "UNCONFIRMED" {
		return errors.New("Mongo artifact status or identity invalid")
	}
	raw, err := json.Marshal(a)
	if err != nil || len(raw) > 64<<10 {
		return errors.New("Mongo artifact oversized")
	}
	if err := mongoExposureExclusive(out, "mongo-exposure.json", raw); err != nil {
		return err
	}
	h := sha256.Sum256(raw)
	t.Schema = mongoExposureTerminalSchema
	t.RunID, t.Nonce, t.NamespaceUID = a.RunID, a.Nonce, a.Source.NamespaceUID
	t.ArtifactSHA256 = hex.EncodeToString(h[:])
	t.Cleanup = a.Cleanup
	t.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if t.Cleanup == "CONFIRMED_ABSENT" && (!t.CollectionAbsent || !t.ClientPodAbsent || !t.NamespacePreserved) {
		return errors.New("Mongo terminal cleanup claim lacks independent absence")
	}
	terminal, err := json.Marshal(t)
	if err != nil || len(terminal) > 4096 {
		return fmt.Errorf("Mongo terminal invalid: %w", err)
	}
	return mongoExposureExclusive(out, "mongo-exposure-terminal.json", terminal)
}
