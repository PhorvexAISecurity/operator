package scenarios

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"k8s.io/apimachinery/pkg/types"
)

// This wire contract is run-private and fsynced; it is not an externally
// supplied signal or receipt API. Kubernetes remains the authority for UIDs.
const natsResponseSchema = "nats-client-response-v1"

var natsResponseRunID = regexp.MustCompile(`^run-[1-9][0-9]*$`)
var natsResponseNonce = regexp.MustCompile(`^[0-9a-f]{24}$`)

type natsResponseObserverReceipt struct {
	Kind               string `json:"kind"`
	Phase              string `json:"phase"`
	Status             string `json:"status"`
	Subject            string `json:"subject"`
	Nonce              string `json:"nonce"`
	PodUID             string `json:"podUID"`
	ServerID           string `json:"serverID"`
	Flushed            bool   `json:"flushed,omitempty"`
	PayloadBytes       int    `json:"payloadBytes,omitempty"`
	PayloadSHA256      string `json:"payloadSHA256,omitempty"`
	NonceHeaderMatches bool   `json:"nonceHeaderMatches,omitempty"`
	PayloadHashMatches bool   `json:"payloadHashMatches,omitempty"`
}

type natsResponseObserverIdentity struct {
	Nonce           string
	PodUID          types.UID
	SubjectM0       string
	SubjectM1       string
	PayloadM0SHA256 string
	PayloadM1SHA256 string
	ServerIDs       map[string]bool
}

var responseReceiptKeys = map[string]bool{
	"kind": true, "phase": true, "status": true, "subject": true, "nonce": true,
	"podUID": true, "serverID": true, "flushed": true, "payloadBytes": true,
	"payloadSHA256": true, "nonceHeaderMatches": true, "payloadHashMatches": true,
}

func decodeNATSResponseReceipt(raw []byte) (natsResponseObserverReceipt, error) {
	var row natsResponseObserverReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	tok, err := decoder.Token()
	if err != nil || tok != json.Delim('{') {
		return row, errors.New("observer receipt object required")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !responseReceiptKeys[key] || seen[key] {
			return row, errors.New("observer receipt key ambiguous")
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return row, errors.New("observer receipt value invalid")
		}
	}
	tok, err = decoder.Token()
	if err != nil || tok != json.Delim('}') || len(seen) < 7 {
		return row, errors.New("observer receipt incomplete")
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return row, errors.New("observer receipt trailing data")
	}
	if json.Unmarshal(raw, &row) != nil {
		return row, errors.New("observer receipt malformed")
	}
	return row, nil
}

// The only accepted prefixes are both subscriptions, then M0, then M1.
// A timeout is preserved as UNKNOWN; only an exact payload is a receipt.
func validateNATSResponseLog(raw []byte, id natsResponseObserverIdentity, want int) ([]natsResponseObserverReceipt, error) {
	if want < 2 || want > 4 || len(raw) == 0 || len(raw) > 4096 || raw[len(raw)-1] != '\n' ||
		id.Nonce == "" || id.PodUID == "" || id.SubjectM0 == id.SubjectM1 ||
		id.PayloadM0SHA256 == id.PayloadM1SHA256 || len(id.ServerIDs) == 0 {
		return nil, errors.New("observer log authority incomplete")
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(lines) != want {
		return nil, errors.New("observer receipt count differs")
	}
	result := make([]natsResponseObserverReceipt, 0, want)
	serverID := ""
	for i, line := range lines {
		if len(line) == 0 || len(line) > 1024 {
			return nil, errors.New("observer receipt size invalid")
		}
		row, err := decodeNATSResponseReceipt(line)
		if err != nil {
			return nil, err
		}
		phase, subject, digest := "M0", id.SubjectM0, id.PayloadM0SHA256
		if i == 1 || i == 3 {
			phase, subject, digest = "M1", id.SubjectM1, id.PayloadM1SHA256
		}
		if row.Phase != phase || row.Subject != subject || row.Nonce != id.Nonce ||
			row.PodUID != string(id.PodUID) || !id.ServerIDs[row.ServerID] {
			return nil, errors.New("observer receipt target or source identity differs")
		}
		if i == 0 {
			serverID = row.ServerID
		}
		if row.ServerID != serverID {
			return nil, errors.New("observer broker changed across phases")
		}
		if i < 2 {
			if row.Kind != "subscription" || row.Status != "READY" || !row.Flushed ||
				row.PayloadBytes != 0 || row.PayloadSHA256 != "" || row.NonceHeaderMatches || row.PayloadHashMatches {
				return nil, errors.New("observer subscription barrier invalid")
			}
		} else {
			if row.Kind != "observation" || row.Flushed || row.PayloadBytes < 0 || row.PayloadBytes > 256 {
				return nil, errors.New("observer packet receipt invalid")
			}
			if row.Status == "EXACT_PAYLOAD_RECEIVED" {
				if !row.NonceHeaderMatches || !row.PayloadHashMatches || row.PayloadSHA256 != digest || row.PayloadBytes < 1 {
					return nil, errors.New("observer exact packet claim mismatched")
				}
			} else if row.Status == "TIMEOUT_UNKNOWN" || row.Status == "TRANSPORT_UNKNOWN" || row.Status == "PERMISSION_DENIED" {
				if i == 2 || row.PayloadSHA256 != "" || row.PayloadBytes != 0 || row.NonceHeaderMatches || row.PayloadHashMatches {
					return nil, errors.New("observer unknown/denied receipt invalid")
				}
			} else if row.Status != "IDENTITY_MISMATCH" && row.Status != "SIZE_INVALID" && row.Status != "WRONG_SUBJECT" {
				return nil, errors.New("observer packet status outside closed set")
			}
			if i == 2 && row.Status != "EXACT_PAYLOAD_RECEIVED" {
				return nil, errors.New("M0 disclosure not established")
			}
		}
		result = append(result, row)
	}
	return result, nil
}

type natsResponseSignalRequest struct {
	Schema              string    `json:"schema"`
	RunID               string    `json:"runId"`
	Nonce               string    `json:"nonce"`
	Namespace           string    `json:"namespace"`
	NamespaceUID        types.UID `json:"namespaceUID"`
	ClientPod           string    `json:"clientPod"`
	ClientPodUID        types.UID `json:"clientPodUID"`
	PeerPodUID          types.UID `json:"peerPodUID"`
	PolicyName          string    `json:"policyName"`
	PolicyUID           types.UID `json:"policyUID"`
	PolicyGeneration    int64     `json:"policyGeneration"`
	ManagerPodUID       types.UID `json:"managerPodUID"`
	ManagerContainerID  string    `json:"managerContainerID"`
	M0ReceiptSHA256     string    `json:"m0ReceiptSHA256"`
	PeerM0ReceiptSHA256 string    `json:"peerM0ReceiptSHA256"`
}

type natsResponseSignalDecision struct {
	Schema                 string    `json:"schema"`
	RunID                  string    `json:"runId"`
	Nonce                  string    `json:"nonce"`
	NamespaceUID           types.UID `json:"namespaceUID"`
	ClientPodUID           types.UID `json:"clientPodUID"`
	PeerPodUID             types.UID `json:"peerPodUID"`
	PolicyUID              types.UID `json:"policyUID"`
	PolicyGeneration       int64     `json:"policyGeneration"`
	ManagerPodUID          types.UID `json:"managerPodUID"`
	ManagerContainerID     string    `json:"managerContainerID"`
	M0ReceiptSHA256        string    `json:"m0ReceiptSHA256"`
	PeerM0ReceiptSHA256    string    `json:"peerM0ReceiptSHA256"`
	EventName              string    `json:"eventName"`
	EventUID               types.UID `json:"eventUID"`
	AttackID               string    `json:"attackId"`
	DecisionID             string    `json:"decisionId"`
	DecisionTraceSHA256    string    `json:"decisionTraceSHA256"`
	DecisionEvidenceSHA256 string    `json:"decisionEvidenceSHA256"`
	SelectedAction         string    `json:"selectedAction"`
	DispatchOutcome        string    `json:"dispatchOutcome"`
	EffectStatus           string    `json:"effectStatus"`
	EventCleanupStatus     string    `json:"eventCleanupStatus"`
}

var natsResponseDecisionKeys = map[string]bool{
	"schema": true, "runId": true, "nonce": true, "clientPodUID": true,
	"namespaceUID": true, "peerPodUID": true, "policyUID": true, "policyGeneration": true,
	"managerPodUID": true, "managerContainerID": true, "m0ReceiptSHA256": true, "peerM0ReceiptSHA256": true,
	"eventName": true, "eventUID": true, "attackId": true,
	"decisionId": true, "decisionTraceSHA256": true, "decisionEvidenceSHA256": true, "selectedAction": true,
	"dispatchOutcome": true, "effectStatus": true,
	"eventCleanupStatus": true,
}

func strictNATSResponseObject(raw []byte, keys map[string]bool) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	tok, err := decoder.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("NATS response barrier requires one object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		tok, err = decoder.Token()
		key, ok := tok.(string)
		if err != nil || !ok || !keys[key] || seen[key] {
			return errors.New("NATS response barrier key ambiguous")
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("NATS response barrier value invalid")
		}
	}
	tok, err = decoder.Token()
	if err != nil || tok != json.Delim('}') || len(seen) != len(keys) {
		return errors.New("NATS response barrier fields incomplete")
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("NATS response barrier trailing data")
	}
	return nil
}

func natsResponseDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validateNATSResponseRequest(r natsResponseSignalRequest) error {
	if r.Schema != natsResponseSchema || !natsResponseRunID.MatchString(r.RunID) ||
		!natsResponseNonce.MatchString(r.Nonce) || r.Namespace != "phorvex-nats-exposure-fixture" ||
		r.NamespaceUID == "" || r.ClientPod == "" || r.ClientPodUID == "" || r.PeerPodUID == "" ||
		r.ClientPodUID == r.PeerPodUID || r.PolicyName != "nats-response-"+r.Nonce ||
		r.PolicyUID == "" || r.PolicyGeneration < 1 || r.ManagerPodUID == "" ||
		r.ManagerContainerID == "" || len(r.M0ReceiptSHA256) != 64 || len(r.PeerM0ReceiptSHA256) != 64 {
		return errors.New("NATS response barrier identity incomplete")
	}
	if _, err := hex.DecodeString(r.M0ReceiptSHA256); err != nil || strings.ToLower(r.M0ReceiptSHA256) != r.M0ReceiptSHA256 {
		return errors.New("NATS response M0 digest invalid")
	}
	if _, err := hex.DecodeString(r.PeerM0ReceiptSHA256); err != nil || strings.ToLower(r.PeerM0ReceiptSHA256) != r.PeerM0ReceiptSHA256 {
		return errors.New("NATS response peer M0 digest invalid")
	}
	return nil
}

func writeNATSResponseRequest(out string, r natsResponseSignalRequest) error {
	if validateNATSResponseRequest(r) != nil {
		return errors.New("NATS response barrier request invalid")
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 4096 {
		return errors.New("NATS response barrier request oversized")
	}
	root, err := natsResponseRoot(out)
	if err != nil {
		return err
	}
	defer root.Close()
	const name = "nats-response-signal-request.json"
	if _, err := root.Lstat(name); err == nil {
		return errors.New("NATS response barrier already published")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("NATS response barrier state unavailable: %w", err)
	}
	tmp := name + ".tmp"
	file, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("NATS response barrier already present or unavailable: %w", err)
	}
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	// Hard-link publishes the complete fsynced bytes without replacing an
	// earlier request; neither a retry nor a second child may rearm a signal.
	if err := root.Link(tmp, name); err != nil {
		return fmt.Errorf("NATS response barrier publication refused: %w", err)
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

func natsResponseRoot(out string) (*os.Root, error) {
	if !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return nil, errors.New("NATS response output directory is not exact and absolute")
	}
	resolved, err := filepath.EvalSymlinks(out)
	if err != nil || resolved != out {
		return nil, errors.New("NATS response output directory crosses a symlink or is unavailable")
	}
	return os.OpenRoot(out)
}

func readNATSResponseFile(out, name string) ([]byte, error) {
	root, err := natsResponseRoot(out)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096 {
		return nil, errors.New("NATS response barrier file absent, linked, or oversized")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("NATS response barrier file changed during read")
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, errors.New("NATS response barrier has another hard link")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) != int(info.Size()) {
		return nil, errors.New("NATS response barrier file changed or exceeded bound")
	}
	return raw, nil
}

func readNATSResponseDecision(out string, request natsResponseSignalRequest) (natsResponseSignalDecision, error) {
	var d natsResponseSignalDecision
	raw, err := readNATSResponseFile(out, "nats-response-signal-decision.json")
	if err != nil {
		return d, errors.New("NATS response decision absent or oversized")
	}
	if err := strictNATSResponseObject(raw, natsResponseDecisionKeys); err != nil {
		return d, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil {
		return d, errors.New("NATS response decision malformed")
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return d, errors.New("NATS response decision trailing data")
	}
	if d.Schema != natsResponseSchema || d.RunID != request.RunID || d.Nonce != request.Nonce ||
		d.NamespaceUID != request.NamespaceUID || d.ClientPodUID != request.ClientPodUID ||
		d.PeerPodUID != request.PeerPodUID || d.PolicyUID != request.PolicyUID ||
		d.PolicyGeneration != request.PolicyGeneration || d.ManagerPodUID != request.ManagerPodUID ||
		d.ManagerContainerID != request.ManagerContainerID || d.M0ReceiptSHA256 != request.M0ReceiptSHA256 ||
		d.PeerM0ReceiptSHA256 != request.PeerM0ReceiptSHA256 || d.EventName == "" ||
		d.EventUID == "" || d.AttackID == "" || d.DecisionID == "" || d.DecisionTraceSHA256 == "" ||
		len(d.DecisionEvidenceSHA256) != 64 || strings.ToLower(d.DecisionEvidenceSHA256) != d.DecisionEvidenceSHA256 ||
		d.SelectedAction == "" || d.DispatchOutcome == "" || d.EffectStatus == "" ||
		d.EventCleanupStatus != "CONFIRMED_ABSENT" {
		return d, fmt.Errorf("NATS response decision not joined to exact run")
	}
	if _, err := hex.DecodeString(d.DecisionEvidenceSHA256); err != nil {
		return d, errors.New("NATS response decision evidence digest invalid")
	}
	if !((d.SelectedAction == "noop" && d.DispatchOutcome == "not-attempted" && d.EffectStatus == "NOT_DISPATCHED") ||
		(d.SelectedAction == "quarantine" && d.DispatchOutcome == "emitted" && d.EffectStatus == "OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED")) {
		return d, errors.New("NATS response decision action/effect is not an admitted terminal barrier")
	}
	return d, nil
}
