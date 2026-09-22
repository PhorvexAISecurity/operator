// installed-audit-observer emits a bounded allowlisted projection of the
// existing authenticated decision audit. It performs no Kubernetes operation.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/installedauditobserver"
)

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error {
	if v == "" {
		return errors.New("empty value")
	}
	*s = append(*s, v)
	return nil
}

type options struct {
	mode, url, serverName, certFile, keyFile, caFile, cursorFile, output     string
	policyNS, policyName, policyUID, targetNS, targetName, targetUID         string
	traceSchema, brainImage, gitSHA, manifestID, manifestHash, overridesHash string
	targetRV, notBefore, notAfter                                            string
	policyGeneration, grace, maxBytes                                        int64
	maxRows                                                                  int
	timeout                                                                  time.Duration
	objects                                                                  stringsFlag
}

func parse(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("installed-audit-observer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.mode, "mode", "", "cursor or observe")
	fs.StringVar(&o.url, "url", "", "bare HTTPS audit source origin")
	fs.StringVar(&o.serverName, "server-name", "", "pinned audit server DNS SAN")
	fs.StringVar(&o.certFile, "client-cert-file", "", "mTLS client certificate path")
	fs.StringVar(&o.keyFile, "client-key-file", "", "mTLS client private key path")
	fs.StringVar(&o.caFile, "ca-file", "", "trusted audit CA path")
	fs.StringVar(&o.cursorFile, "cursor-file", "", "cursor JSON input for observe mode")
	fs.StringVar(&o.output, "output", "-", "output file or - for stdout")
	fs.StringVar(&o.policyNS, "policy-namespace", "", "exact policy namespace")
	fs.StringVar(&o.policyName, "policy-name", "", "exact policy name")
	fs.StringVar(&o.policyUID, "policy-uid", "", "exact policy UID")
	fs.Int64Var(&o.policyGeneration, "policy-generation", 0, "exact policy generation")
	fs.StringVar(&o.targetNS, "target-namespace", "", "exact target namespace")
	fs.StringVar(&o.targetName, "target-name", "", "exact target Pod name")
	fs.StringVar(&o.targetUID, "target-uid", "", "exact target Pod UID")
	fs.StringVar(&o.traceSchema, "trace-schema", "", "expected decision trace schema")
	fs.StringVar(&o.brainImage, "brain-image", "", "expected manager brain image")
	fs.StringVar(&o.gitSHA, "git-sha", "", "expected manager source revision")
	fs.StringVar(&o.manifestID, "parameter-manifest-id", "", "expected decision parameter manifest ID")
	fs.StringVar(&o.manifestHash, "parameter-manifest-hash", "", "expected decision parameter manifest hash")
	fs.StringVar(&o.overridesHash, "policy-overrides-hash", "", "optional expected effective policy override hash")
	fs.StringVar(&o.targetRV, "target-resource-version", "", "expected target Pod resourceVersion for emitted native rotate")
	fs.StringVar(&o.notBefore, "not-before", "", "inclusive RFC3339Nano observation start")
	fs.StringVar(&o.notAfter, "not-after", "", "inclusive RFC3339Nano observation end")
	fs.Int64Var(&o.grace, "expected-grace-seconds", -1, "exact native rotate effective grace; omit as -1 when no emitted rotate is expected")
	fs.Int64Var(&o.maxBytes, "max-bytes", installedauditobserver.DefaultMaxBytes, "maximum source bytes")
	fs.IntVar(&o.maxRows, "max-rows", installedauditobserver.DefaultMaxRows, "maximum source rows")
	fs.DurationVar(&o.timeout, "timeout", 15*time.Second, "whole authenticated read deadline")
	fs.Var(&o.objects, "allowed-object", "exact allowed objectsTouched entry; repeat in producer order")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 {
		return o, errors.New("positional arguments are not accepted")
	}
	for name, value := range map[string]string{"mode": o.mode, "url": o.url, "server-name": o.serverName, "client-cert-file": o.certFile, "client-key-file": o.keyFile, "ca-file": o.caFile} {
		if value == "" {
			return o, fmt.Errorf("--%s is required", name)
		}
	}
	if o.mode != "cursor" && o.mode != "observe" {
		return o, errors.New("--mode must be cursor or observe")
	}
	if o.timeout <= 0 || o.timeout > 30*time.Second {
		return o, errors.New("--timeout must be in (0,30s]")
	}
	if o.grace < -1 {
		return o, errors.New("--expected-grace-seconds must be -1 or positive")
	}
	return o, nil
}

func destination(path string, stdout io.Writer) (io.Writer, func(bool) error, error) {
	if path == "-" {
		return stdout, func(bool) error { return nil }, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(abs+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	finish := func(commit bool) error {
		if !commit {
			closeErr := f.Close()
			_ = os.Remove(abs + ".tmp")
			return closeErr
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(abs + ".tmp")
			return err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(abs + ".tmp")
			return err
		}
		if err := os.Rename(abs+".tmp", abs); err != nil {
			_ = os.Remove(abs + ".tmp")
			return err
		}
		dir, err := os.Open(filepath.Dir(abs))
		if err != nil {
			return err
		}
		return errors.Join(dir.Sync(), dir.Close())
	}
	return f, finish, nil
}

func commitDestination(finish func(bool) error, finalized *bool, stderr io.Writer) bool {
	*finalized = true
	if err := finish(true); err != nil {
		fmt.Fprintln(stderr, "commit output:", err)
		return false
	}
	return true
}

func run(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	o, err := parse(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: o.url, ServerDNSName: o.serverName, CertFile: o.certFile, KeyFile: o.keyFile, CAFile: o.caFile})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	out, finish, err := destination(o.output, stdout)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	finalized := false
	defer func() {
		if !finalized {
			_ = finish(false)
		}
	}()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	if o.mode == "cursor" {
		cursor, err := installedauditobserver.CaptureCursor(ctx, client)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err = enc.Encode(cursor); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if !commitDestination(finish, &finalized, stderr) {
			return 1
		}
		return 0
	}
	if o.cursorFile == "" {
		fmt.Fprintln(stderr, "--cursor-file is required in observe mode")
		return 2
	}
	raw, err := os.ReadFile(o.cursorFile)
	if err != nil {
		fmt.Fprintln(stderr, "read cursor:", err)
		return 1
	}
	if len(raw) > 8192 {
		fmt.Fprintln(stderr, "cursor exceeds its bound")
		return 1
	}
	cursor, err := installedauditobserver.DecodeCursor(raw)
	if err != nil {
		fmt.Fprintln(stderr, "decode cursor:", err)
		return 1
	}
	notBefore, err := time.Parse(time.RFC3339Nano, o.notBefore)
	if err != nil {
		fmt.Fprintln(stderr, "invalid --not-before")
		return 2
	}
	notAfter, err := time.Parse(time.RFC3339Nano, o.notAfter)
	if err != nil {
		fmt.Fprintln(stderr, "invalid --not-after")
		return 2
	}
	var grace *int64
	if o.grace >= 0 {
		grace = &o.grace
	}
	cfg := installedauditobserver.Config{PolicyNamespace: o.policyNS, PolicyName: o.policyName, PolicyUID: o.policyUID,
		PolicyGeneration: o.policyGeneration,
		TargetNamespace:  o.targetNS, TargetName: o.targetName, TargetUID: o.targetUID, ExpectedTraceSchema: o.traceSchema,
		ExpectedBrainImage: o.brainImage, ExpectedGitSHA: o.gitSHA, ExpectedManifestID: o.manifestID, ExpectedManifestHash: o.manifestHash,
		ExpectedOverridesHash: o.overridesHash, ExpectedPodResourceVersion: o.targetRV, ExpectedGraceSeconds: grace,
		AllowedObjectsTouched: append([]string(nil), o.objects...), NotBefore: notBefore, NotAfter: notAfter, MaxBytes: o.maxBytes, MaxRows: o.maxRows}
	receipts, summary, collectErr := installedauditobserver.Collect(ctx, client, cursor, cfg, now)
	for _, receipt := range receipts {
		if err = enc.Encode(receipt); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if err = enc.Encode(summary); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !commitDestination(finish, &finalized, stderr) {
		return 1
	}
	if collectErr != nil {
		fmt.Fprintln(stderr, "observation invalid:", summary.ErrorClass)
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now)) }
