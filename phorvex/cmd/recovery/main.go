// phorvex-recovery inventories protected operation receipts and applies an explicitly reviewed plan.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
)

func main() {
	var operatorNS, namespace, policy, planOut, applyPlan, resultOut string
	var maxItems int
	flag.StringVar(&operatorNS, "operator-namespace", "", "protected operator namespace (required)")
	flag.StringVar(&namespace, "namespace", "", "target policy namespace (required)")
	flag.StringVar(&policy, "policy", "", "target PhorvexPolicy name (required)")
	flag.IntVar(&maxItems, "max-items", 20, "maximum scoped receipts (1-100); protected-journal scan is independently capped at 1000")
	flag.StringVar(&planOut, "plan-out", "", "write a versioned quarantine re-admission plan; inventory remains the default")
	flag.StringVar(&applyPlan, "apply-plan", "", "apply this exact reviewed plan (separate explicit mode)")
	flag.StringVar(&resultOut, "result-out", "", "durably write apply results before exit (required with --apply-plan)")
	flag.Parse()
	if operatorNS == "" || namespace == "" || policy == "" || (planOut != "" && applyPlan != "") || (applyPlan != "" && resultOut == "") {
		fmt.Fprintln(os.Stderr, "usage: phorvex-recovery --operator-namespace NS --namespace NS --policy NAME [--max-items N] [--plan-out FILE | --apply-plan FILE --result-out FILE]")
		os.Exit(2)
	}
	cfg, err := ctrlconfig.GetConfig()
	if err != nil {
		fatal(err)
	}
	scheme := runtime.NewScheme()
	if err = clientgoscheme.AddToScheme(scheme); err != nil {
		fatal(err)
	}
	if err = v1alpha1.AddToScheme(scheme); err != nil {
		fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fatal(err)
	}
	native := actuator.NewNativeActuator(c)
	native.Reader, native.JournalNamespace = c, operatorNS
	scope := actuator.RecoveryScope{OperatorNamespace: operatorNS, Namespace: namespace, PolicyName: policy, MaxItems: maxItems}
	ctx := context.Background()
	if applyPlan != "" {
		data, e := readBoundedPlan(applyPlan)
		if e != nil {
			fatal(e)
		}
		plan, e := actuator.RecoveryPlanFromJSON(data)
		if e != nil {
			fatal(e)
		}
		if plan.Scope != scope {
			fatal(fmt.Errorf("command scope does not exactly match reviewed plan scope"))
		}
		resultFile, e := os.OpenFile(resultOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
		if e != nil {
			fatal(fmt.Errorf("prepare durable recovery result output before apply: %w", e))
		}
		if e = syncParentDirectory(resultOut); e != nil {
			_ = resultFile.Close()
			fatal(fmt.Errorf("persist recovery result directory entry before apply: %w", e))
		}
		recorder := &resultRecorder{file: resultFile}
		_, applyErr := native.ApplyRecoveryWithRecorder(ctx, plan, recorder.Write)
		e = resultFile.Close()
		if e != nil {
			fatal(fmt.Errorf("recovery result output failed after possible effects: %w", e))
		}
		if applyErr != nil {
			fatal(applyErr)
		}
		return
	}
	if planOut != "" {
		plan, e := native.PlanRecovery(ctx, scope)
		if e != nil {
			fatal(e)
		}
		if e = writeExclusive(planOut, plan); e != nil {
			fatal(e)
		}
		return
	}
	inv, err := native.InventoryRecovery(ctx, scope)
	if err != nil {
		fatal(err)
	}
	b, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		fatal(err)
	}
	b = append(b, '\n')
	if _, err = os.Stdout.Write(b); err != nil {
		fatal(err)
	}
}

const recoveryResultMaxBytes int64 = 8 << 20

type resultSink interface {
	Write([]byte) (int, error)
	Sync() error
}

type resultRecorder struct {
	file    resultSink
	written int64
}

func (r *resultRecorder) Write(result actuator.RecoveryApplyResult) error {
	if r == nil || r.file == nil {
		return fmt.Errorf("result sink unavailable")
	}
	line, err := json.Marshal(result)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if r.written+int64(len(line)) > recoveryResultMaxBytes {
		return fmt.Errorf("recovery result log exceeds %d bytes", recoveryResultMaxBytes)
	}
	n, err := r.file.Write(line)
	r.written += int64(n)
	if err != nil {
		return err
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	return r.file.Sync()
}

func syncParentDirectory(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readBoundedPlan(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, actuator.RecoveryPlanMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > actuator.RecoveryPlanMaxBytes {
		return nil, fmt.Errorf("recovery plan exceeds %d bytes", actuator.RecoveryPlanMaxBytes)
	}
	return data, nil
}

func writeExclusive(path string, v any) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	if err = e.Encode(v); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	ok = err == nil
	return err
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "phorvex-recovery:", err); os.Exit(1) }
