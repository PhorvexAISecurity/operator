package actuator

import (
	"bytes"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// M079SetNodeExecUnwiredForTest isolates the package transport in a fresh-process
// composition control. It is test-only and is absent from production builds.
func M079SetNodeExecUnwiredForTest() func() {
	old := pkgNodeRunner
	pkgNodeRunner = nil
	return func() { pkgNodeRunner = old }
}

// M079WireRemoteNodeExecForTest reaches the production wiring function while
// supplying its existing private remotecommand executor seam. No runtime hook is added.
func M079WireRemoteNodeExecForTest(cfg RemoteExecConfig, factory func(*rest.Config, string, *url.URL) (remotecommand.Executor, error)) (func(), error) {
	old := pkgNodeRunner
	cfg.newExecutor = factory
	if err := WireRemoteNodeExec(cfg); err != nil {
		return nil, err
	}
	return func() { pkgNodeRunner = old }, nil
}

// M079RenderChartForTest renders one values document through the repository's pinned
// Helm boundary. Callers parse the resulting workload objects and manager arguments.
func M079RenderChartForTest(t *testing.T, values string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate M079 test source")
	}
	chart := filepath.Join(filepath.Dir(thisFile), "..", "..", "charts", "phorvex")
	valuesFile := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(valuesFile, []byte(values), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(chartHelm(t), "template", "m079-test", chart, "--namespace", "operator", "--values", valuesFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template M079 values: %v\n%s", err, stderr.String())
	}
	return stdout.String()
}
