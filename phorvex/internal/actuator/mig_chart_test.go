package actuator

import (
	"strings"
	"testing"
)

func TestMIGChartDefaultDisabledAndOptInWired(t *testing.T) {
	defaultRender := renderChart(t)
	for _, forbidden := range []string{"--mig-node-exec=true", "phorvex.ai/mig-agent: \"true\"", "phorvex-mig-allocation-helper", "-mig-profiles"} {
		if strings.Contains(defaultRender, forbidden) {
			t.Fatalf("default chart unexpectedly rendered %q", forbidden)
		}
	}

	digest := "sha256:" + strings.Repeat("a", 64)
	enabled := renderChart(t,
		"phorvex.mig.profiles.content=profile-policy",
		"phorvex.mig.nodeExec.enabled=true",
		"phorvex.mig.nodeExec.exclusiveMaintenance=true",
		"phorvex.mig.nodeExec.namespace=gpu-system",
		"phorvex.mig.nodeExec.daemonSetName=phorvex-mig-agent",
		"phorvex.mig.nodeExec.serviceAccountName=phorvex-mig-agent",
		"phorvex.mig.nodeExec.gpuImage.repository=vendor.example/gpu-tools",
		"phorvex.mig.nodeExec.gpuImage.digest="+digest,
		"phorvex.mig.nodeExec.gpuCommand[0]=/gpu-agent",
	)
	for _, required := range []string{
		"--mig-node-exec=true", "--mig-profiles-file=/etc/phorvex-mig/profiles.json",
		"--mig-exclusive-maintenance=true",
		"kind: DaemonSet", "phorvex.ai/mig-agent: \"true\"", "vendor.example/gpu-tools@" + digest,
		"name: allocation-helper", "mountPath: /var/lib/kubelet/pod-resources", "readOnly: true",
		`resources: ["pods/exec"]`, `resourceNames: ["phorvex-mig-agent"]`,
	} {
		if !strings.Contains(enabled, required) {
			t.Fatalf("enabled chart missing %q", required)
		}
	}
	if strings.Count(enabled, "mountPath: /var/lib/kubelet/pod-resources") != 1 {
		t.Fatal("PodResources directory must be mounted only in the helper container")
	}
}
