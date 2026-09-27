package console

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installInPodKubectl(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	log := filepath.Join(dir, "argv.log")
	t.Setenv("PHORVEX_TEST_KUBE_LOG", log)
	return log
}

func TestGuardrailInPodKubectlUsesMountedServiceAccountAndRejectsWrongCluster(t *testing.T) {
	log := installInPodKubectl(t, `
printf '%s\n' "$*" >> "$PHORVEX_TEST_KUBE_LOG"
case " $* " in *' --context='*) exit 91;; esac
case " $* " in
 *' get namespace kube-system '*) printf '{"kind":"Namespace","metadata":{"name":"kube-system","uid":"cluster-current"}}';;
 *' exec '*) printf '{"status":200}';;
 *) exit 92;;
esac
`)
	w := &availabilityWorker{ctx: context.Background(), out: t.TempDir(), deadline: time.Now().Add(time.Minute)}
	w.p.Context = "arn:aws:eks:us-east-2:123456789012:cluster/reviewed"
	w.p.Fixture.ClusterUID = "cluster-current"
	w.p.Fixture.PodName = "vllm-0"
	cluster, err := w.kube("cluster", "get", "namespace", "kube-system", "-o", "json")
	if err != nil || availabilityUID(cluster) != "cluster-current" {
		t.Fatalf("in-Pod namespace GET failed: cluster=%v err=%v", cluster, err)
	}
	if raw, err := w.execGuardrail("chat", "print(1)", []byte(`{}`), 4096, 5*time.Second); err != nil || string(raw) != `{"status":200}` {
		t.Fatalf("in-Pod guarded exec failed: raw=%q err=%v", raw, err)
	}
	argv, err := os.ReadFile(log)
	if err != nil || strings.Contains(string(argv), "--context") ||
		!strings.Contains(string(argv), "get namespace kube-system") || !strings.Contains(string(argv), "exec -i vllm-0") {
		t.Fatalf("kubectl did not use mounted in-Pod identity: %q err=%v", argv, err)
	}
	w.p.Fixture.ClusterUID = "cluster-other"
	if _, err := w.snapshot("wrong-cluster"); err == nil || !strings.Contains(err.Error(), "cluster UID") {
		t.Fatalf("wrong in-cluster UID accepted: %v", err)
	}
}

func TestDrainInPodKubectlRetainsExternalContextOnlyAsProfileProvenance(t *testing.T) {
	p := drainTestProfile()
	p.Context = "arn:aws:eks:us-east-2:123456789012:cluster/reviewed"
	profileBytes, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseDrainLiveProfile(profileBytes); err != nil {
		t.Fatalf("reviewed external-context profile refused before in-Pod transport: %v", err)
	}
	log := installInPodKubectl(t, fmt.Sprintf(`
printf '%%s\n' "$*" >> "$PHORVEX_TEST_KUBE_LOG"
case " $* " in *' --context='*) exit 91;; esac
case " $* " in
 *' get namespace kube-system '*) printf '{"kind":"Namespace","metadata":{"name":"kube-system","uid":"cluster-wrong"}}';;
 *'serving_completion.py'*) printf '{"serving_completion.py":"%s","serving_engine.py":"%s"}';;
 *'model_inventory'*) printf '{"exact":true,"count":1}';;
 *'bodySHA256'*) printf '{"status":200,"valid":true,"bodySHA256":"%s"}';;
 *) exit 0;;
esac
`, p.ServingCompletionSHA256, p.ServingEngineSHA256, strings.Repeat("a", 64)))
	s := NewServer(Config{})
	out := t.TempDir()
	if err := s.drainInstalledSource(context.Background(), out, "before", p); err != nil {
		t.Fatalf("drain installed-source exec refused in-Pod context: %v", err)
	}
	if err := s.drainModelInventory(context.Background(), out, "before", p); err != nil {
		t.Fatalf("drain model exec refused in-Pod context: %v", err)
	}
	if status, valid, err := s.drainBenign(context.Background(), p, []byte(`{}`)); err != nil || status != 200 || !valid {
		t.Fatalf("drain benign exec refused in-Pod context: %d %t %v", status, valid, err)
	}
	stream, err := startDrainStream(context.Background(), p, []byte(`{}`), strings.Repeat("a", 32))
	if err != nil {
		t.Fatalf("drain stream exec refused in-Pod context: %v", err)
	}
	<-stream.done // The fake returns no stream frames; only argv transport is under test.
	stream.cancel()
	if err := s.drainLivePreflight(context.Background(), out, p, "wrong"); err == nil || !strings.Contains(err.Error(), "cluster UID") {
		t.Fatalf("drain accepted wrong in-cluster UID: %v", err)
	}
	argv, err := os.ReadFile(log)
	if err != nil || strings.Contains(string(argv), "--context") {
		t.Fatalf("drain kubectl used external profile context: %q err=%v", argv, err)
	}
}
