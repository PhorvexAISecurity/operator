package actuator

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type migScriptRunner struct {
	calls [][]string
	run   func([]string) (string, error)
}

type terminatingConfigMapReader struct{ client.Reader }

func (r terminatingConfigMapReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Reader.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if cm, ok := obj.(*corev1.ConfigMap); ok {
		now := metav1.Now()
		cm.DeletionTimestamp = &now
	}
	return nil
}

func (r *migScriptRunner) Run(_ context.Context, argv ...string) (string, error) {
	r.calls = append(r.calls, append([]string(nil), argv...))
	return r.run(argv)
}

const (
	testGPUUUID  = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testGI       = "+----------------------------------------------------+\n| GPU instances:                                     |\n| GPU   Name          Profile  Instance   Placement  |\n|                       ID       ID       Start:Size |\n|====================================================|\n|  0  MIG 1g.10gb  19  7  0:1  |\n+----------------------------------------------------+\n|  0  MIG 2g.20gb  14  8  2:2  |\n+----------------------------------------------------+\n"
	testCI       = "+-------------------------------------------------------+\n| Compute instances:                                    |\n| GPU     GPU       Name             Profile   Instance |\n|       Instance                       ID        ID     |\n|         ID                                            |\n|=======================================================|\n|  0  7  MIG 1g.10gb  7  0  |\n+-------------------------------------------------------+\n|  0  8  MIG 2g.20gb  5  0  |\n+-------------------------------------------------------+\n"
	testProfiles = "+--------------------------------------------------------------------------------------+\n| GPU instance profiles:                                                               |\n| GPU   Name             ID    Instances   Memory     P2P    SM    DEC   ENC             |\n|                             Free/Total   GiB              CE    JPEG  OFA             |\n|======================================================================================|\n|  0  MIG 2g.20gb  14  1/3  19.50  No  28  1  0  |\n|                                                             2     0     0           |\n+--------------------------------------------------------------------------------------+\n"
)

func migTestPrior() migGeometry {
	return migGeometry{GPUUUID: testGPUUUID, GIs: []migGI{{ProfileName: "1g.10gb", ProfileID: 19, InstanceID: 7, Start: 0, Size: 1, CI: migCI{ProfileName: "1g.10gb", ProfileID: 7, InstanceID: 0}}}}
}

func migTestCommandOutput(argv []string, configured bool) string {
	s := strings.Join(argv, " ")
	if strings.Contains(s, "--query-gpu=uuid") {
		return testGPUUUID + "\n"
	}
	if configured && strings.HasSuffix(s, "-lgi") {
		return oneGITable("|  0  MIG 1g.10gb  19  7  0:1  |")
	}
	if configured && strings.HasSuffix(s, "-lci") {
		return oneCITable("|  0  7  MIG 1g.10gb  7  0  |")
	}
	return ""
}

func oneGITable(row string) string {
	return "+----------------------------------------------------+\n| GPU instances:                                     |\n| GPU   Name          Profile  Instance   Placement  |\n|                       ID       ID       Start:Size |\n|====================================================|\n" + row + "\n+----------------------------------------------------+\n"
}
func ciTable(rows string) string {
	return "+-------------------------------------------------------+\n| Compute instances:                                    |\n| GPU     GPU       Name             Profile   Instance |\n|       Instance                       ID        ID     |\n|         ID                                            |\n|=======================================================|\n" + rows + "\n+-------------------------------------------------------+\n"
}
func oneCITable(row string) string { return ciTable(row) }

func injectAfterTableSeparator(table, row string) string {
	i := strings.Index(table, "|===")
	if i < 0 {
		return table + row
	}
	i += strings.Index(table[i:], "\n") + 1
	return table[:i] + row + "\n" + table[i:]
}

func TestMIGCaptureBindsUUIDAndCompletePlacedGeometry(t *testing.T) {
	r := &migScriptRunner{run: func(a []string) (string, error) {
		s := strings.Join(a, " ")
		switch {
		case strings.Contains(s, "--query-gpu=uuid"):
			return testGPUUUID + "\n", nil
		case strings.HasSuffix(s, "-lgi"):
			return testGI, nil
		case strings.HasSuffix(s, "-lci"):
			return testCI, nil
		case strings.HasSuffix(s, "-lgip"):
			return testProfiles, nil
		}
		return "", errors.New("unexpected command")
	}}
	g, err := (&preparedNVIDIASMIMIG{run: r}).Capture(context.Background(), "0", "2g.20gb")
	if err != nil || g.GPUUUID != testGPUUUID || len(g.GIs) != 2 || g.GIs[1].ProfileID != 14 || g.GIs[1].Start != 2 {
		t.Fatalf("capture = %+v, %v", g, err)
	}
	for _, call := range r.calls[1:] {
		if call[3] != testGPUUUID {
			t.Fatalf("inventory was not UUID-bound: %v", call)
		}
	}
}

func TestMIGCaptureRefusesUnsupportedCIAndAmbiguousGPU(t *testing.T) {
	for _, tc := range []struct{ name, uuid, ci string }{
		{"multiple-gpus", testGPUUUID + "\nGPU-bbbbbbbb-cccc-dddd-eeee-ffffffffffff\n", testCI},
		{"multiple-ci", testGPUUUID + "\n", ciTable("|  0  7  MIG 1c.1g.10gb  0  0  |\n|  0  7  MIG 1c.1g.10gb  0  1  |\n|  0  8  MIG 2g.20gb  5  0  |")},
		{"single-partial-ci", testGPUUUID + "\n", ciTable("|  0  7  MIG 1c.1g.10gb  0  0  |\n|  0  8  MIG 2g.20gb  5  0  |")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &migScriptRunner{run: func(a []string) (string, error) {
				s := strings.Join(a, " ")
				if strings.Contains(s, "--query") {
					return tc.uuid, nil
				}
				if strings.HasSuffix(s, "-lgi") {
					return testGI, nil
				}
				if strings.HasSuffix(s, "-lgip") {
					return testProfiles, nil
				}
				return tc.ci, nil
			}}
			if _, err := (&preparedNVIDIASMIMIG{run: r}).Capture(context.Background(), "0", "2g.20gb"); err == nil {
				t.Fatal("unsupported inventory accepted")
			}
		})
	}
}

func TestMIGCaptureRejectsZeroExitUnknownTableRows(t *testing.T) {
	for _, tc := range []struct{ name, profiles, gi, ci string }{
		{"unknown-profile-data", injectAfterTableSeparator(testProfiles, "| unreadable profile row |"), testGI, testCI},
		{"unknown-gi-data", testProfiles, injectAfterTableSeparator(testGI, "| unreadable instance row |"), testCI},
		{"unknown-ci-data", testProfiles, testGI, injectAfterTableSeparator(testCI, "| unreadable compute row |")},
		{"unknown-header", strings.Replace(testProfiles, "| GPU instance profiles:", "| unexpected heading:", 1), testGI, testCI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &migScriptRunner{run: func(a []string) (string, error) {
				s := strings.Join(a, " ")
				switch {
				case strings.Contains(s, "--query-gpu=uuid"):
					return testGPUUUID + "\n", nil
				case strings.HasSuffix(s, "-lgip"):
					return tc.profiles, nil
				case strings.HasSuffix(s, "-lgi"):
					return tc.gi, nil
				case strings.HasSuffix(s, "-lci"):
					return tc.ci, nil
				}
				return "", errors.New("unexpected command")
			}}
			if _, err := (&preparedNVIDIASMIMIG{run: r}).Capture(context.Background(), "0", "2g.20gb"); err == nil {
				t.Fatal("zero-exit unknown table content accepted")
			}
		})
	}
}

func TestMIGRepartitionCreateFailureRestoresPlacedPriorGeometry(t *testing.T) {
	prior := migGeometry{GPUUUID: testGPUUUID, GIs: []migGI{{ProfileName: "1g.10gb", ProfileID: 19, InstanceID: 7, Start: 0, Size: 1, CI: migCI{ProfileName: "1g.10gb", ProfileID: 7, InstanceID: 0}}, {ProfileName: "2g.20gb", ProfileID: 14, InstanceID: 8, Start: 2, Size: 2, CI: migCI{ProfileName: "2g.20gb", ProfileID: 5, InstanceID: 0}}}}
	restored := false
	r := &migScriptRunner{run: func(a []string) (string, error) {
		s := strings.Join(a, " ")
		if strings.Contains(s, "--query-gpu=uuid") {
			return testGPUUUID + "\n", nil
		}
		if strings.HasSuffix(s, "-lgi") {
			if restored {
				return testGI, nil
			}
			return "No GPU instances found\n", nil
		}
		if strings.HasSuffix(s, "-lci") {
			if restored {
				return testCI, nil
			}
			return "No compute instances found\n", nil
		}
		if strings.Contains(s, "-cgi 3g.40gb") {
			return "", errors.New("injected target create failure")
		}
		if strings.Contains(s, "-cgi 14:2") {
			restored = true
		}
		return "", nil
	}}
	effect, err := (&preparedNVIDIASMIMIG{run: r}).Repartition(context.Background(), prior, "3g.40gb", func(context.Context) error { return nil })
	if err == nil || effect.Outcome != "prior-geometry-restored" {
		t.Fatalf("effect=%+v err=%v", effect, err)
	}
	joined := ""
	for _, c := range r.calls {
		joined += strings.Join(c, " ") + "\n"
	}
	if !strings.Contains(joined, "-cgi 19:0 -C") || !strings.Contains(joined, "-cgi 14:2 -C") {
		t.Fatalf("placement recovery absent:\n%s", joined)
	}
}

func TestMIGRepartitionDoesNotDestroyForeignReadbackDuringRecovery(t *testing.T) {
	prior := migGeometry{GPUUUID: testGPUUUID, GIs: []migGI{{ProfileName: "1g.10gb", ProfileID: 19, InstanceID: 7, Start: 0, Size: 1, CI: migCI{ProfileName: "1g.10gb", ProfileID: 7, InstanceID: 0}}}}
	r := &migScriptRunner{run: func(a []string) (string, error) {
		s := strings.Join(a, " ")
		if strings.Contains(s, "--query-gpu=uuid") {
			return testGPUUUID + "\n", nil
		}
		if strings.Contains(s, "-cgi 2g.20gb") {
			return "", errors.New("create failed")
		}
		if strings.HasSuffix(s, "-lgi") {
			return oneGITable("|  0  MIG 3g.40gb  9  4  0:4  |"), nil
		}
		if strings.HasSuffix(s, "-lci") {
			return oneCITable("|  0  4  MIG 3g.40gb  2  0  |"), nil
		}
		return "", nil
	}}
	effect, err := (&preparedNVIDIASMIMIG{run: r}).Repartition(context.Background(), prior, "2g.20gb", func(context.Context) error { return nil })
	if err == nil || effect.Outcome != "partial-unrestored" {
		t.Fatalf("effect=%+v err=%v", effect, err)
	}
	seenTarget := false
	for _, c := range r.calls {
		s := strings.Join(c, " ")
		if strings.Contains(s, "-cgi 2g.20gb") {
			seenTarget = true
			continue
		}
		if seenTarget && (strings.Contains(s, "-dci") || strings.Contains(s, "-dgi")) {
			t.Fatalf("foreign geometry destroyed during compensation: %v", c)
		}
	}
}

func TestMIGRecoveryInventoryFailureAuthorizesNoRecoveryMutation(t *testing.T) {
	prior := migGeometry{GPUUUID: testGPUUUID, GIs: []migGI{{ProfileName: "1g.10gb", ProfileID: 19, InstanceID: 7, Start: 0, Size: 1, CI: migCI{ProfileName: "1g.10gb", ProfileID: 7, InstanceID: 0}}}}
	r := &migScriptRunner{run: func(a []string) (string, error) {
		s := strings.Join(a, " ")
		if strings.Contains(s, "--query-gpu=uuid") {
			return testGPUUUID + "\n", nil
		}
		if strings.Contains(s, "-cgi 2g.20gb") {
			return "", errors.New("target create failed")
		}
		if strings.HasSuffix(s, "-lgi") {
			return "truncated garbage", nil
		}
		return "", nil
	}}
	effect, err := (&preparedNVIDIASMIMIG{run: r}).Repartition(context.Background(), prior, "2g.20gb", func(context.Context) error { return nil })
	if err == nil || effect.Outcome != "unknown" {
		t.Fatalf("effect=%+v err=%v", effect, err)
	}
	seenTarget := false
	for _, call := range r.calls {
		s := strings.Join(call, " ")
		if strings.Contains(s, "-cgi 2g.20gb") {
			seenTarget = true
			continue
		}
		if seenTarget && (strings.Contains(s, "-cgi") || strings.Contains(s, "-dci") || strings.Contains(s, "-dgi")) {
			t.Fatalf("inventory failure authorized recovery mutation: %v", call)
		}
	}
}

func TestMIGRecoveryOwnershipLossStopsNextDestructiveCommand(t *testing.T) {
	prior := migGeometry{GPUUUID: testGPUUUID, GIs: []migGI{{ProfileName: "1g.10gb", ProfileID: 19, InstanceID: 7, Start: 0, Size: 1, CI: migCI{ProfileName: "1g.10gb", ProfileID: 7, InstanceID: 0}}}}
	r := &migScriptRunner{run: func(a []string) (string, error) {
		if strings.Contains(strings.Join(a, " "), "--query-gpu=uuid") {
			return testGPUUUID + "\n", nil
		}
		return "", nil
	}}
	guards := 0
	effect, err := (&preparedNVIDIASMIMIG{run: r}).Repartition(context.Background(), prior, "2g.20gb", func(context.Context) error {
		guards++
		if guards > 1 {
			return errors.New("receipt replaced")
		}
		return nil
	})
	if err == nil || effect.Outcome != "unknown" {
		t.Fatalf("effect=%+v err=%v", effect, err)
	}
	for _, call := range r.calls {
		if strings.Contains(strings.Join(call, " "), "-dgi") {
			t.Fatalf("destroy continued after ownership loss: %v", call)
		}
	}
}

func TestMIGFailureAfterCIDestroyRestoresOnlyCapturedFullCIs(t *testing.T) {
	prior := migGeometry{GPUUUID: testGPUUUID, GIs: []migGI{{ProfileName: "1g.10gb", ProfileID: 19, InstanceID: 7, Start: 0, Size: 1, CI: migCI{ProfileName: "1g.10gb", ProfileID: 7, InstanceID: 0}}, {ProfileName: "2g.20gb", ProfileID: 14, InstanceID: 8, Start: 2, Size: 2, CI: migCI{ProfileName: "2g.20gb", ProfileID: 5, InstanceID: 0}}}}
	ciAbsent, restored, cci := false, false, 0
	r := &migScriptRunner{run: func(a []string) (string, error) {
		s := strings.Join(a, " ")
		switch {
		case strings.Contains(s, "--query-gpu=uuid"):
			return testGPUUUID + "\n", nil
		case strings.HasSuffix(s, "-dci"):
			ciAbsent = true
			return "", nil
		case strings.HasSuffix(s, "-dgi"):
			return "", errors.New("injected GI destroy failure")
		case strings.Contains(s, "-cci"):
			cci++
			if cci == 2 {
				restored = true
				ciAbsent = false
			}
			return "", nil
		case strings.HasSuffix(s, "-lgi"):
			return testGI, nil
		case strings.HasSuffix(s, "-lci"):
			if ciAbsent {
				return "No compute instances found\n", nil
			}
			if restored {
				return testCI, nil
			}
			return "", errors.New("unexpected CI state")
		}
		return "", nil
	}}
	effect, err := (&preparedNVIDIASMIMIG{run: r}).Repartition(context.Background(), prior, "3g.40gb", func(context.Context) error { return nil })
	if err == nil || effect.Outcome != "prior-geometry-restored" || cci != 2 {
		t.Fatalf("CI-only recovery effect=%+v cci=%d err=%v", effect, cci, err)
	}
	for _, call := range r.calls {
		s := strings.Join(call, " ")
		if strings.Contains(s, "-cgi") {
			t.Fatalf("CI-only recovery recreated/destroyed GIs: %v", call)
		}
	}
}

func TestMIGCIOnlyRecoveryRefusesChangedGIAndMixedCIState(t *testing.T) {
	prior := migTestPrior()
	for _, tc := range []struct{ name, gi, ci string }{{"changed-gi", oneGITable("|  0  MIG 2g.20gb  14  7  0:2  |"), "No compute instances found\n"}, {"mixed-marker-row", testGI, "No compute instances found\n|  0  7  MIG 1g.10gb  7  0  |\n"}, {"garbage", "nonnumeric truncated garbage", "No compute instances found\n"}} {
		t.Run(tc.name, func(t *testing.T) {
			targetFailed := false
			r := &migScriptRunner{run: func(a []string) (string, error) {
				s := strings.Join(a, " ")
				if strings.Contains(s, "--query-gpu=uuid") {
					return testGPUUUID + "\n", nil
				}
				if strings.Contains(s, "-dci") {
					return "", nil
				}
				if strings.Contains(s, "-dgi") {
					targetFailed = true
					return "", errors.New("fail")
				}
				if targetFailed && strings.HasSuffix(s, "-lgi") {
					return tc.gi, nil
				}
				if targetFailed && strings.HasSuffix(s, "-lci") {
					return tc.ci, nil
				}
				return "", nil
			}}
			effect, err := (&preparedNVIDIASMIMIG{run: r}).Repartition(context.Background(), prior, "2g.20gb", func(context.Context) error { return nil })
			if err == nil || (effect.Outcome != "partial-unrestored" && effect.Outcome != "unknown") {
				t.Fatalf("effect=%+v err=%v", effect, err)
			}
			for _, call := range r.calls {
				if strings.Contains(strings.Join(call, " "), "-cci") || strings.Contains(strings.Join(call, " "), "-cgi") {
					t.Fatalf("unsupported state authorized recovery create: %v", call)
				}
			}
		})
	}
}

func TestMIGRecoveryOwnershipRejectsTerminatingAndWrongNamespaceReceipt(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	ec := EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}
	r := migRecoveryReceipt{Version: 1, Phase: "prepared", PolicyNamespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", TargetName: pod.Name, TargetUID: string(pod.UID), TargetLabels: copyLabels(pod.Labels), Node: "node-a", GPUUUID: testGPUUUID, TargetProfile: "2g.20gb", Prior: migTestPrior()}
	cm, err := migRecoveryWrite(context.Background(), ec, r)
	if err != nil {
		t.Fatal(err)
	}
	wrong := cm.DeepCopy()
	wrong.Namespace = "tenant"
	if err := migRecoveryRequireOwned(context.Background(), ec, wrong, r, r.TargetLabels); err == nil {
		t.Fatal("receipt outside protected namespace accepted")
	}
	ec.Reader = terminatingConfigMapReader{Reader: c}
	if err := migRecoveryRequireOwned(context.Background(), ec, cm, r, r.TargetLabels); err == nil {
		t.Fatal("terminating recovery receipt accepted")
	}
}
