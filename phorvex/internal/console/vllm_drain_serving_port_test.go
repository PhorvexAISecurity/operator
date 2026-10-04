package console

import (
	"encoding/json"
	"testing"
)

func drainSvcWithPorts(ports ...int) vllmServiceState {
	var s vllmServiceState
	for _, p := range ports {
		s.Spec.Ports = append(s.Spec.Ports, struct {
			Port       int             `json:"port"`
			Protocol   string          `json:"protocol"`
			TargetPort json.RawMessage `json:"targetPort"`
		}{Port: p, Protocol: "TCP", TargetPort: json.RawMessage([]byte(itoa(p)))})
	}
	return s
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// A control-plane Service that selects the same Pod but exposes only an admin port (e.g.
// vllm-admin on 8443) is not an alternate serving route and must not block the drain; a
// second Service that can carry serving traffic (port 8000) still must.
func TestDrainServiceReachesServingPort(t *testing.T) {
	serving := drainSvcWithPorts(8000) // the pinned serving Service
	cases := []struct {
		name string
		svc  vllmServiceState
		want bool
	}{
		{"admin-only-8443", drainSvcWithPorts(8443), false},
		{"serving-8000", drainSvcWithPorts(8000), true},
		{"mixed-8000-and-8443", drainSvcWithPorts(8443, 8000), true},
		{"unrelated-9000", drainSvcWithPorts(9000), false},
		{"no-ports", drainSvcWithPorts(), false},
	}
	servingPort := serving.Spec.Ports[0].Port
	servingTarget := string(serving.Spec.Ports[0].TargetPort)
	for _, tc := range cases {
		if got := drainServiceReachesServingPort(tc.svc, servingPort, servingTarget); got != tc.want {
			t.Fatalf("%s: drainServiceReachesServingPort=%v want %v", tc.name, got, tc.want)
		}
	}
}
