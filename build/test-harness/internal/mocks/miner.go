package mocks

import "fmt"

// MinerScript returns the command for a CPU-BOUNDED mining STAND-IN. It is NEVER
// a real miner and contacts NO pool: it is a fixed-duration busy loop that accrues
// CPU time under a hard CPU limit (set on the container by the PodBuilder). It
// records a monotonically increasing CPU-seconds counter the oracle reads.
//
// The loop does pure arithmetic (no network, no fork bomb) for at most
// maxSeconds wall-clock, writing accrued busy-seconds to /tmp/cpu_seconds every
// second so the oracle can read "CPU-seconds accrued before any rotation".
func MinerScript(maxSeconds int) []string {
	return []string{"sh", "-c", fmt.Sprintf(
		`s=0; `+
			`: > /tmp/cpu_seconds; `+
			`while [ $s -lt %d ]; do `+
			`  end=$(( $(date +%%s) + 1 )); `+
			`  while [ $(date +%%s) -lt $end ]; do : ; done; `+ // busy-wait ~1s (CPU-bounded by the cgroup limit)
			`  s=$((s+1)); echo $s > /tmp/cpu_seconds; `+
			`done; `+
			`while true; do sleep 3600; done`, maxSeconds),
	}
}

// CPUSecondsReadCommand returns the command to read the miner's accrued CPU
// seconds from inside the pod.
func CPUSecondsReadCommand() []string {
	return []string{"sh", "-c", "cat /tmp/cpu_seconds 2>/dev/null || echo 0"}
}
