package defenders

import "runtime"

// isWindows reports whether the harness host is Windows (so the operator binary
// is named manager.exe). Portable: the SAME defender code runs on Linux CI where
// the binary is just "manager".
func isWindows() bool { return runtime.GOOS == "windows" }
