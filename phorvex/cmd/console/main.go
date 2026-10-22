// Command console serves the operator UI and API. With --attacks-url it forwards the
// attack routes to the attacks service (cmd/attacks); without it, it serves them too
// (ADR-0001, phase 6).
package main

import (
	"os"

	"github.com/phorvex/phorvex/cmd/internal/consoleserver"
	"github.com/phorvex/phorvex/internal/console"
)

func main() {
	os.Exit(consoleserver.Run(console.ServiceConsole))
}
