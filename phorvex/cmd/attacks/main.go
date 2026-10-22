// Command attacks is the attacks service (ADR-0001, phase 6): it fires the catalogue
// attacks, runs the harness and serves their evidence, behind the console's
// authentication and authorization boundary. The console forwards these routes here.
package main

import (
	"os"

	"github.com/phorvex/phorvex/cmd/internal/consoleserver"
	"github.com/phorvex/phorvex/internal/console"
)

func main() {
	os.Exit(consoleserver.Run(console.ServiceAttacks))
}
