package actuator

import (
	"context"
	"fmt"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	npManagedByLabel  = "app.kubernetes.io/managed-by"
	npManagedByValue  = "phorvex"
	npQuarantineOfKey = "phorvex.ai/quarantine-of"
)

// GCOrphanedQuarantineNPs cannot distinguish canonical protection from a
// foreign label copy without a protected receipt. Only RecoverOperations can
// delete an orphan under current policy authority.
func GCOrphanedQuarantineNPs(context.Context, client.Client, string) (int, error) {
	return 0, fmt.Errorf("quarantine GC requires a protected operation journal")
}
