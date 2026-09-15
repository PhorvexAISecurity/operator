package actuator

import (
	"context"
	"fmt"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ResumeWarmSwaps is retained for source compatibility. Namespace-wide label
// inference has no administrative policy or operation authority and is refused.
func ResumeWarmSwaps(context.Context, client.Client, string) (int, error) {
	return 0, fmt.Errorf("warm-swap resume requires a protected operation journal")
}
