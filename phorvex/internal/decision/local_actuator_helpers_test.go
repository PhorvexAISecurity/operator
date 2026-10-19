package decision

import (
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/actuatorsvc"
	"github.com/phorvex/phorvex/internal/capability"
)

// localActuator puts a backend behind the in-process actuator contract, as the
// runner does, so a capability witness asks it the same questions.
func localActuator(a actuator.Actuator) capability.Actuator {
	if a == nil {
		return nil
	}
	return &actuatorsvc.Local{Actuator: a}
}
