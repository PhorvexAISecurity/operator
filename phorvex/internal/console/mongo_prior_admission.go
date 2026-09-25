package console

import (
	"errors"
	"strings"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

// mongoPriorAdmissionLocked classifies one retained Voice producer's possible
// effects. It does not reconcile that run or authorize another Voice effect.
// Mongo's reviewed producer creates a fresh, initially absent nonce collection
// and only drops its own UUID after a singleton exact-document check. The old
// Voice producer may use the same Mongo server, but its bounded transcript
// deletion is limited to an existing ObjectId, call SID and content hash.
// Caller holds rm.mu; validation performs bounded private-file reads only.
func (rm *RunManager) mongoPriorAdmissionLocked() error {
	if rm.loadErr != nil {
		return errors.New("retained run state unavailable")
	}
	var unsafe *RunStatus
	for _, prior := range rm.runs {
		if prior == nil {
			return errors.New("retained run status is ambiguous")
		}
		if !prior.UnsafeToRetry {
			continue
		}
		if unsafe != nil {
			return errors.New("more than one unsafe predecessor requires reconciliation")
		}
		unsafe = prior
	}
	if unsafe == nil {
		return nil
	}
	if unsafe.ExecutionKind != "fixed-suite" ||
		(unsafe.Config != string(cataloguev1.VoiceMedia) && unsafe.Config != string(cataloguev1.VoiceRecovery)) ||
		unsafe.State != "partial" || unsafe.Outcome != string(cataloguev1.OutcomeTestFailed) ||
		unsafe.CleanupStatus != "FAIL" || unsafe.Finished == "" || unsafe.Owner == "" ||
		unsafe.ScopeTarget != defaultTargetID || unsafe.ScopeTenant != "voice" ||
		rm.cfg.CatalogueV1.VoiceNamespace != "voice" ||
		rm.procs[unsafe.ID] != nil || rm.stopping[unsafe.ID] ||
		strings.Contains(unsafe.Error, "reconciliation pending") ||
		!cataloguev1.ExecutionLockAvailable(rm.cfg.runOutputPath(unsafe.ID)) {
		return errors.New("unsafe predecessor is not a terminal reviewed Voice producer")
	}
	if err := rm.validatePriorVoiceFiles(unsafe); err != nil {
		return errors.New("unsafe Voice predecessor's original evidence is unavailable or differs")
	}
	return nil
}
