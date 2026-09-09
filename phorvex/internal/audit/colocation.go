package audit

import "github.com/phorvex/phorvex/internal/model"

// Colocation writes a separate versioned structured-log record. Deliberately do
// not append it to the legacy decision JSONL sink: those readers expect decisions.
// The existing decision record's bytes and schema remain unchanged (M-34 Q4).
func (l *Logger) Colocation(a model.ColocationAssessment) {
	l.log.Info("colocation-assessment", "kind", a.Kind, "schemaVersion", a.SchemaVersion, "decisionID", a.DecisionID, "assessment", a)
}
