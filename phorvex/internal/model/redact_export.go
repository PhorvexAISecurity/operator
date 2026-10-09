package model

// RedactTraceString applies the decision-trace secret redaction to one string. It is
// exported for exports built outside the trace (Math Lab replay rows) so free-text
// reasons leave the process under the same redaction contract as the trace itself.
func RedactTraceString(s string) string { return redactTraceString(s) }
