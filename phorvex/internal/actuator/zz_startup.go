/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * The completeness BINARY-STARTUP backstop. This file is named to sort LEXICALLY LAST so
 * its init() runs AFTER every handler-registering init() (Go runs a package's init()
 * functions in lexical filename order). If any generatable action lacks a native handler,
 * the process panics on startup — the binary cannot run with a completeness gap. (The CI
 * teeth are completeness_test.go; together they make full coverage a build/CI/startup-
 * enforced theorem — though NOT a compile error: `go build` still succeeds.)
 */

package actuator

func init() { mustCoverAllActions() }
