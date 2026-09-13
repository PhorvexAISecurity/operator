// metricvalidity is deliberately its OWN module, with no dependencies at all.
//
// Both the attack harness (which writes the metric stream) and the Phorvex
// reporters/console (which read it) need the same answer to "may this row be
// used as a measurement?". Making either side import the other would give the
// shipped product a dependency on the test harness, and would drag a whole
// module graph along for one stdlib-only file. A tiny shared module gives them
// one definition and one implementation with neither problem.
//
// Consumers point at it with a local replace directive; a consumer-side replace
// never mutates the dependency.
module github.com/phorvex/metricvalidity

go 1.26.1
