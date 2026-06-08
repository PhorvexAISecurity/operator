package mocks

// InjectedStepMarker is the artifact an injected CI/CD pipeline step writes. The
// c3-cicd oracle checks the mock pipeline output volume for this artifact.
const InjectedStepMarker = "R6TH-INJECTED-PIPELINE-STEP-RAN"

// MockPipelineScript returns the command a MOCK in-namespace pipeline runner pod
// executes. It runs a few "build" steps and then an INJECTED malicious step that
// tampers the build artifact (writes the injected marker into the output volume).
// This faithfully models a compromised CI/CD build step without touching any real
// pipeline.
//
// outputPath is a file inside a shared emptyDir the oracle later reads.
func MockPipelineScript(outputPath string) []string {
	return []string{"sh", "-c",
		"echo '[pipeline] step 1: checkout'; " +
			"echo '[pipeline] step 2: build'; " +
			"echo '[pipeline] step 3: test'; " +
			"echo '[pipeline] INJECTED step: tamper artifact'; " +
			"echo " + InjectedStepMarker + " > " + outputPath + "; " +
			"echo '[pipeline] done'; sleep 3600",
	}
}
