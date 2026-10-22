// Command servicerelease versions each Phorvex service on its own (ADR-0001).
//
// The services share one Go module, so a change to a shared package belongs to
// every service whose binary imports it, and path rules cannot tell which those
// are. servicerelease reads the import graph instead: a service's inputs are the
// source files of every package its image's binaries import (`go list -deps`),
// its Dockerfile, its chart and the other paths its image copies in. A commit is
// part of a service's next release when it touches one of those inputs, and its
// conventional-commit type decides the version bump.
//
//	servicerelease affected --base <rev>   the services a change affects
//	servicerelease plan                    each service's next version and its commits
package main

// Component is one released service: one image, versioned by the tag
// <name>-v<semver>.
type Component struct {
	Name string
	// Image is the name the PR validation images matrix builds it under.
	Image      string
	Dockerfile string
	// Chart deploys it; empty when another component's chart does.
	Chart string
	// Builds are the binaries its image compiles, per Go module.
	Builds []Build
	// Paths are the other inputs its image copies in, as repo-relative directories.
	Paths []string
	// Initial is the version of its first release, when it has no tag yet.
	Initial string
}

// Build is a set of main packages compiled in one Go module.
type Build struct {
	// Module is the module directory, relative to the repository root.
	Module   string
	Packages []string
}

// Components are the released services, in the order they are reported.
var Components = []Component{
	{
		Name: "manager", Image: "operator", Dockerfile: "deploy/docker/operator.Dockerfile", Chart: "phorvex/charts/phorvex",
		Builds: []Build{{Module: "phorvex", Packages: []string{"./cmd", "./cmd/brain-replay", "./cmd/recovery",
			"./cmd/mig-allocation-helper", "./cmd/loss-observer", "./cmd/current-inventory-observer"}}},
		// Continues the 0.4.x line the manager was released under before the split.
		Initial: "0.5.0",
	},
	{
		Name: "brain", Image: "brain", Dockerfile: "deploy/docker/service.Dockerfile", Chart: "deploy/charts/phorvex-brain",
		Builds:  []Build{{Module: "phorvex", Packages: []string{"./cmd/brain"}}},
		Initial: "0.1.0",
	},
	{
		Name: "sensor", Image: "sensor", Dockerfile: "deploy/docker/service.Dockerfile", Chart: "deploy/charts/phorvex-sensor",
		Builds:  []Build{{Module: "phorvex", Packages: []string{"./cmd/sensor"}}},
		Initial: "0.1.0",
	},
	{
		Name: "actuator", Image: "actuator", Dockerfile: "deploy/docker/service.Dockerfile", Chart: "deploy/charts/phorvex-actuator",
		Builds:  []Build{{Module: "phorvex", Packages: []string{"./cmd/actuator"}}},
		Initial: "0.1.0",
	},
	{
		// The manager chart deploys the console.
		Name: "console", Image: "console", Dockerfile: "deploy/docker/console.Dockerfile",
		Builds: []Build{
			{Module: "phorvex", Packages: []string{"./cmd/console", "./cmd"}},
			{Module: "build/test-harness", Packages: []string{"./cmd/harness", "./cmd/nats-owned-observer"}},
		},
		// The web UI, and the harness data the image ships under /data.
		Paths:   []string{"dashboard-web", "build/test-harness"},
		Initial: "0.5.0",
	},
}
