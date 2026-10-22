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
//	servicerelease prepare                 write the release PR: versions and changelogs
//	servicerelease pending                 the prepared releases not yet tagged
//	servicerelease deploy                  pin a released image in an environment
//	servicerelease pull-request            open or update the release PR
package main

// Component is one released service: one image, versioned by the tag
// <name>-v<semver>.
type Component struct {
	Name string
	// Image is the name the PR validation images matrix builds it under.
	Image      string
	Dockerfile string
	// Target is the Dockerfile stage its image is, when it is not the last one.
	Target string
	// Chart deploys it; empty when another component's chart does.
	Chart string
	// Builds are the binaries its image compiles, per Go module.
	Builds []Build
	// Paths are the other inputs its image copies in, as repo-relative directories.
	Paths []string
	// Initial is the version of its first release, when it has no tag yet.
	Initial string
	// Repository is its image repository in the release registry.
	Repository string
	// BuildArgs are its image's build arguments; {version} becomes the release version.
	BuildArgs map[string]string
	// Deploy is where an environment pins its image.
	Deploy ImageValues
}

// ImageValues locate a component's image in deploy/environments/<env>/<File>.yaml:
// the key path of the image values and the names of the values the release sets.
type ImageValues struct {
	File       string
	Path       []string
	Repository string
	Tag        string
	Digest     string
	// Source names the value that records the released commit; empty when the chart has none.
	Source string
}

// serviceImage is where a service chart (deploy/charts/phorvex-<name>) takes its image.
func serviceImage(name string) ImageValues {
	return ImageValues{File: name, Path: []string{"image"}, Repository: "repository", Tag: "tag", Digest: "digest"}
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
		Initial:    "0.5.0",
		Repository: "phorvex/manager",
		Deploy: ImageValues{File: "manager", Path: []string{"phorvex", "image"},
			Repository: "repository", Tag: "tag", Digest: "releaseDigest", Source: "releaseSourceSHA"},
	},
	{
		Name: "brain", Image: "brain", Dockerfile: "deploy/docker/service.Dockerfile", Chart: "deploy/charts/phorvex-brain",
		Builds:  []Build{{Module: "phorvex", Packages: []string{"./cmd/brain"}}},
		Initial: "0.1.0", Repository: "phorvex/brain", BuildArgs: map[string]string{"SERVICE": "brain"}, Deploy: serviceImage("brain"),
	},
	{
		Name: "sensor", Image: "sensor", Dockerfile: "deploy/docker/service.Dockerfile", Chart: "deploy/charts/phorvex-sensor",
		Builds:  []Build{{Module: "phorvex", Packages: []string{"./cmd/sensor"}}},
		Initial: "0.1.0", Repository: "phorvex/sensor", BuildArgs: map[string]string{"SERVICE": "sensor"}, Deploy: serviceImage("sensor"),
	},
	{
		Name: "actuator", Image: "actuator", Dockerfile: "deploy/docker/service.Dockerfile", Chart: "deploy/charts/phorvex-actuator",
		Builds:  []Build{{Module: "phorvex", Packages: []string{"./cmd/actuator"}}},
		Initial: "0.1.0", Repository: "phorvex/actuator", BuildArgs: map[string]string{"SERVICE": "actuator"}, Deploy: serviceImage("actuator"),
	},
	{
		// The manager chart deploys the console.
		Name: "console", Image: "console", Dockerfile: "deploy/docker/console.Dockerfile",
		Builds: []Build{
			// The console Dockerfile builds the attacks service too.
			{Module: "phorvex", Packages: []string{"./cmd/console", "./cmd/attacks", "./cmd"}},
			{Module: "build/test-harness", Packages: []string{"./cmd/harness", "./cmd/nats-owned-observer"}},
		},
		// The web UI, and the harness data the image ships under /data.
		Paths:      []string{"dashboard-web", "build/test-harness"},
		Initial:    "0.5.0",
		Repository: "phorvex/console",
		// The console reports the version it was built as.
		BuildArgs: map[string]string{"CONSOLE_VERSION": "{version}"},
		Deploy: ImageValues{File: "manager", Path: []string{"phorvex", "console", "image"},
			Repository: "repository", Tag: "tag", Digest: "releaseDigest", Source: "releaseSourceSHA"},
	},
	{
		// The console's image without the UI, run as cmd/attacks (docs/services/attacks.md).
		Name: "attacks", Image: "attacks", Dockerfile: "deploy/docker/console.Dockerfile", Target: "attacks",
		Chart: "deploy/charts/phorvex-attacks",
		Builds: []Build{
			{Module: "phorvex", Packages: []string{"./cmd/console", "./cmd/attacks", "./cmd"}},
			{Module: "build/test-harness", Packages: []string{"./cmd/harness", "./cmd/nats-owned-observer"}},
		},
		// The harness data the image ships under /data.
		Paths:      []string{"build/test-harness"},
		Initial:    "0.1.0",
		Repository: "phorvex/attacks",
		BuildArgs:  map[string]string{"CONSOLE_VERSION": "{version}"},
		Deploy:     serviceImage("attacks"),
	},
}
