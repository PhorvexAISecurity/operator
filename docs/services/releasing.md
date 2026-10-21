# Versioning the services

Each service is released on its own (ADR-0001): `manager`, `brain`, `sensor`,
`actuator` and `console`, one image each, with tags such as `brain-v0.1.0`.
`phorvex/tools/servicerelease` decides what a release contains.

## What belongs to a service

The services share one Go module, so a change to a shared package belongs to every
service whose binary imports it. A service's **inputs** are:

- the source files of every package its image's binaries import, read from the
  import graph for linux/amd64 without cgo (`go list -deps`), including the shared
  libraries such as `libs/logging`, and the `go.mod` and `go.sum` of their modules;
- its Dockerfile and its chart;
- the other paths its image copies in, such as the console's `dashboard-web`.

Test files, documentation and other services' charts are not inputs. The
component table in `phorvex/tools/servicerelease/components.go` names each
service's image, Dockerfile, chart and binaries. A test checks it against the
Dockerfiles and the PR validation images matrix.

## The next version

A commit is part of a service's next release when it touches one of the service's
inputs. Its conventional-commit type sets the bump:

| Commit | Bump |
|---|---|
| `!` after the type, or a `BREAKING CHANGE:` footer | major (minor before 1.0.0) |
| `feat` | minor |
| anything else | patch: it still changed what the image is built from |

A service's first release takes its initial version: 0.5.0 for the manager and
console, which continue the 0.4.x line, and 0.1.0 for the brain, sensor and
actuator.

```sh
go -C phorvex run ./tools/servicerelease plan            # every service's next version
go -C phorvex run ./tools/servicerelease plan --json     # with its commits
go -C phorvex run ./tools/servicerelease affected --base origin/main
```

PR validation reports the services each change affects in the go-unit job's
summary. Tagging, building and pushing the images, and writing them into
`deploy/environments`, is the release workflow. It needs write access and
registry credentials, so it lands as its own reviewed change.
