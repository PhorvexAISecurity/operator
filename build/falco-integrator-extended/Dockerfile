# Build the falco-integrator binary.
#
# Build context is the repository `build/` directory, not this module, because
# go.mod replaces github.com/r6security/phoenix with ../phoenix-extended:
#   docker build -f build/falco-integrator-extended/Dockerfile -t <image> build/
FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# The replaced dependency and this module's manifests first so downloads are cached.
COPY phoenix-extended/ phoenix-extended/
COPY falco-integrator-extended/go.mod falco-integrator-extended/go.sum falco-integrator-extended/
WORKDIR /workspace/falco-integrator-extended
RUN go mod download

# Copy the go source (the whole cmd package: main.go, normalize.go)
COPY falco-integrator-extended/cmd/ cmd/
COPY falco-integrator-extended/clients/ clients/
COPY falco-integrator-extended/delivery/ delivery/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o falco-integrator ./cmd

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/falco-integrator-extended/falco-integrator .
USER 65532:65532

ENTRYPOINT ["/falco-integrator"]
