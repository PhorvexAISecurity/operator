# Phorvex operator (the deterministic "brain") image.
#
# IMPORTANT — build context must be the REPO ROOT, not phorvex/. Phorvex's go.mod
# has `replace github.com/r6security/phoenix => ../build/phoenix-extended`, so the
# Phoenix module must be present at that exact relative path inside the build. Build
# with:
#     docker build -f deploy/docker/operator.Dockerfile -t <img> .
#
# Go 1.26: both modules declare `go 1.26.1`, so the upstream Phoenix Dockerfile's
# golang:1.24 base is NOT sufficient here.
FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# The replace target must exist before `go mod download` so the local module resolves.
# Copy it first (and whole, since the operator imports its api/v1beta1 types).
COPY build/phoenix-extended/ build/phoenix-extended/

# Cache dependency download on go.mod/go.sum alone.
COPY phorvex/go.mod phorvex/go.mod
COPY phorvex/go.sum phorvex/go.sum
WORKDIR /workspace/phorvex
RUN go mod download

# Now the operator source.
WORKDIR /workspace
COPY phorvex/ phorvex/
WORKDIR /workspace/phorvex

# Static, stripped manager binary. GOARCH left to BuildKit so the binary matches the
# image platform (amd64 on x86 EKS nodes, arm64 on Graviton).
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -a -o /manager cmd/main.go

# Distroless nonroot, matching the chart's runAsNonRoot + readOnlyRootFilesystem.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /manager .
USER 65532:65532
ENTRYPOINT ["/manager"]
