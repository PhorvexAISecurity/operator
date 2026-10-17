#!/usr/bin/env bash
# Lint and regenerate the service contracts under phorvex/api/proto with pinned
# tools. Run from anywhere; requires Go. CI runs it and fails on a diff.
set -euo pipefail
cd "$(dirname "$0")/../phorvex/api/proto"
BUF_VERSION=v1.50.0
PROTOC_GEN_GO_VERSION=v1.36.7
PROTOC_GEN_GO_GRPC_VERSION=v1.5.1
bin="$(mktemp -d)"
trap 'rm -rf "$bin"' EXIT
for tool in "github.com/bufbuild/buf/cmd/buf@$BUF_VERSION" \
  "google.golang.org/protobuf/cmd/protoc-gen-go@$PROTOC_GEN_GO_VERSION" \
  "google.golang.org/grpc/cmd/protoc-gen-go-grpc@$PROTOC_GEN_GO_GRPC_VERSION"; do
  GOBIN="$bin" go install "$tool"
done
export PATH="$bin:$PATH"
buf lint
buf generate
