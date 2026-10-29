# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM docker.io/library/golang:1.26.1-bookworm@sha256:ab3d6955bbc813a0f3fdf220c1d817dd89c0b3f283777db8ece4a32fe7858edd AS build
ARG SOURCE_DATE_EPOCH
WORKDIR /src
COPY farm-fixtures/agentsim/go.mod farm-fixtures/agentsim/main.go ./
RUN case "${SOURCE_DATE_EPOCH}" in ''|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be an unsigned integer" >&2; exit 1;; esac && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w -buildid=' -o /tmp/agent-sim . && \
    install -D -o 0 -g 0 -m 0555 /tmp/agent-sim /out/agent-sim && \
    touch -d "@${SOURCE_DATE_EPOCH}" /out/agent-sim

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build --chown=0:0 --chmod=0555 /out/agent-sim /agent-sim
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/agent-sim"]
