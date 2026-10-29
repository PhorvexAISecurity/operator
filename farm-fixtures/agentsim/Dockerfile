# syntax=docker/dockerfile:1.7
FROM docker.io/library/golang:1.26.1-bookworm@sha256:ab3d6955bbc813a0f3fdf220c1d817dd89c0b3f283777db8ece4a32fe7858edd AS build
WORKDIR /src
COPY farm-fixtures/agentsim/go.mod farm-fixtures/agentsim/main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w -buildid=' -o /out/agent-sim .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/agent-sim /agent-sim
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/agent-sim"]
