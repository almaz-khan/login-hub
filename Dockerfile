# The login hub: one Go binary and CA roots (for oauth.telegram.org and the bot API). The database
# lives on the volume at /data; nothing about people is in the image.
# Go pinned by digest (multi-platform index), as in Running Club: a re-pushed tag can't change what gets built.
# To update: docker pull golang:<new>-alpine && docker image inspect golang:<new>-alpine --format '{{index .RepoDigests 0}}'
FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY admin/embed.go admin/
COPY admin/build/ admin/build/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /hub ./cmd/hub && mkdir -p /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /hub /hub
# the volume mounts here; without one (a local run) the directory still belongs to the hub's user
COPY --from=build --chown=65534:65534 /out/data /data
USER 65534:65534
ENV DATA_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/hub"]
