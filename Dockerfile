# The login hub: one Go binary, CA roots (for oauth.telegram.org and the bot API) and the access config.
# Go pinned by digest (multi-platform index), as in Running Club: a re-pushed tag can't change what gets built.
# To update: docker pull golang:<new>-alpine && docker image inspect golang:<new>-alpine --format '{{index .RepoDigests 0}}'
FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /hub .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /hub /hub
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/hub"]
