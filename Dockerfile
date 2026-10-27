# Builds the dashboard, the server, the optional separate detection service
# (xdr-detect, same image) and the Rust Linux agent that the server hands out
# to installers and agent updates.

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Static (musl) agent, so it runs on any distribution. amd64 only for now:
# arm64 needs a cross C toolchain for ring.
FROM rust:1-alpine AS agent
RUN apk add --no-cache musl-dev
# Slow or lossy links: one connection at a time, longer timeouts, more retries.
ENV CARGO_HTTP_MULTIPLEXING=false CARGO_HTTP_TIMEOUT=300 CARGO_NET_RETRY=10
WORKDIR /src
COPY agent-rs/ ./
ARG VERSION=dev
# A binary dropped in agent-rs/prebuilt/ (for hosts that can't reach
# crates.io) is used as is; otherwise the agent is compiled here.
RUN mkdir -p /out/downloads && \
    if [ -f prebuilt/xdr-agent-linux-amd64 ]; then cp prebuilt/xdr-agent-linux-amd64 /out/downloads/; \
    else XDR_VERSION=${VERSION} cargo build --release --locked -p xdr-agent && \
      cp target/release/xdr-agent /out/downloads/xdr-agent-linux-amd64; fi && \
    cd /out/downloads && sha256sum xdr-agent-linux-* > SHA256SUMS && echo "${VERSION}" > VERSION

FROM golang:1.26-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w" -o /out/xdr-server ./cmd/xdr-server && \
    go build -trimpath -ldflags "-s -w" -o /out/xdr-detect ./cmd/xdr-detect

FROM alpine:3.22
RUN adduser -D -H -u 10001 xdr && mkdir /data && chown xdr /data
COPY --from=go /out/xdr-server /out/xdr-detect /usr/local/bin/
COPY --from=agent /out/downloads /opt/xdr/downloads
COPY --from=web /src/web/dist /opt/xdr/web
ENV XDR_DATA_DIR=/data XDR_WEB_DIR=/opt/xdr/web XDR_DOWNLOADS_DIR=/opt/xdr/downloads
USER xdr
VOLUME /data
EXPOSE 8080 8443 8444
ENTRYPOINT ["/usr/local/bin/xdr-server"]
